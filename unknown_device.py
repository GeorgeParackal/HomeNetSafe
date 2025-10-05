#!/usr/bin/env python3
"""
risk_scan.py  — Feature #2: Risk Scan (auto-detects local /24 if no target given)

- If you provide an IP/CIDR or --targets file, it scans that.
- If you provide nothing, it auto-detects your primary local IPv4 and assumes /24 (fast + practical).
- Uses nmap (if installed) for service detection, else a fast TCP connect scan.
- Flags simple, explainable risks (Telnet/FTP/SMB/RDP, HTTP w/o HTTPS, etc.).
"""

from __future__ import annotations
import argparse, ipaddress, json, shutil, socket, subprocess, sys, time, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

# --------- Config knobs ----------
DEFAULT_TOP_PORTS = 100
FALLBACK_COMMON_PORTS = [
    21,22,23,25,53,80,110,139,143,161,389,443,445,465,587,631,802,853,
    990,993,995,1900,3306,3389,5000,5432,554,5900,6379,8000,8008,8080,8443,9000,9100
]
CONNECT_TIMEOUT = 0.6
WORKERS = 200

# --------- Risk rules ----------
RISK_RULES = [
    dict(check=lambda p,svc: p==23, title="Telnet open",
         explanation="Port 23 is open (Telnet), which is unencrypted.", remediation="Disable Telnet; use SSH (22)."),
    dict(check=lambda p,svc: p==21, title="FTP open",
         explanation="Port 21 is open (FTP), credentials are sent in plaintext.", remediation="Use SFTP/FTPS or restrict."),
    dict(check=lambda p,svc: p==445, title="SMB exposed",
         explanation="Port 445 (SMB) is open; may expose file shares.", remediation="Restrict to LAN; require auth; patch."),
    dict(check=lambda p,svc: p==3389, title="RDP exposed",
         explanation="Port 3389 (RDP) is open; brute-force target.", remediation="Restrict to VPN; enable MFA; strong creds."),
    dict(check=lambda p,svc: p==5900, title="VNC exposed",
         explanation="Port 5900 (VNC) is open and often unencrypted.", remediation="Tunnel over SSH or disable if not needed."),
]

def add_composite_risks(open_tcp_ports: set, risks: List[Dict]) -> None:
    if 80 in open_tcp_ports and 443 not in open_tcp_ports:
        risks.append(dict(
            title="HTTP without HTTPS",
            explanation="HTTP (80) open but HTTPS (443) closed; traffic may be unencrypted.",
            remediation="Enable HTTPS (443) and force redirect."
        ))
    if 1900 in open_tcp_ports:
        risks.append(dict(
            title="SSDP/UPnP potentially exposed",
            explanation="Port 1900 suggests SSDP/UPnP; can leak info or allow NAT changes.",
            remediation="Disable UPnP on the router or restrict to trusted hosts."
        ))

# --------- Helpers ----------
def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def detect_local_cidr() -> Optional[str]:
    """
    Cross-platform best-effort:
    - Get primary local IPv4 via UDP socket trick
    - Try to parse mask via `ip -o -4 addr show` (Linux) / `ipconfig` (Windows) / `ifconfig` (macOS/BSD)
    - Fallback to /24 if mask cannot be parsed
    """
    # Get primary local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        return None

    # Try Linux: ip -o -4
    if have("ip"):
        try:
            out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True)
            for line in out.splitlines():
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if m and m.group(1) == ip:
                    pref = int(m.group(2))
                    return str(ipaddress.ip_network(f"{ip}/{pref}", strict=False))
        except Exception:
            pass

    # Windows: ipconfig
    if sys.platform.startswith("win"):
        try:
            out = subprocess.check_output(["ipconfig"], text=True, encoding="oem", errors="ignore")
            blocks = re.split(r"\r?\n\r?\n", out)
            for b in blocks:
                if ip in b:
                    m_mask = re.search(r"Subnet\s+Mask[^\d]+((\d{1,3}\.){3}\d{1,3})", b)
                    if m_mask:
                        mask = m_mask.group(1)
                        pref = dotted_mask_to_prefix(mask)
                        if pref is not None:
                            return str(ipaddress.ip_network(f"{ip}/{pref}", strict=False))
        except Exception:
            pass

    # macOS/BSD: ifconfig
    try:
        out = subprocess.check_output(["ifconfig", "-a"], text=True, stderr=subprocess.DEVNULL)
        # look for the block that mentions our IP, and its netmask (hex or dotted)
        blocks = re.split(r"\n(?=[^\s])", out)
        for blk in blocks:
            if re.search(rf"\binet\s+{re.escape(ip)}\b", blk):
                m = re.search(r"netmask\s+([0-9A-Fa-fx\.]+)", blk)
                if m:
                    pref = mask_to_prefix(m.group(1))
                    if pref is not None:
                        return str(ipaddress.ip_network(f"{ip}/{pref}", strict=False))
    except Exception:
        pass

    # Fallback: assume /24
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except Exception:
        return None

def dotted_mask_to_prefix(mask: str) -> Optional[int]:
    try:
        parts = [int(p) for p in mask.split(".")]
        if len(parts) != 4: return None
        bits = "".join(f"{p:08b}" for p in parts)
        if "01" in bits: return None
        return bits.count("1")
    except Exception:
        return None

def mask_to_prefix(mask: str) -> Optional[int]:
    mask = mask.strip().lower()
    if mask.startswith("0x"):
        try:
            val = int(mask, 16)
            return bin(val).count("1")
        except Exception:
            return None
    return dotted_mask_to_prefix(mask)

def expand_targets(ip_or_cidr: Optional[str], targets_file: Optional[str]) -> List[str]:
    ips: List[str] = []
    if ip_or_cidr:
        if "/" in ip_or_cidr:
            net = ipaddress.ip_network(ip_or_cidr, strict=False)
            ips.extend([str(h) for h in net.hosts()])
        else:
            ips.append(ip_or_cidr)
    if targets_file:
        with open(targets_file, "r", encoding="utf-8") as f:
            for line in f:
                t = line.strip()
                if not t or t.startswith("#"):
                    continue
                if "/" in t:
                    net = ipaddress.ip_network(t, strict=False)
                    ips.extend([str(h) for h in net.hosts()])
                else:
                    ips.append(t)
    # de-dupe preserve order
    seen = set(); out=[]
    for ip in ips:
        if ip not in seen:
            seen.add(ip); out.append(ip)
    return out

# --------- Scanning backends ----------
def nmap_scan_host(ip: str, top_ports: int = DEFAULT_TOP_PORTS) -> Dict:
    cmd = ["nmap", "-sV", "--top-ports", str(top_ports), "-oX", "-", ip]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=120)
    except subprocess.CalledProcessError:
        return {"open": []}
    except subprocess.TimeoutExpired:
        return {"open": []}
    import xml.etree.ElementTree as ET
    root = ET.fromstring(out)
    open_ports = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        proto = port.attrib.get("protocol", "tcp")
        portid = int(port.attrib.get("portid"))
        svc = port.find("service")
        name = svc.attrib.get("name") if svc is not None else ""
        product = svc.attrib.get("product") if (svc is not None and "product" in svc.attrib) else None
        version = svc.attrib.get("version") if (svc is not None and "version" in svc.attrib) else None
        open_ports.append({"port": portid, "service": name, "product": product, "version": version, "proto": proto})
    return {"open": open_ports}

def socket_scan_host(ip: str, ports: List[int], timeout: float = CONNECT_TIMEOUT) -> Dict:
    open_ports = []
    for p in ports:
        try:
            with socket.create_connection((ip, p), timeout=timeout):
                open_ports.append({"port": p, "service": "", "product": None, "version": None, "proto": "tcp"})
        except Exception:
            pass
    return {"open": open_ports}

# --------- Risk evaluation ----------
def evaluate_risks(open_entries: List[Dict]) -> List[Dict]:
    ports_tcp = {e["port"] for e in open_entries if e.get("proto","tcp") == "tcp"}
    risks: List[Dict] = []
    for e in open_entries:
        p = e["port"]; svc = (e.get("service") or "").lower()
        for rule in RISK_RULES:
            try:
                if rule["check"](p, svc):
                    risks.append({
                        "title": rule["title"],
                        "explanation": rule["explanation"],
                        "remediation": rule["remediation"]
                    })
            except Exception:
                continue
    add_composite_risks(ports_tcp, risks)
    # de-dupe by title
    seen=set(); uniq=[]
    for r in risks:
        if r["title"] in seen: continue
        seen.add(r["title"]); uniq.append(r)
    return uniq

# --------- Orchestration ----------
def scan_many(ips: List[str], use_nmap: bool, top_ports: int, workers: int,
              timeout: float) -> List[Dict]:
    results = []
    def _scan(ip: str) -> Dict:
        finding = nmap_scan_host(ip, top_ports) if use_nmap else socket_scan_host(ip, FALLBACK_COMMON_PORTS, timeout)
        risks = evaluate_risks(finding["open"])
        return {"target": ip, "open": finding["open"], "risks": risks}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futmap = {ex.submit(_scan, ip): ip for ip in ips}
        for fut in as_completed(futmap):
            ip = futmap[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"target": ip, "error": str(e), "open": [], "risks": []})
    return results

# --------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="HomeNetSafe Risk Scanner (auto-detects local /24 if no target).")
    ap.add_argument("target", nargs="?", help="A single IP or CIDR (e.g., 192.168.1.10 or 192.168.1.0/24)")
    ap.add_argument("--targets", help="Path to a file containing IPs/CIDRs (one per line)")
    ap.add_argument("--top-ports", type=int, default=DEFAULT_TOP_PORTS, help="nmap --top-ports value [default: 100]")
    ap.add_argument("--timeout", type=float, default=CONNECT_TIMEOUT, help="Socket connect timeout [default: 0.6]")
    ap.add_argument("--workers", type=int, default=WORKERS, help="Parallel workers [default: 200]")
    ap.add_argument("--save", help="Save JSON output to a file")
    ap.add_argument("--force-fallback", action="store_true", help="Force pure-Python (no nmap) even if nmap is installed")
    args = ap.parse_args()

    # Build target list (with auto-detect if user gave nothing)
    ips = expand_targets(args.target, args.targets)
    autodetected = None
    if not ips:
        autodetected = detect_local_cidr()
        if not autodetected:
            print("ERROR: Provide a target IP/CIDR or --targets file, and I couldn't auto-detect your network.", file=sys.stderr)
            sys.exit(2)
        print(f"[auto] No target provided — scanning your local network: {autodetected}", file=sys.stderr)
        ips = expand_targets(autodetected, None)

    # Choose backend
    use_nmap = (not args.force_fallback) and have("nmap")

    # Scan
    results = scan_many(ips, use_nmap, args.top_ports, args.workers, args.timeout)

    # Output
    output = {
        "meta": {
            "nmap_used": use_nmap,
            "top_ports": (args.top_ports if use_nmap else None),
            "timeout": args.timeout,
            "workers": args.workers,
            "targets": len(ips),
            "autodetected": autodetected
        },
        "results": results
    }
    text = json.dumps(output, indent=2)
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)

if __name__ == "__main__":
    main()
