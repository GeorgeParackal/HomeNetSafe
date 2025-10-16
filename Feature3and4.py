#!/usr/bin/env python3
"""
HomeNetSafe – Feature 3 & 4 Add-On (Risk scan + Device type inference)

Runs enhanced Nmap scans, parses basic risk indicators, probes SSDP (UPnP),
and infers a device_type (camera/phone/printer/pc/server/router/smart-device/unknown).

Works standalone or alongside scan_device.py:
- Reuses live registry + paths if scan_device.py is importable.
- Otherwise loads saved IPs from hns_data, or auto-discovers your /24.

Typical usage:
  python Feature3and4.py --all-known
  python Feature3and4.py --ips 192.168.29.1 192.168.29.160 --threads 3
  python Feature3and4.py --cidr 192.168.29.0/24 --discover --threads 3
"""

from __future__ import annotations
import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# ---- Console colors (cross-platform) ----
try:
    # On Windows terminals, this enables ANSI colors
    import colorama
    colorama.init()
except Exception:
    pass

CLR = {
    "reset": "\033[0m",
    "dim":   "\033[2m",
    "bold":  "\033[1m",
    "green": "\033[32m",
    "yellow":"\033[33m",
    "red":   "\033[31m",
    "cyan":  "\033[36m",
}

def risk_level(indicators: list[str]) -> tuple[str, str]:
    """
    Return (level, color) where level in {'SAFE','CAUTION','RISKY'}.
    - no indicators => SAFE (green)
    - 'cve-'/'exploit' or >=2 indicators => RISKY (red)
    - otherwise => CAUTION (yellow)
    """
    inds = [i.lower() for i in indicators or []]
    if not inds:
        return "SAFE", CLR["green"]
    if "cve-" in " ".join(inds) or "exploit" in inds or len(inds) >= 2:
        return "RISKY", CLR["red"]
    return "CAUTION", CLR["yellow"]


# ----- Try to import Feature 1–2 (scan_device.py) state -----
DEVICE_REGISTRY: Dict[str, dict] = {}
NMAP_DIR: Path
mac_lookup = None

def _fallback_check_nmap_available() -> bool:
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except Exception:
        return False

try:
    import scan_device  # must be in same folder
    DEVICE_REGISTRY = scan_device.device_registry
    NMAP_DIR = scan_device.NMAP_DIR
    mac_lookup = scan_device.mac_lookup
    check_nmap_available = scan_device.check_nmap_available
    nmap_available = check_nmap_available()
except Exception:
    BASE_DIR = Path(__file__).resolve().parent
    DATA_DIR = BASE_DIR / "hns_data"
    NMAP_DIR = DATA_DIR / "nmap"
    NMAP_DIR.mkdir(parents=True, exist_ok=True)
    check_nmap_available = _fallback_check_nmap_available
    nmap_available = check_nmap_available()

# ----- Paths for saved data (standalone use) -----
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "hns_data"
SCANS_DIR = DATA_DIR / "scans"
KNOWN_PATH = DATA_DIR / "known_devices.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)
SCANS_DIR.mkdir(parents=True, exist_ok=True)
NMAP_DIR.mkdir(parents=True, exist_ok=True)

# ========== Helpers ==========
def _auto_detect_cidr() -> str:
    """Auto-detect current /24 using default-route IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except Exception:
        return "192.168.1.0/24"

def _load_known_ips_from_json() -> list[str]:
    """Load IPs from hns_data/known_devices.json or newest hns_data/scans/scan-*.json."""
    ips = []
    try:
        if KNOWN_PATH.exists():
            data = json.loads(KNOWN_PATH.read_text(encoding="utf-8"))
            for rec in data.values():
                ip = rec.get("ip")
                if ip: ips.append(ip)
            return sorted(set(ips))
    except Exception:
        pass
    # fallback: newest scan snapshot
    try:
        scans = sorted(SCANS_DIR.glob("scan-*.json"), reverse=True)
        if scans:
            snap = json.loads(scans[0].read_text(encoding="utf-8"))
            ips.extend(list(snap.keys()))
    except Exception:
        pass
    return sorted(set(ips))

def _ping_cmd(ip: str) -> list[str]:
    return ["ping","-n","1","-w","600",ip] if os.name=="nt" else ["ping","-c","1","-W","1",ip]

def _ping(ip: str) -> bool:
    try:
        return subprocess.run(_ping_cmd(ip), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2).returncode==0
    except Exception:
        return False

def discover_from_cidr(cidr: str, max_workers: int = 64) -> list[str]:
    """Quick ping discovery to build a target list when running standalone."""
    net = ipaddress.ip_network(cidr, strict=False)
    candidates = [str(h) for h in net.hosts()]
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_ping, ip): ip for ip in candidates}
        for fut in as_completed(futs):
            if fut.result(): alive.append(futs[fut])
    return sorted(alive)

# ========== SSDP probe ==========
def run_ssdp_probe(timeout: float = 1.0) -> Dict[str, List[str]]:
    """Send SSDP M-SEARCH and collect responses: {ip: [raw lines,...]}"""
    results: Dict[str, List[str]] = {}
    msg = '\r\n'.join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        'MX: 1',
        'ST: ssdp:all',
        '', ''
    ]).encode('utf-8')

    addr = ('239.255.255.255', 1900)  # unicast-friendly on some nets; 239.255.255.250 also fine
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.sendto(msg, addr)
        t0 = time.time()
        while True:
            try:
                data, (rip, _) = sock.recvfrom(4096)
                lines = data.decode(errors='replace').splitlines()
                results.setdefault(rip, []).extend(lines)
            except socket.timeout:
                break
            if time.time() - t0 > timeout:
                break
    except Exception:
        pass
    finally:
        try: sock.close()
        except: pass
    return results

# ========== Parse Nmap text for ports/banners/risks ==========
RISK_KEYWORDS = [
    'vulnerable', 'default password', 'weak password', 'authentication required',
    'anonymous', 'exposed', 'backdoor', 'cve-', 'exploit'
]

def parse_nmap_risks(nmap_text: str) -> Dict[str, Any]:
    open_ports: List[tuple] = []
    banners: List[str] = []
    indicators = set()

    for line in nmap_text.splitlines():
        # Typical: "22/tcp open ssh OpenSSH 8.9p1 Ubuntu ..."
        m = re.search(r'^(\d+)\/(tcp|udp)\s+open\s+([\w\-\+\.]+)(?:\s+(.*))?$', line.strip(), re.I)
        if m:
            port = f"{m.group(1)}/{m.group(2)}"
            svc = m.group(3) or ''
            banner = (m.group(4) or '').strip()
            open_ports.append((port, svc, banner))
            if banner:
                banners.append(banner)
                low = banner.lower()
                for kw in RISK_KEYWORDS:
                    if kw in low: indicators.add(kw)
        low_line = line.lower()
        for kw in RISK_KEYWORDS:
            if kw in low_line: indicators.add(kw)
        m2 = re.search(r'http/[\d.]+.*server:\s*(.*)', line, re.I)
        if m2:
            banners.append(m2.group(1).strip())

    return {"open_ports": open_ports, "banners": banners, "risk_indicators": sorted(indicators)}

# ========== Device type inference (heuristic) ==========
def identify_device_type(ip: str, vendor: str | None, nmap_text: str, ssdp_lines: List[str]) -> str:
    vt = (vendor or "").lower()
    txt = nmap_text.lower()
    ssdp_txt = "\n".join(ssdp_lines).lower() if ssdp_lines else ""

    if ssdp_lines:
        if re.search(r'rtsp|onvif|camera|surveillance', txt): return "camera"
        if re.search(r'sonos|spotify|_googlecast|_airplay|dlna', txt + ssdp_txt): return "speaker"
        if re.search(r'philips|hue|lifx|tplink|yeelight', vt + ssdp_txt): return "smart-bulb"
        return "smart-device"

    if re.search(r'(^|[\s/])554/tcp|rtsp|onvif', txt): return "camera"
    if re.search(r'9100/tcp|ipp|printer', txt) or any(v in vt for v in ['hp inc.', 'brother', 'epson']): return "printer"
    if any(x in vt for x in ['apple', 'iphone', 'ipad', 'samsung', 'huawei', 'oneplus', 'xiaomi']): return "phone"
    if 'microsoft' in vt or re.search(r'3389/tcp|rdp|smb|workstation|windows', txt): return "pc"
    if any(x in vt for x in ['cisco', 'netgear', 'mikrotik', 'ubiquiti', 'tp-link']) or 'router' in txt: return "router"
    if re.search(r'22/tcp.*open.*ssh', txt) and re.search(r'(80|443)/tcp.*open.*http', txt): return "server"
    return "unknown"

# ========== Enhanced Nmap ==========
def enhanced_nmap_scan(ip: str, extra_args: Optional[List[str]] = None, ssdp_timeout: float = 1.0) -> bool:
    """Run -sV -sC -O (plus UDP-ish ports 1900/5353 via text parse), SSDP probe, parse risks, update registry."""
    if not nmap_available:
        print(f"[WARN] nmap not available; skipping {ip}")
        return False

    extra_args = extra_args or []
    timestamp = datetime.now().strftime('%Y%m%dT%H%M%S')
    out_file = NMAP_DIR / f"nmap-{ip.replace('.', '-')}-{timestamp}.txt"
    # Note: We include -sV -sC -O -Pn and a reasonable port range for speed.
    cmd = ["nmap", "-sV", "-sC", "-O", "-Pn", "-p", "1-1024,1900,5353", ip] + extra_args

    try:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"Command: {' '.join(cmd)}\n\n")
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
            nmap_text = proc.stdout or ""
            f.write(nmap_text)

            # SSDP probe
            ssdp_map = run_ssdp_probe(timeout=ssdp_timeout)
            ssdp_lines = ssdp_map.get(ip, [])

            # Risks
            risks = parse_nmap_risks(nmap_text)
            f.write("\n--- Risk Summary ---\n")
            f.write(f"Open ports: {risks['open_ports']}\n")
            f.write(f"Risk indicators: {risks['risk_indicators']}\n")

            # Device type
            vendor = DEVICE_REGISTRY.get(ip, {}).get("vendor", "") if DEVICE_REGISTRY.get(ip) else ""
            dtype = identify_device_type(ip, vendor, nmap_text, ssdp_lines)
            f.write(f"\n--- Inferred Device Type: {dtype} ---\n")

        # Merge into registry
        rec = DEVICE_REGISTRY.setdefault(ip, {"ip": ip, "status": "online", "first_seen": timestamp, "last_seen": timestamp})
        rec["last_nmap"] = timestamp
        rec["device_type"] = dtype
        rec["risks"] = risks
        return True
    except Exception as e:
        print(f"[ERROR] Enhanced Nmap failed for {ip}: {e}")
        return False

def enhanced_nmap_parallel(ips: List[str], threads: int = 4, extra_args: Optional[List[str]] = None):
    if not ips:
        print("[i] No IPs provided for Feature 3/4."); return
    if not nmap_available:
        print("[WARN] nmap not available."); return

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Feature 3/4: enhanced Nmap scanning {len(ips)} host(s)...")
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futs = [ex.submit(enhanced_nmap_scan, ip, extra_args) for ip in ips]
        for fut in as_completed(futs):
            try: fut.result()
            except Exception as e: print(f"[ERROR] task: {e}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Feature 3/4 completed.")

# ========== CLI ==========
def parse_args():
    p = argparse.ArgumentParser(description="HomeNetSafe Feature 3 & 4 (Risk scan + Device type)")
    p.add_argument("--all-known", action="store_true", help="Use IPs from hns_data/known_devices.json or latest scan (and any live registry)")
    p.add_argument("--ips", nargs="*", help="Specific IPs to analyze")
    p.add_argument("--threads", type=int, default=4, help="Parallel Nmap threads (default 4)")
    p.add_argument("--extra-nmap-args", nargs="*", default=[], help="Extra args to append to Nmap (optional)")
    p.add_argument("--cidr", help="If given with --discover, ping-scan this subnet (e.g., 192.168.29.0/24)")
    p.add_argument("--discover", action="store_true", help="Ping discover from --cidr when no targets yet")
    return p.parse_args()

def main():
    args = parse_args()
    targets: list[str] = []

    # 1) live registry from scan_device (if available)
    try:
        if DEVICE_REGISTRY:
            targets.extend(DEVICE_REGISTRY.keys())
    except Exception:
        pass

    # 2) explicit IPs
    if args.ips:
        targets.extend(args.ips)

    # 3) saved data
    if args.all_known:
        targets.extend(_load_known_ips_from_json())

    # 4) optional discovery
    if args.discover and args.cidr:
        print(f"[i] Discovering alive hosts in {args.cidr} ...")
        targets.extend(discover_from_cidr(args.cidr))

    # ---- Auto fallback for “Run” with no args ----
    targets = sorted({t for t in targets if t and re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', t)})
    if not targets:
        # Try saved known IPs
        targets = _load_known_ips_from_json()
    if not targets:
        # Last resort: auto-discover current /24
        cidr = _auto_detect_cidr()
        print(f"[i] No explicit targets; discovering alive hosts in {cidr} ...")
        targets = discover_from_cidr(cidr)
    if not targets:
        print("[i] Still no targets found. Are you on the right network?")
        return

    try: NMAP_DIR.mkdir(parents=True, exist_ok=True)
    except Exception: pass

    enhanced_nmap_parallel(targets, threads=args.threads, extra_args=args.extra_nmap_args)

    # ----- Color-coded summary table -----
    print("\n" + CLR["bold"] + "Feature 3/4 — Risk & Type Summary" + CLR["reset"])
    border = "─" * 78
    print("┌" + border + "┐")
    header = f"│ {'IP':15} │ {'Type':14} │ {'Open Ports':10} │ {'Indicators':24} │ {'Risk':7} │"
    print(header)
    print("├" + border + "┤")

    for ip in sorted(set(targets), key=lambda x: tuple(int(p) for p in x.split("."))):
        rec = DEVICE_REGISTRY.get(ip, {}) or {}
        dtype = rec.get("device_type", "unknown")
        risks = rec.get("risks", {}) or {}
        ports = risks.get("open_ports", []) or []
        words = risks.get("risk_indicators", []) or []

        # risk evaluation
        level, col = risk_level(words)
        inds_str = ", ".join(words) if words else "-"

        # type tint: highlight known types a bit
        type_col = CLR["cyan"] if dtype != "unknown" else CLR["dim"]
        type_txt = f"{type_col}{dtype:14}{CLR['reset']}"
        risk_txt = f"{col}{level:7}{CLR['reset']}"

        row = (
            f"│ {ip:15} │ "
            f"{type_txt} │ "
            f"{len(ports):10d} │ "
            f"{inds_str[:24]:24} │ "
            f"{risk_txt} │"
        )
        print(row)

    print("└" + border + "┘")


if __name__ == "__main__":
    main()
