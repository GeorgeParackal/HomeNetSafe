#!/usr/bin/env python3
"""
HomeNetSafe – Feature 3 & 4 (Risk scan + Device type inference)
Auto-detects the current network (CIDR + default interface) and runs a fast pipeline:
  ping (parallel) -> ARP (best-effort) -> enhanced nmap (parallel)

Works standalone or by reusing scan_device.py state/persistence.
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
from typing import Dict, List, Any, Optional, Set

# ---- Console colors ----
try:
    import colorama
    colorama.init()
except Exception:
    pass

CLR = {"reset":"\033[0m","dim":"\033[2m","bold":"\033[1m","green":"\033[32m","yellow":"\033[33m","red":"\033[31m","cyan":"\033[36m"}

# ---- Try to import Feature 1–2 state ----
DEVICE_REGISTRY: Dict[str, dict] = {}
NMAP_DIR: Path
mac_lookup = None
check_nmap_available = None
save_registry_fn = None
ping_sweep_fn = None
arp_scan_fn = None

def _fallback_check_nmap_available() -> bool:
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except Exception:
        return False

try:
    import scan_device  # type: ignore
    DEVICE_REGISTRY = scan_device.device_registry
    NMAP_DIR = scan_device.NMAP_DIR
    mac_lookup = getattr(scan_device, "mac_lookup", None)
    check_nmap_available = getattr(scan_device, "check_nmap_available", _fallback_check_nmap_available)
    save_registry_fn = getattr(scan_device, "save_registry", None)
    ping_sweep_fn = getattr(scan_device, "ping_sweep", None)
    arp_scan_fn = getattr(scan_device, "arp_scan", None)
    nmap_available = check_nmap_available()
except Exception:
    BASE_DIR = Path(__file__).resolve().parent
    DATA_DIR = BASE_DIR / "hns_data"
    NMAP_DIR = DATA_DIR / "nmap"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    NMAP_DIR.mkdir(parents=True, exist_ok=True)
    check_nmap_available = _fallback_check_nmap_available
    nmap_available = check_nmap_available()

# ----- Data paths -----
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "hns_data"
SCANS_DIR = DATA_DIR / "scans"
KNOWN_PATH = DATA_DIR / "known_devices.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)
SCANS_DIR.mkdir(parents=True, exist_ok=True)
NMAP_DIR.mkdir(parents=True, exist_ok=True)

# --- Vendor sets ---
ROUTER_VENDORS = {"asus","asustek","netgear","tp-link","tplink","d-link","dlink","mikrotik","ubiquiti","cisco","arris","technicolor","sagemcom","zyxel","arcadyan","commscope","hitron","humax"}
PRINTER_VENDORS = {"hp","hewlett","brother","epson","canon","ricoh","kyocera","lexmark"}
CAMERA_VENDORS  = {"hikvision","dahua","lorex","amcrest","axis","reolink","uniview"}

# ---- Risk parsing ----
RISK_KEYWORDS = ['vulnerable','default password','weak password','authentication required','anonymous','exposed','backdoor','cve-','exploit']

def risk_level(indicators: list[str]) -> tuple[str, str]:
    inds = [i.lower() for i in (indicators or [])]
    if not inds: return "SAFE", CLR["green"]
    text = " ".join(inds)
    if "cve-" in text or "exploit" in inds or len(inds) >= 2: return "RISKY", CLR["red"]
    return "CAUTION", CLR["yellow"]

def _open_port_set(risks: dict) -> set[int]:
    s = set()
    for p, _, _ in risks.get("open_ports", []):
        s.add(int(p.split("/")[0]))
    return s

# ---- Auto network detect ----
def _get_local_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def auto_detect_cidr() -> str:
    ip = _get_local_ip()
    if not ip:
        return "192.168.1.0/24"
    try:
        return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except Exception:
        return "192.168.1.0/24"

def auto_detect_interface() -> Optional[str]:
    try:
        from scapy.all import conf  # type: ignore
        val = conf.route.route("0.0.0.0")[0]
        return val.decode() if isinstance(val, bytes) else val
    except Exception:
        return "Wi-Fi"

# ---- Fallback ping/ARP if scan_device helpers missing ----
def _ping_cmd(ip: str) -> list[str]:
    return ["ping","-n","1","-w","600",ip] if os.name=="nt" else ["ping","-c","1","-W","1",ip]

def _ping(ip: str) -> bool:
    try:
        return subprocess.run(_ping_cmd(ip), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2).returncode==0
    except Exception:
        return False

def parallel_ping(cidr: str, max_workers: int = 200) -> List[str]:
    if ping_sweep_fn:
        try:
            return sorted(ping_sweep_fn(cidr))
        except Exception:
            pass
    net = ipaddress.ip_network(cidr, strict=False)
    candidates = [str(h) for h in net.hosts()]
    alive: List[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_ping, ip): ip for ip in candidates}
        for fut in as_completed(futs):
            try:
                if fut.result(): alive.append(futs[fut])
            except Exception:
                pass
    return sorted(alive)

def collect_arp(cidr: str, interface: Optional[str] = None, timeout: int = 2) -> Dict[str, str]:
    if arp_scan_fn:
        try:
            return arp_scan_fn(interface or "Wi-Fi", cidr, timeout=timeout)
        except Exception:
            pass
    try:
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
        conf.verb = 0
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr), timeout=timeout, inter=0.1, verbose=False)
        return {pack.psrc: pack.hwsrc.lower() for _, pack in ans}
    except Exception:
        return {}

# ---- SSDP ----
def run_ssdp_probe(timeout: float = 0.8) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    msg = '\r\n'.join([
        'M-SEARCH * HTTP/1.1','HOST: 239.255.255.250:1900','MAN: "ssdp:discover"','MX: 1','ST: ssdp:all','',''
    ]).encode('utf-8')
    addr = ('239.255.255.250', 1900)
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

# ---- Parse Nmap output ----
def parse_nmap_risks(nmap_text: str) -> Dict[str, Any]:
    open_ports: List[tuple] = []
    banners: List[str] = []
    indicators = set()
    for line in nmap_text.splitlines():
        m = re.search(r'^(\d+)\/(tcp|udp)\s+open\s+([\w\-\+\.]+)(?:\s+(.*))?$', line.strip(), re.I)
        if m:
            port = f"{m.group(1)}/{m.group(2)}"
            svc = m.group(3) or ''
            banner = (m.group(4) or '').strip()
            open_ports.append((port, svc, banner))
            if banner:
                low = banner.lower()
                banners.append(banner)
                for kw in RISK_KEYWORDS:
                    if kw in low: indicators.add(kw)
        low_line = line.lower()
        for kw in RISK_KEYWORDS:
            if kw in low_line: indicators.add(kw)
        m2 = re.search(r'http/[\d.]+.*server:\s*(.*)', line, re.I)
        if m2:
            banners.append(m2.group(1).strip())
    return {"open_ports": open_ports, "banners": banners, "risk_indicators": sorted(indicators)}

# ---- Type inference ----
def identify_device_type_scored(ip: str, vendor: Optional[str], risks: dict, ssdp_lines: List[str], is_gateway: bool, nmap_text: str) -> str:
    v = (vendor or "").lower()
    ports = _open_port_set(risks)
    banners = " ".join(risks.get("banners", [])).lower() + " " + nmap_text.lower()
    ssdp_txt = "\n".join(ssdp_lines or []).lower()
    scores = {"router":0.0,"printer":0.0,"camera":0.0,"pc":0.0,"server":0.0,"phone":0.0,"smart-device":0.0}
    if is_gateway: scores["router"] += 1.2
    if any(k in v for k in ROUTER_VENDORS): scores["router"] += 0.8
    if ports & {80,443,53,1900,500,4500,7547,8080,8443,8888}: scores["router"] += 0.6
    if "upnp" in banners or "igd" in banners or "router" in banners: scores["router"] += 0.4
    if ports & {9100,515,631}: scores["printer"] += 0.6
    if any(k in v for k in PRINTER_VENDORS) or "printer" in banners or "ipp/" in banners: scores["printer"] += 0.6
    if ports & {554,8554} or "rtsp" in banners or "onvif" in banners: scores["camera"] += 0.8
    if any(k in v for k in CAMERA_VENDORS): scores["camera"] += 0.5
    if ports & {3389,445} or "windows" in banners or "workstation" in banners or "smb" in banners: scores["pc"] += 0.8
    if any(x in v for x in ["apple","iphone","ipad","samsung","huawei","oneplus","xiaomi","google, inc."]): scores["phone"] += 0.7
    if 22 in ports and (80 in ports or 443 in ports) and scores["router"] < 0.9: scores["server"] += 0.7
    if ssdp_lines:
        if re.search(r'_googlecast|_airplay|dlna|sonos|spotify', ssdp_txt): scores["smart-device"] += 0.9
        else: scores["smart-device"] += 0.5
    best_type, best_score = max(scores.items(), key=lambda kv: kv[1])
    return best_type if best_score >= 0.85 else "unknown"

# ---- Enhanced Nmap per host ----
def _default_gateway_ip(cidr_hint: Optional[str] = None) -> Optional[str]:
    try:
        from scapy.all import conf as _scapy_conf  # type: ignore
        gw = _scapy_conf.route.route("0.0.0.0")[2]
        if gw: return gw
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]; s.close()
        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(list(net.hosts())[0])
    except Exception:
        pass
    try:
        if cidr_hint:
            net = ipaddress.ip_network(cidr_hint, strict=False)
            return str(list(net.hosts())[0])
    except Exception:
        pass
    return None

def enhanced_nmap_scan(ip: str, extra_args: Optional[List[str]] = None, ssdp_timeout: float = 0.8) -> bool:
    if not nmap_available:
        print(f"[WARN] nmap not available; skipping {ip}")
        return False
    extra_args = extra_args or []
    timestamp = datetime.now().strftime('%Y%m%dT%H%M%S')
    out_file = NMAP_DIR / f"nmap-{ip.replace('.', '-')}-{timestamp}.txt"
    cmd = ["nmap", "-sV", "-sC", "-O", "-Pn", "-p", "1-1024,1900,5353", ip] + extra_args
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"Command: {' '.join(cmd)}\n\n")
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
            nmap_text = proc.stdout or ""
            f.write(nmap_text)
            ssdp_map = run_ssdp_probe(timeout=ssdp_timeout)
            ssdp_lines = ssdp_map.get(ip, [])
            risks = parse_nmap_risks(nmap_text)
            f.write("\n--- Risk Summary ---\n")
            f.write(f"Open ports: {risks['open_ports']}\n")
            f.write(f"Risk indicators: {risks['risk_indicators']}\n")
            vendor = DEVICE_REGISTRY.get(ip, {}).get("vendor", "") if DEVICE_REGISTRY.get(ip) else ""
            gw_ip = _default_gateway_ip()
            is_gateway = (gw_ip == ip)
            if is_gateway:
                f.write(f"[i] Default gateway detected: {ip} (biasing to router)\n")
            dtype = identify_device_type_scored(ip, vendor, risks, ssdp_lines, is_gateway, nmap_text)
            f.write(f"\n--- Inferred Device Type: {dtype} ---\n")
        rec = DEVICE_REGISTRY.setdefault(ip, {"ip": ip, "status": "online", "first_seen": timestamp, "last_seen": timestamp})
        rec["last_nmap"] = timestamp
        rec["device_type"] = dtype
        rec["risks"] = risks
        try:
            if save_registry_fn:
                save_registry_fn()
        except Exception:
            pass
        return True
    except Exception as e:
        print(f"[ERROR] Enhanced Nmap failed for {ip}: {e}")
        return False

def enhanced_nmap_parallel(ips: List[str], threads: int = 8, extra_args: Optional[List[str]] = None):
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

# ---- Known IP helpers ----
def _load_known_ips_from_json() -> list[str]:
    ips: List[str] = []
    try:
        if KNOWN_PATH.exists():
            data = json.loads(KNOWN_PATH.read_text(encoding="utf-8"))
            for rec in data.values():
                ip = rec.get("ip")
                if ip: ips.append(ip)
            return sorted(set(ips))
    except Exception:
        pass
    try:
        scans = sorted(SCANS_DIR.glob("scan-*.json"), reverse=True)
        if scans:
            snap = json.loads(scans[0].read_text(encoding="utf-8"))
            ips.extend(list(snap.keys()))
    except Exception:
        pass
    return sorted(set(ips))

# ---- CLI & main ----
def parse_args():
    p = argparse.ArgumentParser(description="HomeNetSafe Feature 3 & 4 (Risk scan + Device type)")
    p.add_argument("--all-known", action="store_true")
    p.add_argument("--ips", nargs="*")
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--extra-nmap-args", nargs="*", default=[])
    p.add_argument("--cidr", help="Optional override (e.g., 192.168.29.0/24)")
    p.add_argument("--discover", action="store_true", help="Force discovery even if targets exist")
    p.add_argument("--interface", type=str, default=None, help="ARP interface override")
    return p.parse_args()

def main():
    args = parse_args()
    targets: Set[str] = set()

    # Auto detect local env first
    local_ip = _get_local_ip()
    detected_cidr = auto_detect_cidr()
    iface = args.interface or auto_detect_interface()
    print(f"[->] Local IP: {local_ip or 'unknown'}")
    print(f"[->] Detected CIDR: {args.cidr or detected_cidr}")
    print(f"[->] Default interface: {iface or 'unknown'}")

    # Use live registry if available
    try:
        if DEVICE_REGISTRY:
            targets.update(DEVICE_REGISTRY.keys())
    except Exception:
        pass

    if args.ips:
        targets.update(args.ips)

    if args.all_known:
        targets.update(_load_known_ips_from_json())

    cidr = args.cidr or detected_cidr

    # Discovery if asked or if we still don't have targets
    if args.discover or not targets:
        print(f"[i] Discovering alive hosts in {cidr} ...")
        alive = parallel_ping(cidr)
        targets.update(alive)

    if not targets:
        print("[i] Still no targets found. Are you on the right network?")
        return

    # Best-effort ARP enrichment (helps vendor detection)
    try:
        arp_results = collect_arp(cidr, interface=iface)
        for ip, mac in arp_results.items():
            rec = DEVICE_REGISTRY.setdefault(ip, {"ip": ip, "status": "online"})
            if not rec.get("mac") and mac:
                rec["mac"] = mac
                try:
                    if mac_lookup:
                        rec["vendor"] = mac_lookup.lookup(mac)
                except Exception:
                    rec["vendor"] = rec.get("vendor", "Unknown")
        if save_registry_fn:
            try: save_registry_fn()
            except Exception: pass
    except Exception:
        pass

    ip_list = sorted(t for t in targets if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', t))
    enhanced_nmap_parallel(ip_list, threads=args.threads, extra_args=args.extra_nmap_args)

    # Color-coded summary (unchanged style)
    print("\n" + CLR["bold"] + "Feature 3/4 — Risk & Type Summary" + CLR["reset"])
    border = "─" * 78
    print("┌" + border + "┐")
    header = f"│ {'IP':15} │ {'Type':14} │ {'Open Ports':10} │ {'Indicators':24} │ {'Risk':7} │"
    print(header)
    print("├" + border + "┤")
    for ip in ip_list:
        rec = DEVICE_REGISTRY.get(ip, {}) or {}
        dtype = rec.get("device_type", "unknown")
        risks = rec.get("risks", {}) or {}
        ports = risks.get("open_ports", []) or []
        words = risks.get("risk_indicators", []) or []
        level, col = risk_level(words)
        inds_str = ", ".join(words) if words else "-"
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