#!/usr/bin/env python3
"""
HomeNetSafe - Enhanced Network Scanner (Feature 1 & 2)
Auto-detects the current network (CIDR + default interface) so it works anywhere.

CLI Flags (still supported):
  --ping-interval SECONDS    (default: 30)
  --arp-interval SECONDS     (default: 300)
  --nmap-interval SECONDS    (default: 1800)
  --cidr NETWORK             (optional override; default: auto-detect)
  --nmap-threads N           (default: 4)
  --interface NAME           (optional override; default: auto-detect)
"""

import argparse
import ipaddress
import json
import platform
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from mac_vendor_lookup import MacLookup, VendorNotFoundError
from scapy.all import ARP, Ether, conf, srp  # type: ignore

GREEN = "\033[32m"
RESET = "\033[0m"

banner = r"""
 _     ____  _        ____  _____ _     _  ____  _____   ____  _  ____  ____  ____  _     _____ ____ ___  _
/ \   /  _ \/ \  /|  /  _ \/  __// \ |\/\/   _\/  __/  /  _ \/ \/ ___\/   _\/  _ \/ \ |\/  __//  __\\  \//
| |   | / \|| |\ ||  | | \||  \  | | //| ||  /  |  \    | | \|| ||    \|  /  | / \|| | //|  \  |  \/| \  / 
| |_/\| |-||| | \||  | |_/||  /_ | \// | ||  \__|  /_   | |_/|| |\___ ||  \__| \_/|| \// |  /_ |    / / /  
\____/\_/ \|\_/  \|  \____/\____\\__/  \_/\____/\____\  \____/\_/\____/\____/\____/\__/  \____\\_/\_\/_/  
"""

# -------------------- Paths & Globals --------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "hns_data"
NMAP_DIR = DATA_DIR / "nmap"
DATA_DIR.mkdir(exist_ok=True)
NMAP_DIR.mkdir(exist_ok=True)

KNOWN_PATH = DATA_DIR / "known_devices.json"

device_registry: Dict[str, dict] = {}
running = True
nmap_available = False

# Initialize MAC lookup
mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except Exception:
    pass


# -------------------- Nmap Availability --------------------
def check_nmap_available() -> bool:
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


# -------------------- Auto Network Detect --------------------
def _get_local_ip() -> Optional[str]:
    """Best-effort: connect to a public DNS IP to learn our local address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def auto_detect_cidr() -> str:
    """
    Auto-detect local network CIDR. If netmask can't be derived, assume /24.
    This is robust enough for home/office/wifi hotspots.
    """
    ip = _get_local_ip()
    if not ip:
        return "192.168.1.0/24"
    try:
        # If you later add netifaces or platform-specific netmask logic, use it here.
        return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except Exception:
        return "192.168.1.0/24"

def auto_detect_interface() -> Optional[str]:
    """Best-effort default interface via scapy's routing table."""
    try:
        return conf.route.route("0.0.0.0")[0].decode() if isinstance(conf.route.route("0.0.0.0")[0], bytes) \
               else conf.route.route("0.0.0.0")[0]
    except Exception:
        # Fallback: common Wi-Fi name on macOS; harmless if ARP uses raw socket anyway.
        return "Wi-Fi"


# -------------------- Utilities --------------------
def get_ping_cmd(ip: str) -> list:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", "1000", ip]
    else:
        return ["ping", "-c", "1", "-W", "1", ip]

def ping_device(ip: str) -> bool:
    try:
        result = subprocess.run(get_ping_cmd(ip), capture_output=True, timeout=2)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False

def ping_sweep(cidr: str) -> Set[str]:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Ping sweeping {cidr}...")
    network = ipaddress.ip_network(cidr, strict=False)
    responsive_ips: Set[str] = set()

    def ping_worker(ip_str: str):
        if ping_device(ip_str):
            responsive_ips.add(ip_str)

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(ping_worker, str(ip)) for ip in network.hosts()]
        for f in futures:
            f.result()

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Ping found {len(responsive_ips)} responsive IPs")
    return responsive_ips

def arp_scan(interface: str, cidr: str, timeout: int = 2, retries: int = 3) -> Dict[str, str]:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ARP scanning {cidr} on {interface}...")
    conf.verb = 0
    found: Dict[str, str] = {}
    try:
        for _ in range(retries):
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                         timeout=timeout, iface=interface, inter=0.1, verbose=False)
            for _, pack in ans:
                found[pack.psrc] = pack.hwsrc.lower()
            time.sleep(0.2)
    except Exception as e:
        print(f"[WARN] ARP scan failed: {e}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ARP found {len(found)} devices with MAC")
    return found


# -------------------- Persistence --------------------
def save_registry() -> None:
    try:
        DATA_DIR.mkdir(exist_ok=True)
        KNOWN_PATH.write_text(json.dumps(device_registry, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[WARN] Failed to save registry: {e}")

def load_registry() -> None:
    try:
        if KNOWN_PATH.exists():
            data = json.loads(KNOWN_PATH.read_text(encoding="utf-8"))
            for ip, rec in data.items():
                device_registry.setdefault(ip, {}).update(rec)
    except Exception as e:
        print(f"[WARN] Failed to load registry: {e}")


# -------------------- Registry Updates --------------------
def update_registry(ip: str, mac: Optional[str] = None, discovered_by: str = "ping") -> None:
    now = datetime.now().isoformat()
    if ip in device_registry:
        old_status = device_registry[ip].get("status", "online")
        device_registry[ip]["last_seen"] = now
        device_registry[ip]["status"] = "online"
        if mac and not device_registry[ip].get("mac"):
            device_registry[ip]["mac"] = mac
            try:
                device_registry[ip]["vendor"] = mac_lookup.lookup(mac)
            except VendorNotFoundError:
                device_registry[ip]["vendor"] = "Unknown"
        if old_status == "offline":
            print(f"[ONLINE] {ip} came back online")
    else:
        vendor = "Unknown"
        if mac:
            try:
                vendor = mac_lookup.lookup(mac)
            except VendorNotFoundError:
                pass
        device_registry[ip] = {
            "ip": ip, "mac": mac or "", "vendor": vendor,
            "discovered_by": discovered_by, "first_seen": now, "last_seen": now, "status": "online",
        }
        print(f"[NEW] Device discovered: {ip} ({vendor}) via {discovered_by}")
    save_registry()


# -------------------- Nmap Wrappers --------------------
def nmap_scan_device(ip: str) -> bool:
    if not nmap_available:
        return False
    timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    output_file = NMAP_DIR / f"nmap-{ip.replace('.', '-')}-{timestamp}.txt"
    try:
        cmd = ["nmap", "-sV", "-Pn", ip]
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Command: {' '.join(cmd)}\n\n")
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True, timeout=300)
        return True
    except Exception as e:
        print(f"[ERROR] Nmap failed for {ip}: {e}")
        return False

def nmap_parallel(ips: list, max_workers: int = 4) -> None:
    if not ips or not nmap_available:
        return
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Nmap scanning {len(ips)} devices...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for f in [executor.submit(nmap_scan_device, ip) for ip in ips]:
            f.result()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Nmap scans completed")


# -------------------- Schedulers --------------------
def ping_scheduler(interval: int, cidr: str) -> None:
    while running:
        if device_registry:
            online_count = 0
            offline_transitions = []
            for ip in list(device_registry.keys()):
                if ping_device(ip):
                    old_status = device_registry[ip].get("status", "online")
                    device_registry[ip]["status"] = "online"
                    device_registry[ip]["last_seen"] = datetime.now().isoformat()
                    online_count += 1
                    if old_status == "offline":
                        print(f"[ONLINE] {ip} is back online")
                else:
                    old_status = device_registry[ip].get("status", "offline")
                    device_registry[ip]["status"] = "offline"
                    if old_status == "online":
                        offline_transitions.append(ip)
            for ip in offline_transitions:
                print(f"[OFFLINE] {ip} went offline")
            save_registry()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Ping: {online_count}/{len(device_registry)} online")
        time.sleep(interval)

def arp_scheduler(interval: int, interface: str, cidr: str) -> None:
    while running:
        responsive_ips = ping_sweep(cidr)
        for ip in responsive_ips:
            update_registry(ip, discovered_by="ping")
        arp_results = arp_scan(interface, cidr)
        for ip, mac in arp_results.items():
            update_registry(ip, mac=mac, discovered_by="arp")
        new_devices = [ip for ip in responsive_ips if ip not in device_registry or
                       device_registry[ip]["first_seen"] == device_registry[ip]["last_seen"]]
        if new_devices:
            nmap_parallel(new_devices)
        time.sleep(interval)

def nmap_scheduler(interval: int, max_workers: int) -> None:
    while running:
        if device_registry:
            online_devices = [ip for ip, info in device_registry.items() if info.get("status") == "online"]
            nmap_parallel(online_devices, max_workers)
        time.sleep(interval)


# -------------------- Status Display --------------------
def display_status() -> None:
    print("\n" + "=" * 70)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Device Registry Status")
    print("=" * 70)
    if not device_registry:
        print("No devices discovered yet.")
        return
    online = sum(1 for d in device_registry.values() if d.get("status") == "online")
    total = len(device_registry)
    print(f"Total: {total} | Online: {online} | Offline: {total - online}")
    print("-" * 70)
    for ip in sorted(device_registry.keys(), key=lambda x: ipaddress.ip_address(x)):
        info = device_registry[ip]
        status_icon = "🟢" if info.get("status") == "online" else "🔴"
        mac_display = (info.get("mac") or "")[:17] or "Unknown"
        vendor_display = (info.get("vendor") or "Unknown")[:20]
        discovered_by = info.get("discovered_by", "unknown")
        print(f"{status_icon} {ip:15} {mac_display:17} {vendor_display:20} ({discovered_by})")
    print("=" * 70)


# -------------------- CLI --------------------
def parse_args():
    p = argparse.ArgumentParser(description="HomeNetSafe - Enhanced Network Scanner (Feature 1 & 2)")
    p.add_argument("--ping-interval", type=int, default=30)
    p.add_argument("--arp-interval", type=int, default=300)
    p.add_argument("--nmap-interval", type=int, default=1800)
    p.add_argument("--cidr", type=str, default=None, help="Override network (e.g. 192.168.29.0/24)")
    p.add_argument("--nmap-threads", type=int, default=4)
    p.add_argument("--interface", type=str, default=None, help="Override interface name")
    return p.parse_args()


# -------------------- Main --------------------
def main():
    global running, nmap_available
    args = parse_args()

    print(GREEN + banner + RESET)
    print("[->] HomeNetSafe - Enhanced Network Scanner")

    nmap_available = check_nmap_available()
    if not nmap_available:
        print("[WARN] nmap not found - port scanning disabled")

    load_registry()

    # Auto detect local IP, CIDR, and interface unless user overrides
    local_ip = _get_local_ip()
    cidr = args.cidr or auto_detect_cidr()
    iface = args.interface or auto_detect_interface()

    print(f"[->] Local IP: {local_ip or 'unknown'}")
    print(f"[->] Detected CIDR: {cidr}")
    print(f"[->] Default interface: {iface or 'unknown'}")

    print("[->] Starting initial discovery sequence...")
    responsive_ips = ping_sweep(cidr)
    for ip in responsive_ips:
        update_registry(ip, discovered_by="ping")

    if iface:
        arp_results = arp_scan(iface, cidr)
        for ip, mac in arp_results.items():
            update_registry(ip, mac=mac, discovered_by="arp")

    if responsive_ips and nmap_available:
        nmap_parallel(list(responsive_ips), args.nmap_threads)

    display_status()

    print(f"\n[->] Starting scheduled monitoring:")
    print(f"    • Ping scan: every {args.ping_interval}s")
    print(f"    • ARP scan: every {args.arp_interval}s")
    print(f"    • Nmap scan: every {args.nmap_interval}s")
    print(f"    • Nmap threads: {args.nmap_threads}")
    print("\n[->] Press Ctrl+C to stop\n")

    ping_thread = threading.Thread(target=ping_scheduler, args=(args.ping_interval, cidr), daemon=True)
    arp_thread = threading.Thread(target=arp_scheduler, args=(args.arp_interval, iface or "Wi-Fi", cidr), daemon=True)
    nmap_thread = threading.Thread(target=nmap_scheduler, args=(args.nmap_interval, args.nmap_threads), daemon=True)

    ping_thread.start()
    arp_thread.start()
    if nmap_available:
        nmap_thread.start()

    try:
        while running:
            time.sleep(60)
            display_status()
            save_registry()
    except KeyboardInterrupt:
        print("\n[->] Stopping schedulers...")
        running = False
        save_registry()
        print("[->] HomeNetSafe stopped. Goodbye!")


if __name__ == "__main__":
    main()