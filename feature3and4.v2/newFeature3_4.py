#!/usr/bin/env python3
"""
HomeNetSafe - Enhanced Network Scanner (Feature 1 & 2)
-----------------------------------------------------
This version:
 - auto-detects local CIDR + interface (best-effort)
 - persistent registry in hns_data/known_devices.json (load/save)
 - sanitizes registry keys so only valid IPv4 addresses are used
 - crash-proof display and scheduler loops (ignore non-IP keys)
 - exposes `device_registry`, `NMAP_DIR`, `mac_lookup`,
   `check_nmap_available`, and `save_registry` for compatibility.

Compatibility note (kept as a commit-string for now):
COMPAT_COMMIT = "compat: export device_registry, NMAP_DIR, mac_lookup, check_nmap_available, save_registry"
"""

from __future__ import annotations
import argparse
import ipaddress
import json
import platform
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set

from mac_vendor_lookup import MacLookup, VendorNotFoundError
from scapy.all import ARP, Ether, conf, srp  # type: ignore

# ---------------------------------------------------------------------
# Compatibility commit string (kept here as requested)
COMPAT_COMMIT = "compat: export device_registry, NMAP_DIR, mac_lookup, check_nmap_available, save_registry"
# ---------------------------------------------------------------------

GREEN = "\033[32m"
RESET = "\033[0m"

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

# -------------------- IPv4 validation helpers --------------------
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ipv4(s: str) -> bool:
    """Return True if s is a syntactically valid IPv4 address string."""
    if not isinstance(s, str) or not _IPV4_RE.match(s):
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


# -------------------- Nmap Availability --------------------
def check_nmap_available() -> bool:
    """Check if nmap is available in PATH"""
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
    """
    ip = _get_local_ip()
    if not ip:
        return "192.168.1.0/24"
    try:
        return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except Exception:
        return "192.168.1.0/24"


def auto_detect_interface() -> Optional[str]:
    """Best-effort default interface via scapy's routing table."""
    try:
        route = conf.route.route("0.0.0.0")
        iface = route[0] if route and len(route) > 0 else None
        return iface.decode() if isinstance(iface, bytes) else iface
    except Exception:
        return None


# -------------------- Utilities --------------------
def get_ping_cmd(ip: str) -> list:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", "1000", ip]
    else:
        return ["ping", "-c", "1", "-W", "1", ip]


def ping_device(ip: str) -> bool:
    """Ping a single device"""
    try:
        result = subprocess.run(get_ping_cmd(ip), capture_output=True, timeout=2)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False


def ping_sweep(cidr: str) -> Set[str]:
    """Fast ping sweep of entire subnet"""
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
    """ARP scan to get MAC addresses"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ARP scanning {cidr} on {interface}...")
    conf.verb = 0
    found: Dict[str, str] = {}
    try:
        for _ in range(retries):
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                         timeout=timeout, iface=interface, inter=0.1, verbose=False)
            for _, pack in ans:
                if _is_ipv4(pack.psrc):
                    found[pack.psrc] = pack.hwsrc.lower()
            time.sleep(0.2)
    except Exception as e:
        print(f"[WARN] ARP scan failed: {e}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ARP found {len(found)} devices with MAC")
    return found


# -------------------- Persistence --------------------
def save_registry() -> None:
    """Persist only entries keyed by valid IPv4 addresses."""
    try:
        DATA_DIR.mkdir(exist_ok=True)
        clean: Dict[str, dict] = {}
        for k, rec in (device_registry or {}).items():
            if _is_ipv4(k):
                r = dict(rec or {})
                r["ip"] = k
                clean[k] = r
            else:
                # Attempt repair if record has a valid ip field
                ipf = (rec or {}).get("ip")
                if _is_ipv4(ipf):
                    r = dict(rec or {})
                    r["ip"] = ipf
                    clean[ipf] = r
                # else skip invalid top-level entries
        KNOWN_PATH.write_text(json.dumps(clean, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[WARN] Failed to save registry: {e}")


def load_registry() -> None:
    """Load and sanitize registry so keys are always IPs."""
    try:
        if KNOWN_PATH.exists():
            data = json.loads(KNOWN_PATH.read_text(encoding="utf-8"))
            for key, rec in (data or {}).items():
                # Prefer 'ip' field if present and valid
                rec_ip = rec.get("ip") if isinstance(rec, dict) else None
                if rec_ip and _is_ipv4(rec_ip):
                    device_registry[rec_ip] = dict(rec)
                    device_registry[rec_ip]["ip"] = rec_ip
                elif _is_ipv4(key):
                    device_registry[key] = dict(rec or {})
                    device_registry[key]["ip"] = key
                else:
                    # Skip invalid entries (e.g., MACs used as keys)
                    continue
    except Exception as e:
        print(f"[WARN] Failed to load registry: {e}")


# -------------------- Registry Updates --------------------
def update_registry(ip: str, mac: Optional[str] = None, discovered_by: str = "ping") -> None:
    """Update device registry with new or existing device (guards non-IP keys)."""
    # Guard: ensure ip is a valid IPv4; attempt simple recovery if possible
    if not _is_ipv4(ip):
        # If caller accidentally passed a MAC as ip but provided a valid ip in mac param, swap
        if isinstance(mac, str) and _is_ipv4(mac):
            ip, mac = mac, None
        else:
            print(f"[WARN] Ignoring non-IP key in update_registry: {ip!r}")
            return

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
            "ip": ip,
            "mac": mac or "",
            "vendor": vendor,
            "discovered_by": discovered_by,
            "first_seen": now,
            "last_seen": now,
            "status": "online",
        }
        print(f"[NEW] Device discovered: {ip} ({vendor}) via {discovered_by}")

    # Persist changes
    save_registry()


# -------------------- Nmap Wrappers --------------------
def nmap_scan_device(ip: str, timeout: int = 300) -> bool:
    """Run nmap on a single device"""
    if not nmap_available:
        return False
    if not _is_ipv4(ip):
        return False

    timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    output_file = NMAP_DIR / f"nmap-{ip.replace('.', '-')}-{timestamp}.txt"
    try:
        cmd = ["nmap", "-sV", "-Pn", ip]
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Command: {' '.join(cmd)}\n\n")
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Nmap failed for {ip}: Command timed out after {timeout} seconds")
        return False
    except Exception as e:
        print(f"[ERROR] Nmap failed for {ip}: {e}")
        return False


def nmap_parallel(ips: list, max_workers: int = 4, timeout: int = 300):
    """Run nmap on multiple IPs in parallel"""
    # filter to valid IPv4 addresses
    ips = [ip for ip in (ips or []) if _is_ipv4(ip)]
    if not ips or not nmap_available:
        return

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Nmap scanning {len(ips)} devices...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(nmap_scan_device, ip, timeout) for ip in ips]
        for f in futures:
            f.result()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Nmap scans completed")


# -------------------- Scheduler --------------------
def scheduler(interface, cidr, ping_interval, arp_interval, nmap_interval, max_workers):
    timers = {"ping": 0, "arp": 0, "nmap": 0}
    while running:
        now = time.time()
        if now - timers["ping"] > ping_interval:
            responsive = ping_sweep(cidr)
            for ip in responsive:
                if _is_ipv4(ip):
                    update_registry(ip, discovered_by="ping")
            timers["ping"] = now

        if now - timers["arp"] > arp_interval:
            arp_results = arp_scan(interface, cidr)
            for ip, mac in arp_results.items():
                update_registry(ip, mac=mac, discovered_by="arp")
            timers["arp"] = now

        if nmap_available and now - timers["nmap"] > nmap_interval:
            online = [ip for ip, info in device_registry.items() if _is_ipv4(ip) and info.get("status") == "online"]
            nmap_parallel(online, max_workers)
            timers["nmap"] = now

        # persist periodically
        save_registry()
        time.sleep(1)


# -------------------- Status Display --------------------
def display_status():
    """Display current device status"""
    print("\n" + "=" * 70)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Device Registry Status")
    print("=" * 70)

    ips = [k for k in device_registry.keys() if _is_ipv4(k)]
    if not ips:
        print("No devices discovered yet.")
        return

    online = sum(1 for ip in ips if device_registry[ip].get("status") == "online")
    total = len(ips)

    print(f"Total: {total} | Online: {online} | Offline: {total - online}")
    print("-" * 70)

    for ip in sorted(ips, key=lambda x: ipaddress.ip_address(x)):
        info = device_registry[ip]
        status_icon = "🟢" if info.get("status") == "online" else "🔴"
        mac_display = (info.get("mac") or "")[:17] or "Unknown"
        vendor_display = (info.get("vendor") or "Unknown")[:20]
        discovered_by = info.get("discovered_by", "unknown")
        print(f"{status_icon} {ip:15} {mac_display:17} {vendor_display:20} ({discovered_by})")

    print("=" * 70)


# -------------------- CLI --------------------
def parse_args():
    parser = argparse.ArgumentParser(description="HomeNetSafe - Enhanced Network Scanner (Feature 1 & 2)")
    parser.add_argument("--ping-interval", type=int, default=30, help="Ping scan interval in seconds (default: 30)")
    parser.add_argument("--arp-interval", type=int, default=300, help="ARP scan interval in seconds (default: 300)")
    parser.add_argument("--nmap-interval", type=int, default=1800, help="Nmap scan interval in seconds (default: 1800)")
    parser.add_argument("--cidr", type=str, default=None, help="Network CIDR to scan (default: auto-detect)")
    parser.add_argument("--nmap-threads", type=int, default=4, help="Parallel nmap threads (default: 4)")
    parser.add_argument("--interface", type=str, default=None, help="Network interface for ARP (optional override)")
    parser.add_argument("--nmap-timeout", type=int, default=300, help="Per-host nmap timeout seconds (default: 300)")
    return parser.parse_args()


# -------------------- Main --------------------
def main():
    global running, nmap_available

    args = parse_args()

    print(GREEN + "HomeNetSafe - Enhanced Network Scanner" + RESET)

    nmap_available = check_nmap_available()
    if not nmap_available:
        print("[WARN] nmap not found - port scanning disabled")

    # Load registry from prior runs
    load_registry()

    # Auto-detect network if not specified
    local_ip = _get_local_ip()
    cidr = args.cidr or auto_detect_cidr()
    iface = args.interface or auto_detect_interface() or "Wi-Fi"

    print(f"[->] Local IP: {local_ip or 'unknown'}")
    print(f"[->] Detected CIDR: {cidr}")
    print(f"[->] Default interface: {iface or 'unknown'}")

    print("[->] Starting initial discovery sequence...")

    # Initial startup sequence: ping → ARP → parallel nmap
    responsive_ips = ping_sweep(cidr)
    for ip in list(responsive_ips):
        if _is_ipv4(ip):
            update_registry(ip, discovered_by="ping")

    if iface:
        arp_results = arp_scan(iface, cidr)
        for ip, mac in arp_results.items():
            update_registry(ip, mac=mac, discovered_by="arp")

    # Initial parallel nmap on all discovered devices (valid IPs)
    valid_ips = [ip for ip in responsive_ips if _is_ipv4(ip)]
    if valid_ips and nmap_available:
        nmap_parallel(valid_ips, args.nmap_threads, timeout=args.nmap_timeout)

    display_status()

    print(f"\n[->] Starting scheduled monitoring:")
    print(f"    • Ping scan: every {args.ping_interval}s")
    print(f"    • ARP scan: every {args.arp_interval}s")
    print(f"    • Nmap scan: every {args.nmap_interval}s")
    print(f"    • Nmap threads: {args.nmap_threads}")
    print("\n[->] Press Ctrl+C to stop\n")

    scheduler_thread = threading.Thread(
        target=scheduler,
        args=(iface, cidr, args.ping_interval, args.arp_interval, args.nmap_interval, args.nmap_threads),
        daemon=True,
    )
    scheduler_thread.start()

    try:
        while running:
            time.sleep(60)  # Display status every minute
            display_status()
    except KeyboardInterrupt:
        print("\n[->] Stopping schedulers...")
        running = False
        save_registry()
        print("[->] HomeNetSafe stopped. Goodbye!")


if __name__ == "__main__":
    main()
