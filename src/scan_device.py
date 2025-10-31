#!/usr/bin/env python3

import argparse
import ipaddress
import platform
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from scapy.all import ARP, Ether, conf, srp

# Setup directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "hns_data"
NMAP_DIR = DATA_DIR / "nmap"
DATA_DIR.mkdir(exist_ok=True)
NMAP_DIR.mkdir(exist_ok=True)

# Global state
device_registry: Dict[str, dict] = {}
running = True
nmap_available = False

# Initialize MAC lookup
mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except Exception:
    pass

def check_nmap_available() -> bool:
    """Check if nmap is available in PATH"""
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def get_ping_cmd(ip: str) -> list:
    """Get cross-platform ping command"""
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", "1000", ip]
    else:  # Linux/macOS
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
    #print(f"[{datetime.now().strftime('%H:%M:%S')}] Ping sweeping {cidr}...")
    
    network = ipaddress.ip_network(cidr, strict=False)
    responsive_ips = set()
    
    def ping_worker(ip_str: str):
        if ping_device(ip_str):
            responsive_ips.add(ip_str)
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(ping_worker, str(ip)) for ip in network.hosts()]
        for future in futures:
            future.result()
    
    #print(f"[{datetime.now().strftime('%H:%M:%S')}] Ping found {len(responsive_ips)} responsive IPs")
    return responsive_ips

def arp_scan(interface: str, cidr: str, timeout: int = 2, retries: int = 3) -> Dict[str, str]:
    """ARP scan to get MAC addresses"""
    #print(f"[{datetime.now().strftime('%H:%M:%S')}] ARP scanning {cidr}...")
    
    conf.verb = 0
    found = {}
    
    try:
        for _ in range(retries):
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr), 
                        timeout=timeout, iface=interface, inter=0.1, verbose=False)
            for _, pack in ans:
                found[pack.psrc] = pack.hwsrc.lower()
            time.sleep(0.2)
    except Exception as e:
        print(f"[WARN] ARP scan failed: {e}")
    
    #print(f"[{datetime.now().strftime('%H:%M:%S')}] ARP found {len(found)} devices with MAC")
    return found

def update_registry(ip: str, mac: Optional[str] = None, discovered_by: str = "ping"):
    """Update device registry with new or existing device"""
    now = datetime.now().isoformat()
    
    if ip in device_registry:
        # Update existing device
        old_status = device_registry[ip]['status']
        device_registry[ip]['last_seen'] = now
        device_registry[ip]['status'] = 'online'
        
        # Merge MAC/vendor if provided
        if mac and not device_registry[ip].get('mac'):
            device_registry[ip]['mac'] = mac
            try:
                device_registry[ip]['vendor'] = mac_lookup.lookup(mac)
            except VendorNotFoundError:
                device_registry[ip]['vendor'] = "Unknown"
        
        # Log status change
        if old_status == 'offline':
            print(f"[NEW] {ip} came back online")
    else:
        # New device discovery
        vendor = "Unknown"
        if mac:
            try:
                vendor = mac_lookup.lookup(mac)
            except VendorNotFoundError:
                pass
        
        device_registry[ip] = {
            'ip': ip,
            'mac': mac or "",
            'vendor': vendor,
            'discovered_by': discovered_by,
            'first_seen': now,
            'last_seen': now,
            'status': 'online'
        }
        
        #print(f"[NEW] Device discovered: {ip} ({vendor}) via {discovered_by}")

def nmap_scan_device(ip: str) -> bool:
    """Run nmap on a single device"""
    if not nmap_available:
        return False
    
    timestamp = datetime.now().strftime('%Y%m%dT%H%M%S')
    output_file = NMAP_DIR / f"nmap-{ip.replace('.', '-')}-{timestamp}.txt"
    
    try:
        cmd = ["nmap", "-sV", "-Pn", ip]
        with open(output_file, 'w') as f:
            f.write(f"Command: {' '.join(cmd)}\n\n")
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True, timeout=300)
        return True
    except Exception as e:
        print(f"[ERROR] Nmap failed for {ip}: {e}")
        return False

def nmap_parallel(ips: list, max_workers: int = 4):
    """Run nmap on multiple IPs in parallel"""
    if not ips or not nmap_available:
        return
    
    #print(f"[{datetime.now().strftime('%H:%M:%S')}] Nmap scanning {len(ips)} devices...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(nmap_scan_device, ip) for ip in ips]
        for future in futures:
            future.result()
    
    #print(f"[{datetime.now().strftime('%H:%M:%S')}] Nmap scans completed")


def scheduler(interface, cidr, ping_interval, arp_interval, nmap_interval, max_workers):
    timers = {"ping": 0, "arp": 0, "nmap": 0}
    while running:
        now = time.time()
        if now - timers["ping"] > ping_interval:
            responsive = ping_sweep(cidr)
            for ip in responsive:
                update_registry(ip, discovered_by="ping")
            timers["ping"] = now

        if now - timers["arp"] > arp_interval:
            arp_results = arp_scan(interface, cidr)
            for ip, mac in arp_results.items():
                update_registry(ip, mac=mac, discovered_by="arp")
            timers["arp"] = now

        if nmap_available and now - timers["nmap"] > nmap_interval:
            online = [ip for ip, info in device_registry.items() if info['status'] == 'online']
            nmap_parallel(online, max_workers)
            timers["nmap"] = now
        
        time.sleep(1)


def display_status():
    """Display current device status"""
    print("\n" + "="*70)
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Device Registry Status")
    print("="*70)
    
    if not device_registry:
        print("No devices discovered yet.")
        return
    
    online = sum(1 for d in device_registry.values() if d['status'] == 'online')
    total = len(device_registry)
    
    print(f"Total: {total} | Online: {online} | Offline: {total-online}")
    print("-"*70)
    
    for ip in sorted(device_registry.keys(), key=lambda x: ipaddress.ip_address(x)):
        info = device_registry[ip]
        status_icon = "🟢" if info['status'] == 'online' else "🔴"
        mac_display = info['mac'][:17] if info['mac'] else "Unknown"
        vendor_display = info['vendor'][:20] if info['vendor'] else "Unknown"
        discovered_by = info.get('discovered_by', 'unknown')
        
        print(f"{status_icon} {ip:15} {mac_display:17} {vendor_display:20} ({discovered_by})")
    
    print("="*70)

def auto_detect_cidr() -> str:
    """Auto-detect local network CIDR"""
    try:
        # Get default route IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Assume /24 network
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network)
    

    except Exception as e:
        print("auto_detect_cidr error:", repr(e))  # or logging.exception(...)
        return "192.168.1.0/24"

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="HomeNetSafe - Enhanced Network Scanner")
    parser.add_argument("--ping-interval", type=int, default=30, help="Ping scan interval in seconds (default: 30)")
    parser.add_argument("--arp-interval", type=int, default=300,help="ARP scan interval in seconds (default: 300)")
    parser.add_argument("--nmap-interval", type=int, default=1800,help="Nmap scan interval in seconds (default: 1800)")
    parser.add_argument("--cidr", type=str, default=None,help="Network CIDR to scan (default: auto-detect)")
    parser.add_argument("--nmap-threads", type=int, default=4,help="Parallel nmap threads (default: 4)")
    parser.add_argument("--interface", type=str, default="Wi-Fi",help="Network interface for ARP (default: Wi-Fi)")
    
    return parser.parse_args()

def main():
    global running, nmap_available
    
    args = parse_args()
    
    print("[->] HomeNetSafe - Enhanced Network Scanner")
    
    # Check nmap availability
    nmap_available = check_nmap_available()
    if not nmap_available:
        print("[WARN] nmap not found - port scanning disabled")
    
    # Auto-detect network if not specified
    cidr = args.cidr or auto_detect_cidr()
    print(f"[->] Scanning network: {cidr}")
    
    print("[->] Starting initial discovery sequence...")
    
    # Initial startup sequence: ping → ARP → parallel nmap
    responsive_ips = ping_sweep(cidr)
    for ip in responsive_ips:
        update_registry(ip, discovered_by="ping")
    
    arp_results = arp_scan(args.interface, cidr)
    for ip, mac in arp_results.items():
        update_registry(ip, mac=mac, discovered_by="arp")
    
    # Initial parallel nmap on all discovered devices
    if responsive_ips and nmap_available:
        nmap_parallel(list(responsive_ips), args.nmap_threads)
    
    display_status()
    

    print("\n[->] Press Ctrl+C to stop\n")
    
    # Start persistent scheduler threads
    scheduler_thread = threading.Thread(target=scheduler, args=(args.interface, cidr, args.ping_interval, args.arp_interval, args.nmap_interval, args.nmap_threads), daemon=True) 
    scheduler_thread.start()

    try:
        while running:
            time.sleep(60)  # Display status every minute
            display_status()
    except KeyboardInterrupt:
        print("\n[->] Stopping schedulers...")
        running = False
        print("[->] HomeNetSafe stopped. Goodbye!")

if __name__ == "__main__":
    main()