#!/usr/bin/env python3
# ↑ Shebang allows running the script directly on Unix-like systems if it’s marked executable.

"""
fast_stream_scan_with_hostnames.py

Streams discovered hosts immediately and includes hostnames when available.
Now also includes a **fast MAC → vendor** lookup with:
 - a small built-in OUI map for common vendors; and
 - optional loading of a local CSV file `local_oui.csv` to expand coverage.

Behavior:
 - When a host responds, we try a short-timeout reverse DNS (fast attempt).
 - If DNS is slow, we stream the host with hostname=None and schedule a background DNS lookup;
   when that finishes we print an "update" JSON line with the hostname for that IP.
 - We resolve the MAC's OUI (first 6 hex chars) to a vendor name instantly (no network calls).

Usage:
  python fast_stream_scan_with_hostnames.py
  python fast_stream_scan_with_hostnames.py 192.168.1.0/24
  python fast_stream_scan_with_hostnames.py --dns-timeout 0.6
  # Optional: place a file named local_oui.csv next to this script with lines like:
  #  00:1A:2B,Acme Devices Inc.
  #  3C:5A:B4,Contoso Ltd
"""

# ---- Standard library imports (no external packages required) ----
from __future__ import annotations                 # Modern typing behavior in older Python 3.
import argparse                                    # Parse CLI args.
import ipaddress                                   # Work with networks like "192.168.1.0/24".
import json                                        # Print results as JSON.
import os                                          # Locate local files like local_oui.csv.
import platform                                    # Detect OS for ping/ARP behavior.
import re                                          # Parse ARP/neigh output and CSV lines.
import shutil                                      # Check if system commands exist (e.g., `ip`).
import socket                                      # Reverse DNS + local IP detection.
import subprocess                                  # Run ping/arp/ip neigh.
import sys                                         # Stdout/stderr, exit codes.
import time                                        # Timing and small sleeps.
from concurrent.futures import ThreadPoolExecutor, as_completed  # Parallelism for speed.
from typing import Dict, List, Optional            # Type hints.

# ---- Tunable performance knobs ----
PING_TIMEOUT = 0.45           # Seconds for a ping attempt (short to keep fast).
PING_WORKERS = 250            # Parallel pings (high for instant-ish results on /24).
ARP_READ_RETRY = 0.45         # Delay before re-reading ARP after a ping.
ARP_READ_ATTEMPTS = 2         # How many times to re-check ARP for MAC.
DNS_IMMEDIATE_TIMEOUT = 0.6   # Seconds to wait for immediate reverse DNS.
DNS_BACKGROUND_WORKERS = 8    # Threads for background DNS (late updates).
LOCAL_OUI_FILENAME = "local_oui.csv"  # Optional local vendor DB (next to this script).

# ---- Built-in tiny OUI map (common vendors) ----
# NOTE: Keys are 6 hex chars (no separators), uppercase. Add more as needed or use local_oui.csv.
_BUILTIN_OUI: Dict[str, str] = {
    # Apple
    "0016CB": "Apple, Inc.", "002241": "Apple, Inc.", "3C15C2": "Apple, Inc.", "A4B1C1": "Apple, Inc.",
    "D89E3F": "Apple, Inc.", "F0D1A9": "Apple, Inc.",
    # Samsung
    "5C497D": "Samsung Electronics", "C8F230": "Samsung Electronics", "B0C559": "Samsung Electronics",
    # Google / Nest
    "F4F5D8": "Google / Nest", "3C5AB4": "Google / Nest", "D4F513": "Google / Nest",
    # Amazon (Echo, Fire, Ring)
    "FCA667": "Amazon Technologies", "B4F1DA": "Amazon Technologies", "0C47C9": "Amazon Technologies",
    # TP-Link
    "50C7BF": "TP-Link Technologies", "D4EE07": "TP-Link Technologies", "F4F26D": "TP-Link Technologies",
    # Netgear
    "A0BDCD": "NETGEAR", "001E2A": "NETGEAR",
    # Ubiquiti
    "24A43C": "Ubiquiti Networks", "F09FC2": "Ubiquiti Networks",
    # Cisco
    "00094C": "Cisco Systems", "00096B": "Cisco Systems", "3C5A37": "Cisco Systems",
    # Intel
    "BC305B": "Intel Corporate", "B499BA": "Intel Corporate", "DC5360": "Intel Corporate",
    # HP / HPE / printers
    "001E0B": "HP Inc.", "F4CE46": "HP Inc.", "8C3AE3": "HP Inc.",
    # Brother / Epson / Canon printers
    "348A7B": "Brother Industries", "0024A0": "SEIKO EPSON", "080007": "Canon Inc.",
    # Microsoft, Dell, Lenovo
    "849CA6": "Microsoft", "BCEC23": "Dell Inc.", "FC45C3": "Lenovo Mobile",
    # Xiaomi / Huawei / LG / Sony
    "64B473": "Xiaomi Communications", "00258D": "Huawei Technologies", "0021FB": "LG Electronics",
    "40B089": "Sony Corporation",
    # Roku
    "B0A7B9": "Roku, Inc.",
    # Raspberry Pi
    "B827EB": "Raspberry Pi Trading", "DC:A6:32".replace(":", ""): "Raspberry Pi Trading",
    # D-Link
    "C83A35": "D-Link International",
    # Asus
    "60A44C": "ASUSTek Computer",
}

# ---- Global vendor maps + cache (populated at startup) ----
_OUI_MAP: Dict[str, str] = {}     # Final map used for lookups (built-in + optional local file).
_VENDOR_CACHE: Dict[str, str] = {}  # Per-MAC cache (avoid repeating work even though it's cheap).


def have(cmd: str) -> bool:
    """Return True if a command exists in PATH (used to choose ip/arp tools)."""
    return shutil.which(cmd) is not None


def _normalize_mac_to_oui(mac: str) -> Optional[str]:
    """
    Convert a MAC 'aa:bb:cc:dd:ee:ff' or 'AA-BB-CC-DD-EE-FF' into a 6-hex OUI key 'AABBCC'.
    Returns None if input isn't a valid MAC.
    """
    if not mac:
        return None
    # Remove separators ':' and '-' then uppercase
    h = re.sub(r'[^0-9a-fA-F]', '', mac).upper()
    if len(h) < 12:
        return None
    return h[:6]  # First 3 bytes = OUI


def _load_local_oui_csv(path: str) -> Dict[str, str]:
    """
    Load a simple 'OUI,Vendor' CSV (no quotes needed).
    Accepts OUI with or without separators. Example lines:
       00:1A:2B,Acme Devices Inc.
       3C5AB4,Contoso Ltd
    Returns a dict { '001A2B': 'Acme Devices Inc.', ... }
    """
    mapping: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                # Strip whitespace; skip empty or commented lines
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                # Split on first comma
                parts = s.split(",", 1)
                if len(parts) != 2:
                    continue
                oui_raw, vendor = parts[0].strip(), parts[1].strip()
                key = re.sub(r'[^0-9a-fA-F]', '', oui_raw).upper()[:6]
                if len(key) == 6 and vendor:
                    mapping[key] = vendor
    except FileNotFoundError:
        # No local file — that's fine; the built-in DB still works.
        pass
    except Exception:
        # If the file exists but is malformed, ignore to keep scan fast/robust.
        pass
    return mapping


def init_vendor_db() -> None:
    """
    Initialize the global OUI map once at startup:
     - start with the built-in small map
     - overlay entries from local_oui.csv if found
    """
    global _OUI_MAP
    _OUI_MAP = dict(_BUILTIN_OUI)  # copy built-in
    # Find local_oui.csv in the same directory as this script
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except Exception:
        here = "."
    local_path = os.path.join(here, LOCAL_OUI_FILENAME)
    _OUI_MAP.update(_load_local_oui_csv(local_path))


def vendor_lookup(mac: Optional[str]) -> Optional[str]:
    """
    Return vendor string for a MAC address using the in-memory OUI map.
    Performs a tiny amount of work (string manipulation) and uses a small cache.
    """
    if not mac:
        return None
    # Cache first for speed (though lookups are already cheap)
    if mac in _VENDOR_CACHE:
        return _VENDOR_CACHE[mac]
    # Normalize and lookup
    key = _normalize_mac_to_oui(mac)
    vendor = _OUI_MAP.get(key) if key else None
    # Cache the result (even None) to avoid repeating work
    _VENDOR_CACHE[mac] = vendor
    return vendor


def local_primary_cidr() -> Optional[str]:
    """
    Guess the primary local IPv4 network and assume /24.
    We open a UDP socket (no packets sent) to get the local interface IP.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except Exception:
        return None


def ping_once(ip: str) -> bool:
    """
    Send a single ping to check liveness. Different flags for Windows vs Unix-like OS.
    """
    sysplat = platform.system().lower()
    if "windows" in sysplat:
        cmd = ["ping", "-n", "1", "-w", str(int(PING_TIMEOUT * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(PING_TIMEOUT))), ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=PING_TIMEOUT + 0.3)
        return res.returncode == 0
    except Exception:
        return False


def read_arp_table() -> Dict[str, str]:
    """
    Read ARP/neighbor table and return { IP -> MAC } best-effort.
    Uses `ip neigh` on Linux if present, else falls back to arp.
    """
    sysplat = platform.system().lower()
    try:
        if "windows" in sysplat:
            out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        else:
            if have("ip"):
                out = subprocess.check_output(["ip", "neigh"], text=True, stderr=subprocess.DEVNULL)
            else:
                out = subprocess.check_output(["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
        pairs: Dict[str, str] = {}
        for line in out.splitlines():
            m_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            m_mac = re.search(r"((?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2})", line, re.I)
            if not (m_ip and m_mac):
                continue
            ip = m_ip.group(1)
            mac = m_mac.group(1).lower().replace("-", ":")
            pairs[ip] = mac
        return pairs
    except Exception:
        return {}


def attempt_arp_for_ip(ip: str) -> Optional[str]:
    """
    After pinging, the kernel may need a moment to populate ARP.
    Check now; if absent, wait briefly and check once more.
    """
    for _ in range(ARP_READ_ATTEMPTS):
        arp = read_arp_table()
        if ip in arp:
            return arp[ip]
        time.sleep(ARP_READ_RETRY)
    return None


def reverse_dns(ip: str) -> Optional[str]:
    """
    Attempt reverse DNS (IP -> hostname). Returns None if no PTR or DNS is slow.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _dns_done_callback(fut, ip):
    """
    When a background DNS lookup finishes, print an update JSON line with the hostname.
    """
    try:
        hostname = fut.result()
    except Exception:
        hostname = None
    if hostname:
        update = {"ip": ip, "hostname": hostname, "update": True}
        sys.stdout.write(json.dumps(update) + "\n")
        sys.stdout.flush()


def stream_scan_cidr_with_hostnames(cidr: str,
                                    dns_immediate_timeout: float,
                                    do_background_dns: bool) -> Dict:
    """
    Main fast scanner:
      • Pings all hosts in the CIDR in parallel.
      • For each live host: reads MAC, resolves vendor, attempts quick hostname.
      • Streams a JSON line immediately; prints an update later if hostname appears.
    Returns a summary dict.
    """
    net = ipaddress.ip_network(cidr, strict=False)     # Parse CIDR safely (no strict net/broadcast checks).
    ips = [str(h) for h in net.hosts()]               # List usable host IPs.

    discovered_count = 0                               # Count live hosts.
    start = time.time()                                # For elapsed time measurement.

    # Optional DNS thread pool for background lookups (to avoid blocking streaming).
    dns_executor = ThreadPoolExecutor(max_workers=DNS_BACKGROUND_WORKERS) if do_background_dns else None

    # Ping many hosts at once for speed.
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futures = {ex.submit(ping_once, ip): ip for ip in ips}
        try:
            for fut in as_completed(futures):          # Handle results as soon as they arrive (streaming).
                ip = futures[fut]
                try:
                    up = fut.result()                  # True if host responded to ping.
                except Exception:
                    up = False
                if not up:
                    continue

                discovered_count += 1                  # Count this live host.

                # Immediate, short reverse DNS try.
                hostname = None
                if dns_immediate_timeout and dns_immediate_timeout > 0 and dns_executor:
                    fut_dns = dns_executor.submit(reverse_dns, ip)
                    try:
                        hostname = fut_dns.result(timeout=dns_immediate_timeout)
                    except Exception:
                        # Too slow or failed now — attach callback for a future "update" line.
                        fut_dns.add_done_callback(lambda f, ip=ip: _dns_done_callback(f, ip))
                        hostname = None

                # Get MAC now (best-effort) and resolve vendor instantly via OUI map.
                mac = attempt_arp_for_ip(ip)
                vendor = vendor_lookup(mac)

                # Stream the record right away.
                rec = {"ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor}
                sys.stdout.write(json.dumps(rec) + "\n")
                sys.stdout.flush()

        except KeyboardInterrupt:
            print("\n[!] scan interrupted by user", file=sys.stderr)
        finally:
            if dns_executor:
                # Don't block shutdown; callbacks will still print if they complete very soon.
                dns_executor.shutdown(wait=False)

    elapsed = time.time() - start
    summary = {"cidr": cidr, "elapsed": round(elapsed, 2),
               "discovered": discovered_count, "total_ips": len(ips)}
    return summary


def main():
    """
    CLI entry: parse args, init vendor DB, decide CIDR, run streaming scan, print final summary.
    """
    # Parse flags/args.
    ap = argparse.ArgumentParser(description="Fast streaming scan with hostnames + MAC vendor lookup.")
    ap.add_argument("cidr", nargs="?", help="CIDR to scan (optional). If omitted, auto-detect /24.")
    ap.add_argument("--dns-timeout", type=float, default=DNS_IMMEDIATE_TIMEOUT,
                    help="Seconds to wait for immediate DNS (default 0.6). Set 0 to skip immediate attempt.")
    ap.add_argument("--no-background-dns", action="store_true",
                    help="Disable background DNS lookups (fastest; hostnames may never appear).")
    args = ap.parse_args()

    # Initialize the vendor DB once (built-in + optional local CSV overlay).
    init_vendor_db()

    # Determine which network to scan (provided or auto-detected /24).
    cidr = args.cidr or local_primary_cidr()
    if not cidr:
        print("ERROR: could not detect local network; provide a CIDR (e.g., 192.168.1.0/24).", file=sys.stderr)
        sys.exit(2)

    # Background DNS flag (default on).
    do_bg = not args.no_background_dns

    # Print header to stderr so stdout stays clean JSON (easy to pipe/parse).
    print(f"[+] streaming fast scan for {cidr}  "
          f"(dns_immediate={args.dns_timeout}s, background_dns={'yes' if do_bg else 'no'})", file=sys.stderr)

    # Run the scanner and print a final summary JSON block.
    summary = stream_scan_cidr_with_hostnames(
        cidr,
        dns_immediate_timeout=args.dns_timeout,
        do_background_dns=do_bg
    )
    print("\n" + json.dumps({"summary": summary}, indent=2))


# Run main() only when executed directly (import-safe).
if __name__ == "__main__":
    main()
