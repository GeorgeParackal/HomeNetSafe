#!/usr/bin/env python3
"""
unknown_device.py  —  2s new/unknown device detector (ARP + tiny provoke sweep)

What it does
------------
- Polls the ARP/neighbor table every ~2 seconds.
- Sends a tiny burst of fast pings across your LAN to "provoke" fresh ARP entries
  so newly joined devices appear immediately (even if they ignore ICMP echo).
- On first run, prints a BASELINE of what's already present.
- Afterwards, prints alerts only for truly NEW devices (IP/MAC not seen before).
- If risk_scan.py exists in the same folder, runs a quick risk scan for each new device.

Recommended: Run terminal as Administrator (Windows) / use sudo (macOS/Linux).

Usage
-----
  python unknown_device.py                          # 2s interval, provoke sweep on, risk scan on (if available)
  python unknown_device.py --interval 2 --no-risk-scan
  python unknown_device.py --no-provoke             # skip ping provoke (less noisy, slightly slower to detect)
  python unknown_device.py --quiet-start            # don't print baseline at start
  python unknown_device.py --save known_devices.json
"""

from __future__ import annotations
import argparse, ipaddress, json, os, platform, re, shutil, socket, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

# ---------- Tunables ----------
INTERVAL_SECONDS = 2.0           # poll frequency
CACHE_FILENAME = "known_devices.json"
RISK_SCAN_TIMEOUT = 45
PROVOKE_COUNT = 64               # how many IPs to ping each round to refresh ARP
PROVOKE_TIMEOUT_MS = 120         # per-ping timeout (ms)
PROVOKE_WORKERS = 64             # concurrency for provoke pings
IGNORE_MACS = {"ff:ff:ff:ff:ff:ff"}  # broadcast

# ---------- Utilities ----------
def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def norm_mac(mac: str) -> str:
    return mac.lower().replace("-", ":").strip()

def load_known(path: str) -> Dict[str, Dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_known(path: str, data: Dict[str, Dict]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def is_locally_administered(mac: Optional[str]) -> bool:
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False

def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# ---------- Detect local /24 for provoke sweep ----------
def detect_local_cidr() -> Optional[ipaddress.IPv4Network]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except Exception:
        return None

# ---------- ARP/neighbor table parsing ----------
def snapshot_arp() -> Dict[str, str]:
    """
    Returns {ip -> mac}. Works on Windows/macOS/Linux.
    """
    sysplat = platform.system().lower()
    try:
        if "windows" in sysplat:
            out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL,
                                          encoding="oem", errors="ignore")
            pairs: Dict[str, str] = {}
            for line in out.splitlines():
                m_ip = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", line)
                m_mac = re.search(r"((?:[0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2})", line)
                if not (m_ip and m_mac):
                    continue
                ip = m_ip.group(1)
                mac = norm_mac(m_mac.group(1))
                if mac in IGNORE_MACS:
                    continue
                pairs[ip] = mac
            return pairs
        else:
            # Linux prefers ip neigh; macOS uses arp -n
            if have("ip"):
                out = subprocess.check_output(["ip", "neigh"], text=True, stderr=subprocess.DEVNULL)
            else:
                out = subprocess.check_output(["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
            pairs: Dict[str, str] = {}
            for line in out.splitlines():
                m_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                m_mac = re.search(r"((?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2})", line)
                if not (m_ip and m_mac):
                    continue
                ip = m_ip.group(1)
                mac = norm_mac(m_mac.group(1))
                if mac in IGNORE_MACS:
                    continue
                pairs[ip] = mac
            return pairs
    except Exception:
        return {}

# ---------- Provoke ARP entries quickly ----------
def ping_one(ip: str, timeout_ms: int) -> None:
    sysplat = platform.system().lower()
    try:
        if "windows" in sysplat:
            # -n 1 send one echo, -w timeout in ms
            subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=(timeout_ms/1000.0 + 0.3))
        else:
            # -c 1 send one echo, -W timeout seconds (rounded); keep short
            t = max(1, int(round(timeout_ms/1000.0)))
            subprocess.run(["ping", "-c", "1", "-W", str(t), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=(t + 0.3))
    except Exception:
        pass  # best-effort only

def provoke_arp_burst(net: Optional[ipaddress.IPv4Network],
                      count: int = PROVOKE_COUNT,
                      timeout_ms: int = PROVOKE_TIMEOUT_MS,
                      workers: int = PROVOKE_WORKERS) -> None:
    """
    Send a tiny burst of pings across the last N IPs of the local /24 to refresh ARP.
    This helps new phones show up instantly even if they ignore ICMP replies.
    """
    if not net:
        net = detect_local_cidr()
    if not net:
        return
    hosts = list(net.hosts())
    if not hosts:
        return
    # Prefer the higher part of the range (where many DHCP pools live).
    targets = [str(ip) for ip in hosts[-count:]]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(ping_one, ip, timeout_ms) for ip in targets]
        for _ in as_completed(futs):
            pass  # don't block long; each has its own short timeout

# ---------- Optional external risk scan ----------
def run_external_risk_scan(target_ip: str, timeout: int = RISK_SCAN_TIMEOUT) -> Optional[Dict]:
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, "risk_scan.py")
    if not os.path.isfile(candidate):
        return None
    try:
        out = subprocess.check_output([sys.executable, candidate, target_ip, "--top-ports", "50"],
                                      text=True, stderr=subprocess.DEVNULL, timeout=timeout)
        data = json.loads(out)
        for r in data.get("results", []):
            if r.get("target") == target_ip:
                return r
    except Exception:
        return None
    return None

# ---------- Main loop ----------
def main():
    ap = argparse.ArgumentParser(description="Fast new/unknown device detector (ARP + provoke).")
    ap.add_argument("--interval", type=float, default=INTERVAL_SECONDS, help="Seconds between polls (default 2)")
    ap.add_argument("--save", default=CACHE_FILENAME, help="Known device cache path (default known_devices.json)")
    ap.add_argument("--no-risk-scan", action="store_true", help="Do not run risk scan for new devices")
    ap.add_argument("--no-provoke", action="store_true", help="Skip the tiny ping burst (slower detection)")
    ap.add_argument("--quiet-start", action="store_true", help="Do not print baseline on first run")
    args = ap.parse_args()

    print(f"[monitor-arp] polling every {args.interval}s "
          f"(provoke={'off' if args.no_provoke else 'on'}, risk_scan={'off' if args.no_risk_scan else 'on'})")

    known = load_known(args.save)   # key: MAC if present else "IP:..."
    # Take initial snapshot and (optionally) show baseline so you see it's working
    if not args.no_provoke:
        provoke_arp_burst(detect_local_cidr())
    table = snapshot_arp()  # {ip -> mac}

    if not args.quiet_start:
        if table:
            print("\n--- BASELINE (seen at start) ---")
            for ip, mac in sorted(table.items(), key=lambda kv: tuple(map(int, kv[0].split(".")))):
                host = reverse_dns(ip)
                vendor_hint = "Locally administered (randomized)" if is_locally_administered(mac) else None
                print(f"{ip:15}  {mac:17}  {host or ''}  {vendor_hint or ''}")
        else:
            print("\n--- BASELINE: no ARP entries yet (will populate shortly) ---")

    # Merge baseline into known so we don't alert for everything present at start
    # (If you want alerts for all existing devices on first run, delete this block.)
    changed = False
    for ip, mac in table.items():
        key = mac if mac else f"IP:{ip}"
        if key not in known:
            known[key] = {"ip": ip, "mac": mac, "hostname": reverse_dns(ip)}
            changed = True
    if changed:
        save_known(args.save, known)

    # --------- Continuous monitor ---------
    try:
        while True:
            t0 = time.time()
            if not args.no_provoke:
                provoke_arp_burst(detect_local_cidr())
            table = snapshot_arp()

            # Check for NEW entries (IP/MAC not seen before)
            for ip, mac in table.items():
                key = mac if mac else f"IP:{ip}"
                if key in known:
                    # update IP if changed for that key (DHCP move)
                    if known[key].get("ip") != ip:
                        known[key]["ip"] = ip
                        save_known(args.save, known)
                    continue

                # NEW device!
                hostname = reverse_dns(ip)
                vendor_hint = "Locally administered (randomized)" if is_locally_administered(mac) else None

                print("\n===== [NEW DEVICE DETECTED] =====")
                print(f"IP:      {ip}")
                print(f"MAC:     {mac or 'None'}")
                print(f"Vendor:  {vendor_hint}")
                print(f"Name:    {hostname}")
                sys.stdout.flush()

                if not args.no_risk_scan:
                    print("[scan]  Running risk scan for new device...")
                    rs = run_external_risk_scan(ip)
                    if rs is not None:
                        open_ports = [str(e.get("port")) for e in rs.get("open", [])]
                        print(f"[scan]  Open ports: {', '.join(open_ports) if open_ports else 'none'}")
                        if rs.get("risks"):
                            print("[scan]  Risks:")
                            for r in rs["risks"]:
                                print(f"  - {r.get('title')}: {r.get('explanation')}")
                        else:
                            print("[scan]  No common risks found.")
                    else:
                        print("[scan]  (risk_scan.py not found or timed out)")

                known[key] = {"ip": ip, "mac": mac, "hostname": hostname}
                save_known(args.save, known)

            # sleep the remainder of the interval
            elapsed = time.time() - t0
            time.sleep(max(0.1, args.interval - elapsed))
    except KeyboardInterrupt:
        print("\n[monitor-arp] stopped by user.")
    except Exception as e:
        print(f"[monitor-arp] error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
