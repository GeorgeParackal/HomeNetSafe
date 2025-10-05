from datetime import datetime
from scapy.all import srp, Ether, ARP, conf
import time

def arp_scan(interface, ips, timeout=2, retries=3):
    print("[->] Scanning")
    start = datetime.now()
    conf.verb = 0
    #silent mode on Scapy, keeps output clean

    found = {}
    #empty dict to store found devices, tying IP to MAC


#srp returns ans, unans - answered packts and unanswered packets, for now we will ignore the second value with an underscore
    for i in range(retries):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips),timeout=timeout, iface=interface, inter=0.1)
        for _, recivedPack in ans:
            found[recivedPack.psrc] = recivedPack.hwsrc
        time.sleep(0.2)

    print("\n[->] IP - MAC Address")
    for ip, mac in sorted(found.items()):
        print(f"{ip} - {mac}")

    print("\n[->] Scan Complete. Duration:", datetime.now() - start)

arp_scan("Wi-Fi", "x/24", timeout=3, retries=4)

#change to ens33 for linux of rasberry pi os, wifi adapter is for windows. 
#use yours IPv4 Address found with the ipconfig command, this dervies network range based on device IP address

#WILL ADD list of manufac, just refence a JSON instead of putting it in here. 

# ---note---
# code will take a while to run, it's making sure mulitple passes are done and waits between each pass to allow
# for unanswered devices and powered off devices to answer

#AGAIN CODE only returns an IP if the device is powered on and is able to respond to ARP scan