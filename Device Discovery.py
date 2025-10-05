from datetime import datetime
from click_spinner import spinner
from scapy.all import srp, Ether, ARP, conf
import time
from mac_vendor_lookup import MacLookup, VendorNotFoundError



GREEN = "\033[32m"
RESET = "\033[0m"
                                                                                                  
banner = r"""
                                      
                ##################                
            ##########################            
         ########                ########         
       #######        .####.        #######       
      #####     .################.     #####      
        .     ##########  ##########     .        
           #######              #######
 _     ____  _        ____  _____ _     _  ____  _____   ____  _  ____  ____  ____  _     _____ ____ ___  _
/ \   /  _ \/ \  /|  /  _ \/  __// \ |\/ \/   _\/  __/  /  _ \/ \/ ___\/   _\/  _ \/ \ |\/  __//  __\\  \//
| |   | / \|| |\ ||  | | \||  \  | | //| ||  /  |  \    | | \|| ||    \|  /  | / \|| | //|  \  |  \/| \  / 
| |_/\| |-||| | \||  | |_/||  /_ | \// | ||  \__|  /_   | |_/|| |\___ ||  \__| \_/|| \// |  /_ |    / / /                        
\____/\_/ \|\_/  \|  \____/\____\\__/  \_/\____/\____\  \____/\_/\____/\____/\____/\__/  \____\\_/\_\/_/          
           ####      ########      ####           
                  ##############                  
                ######      ######      Written by Chenchu H. Yakasiri Saravanan with George Paracakal
                 ##            ##       - Oct 2025 
                       .###                       
                      ######                      
                     ########                     
                      ######                      
                                                
"""

mac_lookup=MacLookup()

try: 
    mac_lookup.update_vendors()
except Exception:
    pass


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
        try: 
            vendor = mac_lookup.lookup(mac)
        except VendorNotFoundError:
            vendor = "vendor not found"
        print(f"{ip} - {mac} - {vendor}")

    print("\n[->] Scan Complete. Duration:", datetime.now() - start)


print(GREEN+banner+RESET)
with spinner():
    arp_scan("Wi-Fi", "192.168.1.2/24", timeout=3, retries=4)


#change to ens33 for linux of rasberry pi os, wifi adapter is for windows. 
#use yours IPv4 Address found with the ipconfig command, this dervies network range based on device IP address

#WILL ADD list of manufac, just refence a JSON instead of putting it in here. 

# ---note---
# code will take a while to run, it's making sure mulitple passes are done and waits between each pass to allow
# for unanswered devices and powered off devices to answer

#AGAIN CODE only returns an IP if the device is powered on and is able to respond to ARP scan