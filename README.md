                        
![Logo](</images/logo.png>)                                

Team Becrux submission for CSULB Project Starbound, currently ran as a script with modules to be installed but will be containarized via Docker to run as a "one click" application on user devices 

### Getting Started
Currently configured to run on windows, but easily translated into Linux/MacOS systems. 

Windows Users only 
- Please be sure to install NPCAP to run program

MacOS/Linus Users only
- Please replace "wifi" on line 28 to "ens33"

### Installation
run the following in command line/powershell

- `pip install scapy`
- `pip install click_spinner`
- `pip install mac_vendor_lookup`

If on windows, instal "Npcap" from browser

### Usage
Run `ipconfig` within command line
replace x on line 75 with IPv4 address 
![temp_IPv4](</images/IMG_0047.png>)
![IPv4_loc](</images/IMG_0048.png>)

### Roadmap
- [x] LAN Device Discovery
- [x] Tying devices to manufacturer and device names 
- [ ] Scan for New/Unknown Devices/Alerts on a new device/Unanaswered Packets
- [ ] Frontend UI, user should not have to replace anything within code or find there IPv4 address 
- [ ] Raspberry Pi OS localization


### Project Schematics
![alt text](/images/image.png) 
