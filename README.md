## HomeNetSafe
Team Becrux submission for CSULB Project Starbound, currently ran as a script with modules to be installed but will be containarized via Docker to run as a "one click" application on user devices 

### Getting Started
Currently configured to run on windows, but easily translated into Linux/MacOS systems. 

Windows Users only 
- Please be sure to install NPCAP to run program

MacOS/Linus Users only
- Please replace "wifi" on line 28 to "ens33"

### Installation
run the following to install scapy module
"pip install scapy"

   
### Usage
Run "ipconfig" within command line
replace x on line 28 with IPv4 address

### Roadmap
- [x] LAN Device Discovery
- [ ] Tying devices to manufacturer and device names 
- [ ] Scan for New/Unknown Devices/Alerts on a new device/Unanaswered Packets
- [ ] Frontend UI, user should not have to replace anything within code or find there IPv4 address 


### Project Schematics
![alt text](image.png) 
