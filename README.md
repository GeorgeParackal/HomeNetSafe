                        
![Logo](</images/logo.png>)                                

Team Becrux submission for CSULB Project Starbound, currently ran as a script with modules to be installed but will be containarized via Docker to run as a "one click" application on user devices 

### Getting Started
Currently configured to run on windows, but easily translated into Linux/MacOS systems. 

Windows Users only 
- Please be sure to install NPCAP to run program

MacOS/Linus Users only
- Please replace "wifi" on line 28 to "ens33"

### How to run the program on Windows

Navigate to the correct folder in VSCode

Open the terminal and make sure you are in the folder that contains the requirements.txt file.
cd /path/to/your/project

Make a venv (if you haven't made one yet) by running:
python -m venv HNS_venv

Activate the venv by running. Run this command in terminal each time after you open VSCode again:
HNS_venv\Scripts\activate

Install all dependencies to the venv using:
pip install -r requirements.txt

Make sure you are using the right interpreter by
- clicking on View>Command Palette
- type in interpreter and click on "Python: Select Interpreter"
- click on the option that contains 'HNS_venv' in the name

### Github Commands
- git checkout -b your-branch-name : creating new branch to work on
- git checkout your-branch-name : switching between branches
- git branch : see which branch you are on
- git push -u origin your-branch-name : pushing changes in your branch
- git fetch origin + git rebase origin/main : get the latest changes from main onto your branch

### Roadmap
- [x] LAN Device Discovery
- [x] Tying devices to manufacturer and device names 
- [x] Scan for New/Unknown Devices/Alerts on a new device/Unanaswered Packets
- [ ] Frontend UI, user should not have to replace anything within code or find there IPv4 address 
- [ ] Raspberry Pi OS localization


### Project Schematics
![alt text](/images/image.png) 
