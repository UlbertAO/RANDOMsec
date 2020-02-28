# RANDOMsec
Find who is alive on your local network .

installation:
download or clone this after that install these python packages
pip3 install python-nmap
pip3 install psutil
if you do not have sys,re,getopt already installed install then as well

How To Run:

netdisco -i <interface>
-i  :specify interface
-h  :show help
-t  :specify target
Example:
    python3 netdisco.py -i wlan0
    python netdisco.py -i Wi-Fi
    python3 netdisco.py -i wlan0 -t 198.168.0.55(find if specific ip is alive or not)

#thats it
