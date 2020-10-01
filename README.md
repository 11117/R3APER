# R3APER
Written in python3 using python-nmap library
This tool is used to scan an IP with specific port using python-nmap libraries

# Reqiurements
Need to have latest "nmap" installed on your OS
Install "python-nmap" library: for python V3 and above: "pip3 install python-nmap"

# How to Use

1. Make a "test.csv" file which contains all the IP's with its respective ports and save it under the same directory as your R3APER script location
2. The "test.csv" file should be the following format => "ip,port" (Have attached a sample test.csv)
3. To Run the file:  python3 R3APER.py
4. Depending on the type of scan needed you can change the nmap parameters in the code (R3APER.py Line 55:  t=nscan.scan(j['ip'],j['port'],'-sVUS -Pn'))

# Note: 
The script was tested successfully in windows 10 environment
