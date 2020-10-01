# R3APER
Written in python3 using python-nmap library
This tool is used to scan an IP with specific port using python-nmap libraries

# Reqiurements
Need to have latest "nmap" installed on your OS
Install "python-nmap" library: for python V3 and above: "pip3 install python-nmap"

# How to Use

1. Add the filename of your IP list into the code (Line 39 : path_to_iplist=current_directory+'\\test.csv')
2. The Ip's list should be placed as a csv file and be in the given format => "ip,port" (Have attached a sample test.csv)
3. To Run the file:  python3 R3APER.py
4. Depending on the type of scan needed you can the nmap parameters in the code (Line 55:  t=nscan.scan(j['ip'],j['port'],'-sVUS -Pn'))

# Note: 
The script was tested successfully in windows 10 environment
