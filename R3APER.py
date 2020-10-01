import nmap
import csv
from os import getcwd


print("           _____                    _____                    _____                    _____                    _____                    _____          ")    
print("          /\    \                  /\    \                  /\    \                  /\    \                  /\    \                  /\    \         ")
print("         /::\    \                /::\    \                /::\    \                /::\    \                /::\    \                /::\    \        ")
print("        /::::\    \              /::::\    \              /::::\    \              /::::\    \              /::::\    \              /::::\    \       ")
print("       /::::::\    \            /::::::\    \            /::::::\    \            /::::::\    \            /::::::\    \            /::::::\    \      ")
print("      /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \     ")
print("     /:::/__\:::\    \        /:::/__\:::\    \        /:::/__\:::\    \        /:::/__\:::\    \        /:::/__\:::\    \        /:::/__\:::\    \    ")
print("    /::::\   \:::\    \      /::::\   \:::\    \      /::::\   \:::\    \      /::::\   \:::\    \      /::::\   \:::\    \      /::::\   \:::\    \   ")
print("   /::::::\   \:::\    \    /::::::\   \:::\    \    /::::::\   \:::\    \    /::::::\   \:::\    \    /::::::\   \:::\    \    /::::::\   \:::\    \  ")
print("  /:::/\:::\   \:::\____\  /:::/\:::\   \:::\    \  /:::/\:::\   \:::\    \  /:::/\:::\   \:::\____\  /:::/\:::\   \:::\    \  /:::/\:::\   \:::\____\ ")
print(" /:::/  \:::\   \:::|    |/:::/__\:::\   \:::\____\/:::/  \:::\   \:::\____\/:::/  \:::\   \:::|    |/:::/__\:::\   \:::\____\/:::/  \:::\   \:::|    |")
print(" \::/   |::::\  /:::|____|\:::\   \:::\   \::/    /\::/    \:::\  /:::/    /\::/    \:::\  /:::|____|\:::\   \:::\   \::/    /\::/   |::::\  /:::|____|")
print("  \/____|:::::\/:::/    /  \:::\   \:::\   \/____/  \/____/ \:::\/:::/    /  \/_____/\:::\/:::/    /  \:::\   \:::\   \/____/  \/____|:::::\/:::/    / ")
print("        |:::::::::/    /    \:::\   \:::\    \               \::::::/    /            \::::::/    /    \:::\   \:::\    \            |:::::::::/    /  ")
print("        |::|\::::/    /      \:::\   \:::\____\               \::::/    /              \::::/    /      \:::\   \:::\____\           |::|\::::/    /   ")
print("        |::| \::/____/        \:::\   \::/    /               /:::/    /                \::/____/        \:::\   \::/    /           |::| \::/____/    ")
print("        |::|  ~|               \:::\   \/____/               /:::/    /                  ~~               \:::\   \/____/            |::|  ~|          ")
print("        |::|   |                \:::\    \                  /:::/    /                                     \:::\    \                |::|   |          ")
print("        \::|   |                 \:::\____\                /:::/    /                                       \:::\____\               \::|   |          ")
print("         \:|   |                  \::/    /                \::/    /                                         \::/    /                \:|   |          ")
print("          \|___|                   \/____/                  \/____/                                           \/____/                  \|___|          ")
print("                                                                                                                                                       ")
print("                                                                                       .: Author- Jean Paul :.                                        ")
print('\n'*3)
print("                                                             .:Starting REAPER:.")
print('\n'*2)
print("                                                     REcon to Attack and Pull Exact Results")
print('\n'*2)
print("                       .:Nmap has been Initilized:.")
nscan=nmap.PortScanner()
"""gets current working directory"""
current_directory=getcwd() 
print("               Your Current Working Directory is  : ",current_directory)
path_to_iplist=current_directory+'\\test.csv'
lines = len(open(path_to_iplist).readlines(  ))
totalnum=lines-1

"""Note:filepath may wary for different operating system"""
print('=='*70)
outpath=current_directory+"\\R3APER_Output.csv"
myFile = open(outpath, 'a+',newline='')
csv_out = csv.writer(myFile)
csv_out.writerow(["CommandLine","Scan_time","Time_Elapsed","UpHost","DownHost","TotalHosts","IP","Hostnames","Host_status","Addresses","TCP_Port_State","TCP_Reason","TCP_Name","UDP_Port_State","UDP_Reason","UDP_Name","TCP_Product","TCP_Version","TCP_CPE","TCP_ExtraInfo","UDP_Product","UDP_Version","UDP_CPE","UDP_ExtraInfo"])

with open(path_to_iplist,'r') as file:    
    csv_file=csv.DictReader(file)
    for i,j in enumerate(csv_file):
        print("Currently working on : ",i+1,"IP from Total IP(s) to Scan: ",totalnum)
        print("Scanning  ===>  ",j['ip'])
        t=nscan.scan(j['ip'],j['port'],'-sVUS -Pn')
        try:
            cmdline=t['nmap']['command_line']
            scanstats=t['nmap']['scanstats']
            Scan_Time=t['nmap']['scanstats']['timestr']
            Time_Elapsed=t['nmap']['scanstats']['elapsed']
            UpHost=t['nmap']['scanstats']['uphosts']
            DownHost=t['nmap']['scanstats']['downhosts']
            TotalHosts=t['nmap']['scanstats']['totalhosts']
            scaninfo=t['nmap']['scaninfo']
            scan=t['scan']
            IP=j['ip']
            Host_status=t['scan'][j['ip']].state()
            Hostnames=t['scan'][j['ip']]['hostnames']
            Addresses=t['scan'][j['ip']]['addresses']
            for k in t['scan'][j['ip']]['tcp'].keys():
                port_state=t['scan'][j['ip']]['tcp'][k]['state']
                reason=t['scan'][j['ip']]['tcp'][k]['reason']
                name=t['scan'][j['ip']]['tcp'][k]['name']
                product=t['scan'][j['ip']]['tcp'][k]['product']
                version=t['scan'][j['ip']]['tcp'][k]['version']
                cpe=t['scan'][j['ip']]['tcp'][k]['cpe']
                extrainfo=t['scan'][j['ip']]['tcp'][k]['extrainfo']
            for u in t['scan'][j['ip']]['udp'].keys():
                udp_port_state=t['scan'][j['ip']]['udp'][u]['state']
                udp_reason=t['scan'][j['ip']]['udp'][u]['reason']
                udp_name=t['scan'][j['ip']]['udp'][u]['name']
                udp_product=t['scan'][j['ip']]['udp'][u]['product']
                udp_version=t['scan'][j['ip']]['udp'][u]['version']
                udp_cpe=t['scan'][j['ip']]['udp'][u]['cpe']
                udp_extrainfo=t['scan'][j['ip']]['udp'][u]['extrainfo']
        except:
                Host_status="None"
                udp_port_state="None"
                udp_reason="None"
                udp_name="None"
                udp_product="None"
                udp_version="None"
                udp_cpe="None"
                udp_extrainfo="None"
                port_state="None"
                Time_Elapsed="None"
                UpHost="None"
                DownHost="None"
                TotalHosts="None"
                IP="None"
                Addresses="None"
                Vendor="None"
                reason="None"
                name="None"
                product="None"
                version="None"
                cpe="None"
                extrainfo="None"
                
        print('_'*20)
        csv_out.writerow([cmdline,Scan_Time,Time_Elapsed,UpHost,DownHost,TotalHosts,IP,Hostnames,Host_status,Addresses,port_state,reason,name,udp_port_state,udp_reason,udp_name,product,version,cpe,extrainfo,udp_product,udp_version,udp_cpe,udp_extrainfo])
        print("Command Line:::",cmdline)
        print('_'*20)
        print("|| ScanStats:::        ||\n")
        print("||   Scan-Time: ",Scan_Time,"||   Time-Elapsed: ",Time_Elapsed,"||   UpHost: ",UpHost,"||   DownHost: ",DownHost,"||   TotalHosts: ",TotalHosts)
        print('_'*20)
        print("|| Scan Data:::        ||\n")
        print("||   IP: ",IP," Addresses: ",Addresses,"  Hostnames: ",Hostnames,"  Host_status: ",Host_status,"  TCP_Port-Status::",port_state,"  TCP_Reason: ",reason," TCP_Name: ",name,"  TCP_Product: ",product," TCP_Version: ",version,"  TCP_CPE: ",cpe,"  TCP_ExtraInfo: \n",extrainfo)
        print("||   UDP_Port-Status::",udp_port_state,"  UDP_Reason: ",udp_reason," UDP_Name: ",udp_name," UDP_Product: ",udp_product," UDP_Version: ",udp_version,"  UDP_CPE: ",udp_cpe," UDP_ExtraInfo: \n",udp_extrainfo)
        
        print('=='*70)
    
 
