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
print("                                                                                       .: Authour- Jean Paul :.                                        ")
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

"""Note:filepath may wary for different operating system"""
print('=='*70)

with open("D:\\test\\test.csv",'r') as file:    
    csv_file=csv.DictReader(file)
    for i,j in enumerate(csv_file):
        t=nscan.scan(j['ip'],j['port'])
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
        except:
                Host_status="None"
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
        print("Command Line:::",cmdline)
        print('_'*20)
        print("|| ScanStats:::        ||\n")
        print("||   Scan-Time: ",Scan_Time)
        print("||   Time-Elapsed: ",Time_Elapsed)
        print("||   UpHost: ",UpHost)
        print("||   DownHost: ",DownHost)
        print("||   TotalHosts: ",TotalHosts)
        print('_'*20)
        print("|| Scan Data:::        ||\n")
        print("||   IP: ",IP)
        print("||   Addresses: ",Addresses)
        print("||   Host_status: ",Host_status)
        print("||   Port-Status::",port_state)
        print("||   Reason: ",reason)
        print("||   Name: ",name)
        print("||   Product: ",product)
        print("||   Version: ",version)
        print("||   CPE: ",cpe)
        print("||   ExtraInfo: ",extrainfo)
        
        
        print('=='*70)
    
    
    
    
    
    
    