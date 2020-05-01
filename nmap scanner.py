#!/usr/bin/python3
# Automating scan using nmap library in python

import nmap

scanner = nmap.PortScanner()

print("Welcome to Nmap scanner{}", scanner.nmap_version())

ports = '1-1024'
protocols = ['tcp', 'udp', 'icmp']
scan_modes = ['-sS', '-sU', '-sP', '-sS -sV -sC -A -O']

def scan_function(ip_addr, ports, protocols, modes):
    scanner.scan(ip_addr, ports, modes)                            #Performs scan as per mentioned mode 
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())                 #Displays the state of the ip
    print(scanner[ip_addr].all_protocols())                        #Displays all available Ports
    print("Open Ports: ", scanner[ip_addr][protocols].keys())      #Displays Open Ports

ip_addr = input("Enter an ip address to scan")

response = input("Type of scan - 1.SYN 2.UDP 3.PING 4.FULL SCAN. Enter the number or type - ")
 
if response == '1' or 'SYN':
   scan_function(ip_addr, ports, protocols[0], scan_modes[0]) 
   
elif response == '2' or 'UDP':
    scan_function(ip_addr, ports, protocols[1], scan_modes[1])
    
elif response == '3' or 'PING':
    scan_function(ip_addr, ports, protocols[2], scan_modes[2])

elif response == '4' or 'FULL SCAN':
    scan_function(ip_addr, ports, protocols[0], scan_modes[3])
    
elif response >= '5':
    print("Invalid option")
