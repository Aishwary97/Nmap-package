#!/usr/bin/python3
# Automating scan using nmap package in python

import nmap

scanner = nmap.PortScanner()

print("Welcome to Nmap scanner{}", scanner.nmap_version())

ip_addr = input("Enter the IP address you want to scan: ")

response = input("1)SYN Scan 2)UDP Scan 3) Ping scan 4)Full Scan \n")

def default_scan(ip_addr):
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())

if response == '1':
    scanner.scan(ip_addr, '1-1024', '-v -sS') 
    print(scanner.scaninfo())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    default_scan(ip_addr)
  
elif response == '2':
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
    default_scan(ip_addr)

elif response == '3':
    scanner.scan(ip_addr, '1-1024', '-v -sP')
    print(scanner.scaninfo())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
    default_scan(ip_addr)

elif response == '4':
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    default_scan(ip_addr)

elif response >= '5':
    print("Invalid option")




