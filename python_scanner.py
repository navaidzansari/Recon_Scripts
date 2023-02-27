import nmap
import subprocess
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

# Take user input
target = input("Enter target IP/Subnet: ")

# Initialize Nmap scanner
nm = nmap.PortScanner()

# Scan for open ports
print("Scanning for open ports...")
nm.scan(hosts=target, arguments='-p 80,443,8080 -Pn')

# Find live hosts with open ports
open_hosts = [x for x in nm.all_hosts() if nm[x].state() == 'up' and nm[x].all_tcp() != {}]
if not open_hosts:
    print("No live hosts with open ports found.")
    exit()

# Run Nmap scripts on live hosts
print(f"Found {len(open_hosts)} live hosts with open ports. Running Nmap scripts...")
for host in open_hosts:
    nmap_command = f"nmap -Pn -sC -sV -oN {host}_nmap_scan.txt {host}"
    subprocess.check_output(nmap_command, shell=True)

# Run Nuclei on last Nmap result
if open_hosts:
    last_nmap_scan = f"{open_hosts[-1]}_nmap_scan.txt"
    nuclei_templates_dir = "/home/kali/nuclei-templates"
    nuclei_command = f"nuclei -silent -u http://{open_hosts[-1]} -t {nuclei_templates_dir} -severity high,medium"
    print("Running Nuclei full scan...")
    subprocess.check_output(nuclei_command, shell=True)

# Run Dirb scan on last Nmap result
if open_hosts:
    dirb_command = f"dirb http://{open_hosts[-1]} -r -o dirb_scan.txt /usr/share/dirb/wordlists/common.txt"
    print("Running Dirb scan...")
    subprocess.check_output(dirb_command, shell=True)

# Run Nikto scan on last Nmap result
if open_hosts:
    nikto_command = f"nikto -h {open_hosts[-1]} -o nikto_scan.txt"
    print("Running Nikto scan...")
    subprocess.check_output(nikto_command, shell=True)

# Search for SQLi and XSS vulnerabilities in Dirb and Nikto scan results
if open_hosts:
    print("Searching for SQLi and XSS vulnerabilities in Dirb and Nikto scan results...")
    with open('dirb_scan.txt', 'r') as dirb_scan_file:
        for line in dirb_scan_file:
            if line.startswith('+ '):
                url_path = re.search(r'\+ (\S+)', line).group(1)
                full_url = urljoin(f'http://{open_hosts[-1]}', url_path)
                response = requests.get(full_url)
                soup = BeautifulSoup(response.text, 'html.parser')
                if "sql" in soup.text.lower():
                    print(f"SQLi vulnerability found in {full_url}")
                if "<script>" in soup.text.lower():
                    print(f"XSS vulnerability found in {full_url}")
    with open('nikto_scan.txt', 'r') as nikto_scan_file:
        for line in nikto_scan_file:
            if "OSVDB" in line:
                print(f"Vulnerability found in Nikto scan: {line.strip()}")

print("Done.")
