# Automated Vulnerability Scanner
Purpose to make recon fast

This script automates vulnerability scanning of web applications using Nmap, Nuclei, and Dirb. The script takes user input for the target IP/subnet to scan and performs the following steps:

## Scans for open ports using Nmap.
Finds live hosts with open ports.
Runs Nmap scripts on live hosts.
Runs Nuclei full scan on the last Nmap result.
Runs Dirb scan on the last Nmap result.
Searches for SQLi and XSS vulnerabilities in Dirb scan results.
## Prerequisites
- Python 3.x
- Nmap
- Nuclei
- Dirb
- Requests
- Beautiful Soup 4
