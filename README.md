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

## Disclaimer:

The code provided is for educational and informational purposes only. The use of this code is at the user's own risk. The author and publisher of this code make no representations or warranties of any kind with respect to the accuracy or completeness of the code. The author and publisher of this code disclaim all liability for any direct, indirect, incidental, or consequential damages arising from the use of or reliance on the code. Users are solely responsible for ensuring that their use of the code complies with all applicable laws and regulations.
