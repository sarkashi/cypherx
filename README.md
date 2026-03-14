<p align="center">
  <img src="logo.jpg" width="220"/>
</p>

<h1 align="center">CypherX</h1>
<p align="center"><b>Cyber Intelligence Suite</b></p>
<p align="center">OSINT · Recon · Scanner · Vuln · Forensics · Bruteforce · Monitor</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Kali%20%7C%20Ubuntu%20%7C%20Arch%20%7C%20Windows-cyan?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/api%20keys-none-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/malware-free-brightgreen?style=flat-square"/>
</p>

---

## What is CypherX?

CypherX is an open source cyber intelligence suite built for security professionals, penetration testers, and researchers. It combines OSINT, reconnaissance, port scanning, vulnerability detection, log forensics, bruteforce testing, live traffic monitoring, and report generation into a single command-line tool.

- No API keys required — everything is free
- Works on Kali Linux, Ubuntu, Arch Linux, and Windows
- All results saved as JSON automatically
- Professional minimal terminal output
- Fast multi-threaded engine

---

## Modules

| Module | Short Flag | Description |
|--------|-----------|-------------|
| osint | -os | Username / email / phone / domain / IP intelligence |
| recon | -r | Full target reconnaissance |
| scan | -sc | Fast deep port scan + service detection |
| network | -n | Host discovery + OS fingerprint |
| monitor | -m | Live terminal traffic monitor |
| brute | -b | Bruteforce SSH / FTP / HTTP / MySQL / RDP / SMTP |
| vuln | -v | Deep vulnerability detection with CVE database |
| audit | -a | Full system security audit |
| forensics | -f | Log analysis + IOC extraction |
| hardening | -h2 | System hardening guide |
| filecheck | -fc | Deep file safety analysis |
| report | -rp | HTML / PDF / TXT report generator |
| update | -u | Check and apply updates |

---

## Installation

### Kali Linux / Ubuntu / Debian

**Method 1 — Git (Recommended):**
```bash
git clone https://github.com/sarkashi/cypherx.git
cd cypherx
bash install.sh
Method 2 — ZIP Download:
Go to https://github.com/sarkashi/cypherx
Click green Code button → Download ZIP
Extract the ZIP file
Open terminal in the extracted folder:
cd cypherx-main
bash install.sh
After install, use from anywhere:
cypherx --help
Arch Linux
git clone https://github.com/sarkashi/cypherx.git
cd cypherx
pip install -r requirements.txt
bash install.sh
Windows
Requirements: Python 3.8+ from python.org — check "Add Python to PATH" during install.
Method 1 — Git:
git clone https://github.com/sarkashi/cypherx.git
cd cypherx
install.bat
Method 2 — ZIP Download:
Go to https://github.com/sarkashi/cypherx
Click green Code button → Download ZIP
Right-click ZIP → Extract All → open the folder
Double-click install.bat — CMD opens automatically, installation starts
After install:
python cypherx.py --help
Quick Start
cypherx --help
cypherx --version
Usage
OSINT — Open Source Intelligence
Search username across 70+ platforms (GitHub, Instagram, Twitter, TikTok, Steam, Reddit, LinkedIn, Telegram and 60+ more):
cypherx osint --username target --limit 30
cypherx -os --username target --limit 30
Analyze email (validity, MX records, Gravatar, disposable check):
cypherx osint --email target@gmail.com
Analyze phone number (country, carrier, type):
cypherx osint --phone +905001234567
Full domain intelligence (WHOIS, DNS, subdomains, SSL, technology stack):
cypherx osint --domain example.com --limit 50
IP address intelligence (geolocation, ISP, ASN, proxy/hosting detection):
cypherx osint --ip 1.1.1.1
Combine targets:
cypherx osint --username ali --email ali@gmail.com --domain example.com
Save as JSON:
cypherx osint --username ali --limit 20 --json
RECON — Full Reconnaissance
cypherx recon --target example.com --limit 50
cypherx -r --target example.com --json
SCAN — Port Scanner
cypherx scan 192.168.1.1
cypherx scan 192.168.1.1 --ports 1-1024
cypherx scan 192.168.1.1 --ports 1-65535
cypherx scan 192.168.1.1 --ports 22,80,443,3306
cypherx scan 192.168.1.1 --ports 1-65535 --threads 1000 --timeout 0.3
cypherx -sc 192.168.1.1 --ports 1-1024 --json
Shows: open ports, service names, banner info, risky ports marked with ⚠
NETWORK — Host Discovery
cypherx network 192.168.1.0/24
cypherx -n 192.168.1.0/24 --limit 50 --json
Shows: live hosts, MAC address, OS guess, open ports per host.
MONITOR — Live Traffic Monitor
sudo cypherx monitor --iface eth0
sudo cypherx monitor --iface eth0 --duration 60
sudo cypherx -m --iface eth0
BRUTE — Bruteforce
cypherx brute ssh 192.168.1.1
cypherx brute ssh 192.168.1.1 --passlist wordlist.txt --limit 1000
cypherx brute ssh 192.168.1.1 --user root --port 2222
cypherx -b ftp 192.168.1.1 --json
Protocols: ssh ftp http smtp rdp mysql postgres telnet
Warning: Use only on systems you own or have explicit written permission to test.
VULN — Vulnerability Detection
cypherx vuln --target 192.168.1.1
cypherx -v --target 192.168.1.1 --json
Detects: EternalBlue CVE-2017-0144, BlueKeep CVE-2019-0708, Log4Shell CVE-2021-44228, Heartbleed CVE-2014-0160, SMBGhost CVE-2020-0796, Spring4Shell CVE-2022-22965, Redis/MongoDB no-auth, Docker/Kubernetes API exposed, HTTP missing security headers — all with CVSS scores.
AUDIT — System Security Audit
cypherx audit --full
cypherx -a --full --json
FORENSICS — Log Analysis
cypherx forensics --log /var/log/auth.log
cypherx forensics --log /var/log/auth.log --limit 500 --json
cypherx -f
Extracts: failed logins, suspicious commands, IOCs (IPs, domains, hashes), base64 strings.
HARDENING — System Hardening
cypherx hardening
cypherx -h2 --json
FILECHECK — File Safety Analysis
cypherx filecheck suspicious.exe
cypherx -fc suspicious.pdf --json
Analyzes: file type, MD5/SHA1/SHA256 hashes, entropy, dangerous extensions, suspicious strings, PE header, risk score 0-100 (LOW / MEDIUM / HIGH).
REPORT — Generate Reports
cypherx report --last --format html
cypherx report --last --format txt
cypherx report --last --format pdf
cypherx report --input results/scan.json --format html
cypherx -rp --last --format html
Reports saved to reports/ folder.
UPDATE
cypherx update
cypherx -u
git pull
Short Flags Reference
-os   →  osint
-r    →  recon
-sc   →  scan
-n    →  network
-m    →  monitor
-b    →  brute
-v    →  vuln
-a    →  audit
-f    →  forensics
-h2   →  hardening
-fc   →  filecheck
-rp   →  report
-u    →  update
Global Flags
Flag
Description
--limit N
Maximum number of results
--json
Save results as JSON file
--quiet
Show summary only
--timeout N
Connection timeout in seconds
--threads N
Number of concurrent threads
--proxy URL
Use HTTP proxy
--output DIR
Custom output directory
Output Structure
cypherx/
├── results/       ← JSON scan results
├── reports/       ← HTML / PDF / TXT reports
├── logs/          ← Internal logs
└── wordlists/     ← Custom wordlists for bruteforce

Requirements
Python 3.8+
All dependencies installed automatically by install.sh / install.bat
Packages: click rich requests dnspython python-whois paramiko scapy
Legal Disclaimer

CypherX is intended for authorized security testing and educational purposes only.
Only use on systems you own or have explicit written permission to test
The author is NOT responsible for any misuse or damage
Unauthorized use is illegal in most jurisdictions
By using CypherX, you accept full legal responsibility.
Contributing
Contributions are welcome. See CONTRIBUTING.md for guidelines.
License
MIT License — Copyright (c) 2026 CypherX — See LICENSE


CypherX v1.0.0
github.com/sarkashi/cypherx 

```
