<p align="center">
  <img src="logo.jpg" width="300"/>
</p>

<h1 align="center">CypherX</h1>

<p align="center">
  Cyber Intelligence Suite
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Kali%20%7C%20Ubuntu%20%7C%20Arch%20%7C%20Windows-cyan?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/api%20keys-none-brightgreen?style=flat-square"/>
</p>

---

CypherX is an open source cyber intelligence suite for security professionals, penetration testers, and researchers.
It brings OSINT, port scanning, vulnerability detection, forensics, bruteforce, traffic monitoring, and reporting into one tool.

No API keys. No registration. Free.

---

## Modules

| Module | Flag | Description |
|--------|------|-------------|
| osint | -os | Username / email / phone / domain / IP intelligence |
| recon | -r | Full target reconnaissance |
| scan | -sc | Fast port scan + service detection |
| network | -n | Host discovery + OS fingerprint |
| monitor | -m | Live traffic monitor |
| brute | -b | Bruteforce SSH / FTP / HTTP / RDP / MySQL / SMTP |
| vuln | -v | Vulnerability detection with CVE + CVSS scores |
| audit | -a | System security audit |
| forensics | -f | Log analysis + IOC extraction |
| hardening | -h2 | System hardening recommendations |
| filecheck | -fc | File safety analysis |
| report | -rp | HTML / PDF / TXT report generator |
| update | -u | Check and apply updates |

---

## Installation

### Kali Linux / Ubuntu / Debian

**Option 1 — Git**

```bash
git clone https://github.com/sarkashi/cypherx.git
cd cypherx
bash install.sh
```

**Option 2 — ZIP**

1. Go to [github.com/sarkashi/cypherx](https://github.com/sarkashi/cypherx)
2. Click the green **Code** button
3. Click **Download ZIP**
4. Extract the ZIP
5. Open terminal inside the folder

```bash
cd cypherx-main
bash install.sh
```

After installation, run from anywhere:

```bash
cypherx --help
```

---

### Arch Linux

```bash
git clone https://github.com/sarkashi/cypherx.git
cd cypherx
pip install -r requirements.txt
bash install.sh
```

---

### Windows

First install Python 3.8+ from [python.org](https://python.org)
During install, check **"Add Python to PATH"**

**Option 1 — Git**

```cmd
git clone https://github.com/sarkashi/cypherx.git
cd cypherx
install.bat
```

**Option 2 — ZIP**

1. Go to [github.com/sarkashi/cypherx](https://github.com/sarkashi/cypherx)
2. Click the green **Code** button
3. Click **Download ZIP**
4. Right-click the ZIP → **Extract All**
5. Open the extracted folder
6. Double-click **install.bat** — CMD opens and installs automatically

After installation:

```cmd
python cypherx.py --help
```

---

## Usage

```bash
cypherx --help
cypherx --version
```

---

### OSINT

Search a username across 70+ platforms:

```bash
cypherx osint --username target --limit 30
cypherx -os --username target --limit 30
```

Analyze an email address:

```bash
cypherx osint --email target@gmail.com
```

Analyze a phone number:

```bash
cypherx osint --phone +905001234567
```

Full domain intelligence:

```bash
cypherx osint --domain example.com --limit 50
```

IP address intelligence:

```bash
cypherx osint --ip 1.1.1.1
```

Multiple targets at once:

```bash
cypherx osint --username ali --email ali@gmail.com --domain example.com
```

Save as JSON:

```bash
cypherx osint --username ali --limit 20 --json
```

---

### Recon

```bash
cypherx recon --target example.com --limit 50
cypherx recon --target example.com --json
```

---

### Scan

```bash
cypherx scan 192.168.1.1
cypherx scan 192.168.1.1 --ports 1-1024
cypherx scan 192.168.1.1 --ports 1-65535
cypherx scan 192.168.1.1 --ports 22,80,443,3306
cypherx scan 192.168.1.1 --ports 1-65535 --threads 1000
cypherx scan 192.168.1.1 --ports 1-1024 --json
```

---

### Network

```bash
cypherx network 192.168.1.0/24
cypherx network 192.168.1.0/24 --limit 50
cypherx network 192.168.1.0/24 --json
```

---

### Monitor

Requires root on Linux:

```bash
sudo cypherx monitor --iface eth0
sudo cypherx monitor --iface eth0 --duration 60
```

---

### Brute

```bash
cypherx brute ssh 192.168.1.1
cypherx brute ssh 192.168.1.1 --passlist wordlist.txt --limit 1000
cypherx brute ssh 192.168.1.1 --user root --port 2222
```

Supported: `ssh` `ftp` `http` `smtp` `rdp` `mysql` `postgres` `telnet`

---

### Vuln

```bash
cypherx vuln --target 192.168.1.1
cypherx vuln --target 192.168.1.1 --json
```

Detects: EternalBlue, BlueKeep, Log4Shell, Heartbleed, SMBGhost, Spring4Shell, Redis/MongoDB no-auth, Docker/Kubernetes exposed APIs, missing HTTP security headers — all with CVSS scores.

---

### Audit

```bash
cypherx audit --full
cypherx audit --full --json
```

---

### Forensics

```bash
cypherx forensics --log /var/log/auth.log
cypherx forensics --log /var/log/auth.log --limit 500 --json
cypherx forensics
```

---

### Hardening

```bash
cypherx hardening
cypherx hardening --json
```

---

### Filecheck

```bash
cypherx filecheck suspicious.exe
cypherx filecheck suspicious.pdf --json
```

Analyzes file type, hashes (MD5/SHA1/SHA256), entropy, suspicious strings, PE header, risk score 0-100.

---

### Report

```bash
cypherx report --last --format html
cypherx report --last --format pdf
cypherx report --last --format txt
cypherx report --input results/scan.json --format html
```

Reports saved to `reports/`

---

### Update

```bash
cypherx update
```

Or manually:

```bash
git pull
```

---

## Short Flags

```
-os    osint
-r     recon
-sc    scan
-n     network
-m     monitor
-b     brute
-v     vuln
-a     audit
-f     forensics
-h2    hardening
-fc    filecheck
-rp    report
-u     update
```

---

## Global Flags

| Flag | Description |
|------|-------------|
| --limit N | Maximum number of results |
| --json | Save output as JSON |
| --quiet | Show summary only |
| --timeout N | Connection timeout in seconds |
| --threads N | Number of threads |
| --proxy URL | Use HTTP proxy |

---

## Output

```
cypherx/
├── results/      JSON scan results
├── reports/      HTML / PDF / TXT reports
├── logs/         Internal logs
└── wordlists/    Custom wordlists
```

---

## Requirements

- Python 3.8 or higher
- Dependencies installed automatically by `install.sh` or `install.bat`

---

## Legal

CypherX is for authorized security testing and educational use only.

Only use on systems you own or have explicit written permission to test.
The author is not responsible for any misuse or damage.
Unauthorized use may be illegal in your jurisdiction.

By using CypherX, you accept full responsibility.

---

## License

MIT License — Copyright (c) 2026 CypherX

---

<p align="center">
  CypherX v1.0.0 — github.com/sarkashi/cypherx
</p>
