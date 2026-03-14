<p align="center"><img src="logo.jpg" width="180"/></p>
<h1 align="center">CypherX</h1>
<p align="center">Cyber Intelligence Suite</p>
<p align="center">
<img src="https://img.shields.io/badge/version-1.0.0-blue"/>
<img src="https://img.shields.io/badge/python-3.8%2B-green"/>
<img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-cyan"/>
<img src="https://img.shields.io/badge/license-MIT-orange"/>
<img src="https://img.shields.io/badge/api-free-brightgreen"/>
</p>

---

## Modules

| Module | Description |
|--------|-------------|
| osint | Username / email / phone / domain / IP intelligence |
| recon | Full target reconnaissance |
| scan | Port scan + service detection |
| network | Host discovery |
| monitor | Live terminal traffic monitor |
| brute | Bruteforce SSH/FTP/HTTP/MySQL |
| vuln | Vulnerability detection |
| audit | System security audit |
| forensics | Log analysis + IOC extraction |
| hardening | System hardening recommendations |
| filecheck | File safety analysis |
| report | HTML / PDF / TXT report generator |
| update | Check and apply updates |

## Install

**Kali Linux:**
```bash
git clone https://github.com/sarkashi/cypherx
cd cypherx
bash install.sh
```

**Windows:**
```bash
git clone https://github.com/sarkashi/cypherx
cd cypherx
install.bat
```

## Usage

```bash
python3 cypherx.py --help

python3 cypherx.py osint --username ali --limit 20
python3 cypherx.py osint --email test@gmail.com
python3 cypherx.py osint --phone +905001234567
python3 cypherx.py osint --domain example.com --limit 30
python3 cypherx.py osint --ip 1.1.1.1

python3 cypherx.py recon --target example.com --limit 50
python3 cypherx.py scan 192.168.1.1 --ports 1-1024 --limit 100
python3 cypherx.py network 192.168.1.0/24 --limit 50
python3 cypherx.py monitor --iface eth0
python3 cypherx.py brute ssh 192.168.1.1 --limit 100
python3 cypherx.py vuln --target 192.168.1.1
python3 cypherx.py audit --full
python3 cypherx.py forensics --log /var/log/auth.log --limit 200
python3 cypherx.py hardening
python3 cypherx.py filecheck suspicious.pdf
python3 cypherx.py report --last --format html
python3 cypherx.py update
```

**Short flags:**
```bash
python3 cypherx.py -os --username ali
python3 cypherx.py -sc 192.168.1.1
python3 cypherx.py -n 192.168.1.0/24
python3 cypherx.py -fc file.exe
```

## Notes

- No API keys required
- Kali Linux and Windows compatible
- All results saved as JSON in `results/`
- Reports exported to `reports/`

## Legal

For authorized testing and educational use only.
