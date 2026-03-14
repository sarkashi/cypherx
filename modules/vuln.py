#!/usr/bin/env python3

import os
import json
import socket
import threading
import time
from queue import Queue, Empty
from datetime import datetime
from typing import Optional, List

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

SERVICE_MAP = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",587:"SMTP-TLS",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",1521:"Oracle",3000:"Node.js",3306:"MySQL",
    3389:"RDP",4444:"Backdoor",5432:"PostgreSQL",5900:"VNC",
    6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",
    9200:"Elasticsearch",27017:"MongoDB",11211:"Memcached",
    2049:"NFS",111:"RPCbind",135:"MSRPC",139:"NetBIOS",
    389:"LDAP",636:"LDAPS",873:"Rsync",2375:"Docker",
    6443:"Kubernetes",5601:"Kibana",9092:"Kafka",
}

VULN_DB = {
    "FTP": [
        {"id":"CVE-2011-2523","desc":"vsftpd 2.3.4 Backdoor Command Execution","severity":"CRITICAL","cvss":10.0},
        {"id":"CVE-2010-4221","desc":"ProFTPD 1.3.2rc3 Remote Code Execution","severity":"CRITICAL","cvss":9.8},
        {"id":"FTP-ANON","desc":"Anonymous FTP login allowed","severity":"HIGH","cvss":7.5},
        {"id":"FTP-CLEARTEXT","desc":"FTP transmits credentials in cleartext","severity":"MEDIUM","cvss":6.5},
    ],
    "SSH": [
        {"id":"CVE-2018-10933","desc":"libssh Authentication Bypass","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2023-38408","desc":"OpenSSH ssh-agent RCE","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2016-0777","desc":"OpenSSH UseRoaming Memory Leak","severity":"HIGH","cvss":8.1},
        {"id":"CVE-2023-48795","desc":"Terrapin SSH Prefix Truncation","severity":"MEDIUM","cvss":5.9},
        {"id":"SSH-DEFAULT-PORT","desc":"Default SSH port 22 exposed","severity":"LOW","cvss":3.1},
    ],
    "Telnet": [
        {"id":"TELNET-CLEARTEXT","desc":"Telnet transmits all data in cleartext","severity":"CRITICAL","cvss":9.1},
        {"id":"TELNET-ENABLED","desc":"Telnet service is running","severity":"HIGH","cvss":7.5},
    ],
    "SMB": [
        {"id":"CVE-2017-0144","desc":"EternalBlue MS17-010 Remote Code Execution","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2017-0145","desc":"EternalRomance MS17-010 RCE","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2020-0796","desc":"SMBGhost CVE-2020-0796 Remote Code Execution","severity":"CRITICAL","cvss":10.0},
        {"id":"CVE-2021-44142","desc":"Samba Out-of-Bounds Read/Write","severity":"CRITICAL","cvss":9.9},
        {"id":"SMB-NULL-SESSION","desc":"SMB null session allowed","severity":"HIGH","cvss":7.5},
    ],
    "HTTP": [
        {"id":"CVE-2021-41773","desc":"Apache 2.4.49 Path Traversal RCE","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2021-42013","desc":"Apache 2.4.49/50 Path Traversal RCE","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2021-44228","desc":"Log4Shell Log4j2 RCE","severity":"CRITICAL","cvss":10.0},
        {"id":"CVE-2022-22965","desc":"Spring4Shell Spring Framework RCE","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2023-44487","desc":"HTTP/2 Rapid Reset DDoS","severity":"HIGH","cvss":7.5},
        {"id":"HTTP-MISSING-HSTS","desc":"HSTS header missing","severity":"MEDIUM","cvss":5.3},
        {"id":"HTTP-MISSING-CSP","desc":"Content-Security-Policy header missing","severity":"MEDIUM","cvss":5.3},
        {"id":"HTTP-CLICKJACKING","desc":"X-Frame-Options header missing","severity":"MEDIUM","cvss":4.3},
    ],
    "HTTPS": [
        {"id":"CVE-2014-0160","desc":"Heartbleed OpenSSL Memory Disclosure","severity":"CRITICAL","cvss":7.5},
        {"id":"CVE-2015-0204","desc":"FREAK SSL Export Cipher Downgrade","severity":"HIGH","cvss":7.4},
        {"id":"CVE-2016-2107","desc":"POODLE AES-CBC Padding Oracle","severity":"HIGH","cvss":5.9},
        {"id":"CVE-2021-44228","desc":"Log4Shell Log4j2 RCE","severity":"CRITICAL","cvss":10.0},
        {"id":"SSL-SELF-SIGNED","desc":"Self-signed SSL certificate","severity":"MEDIUM","cvss":5.3},
    ],
    "MySQL": [
        {"id":"CVE-2012-2122","desc":"MySQL Authentication Bypass","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2016-6662","desc":"MySQL Remote Code Execution","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2021-22946","desc":"MySQL Client Protocol Downgrade","severity":"HIGH","cvss":7.5},
        {"id":"MYSQL-REMOTE","desc":"MySQL accessible remotely","severity":"HIGH","cvss":7.5},
    ],
    "Redis": [
        {"id":"REDIS-NOAUTH","desc":"Redis running without authentication","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2022-0543","desc":"Redis Sandbox Escape Lua RCE","severity":"CRITICAL","cvss":10.0},
        {"id":"CVE-2023-28425","desc":"Redis SINTERCARD Integer Overflow","severity":"HIGH","cvss":7.5},
    ],
    "MongoDB": [
        {"id":"MONGO-NOAUTH","desc":"MongoDB running without authentication","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2021-20328","desc":"MongoDB Client-Side Field Level Encryption","severity":"HIGH","cvss":6.5},
    ],
    "RDP": [
        {"id":"CVE-2019-0708","desc":"BlueKeep RDP Remote Code Execution","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2019-1181","desc":"DejaBlue RDP Remote Code Execution","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2020-0609","desc":"Windows RD Gateway RCE","severity":"CRITICAL","cvss":9.8},
        {"id":"RDP-NLA-DISABLED","desc":"Network Level Authentication disabled","severity":"HIGH","cvss":7.5},
    ],
    "MSSQL": [
        {"id":"CVE-2020-0618","desc":"MSSQL Reporting Services Remote Code Execution","severity":"CRITICAL","cvss":8.8},
        {"id":"CVE-2021-1636","desc":"MSSQL Privilege Escalation","severity":"HIGH","cvss":7.8},
        {"id":"MSSQL-REMOTE","desc":"MSSQL accessible remotely","severity":"HIGH","cvss":7.5},
    ],
    "Elasticsearch": [
        {"id":"ES-NOAUTH","desc":"Elasticsearch running without authentication","severity":"CRITICAL","cvss":9.8},
        {"id":"CVE-2021-22145","desc":"Elasticsearch Memory Disclosure","severity":"MEDIUM","cvss":5.3},
    ],
    "Docker": [
        {"id":"DOCKER-API-EXPOSED","desc":"Docker API exposed without authentication","severity":"CRITICAL","cvss":10.0},
        {"id":"CVE-2019-5736","desc":"Docker runc Container Escape","severity":"CRITICAL","cvss":8.6},
    ],
    "Kubernetes": [
        {"id":"K8S-API-EXPOSED","desc":"Kubernetes API server exposed","severity":"CRITICAL","cvss":10.0},
        {"id":"CVE-2018-1002105","desc":"Kubernetes API Server Privilege Escalation","severity":"CRITICAL","cvss":9.8},
    ],
    "VNC": [
        {"id":"VNC-NOAUTH","desc":"VNC running without authentication","severity":"CRITICAL","cvss":9.8},
        {"id":"VNC-CLEARTEXT","desc":"VNC transmits data in cleartext","severity":"HIGH","cvss":7.5},
    ],
    "MSRPC": [
        {"id":"CVE-2003-0352","desc":"MS03-026 DCOM RPC Buffer Overflow","severity":"CRITICAL","cvss":9.8},
        {"id":"MSRPC-EXPOSED","desc":"MSRPC exposed to network","severity":"HIGH","cvss":7.5},
    ],
    "NetBIOS": [
        {"id":"NETBIOS-INFO","desc":"NetBIOS information disclosure","severity":"MEDIUM","cvss":5.3},
    ],
    "Backdoor": [
        {"id":"BACKDOOR-PORT","desc":"Suspicious backdoor port open","severity":"CRITICAL","cvss":10.0},
    ],
    "NFS": [
        {"id":"NFS-EXPORT","desc":"NFS shares may be accessible","severity":"HIGH","cvss":7.5},
    ],
}


class VulnScanner:
    def __init__(self, timeout: int = 10, quiet: bool = False, threads: int = 50):
        self.timeout = timeout
        self.quiet   = quiet
        self.threads = threads

    def _grab_banner(self, ip: str, port: int) -> str:
        probes = {
            80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            6379: b"PING\r\n",
            9200: b"GET / HTTP/1.0\r\n\r\n",
        }
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((ip, port))
            probe = probes.get(port, b"")
            if probe:
                s.send(probe)
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            s.close()
            return " ".join(banner.split())[:100]
        except Exception:
            return ""

    def _scan_ports(self, ip: str, limit: int) -> List[dict]:
        ports      = list(SERVICE_MAP.keys())[:limit]
        open_ports = []
        lock       = threading.Lock()
        q          = Queue()
        for p in ports:
            q.put(p)

        def worker():
            while True:
                try:
                    port = q.get_nowait()
                except Empty:
                    break
                try:
                    s = socket.socket()
                    s.settimeout(1.0)
                    if s.connect_ex((ip, port)) == 0:
                        s.close()
                        banner = self._grab_banner(ip, port)
                        with lock:
                            open_ports.append({
                                "port":    port,
                                "service": SERVICE_MAP.get(port,"unknown"),
                                "banner":  banner,
                            })
                except Exception:
                    pass
                finally:
                    q.task_done()

        ws = [threading.Thread(target=worker, daemon=True) for _ in range(min(self.threads, len(ports)))]
        for w in ws:
            w.start()
        for w in ws:
            w.join()
        return sorted(open_ports, key=lambda x: x["port"])

    def _check_http_headers(self, ip: str, port: int) -> List[dict]:
        vulns = []
        try:
            r = requests.get(f"http://{ip}:{port}", timeout=self.timeout, verify=False,
                             headers={"User-Agent":"Mozilla/5.0"}, allow_redirects=True)
            h = r.headers
            if not h.get("Strict-Transport-Security"):
                vulns.append({"id":"HTTP-MISSING-HSTS","desc":"HSTS header missing","severity":"MEDIUM","cvss":5.3})
            if not h.get("Content-Security-Policy"):
                vulns.append({"id":"HTTP-MISSING-CSP","desc":"CSP header missing","severity":"MEDIUM","cvss":5.3})
            if not h.get("X-Frame-Options"):
                vulns.append({"id":"HTTP-CLICKJACKING","desc":"X-Frame-Options missing","severity":"MEDIUM","cvss":4.3})
            if not h.get("X-Content-Type-Options"):
                vulns.append({"id":"HTTP-MIME-SNIFF","desc":"X-Content-Type-Options missing","severity":"LOW","cvss":3.1})
        except Exception:
            pass
        return vulns

    def run(self, target: str, limit: int = 50, output_dir: str = "results", save_json: bool = False):
        from core.security import guard
        target = guard.sanitize(target, "target")
        start  = time.time()

        ip = target
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            pass

        console.print(f"\n  [*] Vuln scan: {target} ({ip})  limit={limit}")
        console.print(f"  [*] Detecting open ports...")

        open_ports = self._scan_ports(ip, limit)
        vulns      = []

        for p in open_ports:
            service = p["service"]
            port    = p["port"]
            if not self.quiet:
                console.print(f"  [cyan]OPEN[/cyan]  [yellow]{port:5}[/yellow]  {service:16}  [dim]{p['banner'][:40]}[/dim]")

            if service in VULN_DB:
                for vuln in VULN_DB[service]:
                    entry = {
                        "port":     port,
                        "service":  service,
                        "id":       vuln["id"],
                        "desc":     vuln["desc"],
                        "severity": vuln["severity"],
                        "cvss":     vuln["cvss"],
                        "banner":   p["banner"][:60],
                    }
                    vulns.append(entry)
                    if not self.quiet:
                        color = "bold red" if vuln["severity"] == "CRITICAL" else "red" if vuln["severity"] == "HIGH" else "yellow"
                        console.print(
                            f"  [{color}]⚠ {vuln['severity']:8}[/{color}]  "
                            f"CVSS:{vuln['cvss']:4}  "
                            f"{vuln['id']:22}  {vuln['desc']}"
                        )

            if service in ("HTTP","HTTP-Alt","HTTP-Alt2"):
                extra = self._check_http_headers(ip, port)
                for v in extra:
                    vulns.append({**v, "port": port, "service": service, "banner": ""})

        elapsed = round(time.time() - start, 2)

        crit  = [v for v in vulns if v["severity"] == "CRITICAL"]
        high  = [v for v in vulns if v["severity"] == "HIGH"]
        med   = [v for v in vulns if v["severity"] == "MEDIUM"]
        low   = [v for v in vulns if v["severity"] == "LOW"]

        console.print(f"\n  Summary: [bold red]{len(crit)} CRITICAL[/bold red]  [red]{len(high)} HIGH[/red]  [yellow]{len(med)} MEDIUM[/yellow]  [dim]{len(low)} LOW[/dim]")

        t = Table(title=f"Vulnerabilities: {len(vulns)}", box=box.SIMPLE)
        t.add_column("Port",     style="yellow", width=6)
        t.add_column("CVSS",     style="red",    width=6)
        t.add_column("Severity", style="red",    width=10)
        t.add_column("CVE/ID",   style="cyan",   width=24)
        t.add_column("Description", style="white", width=45)
        for v in sorted(vulns, key=lambda x: x["cvss"], reverse=True):
            color = "bold red" if v["severity"] == "CRITICAL" else "red" if v["severity"] == "HIGH" else "yellow"
            t.add_row(
                str(v["port"]),
                str(v["cvss"]),
                f"[{color}]{v['severity']}[/{color}]",
                v["id"],
                v["desc"]
            )
        console.print(t)
        console.print(f"\n  Scan complete in {elapsed}s")

        payload = {
            "tool":       "CypherX",
            "target":     target,
            "ip":         ip,
            "scan_time":  datetime.now().isoformat(),
            "elapsed":    elapsed,
            "open_ports": open_ports,
            "vulns":      vulns,
            "summary":    {"critical": len(crit), "high": len(high), "medium": len(med), "low": len(low)},
        }

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir,
                f"vuln_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path, "w") as f:
                json.dump(payload, f, indent=4)
            console.print(f"  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  vuln {target}\n")
        return payload
