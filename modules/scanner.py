#!/usr/bin/env python3

import os
import json
import time
import socket
import select
import struct
import threading
import platform
from queue import Queue, Empty
from datetime import datetime
from typing import List, Dict, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

console = Console()

SERVICE_MAP = {
    20: "FTP-Data",    21: "FTP",         22: "SSH",          23: "Telnet",
    25: "SMTP",        53: "DNS",          67: "DHCP",         69: "TFTP",
    79: "Finger",      80: "HTTP",         88: "Kerberos",     110: "POP3",
    111: "RPCbind",    119: "NNTP",        123: "NTP",         135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP",       162: "SNMP-Trap",   179: "BGP",         194: "IRC",
    389: "LDAP",       443: "HTTPS",       445: "SMB",         465: "SMTPS",
    500: "IKE",        513: "rlogin",      514: "Syslog",      515: "LPD",
    543: "Kerberos",   587: "SMTP-TLS",    631: "IPP",         636: "LDAPS",
    873: "Rsync",      902: "VMware",      990: "FTPS",        993: "IMAPS",
    995: "POP3S",      1080: "SOCKS",      1194: "OpenVPN",    1433: "MSSQL",
    1434: "MSSQL-UDP", 1521: "Oracle",     1723: "PPTP",       1883: "MQTT",
    2049: "NFS",       2121: "FTP-Alt",    2222: "SSH-Alt",    2375: "Docker",
    2376: "Docker-TLS",3000: "Node.js",    3306: "MySQL",      3389: "RDP",
    3690: "SVN",       4444: "Backdoor",   4500: "IKE-NAT",    4848: "GlassFish",
    5000: "UPnP",      5432: "PostgreSQL", 5601: "Kibana",     5672: "RabbitMQ",
    5900: "VNC",       5984: "CouchDB",    6000: "X11",        6379: "Redis",
    6443: "K8s-API",   7001: "WebLogic",   7077: "Spark",      8000: "HTTP-Alt",
    8080: "HTTP-Proxy",8081: "HTTP-Alt2",  8443: "HTTPS-Alt",  8888: "Jupyter",
    8983: "Solr",      9000: "SonarQube",  9092: "Kafka",      9200: "Elasticsearch",
    9300: "ES-Transport",10000: "Webmin",  11211: "Memcached", 15672: "RabbitMQ-UI",
    27017: "MongoDB",  27018: "MongoDB",   28017: "MongoDB-Web",50000: "SAP",
    50070: "Hadoop",   61616: "ActiveMQ",
}

RISKY_PORTS = {
    21, 23, 69, 111, 135, 137, 138, 139, 445, 512, 513, 514,
    1080, 1433, 1521, 2375, 3389, 4444, 5900, 6000, 7001,
    27017, 50000
}

BANNER_PROBES = {
    21:    b"",
    22:    b"",
    23:    b"",
    25:    b"EHLO cypherx\r\n",
    80:    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:   b"",
    143:   b"",
    443:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    3306:  b"",
    5432:  b"",
    6379:  b"PING\r\n",
    9200:  b"GET / HTTP/1.0\r\n\r\n",
    27017: b"",
}


class PortScanner:
    def __init__(self, timeout: float = 0.5, quiet: bool = False,
                 threads: int = 500, grab_banner: bool = True):
        self.timeout     = max(0.1, timeout)
        self.quiet       = quiet
        self.threads     = min(threads, 1000)
        self.grab_banner = grab_banner
        self._open       = []
        self._lock       = threading.Lock()

    def _resolve(self, target: str) -> Optional[str]:
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None

    def _grab_banner(self, ip: str, port: int) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((ip, port))
            probe = BANNER_PROBES.get(port, b"")
            if probe:
                s.send(probe)
            ready = select.select([s], [], [], 1.5)
            if ready[0]:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                banner = " ".join(banner.split())
                return banner[:100]
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        return ""

    def _tcp_connect(self, ip: str, port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((ip, port))
            s.close()
            return result == 0
        except Exception:
            return False

    def _syn_scan_available(self) -> bool:
        if platform.system() == "Windows":
            return False
        try:
            return os.geteuid() == 0
        except Exception:
            return False

    def _parse_ports(self, ports_str: str, limit: int) -> List[int]:
        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                s, e = part.split("-")
                ports.extend(range(int(s), int(e) + 1))
            else:
                ports.append(int(part))
        seen = set()
        result = []
        for p in ports:
            if p not in seen and 1 <= p <= 65535:
                seen.add(p)
                result.append(p)
        return result[:limit]

    def _worker(self, ip: str, q: Queue):
        while True:
            try:
                port = q.get_nowait()
            except Empty:
                break
            try:
                if self._tcp_connect(ip, port):
                    service = SERVICE_MAP.get(port, "unknown")
                    banner  = ""
                    if self.grab_banner:
                        banner = self._grab_banner(ip, port)
                    risk    = port in RISKY_PORTS
                    result  = {
                        "port":    port,
                        "state":   "open",
                        "service": service,
                        "banner":  banner,
                        "risk":    risk,
                    }
                    with self._lock:
                        self._open.append(result)
                        if not self.quiet:
                            risk_str = "  [bold red]⚠ RISKY[/bold red]" if risk else ""
                            console.print(
                                f"  [green]OPEN[/green]  "
                                f"[yellow]{port:5}[/yellow]  "
                                f"[cyan]{service:16}[/cyan]  "
                                f"[dim]{banner[:50]}[/dim]{risk_str}"
                            )
            except Exception:
                pass
            finally:
                q.task_done()

    def run(self, target: str, ports: str = "1-1024", limit: int = 200,
            output_dir: str = "results", save_json: bool = False):
        from core.security import guard

        target = guard.sanitize(target, "target")
        if not guard.validate_port_range(ports):
            console.print("  [red]Error:[/red] Invalid port range.")
            return {}

        ip = self._resolve(target)
        if not ip:
            console.print(f"  [red]Error:[/red] Cannot resolve: {target}")
            return {}

        port_list = self._parse_ports(ports, limit)
        start     = time.time()

        console.print(f"\n  [*] Target:  {target} ({ip})")
        console.print(f"  [*] Ports:   {ports}  ({len(port_list)} total)")
        console.print(f"  [*] Threads: {self.threads}  Timeout: {self.timeout}s")
        console.print(f"  [*] Scanning...\n")

        q = Queue()
        for p in port_list:
            q.put(p)

        workers = []
        for _ in range(min(self.threads, len(port_list))):
            t = threading.Thread(target=self._worker, args=(ip, q), daemon=True)
            t.start()
            workers.append(t)

        for t in workers:
            t.join()

        elapsed   = round(time.time() - start, 2)
        open_list = sorted(self._open, key=lambda x: x["port"])

        if open_list:
            t2 = Table(title=f"Open Ports: {len(open_list)}", box=box.SIMPLE)
            t2.add_column("Port",    style="yellow", width=7)
            t2.add_column("Service", style="cyan",   width=18)
            t2.add_column("Banner",  style="white",  width=50)
            t2.add_column("Risk",    style="red",     width=6)
            for p in open_list:
                t2.add_row(
                    str(p["port"]),
                    p["service"],
                    p["banner"][:50] or "—",
                    "[bold red]⚠[/bold red]" if p["risk"] else ""
                )
            console.print(t2)
        else:
            console.print(f"  No open ports found.")

        console.print(f"\n  Scanned {len(port_list)} ports in {elapsed}s  |  {len(open_list)} open")

        payload = {
            "tool":       "CypherX",
            "target":     target,
            "ip":         ip,
            "ports":      ports,
            "scan_time":  datetime.now().isoformat(),
            "elapsed":    elapsed,
            "open_ports": open_list,
            "total_open": len(open_list),
        }

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            fname = f"scan_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            path  = os.path.join(output_dir, fname)
            with open(path, "w") as f:
                json.dump(payload, f, indent=4)
            console.print(f"  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  scan {target}\n")
        return payload
