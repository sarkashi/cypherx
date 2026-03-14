#!/usr/bin/env python3

import os
import json
import time
import socket
import struct
import threading
import ipaddress
import platform
import subprocess
from queue import Queue, Empty
from datetime import datetime
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

QUICK_PORTS  = [22, 23, 25, 53, 80, 135, 139, 443, 445, 3306, 3389, 5900, 8080]
SERVICE_MAP  = {
    22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    135:"MSRPC",139:"NetBIOS",443:"HTTPS",445:"SMB",
    1433:"MSSQL",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    5900:"VNC",8080:"HTTP-Alt",8443:"HTTPS-Alt",
}

OS_TTLS = {
    (64, 64):   "Linux/Unix",
    (128, 128): "Windows",
    (254, 255): "Solaris/AIX",
    (127, 128): "Windows",
    (63, 64):   "Linux",
}


class NetworkEngine:
    def __init__(self, timeout: float = 1.0, quiet: bool = False, threads: int = 100):
        self.timeout = timeout
        self.quiet   = quiet
        self.threads = threads

    def _expand(self, target: str) -> List[str]:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            return [target]

    def _tcp_ping(self, ip: str) -> bool:
        for port in [80, 443, 22, 445, 135, 8080, 3389]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
        return False

    def _icmp_ping(self, ip: str) -> bool:
        sys = platform.system()
        try:
            if sys == "Windows":
                r = subprocess.run(
                    ["ping", "-n", "1", "-w", "500", ip],
                    capture_output=True, timeout=2
                )
            else:
                r = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", ip],
                    capture_output=True, timeout=2
                )
            return r.returncode == 0
        except Exception:
            return False

    def _is_alive(self, ip: str) -> bool:
        if self._icmp_ping(ip):
            return True
        return self._tcp_ping(ip)

    def _resolve(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def _get_mac(self, ip: str) -> str:
        if platform.system() == "Windows":
            try:
                r = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3)
                match = __import__("re").search(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", r.stdout, __import__("re").I)
                return match.group(0) if match else ""
            except Exception:
                return ""
        else:
            try:
                r = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3)
                match = __import__("re").search(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", r.stdout, __import__("re").I)
                return match.group(0) if match else ""
            except Exception:
                return ""

    def _guess_os(self, ip: str) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip, 80))
            s.close()
            return "Linux/Unix"
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip, 445))
            s.close()
            return "Windows"
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip, 22))
            s.close()
            return "Linux/Unix"
        except Exception:
            pass
        return "Unknown"

    def _quick_ports(self, ip: str) -> List[dict]:
        open_ports = []
        for port in QUICK_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append({"port": port, "service": SERVICE_MAP.get(port, "unknown")})
                s.close()
            except Exception:
                pass
        return open_ports

    def run(self, target: str, limit: int = 254, output_dir: str = "results", save_json: bool = False):
        from core.security import guard
        target = guard.sanitize(target, "target")
        hosts  = self._expand(target)[:limit]

        console.print(f"\n  [*] Network: {target}  hosts={len(hosts)}")
        console.print(f"  [*] Threads: {self.threads}  Timeout: {self.timeout}s\n")

        results = []
        lock    = threading.Lock()
        q       = Queue()
        start   = time.time()

        for h in hosts:
            q.put(h)

        def worker():
            while True:
                try:
                    ip = q.get_nowait()
                except Empty:
                    break
                try:
                    if self._is_alive(ip):
                        hostname   = self._resolve(ip)
                        ports      = self._quick_ports(ip)
                        mac        = self._get_mac(ip)
                        os_guess   = self._guess_os(ip)
                        entry      = {
                            "ip":       ip,
                            "hostname": hostname,
                            "mac":      mac,
                            "os":       os_guess,
                            "ports":    ports,
                        }
                        with lock:
                            results.append(entry)
                            if not self.quiet:
                                p_str = ", ".join(f"{p['port']}/{p['service']}" for p in ports[:4])
                                console.print(
                                    f"  [green]UP[/green]  "
                                    f"[yellow]{ip:16}[/yellow]  "
                                    f"[cyan]{os_guess:14}[/cyan]  "
                                    f"[dim]{hostname[:24]:24}[/dim]  "
                                    f"{p_str}"
                                )
                except Exception:
                    pass
                finally:
                    q.task_done()

        workers = [threading.Thread(target=worker, daemon=True) for _ in range(min(self.threads, len(hosts)))]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

        elapsed = round(time.time() - start, 2)

        t = Table(title=f"Live Hosts: {len(results)}", box=box.SIMPLE)
        t.add_column("IP",       style="yellow", width=16)
        t.add_column("OS",       style="cyan",   width=14)
        t.add_column("Hostname", style="white",  width=28)
        t.add_column("MAC",      style="dim",    width=18)
        t.add_column("Ports",    style="white",  width=35)
        for r in sorted(results, key=lambda x: x["ip"]):
            p_str = ", ".join(f"{p['port']}/{p['service']}" for p in r["ports"][:5])
            t.add_row(r["ip"], r["os"], r["hostname"][:28] or "—", r["mac"] or "—", p_str or "—")
        console.print(t)
        console.print(f"\n  Scanned {len(hosts)} hosts in {elapsed}s  |  {len(results)} alive")

        payload = {
            "tool":      "CypherX",
            "target":    target,
            "scan_time": datetime.now().isoformat(),
            "elapsed":   elapsed,
            "total":     len(hosts),
            "alive":     len(results),
            "hosts":     results,
        }

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir,
                f"network_{target.replace('/','_').replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path, "w") as f:
                json.dump(payload, f, indent=4, default=str)
            console.print(f"  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  network {target}\n")
        return payload
