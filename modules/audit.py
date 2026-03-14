#!/usr/bin/env python3

import os
import json
import platform
import subprocess
from datetime import datetime
from typing import List, Dict

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


class SystemAudit:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self._os   = platform.system()

    def _run(self, cmd: str) -> str:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return r.stdout.strip()
        except Exception:
            return ""

    def _ssh_config(self) -> List[dict]:
        issues = []
        path   = "/etc/ssh/sshd_config"
        if not os.path.exists(path):
            return issues
        with open(path) as f:
            content = f.read()
        checks = {
            "PermitRootLogin yes":  "Root login allowed via SSH",
            "PasswordAuthentication yes": "Password auth enabled (use keys)",
            "Port 22":              "Default SSH port (change it)",
            "X11Forwarding yes":    "X11 forwarding enabled",
        }
        for pattern, desc in checks.items():
            if pattern.lower() in content.lower():
                issues.append({"check": pattern, "issue": desc, "severity": "MEDIUM"})
        return issues

    def _sudoers(self) -> List[dict]:
        issues = []
        if self._os == "Windows":
            return issues
        out = self._run("sudo -l 2>/dev/null")
        if "NOPASSWD" in out:
            issues.append({"check": "sudoers", "issue": "NOPASSWD entries found", "severity": "HIGH"})
        if "ALL=(ALL)" in out:
            issues.append({"check": "sudoers", "issue": "Full sudo access granted", "severity": "MEDIUM"})
        return issues

    def _open_ports(self) -> List[dict]:
        issues = []
        if self._os == "Windows":
            out = self._run("netstat -an")
        else:
            out = self._run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        risky = ["0.0.0.0:23","0.0.0.0:21","0.0.0.0:135","0.0.0.0:139","0.0.0.0:445"]
        for r in risky:
            if r in out:
                issues.append({"check": "open_ports", "issue": f"Risky port open: {r}", "severity": "HIGH"})
        return issues

    def _world_writable(self) -> List[str]:
        if self._os == "Windows":
            return []
        out = self._run("find /etc /usr /bin /sbin -perm -002 -type f 2>/dev/null | head -20")
        return [f for f in out.split("\n") if f.strip()]

    def _users(self) -> List[dict]:
        issues = []
        if self._os == "Windows":
            return issues
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7 and parts[2] == "0" and parts[0] != "root":
                        issues.append({"check": "users", "issue": f"UID 0 user: {parts[0]}", "severity": "CRITICAL"})
        except Exception:
            pass
        return issues

    def run(self, full: bool = False, limit: int = 50, output_dir: str = "results", save_json: bool = False):
        console.print(f"\n  [*] System audit  full={full}  os={self._os}")

        all_issues = []

        console.print(f"\n  [*] SSH configuration...")
        ssh = self._ssh_config()
        all_issues.extend(ssh)

        console.print(f"\n  [*] Sudo permissions...")
        sudo = self._sudoers()
        all_issues.extend(sudo)

        console.print(f"\n  [*] Open ports...")
        ports = self._open_ports()
        all_issues.extend(ports)

        console.print(f"\n  [*] User accounts...")
        users = self._users()
        all_issues.extend(users)

        if full:
            console.print(f"\n  [*] World-writable files...")
            ww = self._world_writable()
            for f in ww[:10]:
                all_issues.append({"check": "file_perms", "issue": f"World-writable: {f}", "severity": "MEDIUM"})

        all_issues = all_issues[:limit]

        t = Table(title=f"Audit Issues: {len(all_issues)}", box=box.SIMPLE)
        t.add_column("Severity", style="red",   width=10)
        t.add_column("Check",    style="cyan",  width=16)
        t.add_column("Issue",    style="white", width=50)
        for issue in all_issues:
            sev   = issue["severity"]
            color = "bold red" if sev == "CRITICAL" else "red" if sev == "HIGH" else "yellow"
            t.add_row(f"[{color}]{sev}[/{color}]", issue["check"], issue["issue"])
        console.print(t)

        payload = {
            "tool":      "CypherX",
            "scan_time": datetime.now().isoformat(),
            "os":        self._os,
            "issues":    all_issues,
        }

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir, f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path,"w") as f:
                json.dump(payload, f, indent=4)
            console.print(f"\n  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  audit\n")
        return payload
