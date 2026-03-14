#!/usr/bin/env python3

import os
import json
import platform
import subprocess
from datetime import datetime
from typing import List

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


class HardeningEngine:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self._os   = platform.system()

    def _run(self, cmd: str) -> str:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return r.stdout.strip()
        except Exception:
            return ""

    def _checks(self) -> List[dict]:
        checks = []

        if self._os != "Windows":
            if os.path.exists("/etc/ssh/sshd_config"):
                with open("/etc/ssh/sshd_config") as f:
                    c = f.read()
                if "PermitRootLogin yes" in c:
                    checks.append({
                        "category": "SSH",
                        "issue":    "Root login allowed",
                        "fix":      "Set PermitRootLogin no in /etc/ssh/sshd_config",
                        "priority": "HIGH"
                    })
                if "Port 22" in c or "Port" not in c:
                    checks.append({
                        "category": "SSH",
                        "issue":    "Default port 22",
                        "fix":      "Change SSH port in /etc/ssh/sshd_config",
                        "priority": "MEDIUM"
                    })

            fw = self._run("ufw status 2>/dev/null || firewall-cmd --state 2>/dev/null || iptables -L 2>/dev/null | head -5")
            if not fw or "inactive" in fw.lower():
                checks.append({
                    "category": "Firewall",
                    "issue":    "Firewall may be disabled",
                    "fix":      "Enable: sudo ufw enable",
                    "priority": "CRITICAL"
                })

            fail2ban = self._run("systemctl is-active fail2ban 2>/dev/null")
            if fail2ban != "active":
                checks.append({
                    "category": "Brute Force",
                    "issue":    "fail2ban not running",
                    "fix":      "Install: sudo apt install fail2ban && sudo systemctl start fail2ban",
                    "priority": "HIGH"
                })

            updates = self._run("apt list --upgradable 2>/dev/null | wc -l")
            if updates and int(updates) > 1:
                checks.append({
                    "category": "Updates",
                    "issue":    f"{updates} package updates available",
                    "fix":      "Run: sudo apt upgrade",
                    "priority": "MEDIUM"
                })

            umask = self._run("umask")
            if umask and umask not in ("0022","0027","027","022"):
                checks.append({
                    "category": "Permissions",
                    "issue":    f"Permissive umask: {umask}",
                    "fix":      "Set umask 027 in /etc/profile",
                    "priority": "MEDIUM"
                })

        checks.extend([
            {
                "category": "Passwords",
                "issue":    "Ensure strong password policy",
                "fix":      "Use 12+ chars, mixed case, numbers, symbols",
                "priority": "HIGH"
            },
            {
                "category": "2FA",
                "issue":    "Multi-factor authentication",
                "fix":      "Enable 2FA on all critical accounts",
                "priority": "HIGH"
            },
            {
                "category": "Backups",
                "issue":    "Verify backup procedures",
                "fix":      "Ensure encrypted offsite backups exist",
                "priority": "MEDIUM"
            },
            {
                "category": "Logging",
                "issue":    "Centralized logging",
                "fix":      "Configure syslog/rsyslog to remote server",
                "priority": "MEDIUM"
            },
        ])

        return checks

    def run(self, output_dir: str = "results", save_json: bool = False):
        console.print(f"\n  [*] Hardening analysis  os={self._os}")
        checks = self._checks()

        t = Table(title=f"Hardening Recommendations: {len(checks)}", box=box.SIMPLE)
        t.add_column("Priority", style="red",   width=10)
        t.add_column("Category", style="cyan",  width=14)
        t.add_column("Issue",    style="white", width=32)
        t.add_column("Fix",      style="dim",   width=50)
        for c in checks:
            prio  = c["priority"]
            color = "bold red" if prio == "CRITICAL" else "red" if prio == "HIGH" else "yellow"
            t.add_row(f"[{color}]{prio}[/{color}]", c["category"], c["issue"], c["fix"])
        console.print(t)

        payload = {
            "tool":      "CypherX",
            "scan_time": datetime.now().isoformat(),
            "os":        self._os,
            "checks":    checks,
        }

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir, f"hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path,"w") as f:
                json.dump(payload, f, indent=4)
            console.print(f"\n  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  hardening\n")
        return payload
