#!/usr/bin/env python3

import os
import re
import json
from datetime import datetime
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

IOC_PATTERNS = {
    "ipv4":    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6":    re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "domain":  re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz)\b"),
    "email":   re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b"),
    "url":     re.compile(r"https?://[^\s\"'<>]+"),
    "hash_md5":re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "hash_sha1":re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "hash_sha256":re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "base64":  re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
}

SUSPICIOUS_PATTERNS = [
    r"sudo\s+\w+",
    r"chmod\s+[0-9]+",
    r"passwd\s+\w+",
    r"useradd\s+\w+",
    r"wget\s+http",
    r"curl\s+http",
    r"base64\s+-d",
    r"nc\s+-[el]",
    r"python.*-c\s+",
    r"eval\s*\(",
    r"exec\s*\(",
    r"/bin/sh",
    r"/bin/bash",
    r"reverse.shell",
    r"failed\s+password",
    r"invalid\s+user",
    r"authentication\s+failure",
    r"connection\s+refused",
]

DEFAULT_LOGS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/kern.log",
    "/var/log/dpkg.log",
]


class ForensicsEngine:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet

    def _read_log(self, path: str, limit: int) -> List[str]:
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", errors="ignore") as f:
                lines = f.readlines()
            return lines[-limit:]
        except Exception:
            return []

    def _extract_iocs(self, lines: List[str]) -> dict:
        iocs = {k: set() for k in IOC_PATTERNS}
        for line in lines:
            for ioc_type, pattern in IOC_PATTERNS.items():
                for match in pattern.findall(line):
                    if len(match) > 5:
                        iocs[ioc_type].add(match)
        return {k: list(v)[:20] for k, v in iocs.items() if v}

    def _suspicious(self, lines: List[str]) -> List[dict]:
        found = []
        for i, line in enumerate(lines):
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    found.append({"line": i+1, "pattern": pattern, "content": line.strip()[:100]})
        return found

    def _failed_logins(self, lines: List[str]) -> List[dict]:
        failed = []
        pattern = re.compile(r"Failed password for (?:invalid user )?(\w+) from ([\d.]+)")
        for line in lines:
            m = pattern.search(line)
            if m:
                failed.append({"user": m.group(1), "ip": m.group(2), "line": line.strip()[:80]})
        return failed[:50]

    def run(self, log_path: Optional[str] = None, limit: int = 100,
            output_dir: str = "results", save_json: bool = False):
        results = {"tool": "CypherX", "scan_time": datetime.now().isoformat(), "logs": {}}

        logs_to_check = [log_path] if log_path else DEFAULT_LOGS

        console.print(f"\n  [*] Forensics  limit={limit}")

        for log in logs_to_check:
            if not os.path.exists(log):
                continue
            console.print(f"\n  [*] Analyzing: {log}")
            lines   = self._read_log(log, limit)
            iocs    = self._extract_iocs(lines)
            sus     = self._suspicious(lines)
            failed  = self._failed_logins(lines)

            results["logs"][log] = {
                "lines_analyzed": len(lines),
                "iocs":           iocs,
                "suspicious":     sus[:20],
                "failed_logins":  failed,
            }

            if iocs:
                console.print(f"  IOCs found:")
                for ioc_type, values in iocs.items():
                    if values:
                        console.print(f"  [cyan]{ioc_type:12}[/cyan]  {len(values)} unique")

            if failed:
                t = Table(title=f"Failed Logins: {len(failed)}", box=box.SIMPLE)
                t.add_column("User", style="red",   width=16)
                t.add_column("IP",   style="yellow", width=16)
                for f in failed[:10]:
                    t.add_row(f["user"], f["ip"])
                console.print(t)

            if sus and not self.quiet:
                console.print(f"  [red]⚠[/red]  {len(sus)} suspicious pattern(s) detected")
                for s in sus[:5]:
                    console.print(f"     line {s['line']}: {s['content'][:70]}")

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir, f"forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path,"w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False, default=str)
            console.print(f"\n  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  forensics\n")
        return results
