#!/usr/bin/env python3

import os
import re
import json
import math
import struct
import hashlib
from datetime import datetime
from typing import List

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

DANGEROUS_EXTS = {
    ".exe",".bat",".cmd",".vbs",".ps1",".msi",".dll",".scr",
    ".jar",".py",".sh",".pl",".rb",".php",".js",".hta",".pif",
    ".com",".lnk",".reg",".inf",".ws",".wsf",".msc",".cpl",
}

FILE_SIGS = {
    b"MZ":               "Windows PE Executable",
    b"\x7fELF":          "Linux ELF Executable",
    b"PK\x03\x04":      "ZIP Archive",
    b"%PDF":             "PDF Document",
    b"\xd0\xcf\x11\xe0":"Microsoft Office (OLE)",
    b"\x89PNG":          "PNG Image",
    b"\xff\xd8\xff":     "JPEG Image",
    b"GIF8":             "GIF Image",
    b"Rar!":             "RAR Archive",
    b"\x1f\x8b":         "GZIP Archive",
    b"7z\xbc\xaf":      "7-Zip Archive",
    b"\xca\xfe\xba\xbe":"Java Class / Mach-O",
}

SUSPICIOUS_STRINGS = [
    b"cmd.exe",b"powershell",b"WScript",b"eval(",b"exec(",
    b"base64",b"ActiveXObject",b"ShellExecute",b"CreateObject",
    b"HKEY_",b"RegOpenKey",b"VirtualAlloc",b"WriteProcessMemory",
    b"CreateRemoteThread",b"/bin/sh",b"/bin/bash",b"chmod +x",
    b"wget ",b"curl ",b"nc -",b"reverse shell",b"meterpreter",
]


class FileChecker:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet

    def _hashes(self, path: str) -> dict:
        md5    = hashlib.md5()
        sha1   = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        e = 0.0
        for f in freq.values():
            p  = f / len(data)
            e -= p * math.log2(p)
        return round(e, 4)

    def _sig(self, data: bytes) -> str:
        for sig, name in FILE_SIGS.items():
            if data.startswith(sig):
                return name
        return "Unknown"

    def _suspicious(self, data: bytes) -> List[str]:
        return [s.decode("utf-8", errors="ignore") for s in SUSPICIOUS_STRINGS if s in data]

    def _pe_info(self, data: bytes) -> dict:
        if not data.startswith(b"MZ"):
            return {}
        try:
            offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[offset:offset+4] == b"PE\x00\x00":
                machine = struct.unpack_from("<H", data, offset+4)[0]
                return {"is_pe": True, "arch": "x64" if machine == 0x8664 else "x86"}
        except Exception:
            pass
        return {}

    def run(self, filepath: str, output_dir: str = "results", save_json: bool = False):
        from core.security import guard
        if not guard.validate_path(filepath):
            console.print(f"  [red]Error:[/red] Invalid path: {filepath}")
            return {}
        if not os.path.exists(filepath):
            console.print(f"  [red]Error:[/red] File not found: {filepath}")
            return {}

        console.print(f"\n  [*] File check: {os.path.basename(filepath)}")

        size    = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            data = f.read(min(size, 1024*1024))

        hashes   = self._hashes(filepath)
        entropy  = self._entropy(data)
        sig      = self._sig(data)
        sus      = self._suspicious(data)
        ext_risk = os.path.splitext(filepath)[1].lower() in DANGEROUS_EXTS
        pe_info  = self._pe_info(data)

        score = 0
        if ext_risk:  score += 30
        if entropy > 7.0: score += 25
        if sus:       score += min(len(sus)*10, 40)
        if sig in ["Windows PE Executable","Linux ELF Executable"]: score += 10

        level = "LOW" if score < 30 else "MEDIUM" if score < 60 else "HIGH"
        color = "green" if level == "LOW" else "yellow" if level == "MEDIUM" else "red"

        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("", style="cyan",  width=18)
        t.add_column("", style="white")
        t.add_row("File",         os.path.basename(filepath))
        t.add_row("Size",         f"{size:,} bytes")
        t.add_row("Type",         sig)
        t.add_row("Entropy",      f"{entropy}  {'← high, possible encryption' if entropy > 7.0 else ''}")
        t.add_row("Ext Risk",     "Yes" if ext_risk else "No")
        t.add_row("MD5",          hashes["md5"])
        t.add_row("SHA1",         hashes["sha1"])
        t.add_row("SHA256",       hashes["sha256"])
        t.add_row("Risk Score",   f"{score}/100")
        t.add_row("Risk Level",   f"[{color}]{level}[/{color}]")
        if pe_info:
            t.add_row("Arch",     pe_info.get("arch",""))
        console.print(t)

        if sus:
            console.print(f"\n  [red]⚠[/red]  Suspicious strings ({len(sus)}):")
            for s in sus[:10]:
                console.print(f"     · {s}")

        results = {
            "tool":       "CypherX",
            "file":       filepath,
            "size":       size,
            "sig":        sig,
            "entropy":    entropy,
            "hashes":     hashes,
            "ext_risk":   ext_risk,
            "suspicious": sus,
            "risk_score": score,
            "risk_level": level,
            "pe_info":    pe_info,
            "scan_time":  datetime.now().isoformat(),
        }

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir,
                f"filecheck_{os.path.basename(filepath)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path,"w") as f:
                json.dump(results, f, indent=4, default=str)
            console.print(f"\n  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  filecheck {os.path.basename(filepath)}\n")
        return results
