#!/usr/bin/env python3

import os
import subprocess
from rich.console import Console

console = Console()

class Updater:
    def __init__(self, current: str):
        self._current = current
        self._url     = "https://raw.githubusercontent.com/sarkashi/cypherx/main/version.txt"

    def _latest(self) -> str:
        try:
            import requests
            r = requests.get(self._url, timeout=5)
            return r.text.strip()
        except Exception:
            return self._current

    def run(self):
        console.print(f"  Current: v{self._current}")
        console.print(f"  Checking for updates...")
        latest = self._latest()
        if latest == self._current:
            console.print(f"  [green]✓[/green]  Already up to date.")
            return
        console.print(f"  [yellow]⚠[/yellow]  New version: v{latest}")
        if os.path.exists(".git"):
            try:
                r = subprocess.run(["git","pull"], capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    console.print(f"  [green]✓[/green]  Updated. Restart CypherX.")
                else:
                    console.print(f"  [red]✗[/red]  git pull failed: {r.stderr[:60]}")
            except Exception as e:
                console.print(f"  [red]✗[/red]  {e}")
        else:
            console.print(f"  Run: git clone https://github.com/sarkashi/cypherx")
