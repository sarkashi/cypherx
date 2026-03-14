#!/usr/bin/env python3

import os
import time
import json
import threading
from collections import defaultdict
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich import box

console = Console()

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


class TrafficMonitor:
    def __init__(self, quiet: bool = False):
        self.quiet      = quiet
        self._packets   = []
        self._lock      = threading.Lock()
        self._stats     = defaultdict(int)
        self._alerts    = []

    def _analyze(self, pkt):
        with self._lock:
            try:
                entry = {
                    "time":  datetime.now().strftime("%H:%M:%S"),
                    "proto": "?",
                    "src":   "",
                    "dst":   "",
                    "sport": 0,
                    "dport": 0,
                    "alert": "",
                    "len":   len(pkt),
                }
                if IP in pkt:
                    entry["src"] = pkt[IP].src
                    entry["dst"] = pkt[IP].dst
                    self._stats["ip"] += 1
                    if TCP in pkt:
                        entry["proto"]  = "TCP"
                        entry["sport"]  = pkt[TCP].sport
                        entry["dport"]  = pkt[TCP].dport
                        self._stats["tcp"] += 1
                        if entry["dport"] in {4444,5555,7777,31337}:
                            entry["alert"] = "SUSPICIOUS PORT"
                            self._alerts.append(f"Suspicious port: {entry['dport']} from {entry['src']}")
                    elif UDP in pkt:
                        entry["proto"]  = "UDP"
                        entry["sport"]  = pkt[UDP].sport
                        entry["dport"]  = pkt[UDP].dport
                        self._stats["udp"] += 1
                    elif ICMP in pkt:
                        entry["proto"] = "ICMP"
                        self._stats["icmp"] += 1
                elif ARP in pkt:
                    entry["proto"] = "ARP"
                    entry["src"]   = pkt[ARP].psrc
                    entry["dst"]   = pkt[ARP].pdst
                    self._stats["arp"] += 1
                self._packets.append(entry)
            except Exception:
                pass

    def _table(self, limit: int) -> Table:
        t = Table(
            title=f"CypherX Monitor  tcp={self._stats['tcp']}  udp={self._stats['udp']}  arp={self._stats['arp']}  total={len(self._packets)}",
            box=box.SIMPLE, expand=True
        )
        t.add_column("Time",   style="dim",    width=10)
        t.add_column("Proto",  style="cyan",   width=6)
        t.add_column("Src",    style="white",  width=18)
        t.add_column("Dst",    style="white",  width=18)
        t.add_column("Port",   style="yellow", width=12)
        t.add_column("Alert",  style="red",    width=22)
        recent = self._packets[-limit:]
        for p in reversed(recent):
            port = f"{p['sport']}→{p['dport']}" if p["dport"] else ""
            t.add_row(p["time"],p["proto"],p["src"][:18],p["dst"][:18],port[:12],p["alert"])
        return t

    def run(self, iface=None, duration: int = 0, limit: int = 500, output_dir: str = "results"):
        console.print(f"\n  [*] Monitor  iface={iface or 'auto'}  duration={duration or '∞'}  Ctrl+C to stop")

        if not SCAPY_OK:
            console.print("  [yellow]⚠[/yellow]  scapy not found. Install: pip install scapy")
            return

        stop_evt   = threading.Event()
        start_time = time.time()

        def sniff_worker():
            kwargs = {"prn": self._analyze, "store": False,
                      "stop_filter": lambda _: stop_evt.is_set()}
            if iface:
                kwargs["iface"] = iface
            if duration:
                kwargs["timeout"] = duration
            try:
                sniff(**kwargs)
            except Exception as e:
                console.print(f"  [red]Sniff error: {e}[/red]")
            finally:
                stop_evt.set()

        t = threading.Thread(target=sniff_worker, daemon=True)
        t.start()

        try:
            with Live(self._table(50), console=console, refresh_per_second=2) as live:
                while not stop_evt.is_set():
                    if duration and (time.time() - start_time) > duration:
                        stop_evt.set()
                        break
                    with self._lock:
                        live.update(self._table(50))
                    time.sleep(0.5)
        except KeyboardInterrupt:
            stop_evt.set()

        t.join(timeout=3)
        console.print(f"\n  [green]✓[/green]  Captured {len(self._packets)} packets")

        if self._alerts:
            console.print(f"  [red]⚠[/red]  {len(self._alerts)} alert(s):")
            for a in list(set(self._alerts))[:10]:
                console.print(f"     · {a}")

        if self._packets:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir, f"monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path,"w") as f:
                json.dump({
                    "tool":    "CypherX",
                    "time":    datetime.now().isoformat(),
                    "packets": self._packets[-500:],
                    "stats":   dict(self._stats),
                    "alerts":  list(set(self._alerts)),
                }, f, indent=4)
            console.print(f"  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  monitor\n")
