#!/usr/bin/env python3

import os
import re
import json
import time
import socket
import threading
from queue import Queue, Empty
from datetime import datetime
from typing import List, Dict, Optional

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"

SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","admin","api","dev","test","staging","app","portal",
    "remote","vpn","ns1","ns2","ns3","smtp","webmail","secure","login","shop",
    "blog","forum","support","docs","cdn","static","mobile","beta","git",
    "jenkins","ci","jira","wiki","intranet","backup","db","redis","auth",
    "payment","billing","crm","status","dashboard","panel","console","v1","v2",
    "v3","api2","old","new","demo","prod","stage","qa","uat","exchange",
    "autodiscover","cpanel","whm","plesk","phpmyadmin","grafana","kibana",
    "elastic","prometheus","gitlab","sonar","vault","download","media","assets",
    "files","storage","cloud","bak","archive","logs","monitor","s3","images",
]


class ReconEngine:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None,
                 quiet: bool = False, threads: int = 50):
        self.timeout = timeout
        self.proxy   = proxy
        self.quiet   = quiet
        self.threads = threads

    def _req(self, url: str):
        if not REQUESTS_OK:
            return None
        try:
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            return requests.get(url, headers={"User-Agent": UA},
                                timeout=self.timeout, proxies=proxies,
                                allow_redirects=True, verify=False)
        except Exception:
            return None

    def _whois(self, target: str) -> dict:
        try:
            import whois as w
            data = w.whois(target)
            return {
                "registrar":       str(data.registrar or ""),
                "creation_date":   str(data.creation_date or ""),
                "expiration_date": str(data.expiration_date or ""),
                "updated_date":    str(data.updated_date or ""),
                "org":             str(data.org or ""),
                "country":         str(data.country or ""),
                "name_servers":    str(data.name_servers or ""),
                "status":          str(data.status or ""),
                "emails":          str(data.emails or ""),
            }
        except Exception as e:
            return {"error": str(e)}

    def _dns(self, target: str) -> dict:
        records = {}
        try:
            import dns.resolver
            r = dns.resolver.Resolver()
            r.timeout = 5
            for rtype in ["A","AAAA","MX","NS","TXT","SOA","CAA","CNAME","PTR"]:
                try:
                    records[rtype] = [str(x) for x in r.resolve(target, rtype)]
                except Exception:
                    records[rtype] = []
        except ImportError:
            try:
                records["A"] = [socket.gethostbyname(target)]
            except Exception:
                pass
        return records

    def _subdomains(self, target: str, limit: int) -> List[dict]:
        found = []
        r     = self._req(f"https://crt.sh/?q=%.{target}&output=json")
        if r and r.status_code == 200:
            try:
                subs = set()
                for e in r.json():
                    for name in e.get("name_value","").split("\n"):
                        name = name.strip().lower()
                        if name.endswith(f".{target}") and "*" not in name:
                            subs.add(name)
                for s in list(subs)[:limit]:
                    try:
                        ip = socket.gethostbyname(s)
                        found.append({"sub": s, "ip": ip, "source": "crt.sh"})
                        if not self.quiet:
                            console.print(f"  [green]✓[/green]  {s:42}  {ip}")
                    except Exception:
                        pass
            except Exception:
                pass

        q    = Queue()
        lock = threading.Lock()
        for word in SUBDOMAIN_WORDLIST:
            fqdn = f"{word}.{target}"
            if not any(f["sub"] == fqdn for f in found):
                q.put(fqdn)

        def worker():
            while True:
                try:
                    fqdn = q.get_nowait()
                except Empty:
                    break
                try:
                    ip = socket.gethostbyname(fqdn)
                    with lock:
                        found.append({"sub": fqdn, "ip": ip, "source": "bruteforce"})
                        if not self.quiet:
                            console.print(f"  [green]✓[/green]  {fqdn:42}  {ip}")
                except Exception:
                    pass
                finally:
                    q.task_done()

        ts = [threading.Thread(target=worker, daemon=True) for _ in range(min(self.threads, 30))]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        return found[:limit]

    def _tech(self, target: str) -> dict:
        tech = {}
        for scheme in ["https", "http"]:
            r = self._req(f"{scheme}://{target}")
            if r:
                h    = r.headers
                body = r.text.lower()
                tech = {
                    "status":          r.status_code,
                    "server":          h.get("Server",""),
                    "x_powered_by":    h.get("X-Powered-By",""),
                    "hsts":            bool(h.get("Strict-Transport-Security")),
                    "csp":             bool(h.get("Content-Security-Policy")),
                    "x_frame":         h.get("X-Frame-Options",""),
                    "x_content_type":  h.get("X-Content-Type-Options",""),
                }
                for cms, sigs in {
                    "WordPress":   ["wp-content","wp-includes"],
                    "Joomla":      ["joomla"],
                    "Drupal":      ["drupal"],
                    "Laravel":     ["laravel_session"],
                    "Django":      ["csrfmiddlewaretoken"],
                    "React":       ["__react"],
                    "Vue.js":      ["__vue__"],
                    "Angular":     ["ng-version"],
                    "Next.js":     ["__next"],
                    "Shopify":     ["cdn.shopify.com"],
                }.items():
                    if any(s in body for s in sigs):
                        tech["cms"] = cms
                        break
                break
        return tech

    def run(self, target: str, limit: int = 50, output_dir: str = "results", save_json: bool = False):
        from core.security import guard
        target  = guard.sanitize(target, "target")
        results = {"tool": "CypherX", "target": target, "scan_time": datetime.now().isoformat()}
        start   = time.time()

        console.print(f"\n  [*] Recon: {target}  limit={limit}")

        console.print(f"\n  [*] WHOIS...")
        results["whois"] = self._whois(target)
        for k, v in results["whois"].items():
            if v and k != "error" and not self.quiet:
                console.print(f"  [cyan]{k:20}[/cyan]  {str(v)[:70]}")

        console.print(f"\n  [*] DNS records...")
        results["dns"] = self._dns(target)
        for rtype, recs in results["dns"].items():
            if recs and not self.quiet:
                console.print(f"  [cyan]{rtype:8}[/cyan]  {' | '.join(str(r)[:40] for r in recs[:3])}")

        console.print(f"\n  [*] Technology...")
        results["tech"] = self._tech(target)
        for k, v in results["tech"].items():
            if v and not self.quiet:
                console.print(f"  [cyan]{k:20}[/cyan]  {v}")

        console.print(f"\n  [*] Subdomains  limit={limit}...")
        results["subdomains"] = self._subdomains(target, limit)

        t = Table(title=f"Subdomains: {len(results['subdomains'])}", box=box.SIMPLE)
        t.add_column("Subdomain", style="cyan",  width=42)
        t.add_column("IP",        style="white", width=16)
        t.add_column("Source",    style="dim",   width=12)
        for s in results["subdomains"][:30]:
            t.add_row(s["sub"], s["ip"], s["source"])
        console.print(t)

        elapsed = round(time.time() - start, 2)
        console.print(f"\n  Recon complete in {elapsed}s")

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir,
                f"recon_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False, default=str)
            console.print(f"  [green]✓[/green]  Saved → {path}")

        console.print(f"\n  CypherX  |  recon {target}\n")
        return results
