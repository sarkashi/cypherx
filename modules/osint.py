#!/usr/bin/env python3

import os
import re
import json
import time
import socket
import hashlib
import threading
from queue import Queue, Empty
from datetime import datetime
from typing import Optional, List, Dict

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"

PLATFORMS = {
    "GitHub":        "https://github.com/{}",
    "GitLab":        "https://gitlab.com/{}",
    "Twitter":       "https://twitter.com/{}",
    "Instagram":     "https://instagram.com/{}",
    "Reddit":        "https://reddit.com/user/{}",
    "TikTok":        "https://tiktok.com/@{}",
    "YouTube":       "https://youtube.com/@{}",
    "Twitch":        "https://twitch.tv/{}",
    "Pinterest":     "https://pinterest.com/{}",
    "LinkedIn":      "https://linkedin.com/in/{}",
    "Telegram":      "https://t.me/{}",
    "Medium":        "https://medium.com/@{}",
    "Dev.to":        "https://dev.to/{}",
    "HackerNews":    "https://news.ycombinator.com/user?id={}",
    "Keybase":       "https://keybase.io/{}",
    "HackerOne":     "https://hackerone.com/{}",
    "BugCrowd":      "https://bugcrowd.com/{}",
    "CodePen":       "https://codepen.io/{}",
    "Replit":        "https://replit.com/@{}",
    "Steam":         "https://steamcommunity.com/id/{}",
    "Pastebin":      "https://pastebin.com/u/{}",
    "ProductHunt":   "https://producthunt.com/@{}",
    "Dribbble":      "https://dribbble.com/{}",
    "Behance":       "https://behance.net/{}",
    "SoundCloud":    "https://soundcloud.com/{}",
    "Vimeo":         "https://vimeo.com/{}",
    "Flickr":        "https://flickr.com/people/{}",
    "Quora":         "https://quora.com/profile/{}",
    "Tumblr":        "https://{}.tumblr.com",
    "VK":            "https://vk.com/{}",
    "Last.fm":       "https://last.fm/user/{}",
    "Letterboxd":    "https://letterboxd.com/{}",
    "Goodreads":     "https://goodreads.com/{}",
    "Chess.com":     "https://chess.com/member/{}",
    "Lichess":       "https://lichess.org/@/{}",
    "Fiverr":        "https://fiverr.com/{}",
    "Patreon":       "https://patreon.com/{}",
    "DeviantArt":    "https://deviantart.com/{}",
    "ArtStation":    "https://artstation.com/{}",
    "Kaggle":        "https://kaggle.com/{}",
    "HuggingFace":   "https://huggingface.co/{}",
    "npm":           "https://npmjs.com/~{}",
    "PyPI":          "https://pypi.org/user/{}",
    "DockerHub":     "https://hub.docker.com/u/{}",
    "Linktree":      "https://linktr.ee/{}",
    "About.me":      "https://about.me/{}",
    "Imgur":         "https://imgur.com/user/{}",
    "Etsy":          "https://etsy.com/people/{}",
    "Wattpad":       "https://wattpad.com/user/{}",
    "Bitbucket":     "https://bitbucket.org/{}",
    "MyAnimeList":   "https://myanimelist.net/profile/{}",
    "AniList":       "https://anilist.co/user/{}",
    "Mastodon":      "https://mastodon.social/@{}",
    "Odysee":        "https://odysee.com/@{}",
    "Minds":         "https://minds.com/{}",
    "Ko-fi":         "https://ko-fi.com/{}",
    "Bandcamp":      "https://{}.bandcamp.com",
    "WordPress":     "https://{}.wordpress.com",
    "Substack":      "https://{}.substack.com",
    "Strava":        "https://strava.com/athletes/{}",
    "Unsplash":      "https://unsplash.com/@{}",
    "500px":         "https://500px.com/p/{}",
    "Kickstarter":   "https://kickstarter.com/profile/{}",
    "AngelList":     "https://angel.co/u/{}",
    "Trello":        "https://trello.com/{}",
    "Gravatar":      "https://gravatar.com/{}",
    "Sourceforge":   "https://sourceforge.net/u/{}/profile",
    "Hackaday":      "https://hackaday.io/{}",
    "Instructables": "https://instructables.com/member/{}",
    "Disqus":        "https://disqus.com/by/{}/",
    "Giphy":         "https://giphy.com/@{}",
    "Flipboard":     "https://flipboard.com/@{}",
    "Mix":           "https://mix.com/{}",
    "Digg":          "https://digg.com/u/{}",
    "Foursquare":    "https://foursquare.com/{}",
    "Weheartit":     "https://weheartit.com/{}",
    "Designspiration":"https://designspiration.com/{}",
    "Hubpages":      "https://hubpages.com/@{}",
    "Livejournal":   "https://livejournal.com/{}",
    "Blogspot":      "https://{}.blogspot.com",
    "Wikipedia":     "https://en.wikipedia.org/wiki/User:{}",
    "Wikia":         "https://www.wikia.com/wiki/User:{}",
    "Archive":       "https://archive.org/search?query={}",
    "Roblox":        "https://roblox.com/user.aspx?username={}",
    "Xbox":          "https://xboxgamertag.com/search/{}",
    "PSN":           "https://psnprofiles.com/{}",
    "Twitch":        "https://twitch.tv/{}",
    "Spotify":       "https://open.spotify.com/user/{}",
    "Apple":         "https://discussions.apple.com/profile/{}",
    "MicrosoftTeams":"https://teams.live.com/l/community/{}",
}

COUNTRY_CODES = {
    "1":"US/Canada","7":"Russia","20":"Egypt","27":"South Africa",
    "30":"Greece","31":"Netherlands","32":"Belgium","33":"France",
    "34":"Spain","36":"Hungary","39":"Italy","40":"Romania",
    "41":"Switzerland","43":"Austria","44":"United Kingdom",
    "45":"Denmark","46":"Sweden","47":"Norway","48":"Poland",
    "49":"Germany","51":"Peru","52":"Mexico","54":"Argentina",
    "55":"Brazil","56":"Chile","57":"Colombia","60":"Malaysia",
    "61":"Australia","62":"Indonesia","63":"Philippines",
    "64":"New Zealand","65":"Singapore","66":"Thailand",
    "81":"Japan","82":"South Korea","84":"Vietnam","86":"China",
    "90":"Turkey","91":"India","92":"Pakistan","98":"Iran",
    "212":"Morocco","213":"Algeria","216":"Tunisia","234":"Nigeria",
    "254":"Kenya","351":"Portugal","380":"Ukraine","420":"Czech Republic",
    "966":"Saudi Arabia","971":"UAE","972":"Israel","974":"Qatar",
}

SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","admin","api","dev","test","staging","app","portal",
    "remote","vpn","ns1","ns2","ns3","smtp","webmail","secure","login","shop",
    "blog","forum","support","docs","cdn","static","mobile","beta","git",
    "jenkins","ci","jira","wiki","intranet","backup","db","redis","auth",
    "payment","billing","crm","status","dashboard","panel","console","v1","v2",
    "v3","api2","old","new","demo","prod","production","stage","qa","uat",
    "mx","mx1","mx2","smtp2","pop","imap","exchange","autodiscover","cpanel",
    "whm","plesk","phpmyadmin","mysql","postgres","mongodb","elastic","kibana",
    "grafana","prometheus","jenkins","gitlab","bitbucket","sonar","nexus",
    "artifactory","vault","consul","nomad","rancher","harbor","registry",
    "download","downloads","upload","uploads","media","images","img","assets",
    "files","storage","s3","cloud","backup","bak","archive","logs","monitor",
]


def _make_session(timeout: int, proxy: Optional[str]) -> Optional[object]:
    if not REQUESTS_OK:
        return None
    s       = requests.Session()
    retry   = Retry(total=1, backoff_factor=0.1, status_forcelist=[500,502,503,504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    s.mount("http://",  adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": UA})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.timeout = timeout
    s.verify  = False
    return s


class OSINTEngine:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None,
                 quiet: bool = False, threads: int = 50):
        self.timeout = timeout
        self.proxy   = proxy
        self.quiet   = quiet
        self.threads = threads
        self._sess   = _make_session(timeout, proxy)

    def _req(self, url: str) -> Optional[object]:
        if not self._sess:
            return None
        try:
            return self._sess.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None

    def _username_scan(self, username: str, limit: int) -> List[dict]:
        platforms = dict(list(PLATFORMS.items())[:limit])
        found     = []
        lock      = threading.Lock()
        q         = Queue()

        for plat, url_tpl in platforms.items():
            q.put((plat, url_tpl.format(username)))

        console.print(f"  [*] Scanning {len(platforms)} platforms...")

        def worker():
            while True:
                try:
                    plat, url = q.get_nowait()
                except Empty:
                    break
                try:
                    r = self._req(url)
                    if r and r.status_code == 200 and len(r.text) > 300:
                        with lock:
                            found.append({"platform": plat, "url": url, "status": 200})
                            if not self.quiet:
                                console.print(f"  [green]✓[/green]  {plat:22}  {url}")
                except Exception:
                    pass
                finally:
                    q.task_done()

        workers = [threading.Thread(target=worker, daemon=True) for _ in range(min(self.threads, len(platforms)))]
        for w in workers:
            w.start()
        for w in workers:
            w.join()

        return found

    def _email_scan(self, email: str) -> dict:
        result = {
            "email":   email,
            "valid":   False,
            "domain":  "",
            "format":  "",
            "mx":      [],
            "gravatar": {},
            "breaches": [],
        }

        if not re.match(r"^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$", email):
            result["format"] = "invalid"
            return result

        result["valid"]  = True
        result["format"] = "valid"
        result["domain"] = email.split("@")[1]

        try:
            import dns.resolver
            result["mx"] = [str(r.exchange) for r in dns.resolver.resolve(result["domain"], "MX")]
        except Exception:
            pass

        md5 = hashlib.md5(email.lower().strip().encode()).hexdigest()
        result["gravatar"]["hash"]   = md5
        result["gravatar"]["avatar"] = f"https://www.gravatar.com/avatar/{md5}?d=404"

        r = self._req(f"https://www.gravatar.com/{md5}.json")
        if r and r.status_code == 200:
            try:
                entry = r.json().get("entry", [{}])[0]
                result["gravatar"].update({
                    "found":        True,
                    "display_name": entry.get("displayName", ""),
                    "location":     entry.get("currentLocation", ""),
                    "about":        entry.get("aboutMe", ""),
                    "accounts":     [a.get("shortname","") for a in entry.get("accounts",[])],
                })
            except Exception:
                pass

        disposable_domains = [
            "mailinator.com","guerrillamail.com","tempmail.com","throwaway.email",
            "yopmail.com","sharklasers.com","guerrillamailblock.com","10minutemail.com",
        ]
        result["disposable"] = result["domain"] in disposable_domains

        return result

    def _phone_scan(self, phone: str) -> dict:
        clean   = re.sub(r"[\s\-\(\)\.\+]", "", phone)
        country = "Unknown"
        code    = ""

        for length in [3, 2, 1]:
            c = clean[:length]
            if c in COUNTRY_CODES:
                code    = c
                country = COUNTRY_CODES[c]
                break

        result = {
            "number":         phone,
            "normalized":     f"+{clean}",
            "clean":          clean,
            "country_code":   f"+{code}" if code else "unknown",
            "country":        country,
            "length":         len(clean),
            "valid":          7 <= len(clean) <= 15,
            "possible_type":  "mobile" if len(clean) >= 10 else "landline",
        }

        r = self._req(f"https://phone-validation.abstractapi.com/v1/?api_key=&phone={clean}")
        if r and r.status_code == 200:
            try:
                data = r.json()
                result.update({
                    "carrier": data.get("carrier",""),
                    "line_type": data.get("line_type",""),
                })
            except Exception:
                pass

        return result

    def _domain_scan(self, domain: str, limit: int) -> dict:
        result = {
            "domain":     domain,
            "whois":      {},
            "dns":        {},
            "ip_info":    {},
            "tech":       {},
            "subdomains": [],
            "emails":     [],
            "ssl":        {},
        }

        try:
            import whois as w
            data = w.whois(domain)
            result["whois"] = {
                "registrar":       str(data.registrar or ""),
                "creation_date":   str(data.creation_date or ""),
                "expiration_date": str(data.expiration_date or ""),
                "updated_date":    str(data.updated_date or ""),
                "org":             str(data.org or ""),
                "country":         str(data.country or ""),
                "name_servers":    str(data.name_servers or ""),
                "status":          str(data.status or ""),
            }
            if not self.quiet:
                console.print(f"  [green]✓[/green]  WHOIS complete")
        except Exception:
            pass

        try:
            import dns.resolver
            r = dns.resolver.Resolver()
            r.timeout = 5
            for rtype in ["A","AAAA","MX","NS","TXT","SOA","CAA","CNAME"]:
                try:
                    result["dns"][rtype] = [str(x) for x in r.resolve(domain, rtype)]
                    if not self.quiet and result["dns"][rtype]:
                        console.print(f"  [green]✓[/green]  DNS {rtype:6}  {' | '.join(result['dns'][rtype][:2])[:60]}")
                except Exception:
                    result["dns"][rtype] = []
        except ImportError:
            try:
                result["dns"]["A"] = [socket.gethostbyname(domain)]
            except Exception:
                pass

        try:
            ip = socket.gethostbyname(domain)
            r2 = self._req(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as,proxy,hosting,mobile")
            if r2 and r2.status_code == 200:
                result["ip_info"] = {"ip": ip}
                result["ip_info"].update(r2.json())
                if not self.quiet:
                    d = result["ip_info"]
                    console.print(f"  [green]✓[/green]  IP: {ip}  {d.get('city','')} {d.get('country','')}")
        except Exception:
            pass

        for scheme in ["https", "http"]:
            r3 = self._req(f"{scheme}://{domain}")
            if r3:
                h    = r3.headers
                body = r3.text.lower()
                result["tech"] = {
                    "status":         r3.status_code,
                    "server":         h.get("Server",""),
                    "x_powered_by":   h.get("X-Powered-By",""),
                    "hsts":           bool(h.get("Strict-Transport-Security")),
                    "csp":            bool(h.get("Content-Security-Policy")),
                    "x_frame":        h.get("X-Frame-Options",""),
                    "x_content_type": h.get("X-Content-Type-Options",""),
                    "referrer_policy":h.get("Referrer-Policy",""),
                    "scheme":         scheme,
                }
                for cms, sigs in {
                    "WordPress":  ["wp-content","wp-includes","wp-json"],
                    "Joomla":     ["joomla","/components/com_"],
                    "Drupal":     ["drupal","sites/default"],
                    "Laravel":    ["laravel_session","csrf-token"],
                    "Django":     ["csrfmiddlewaretoken","django"],
                    "React":      ["__react","react-root","_reactroot"],
                    "Vue.js":     ["__vue__","data-v-"],
                    "Angular":    ["ng-version","_nghost"],
                    "Next.js":    ["__next","_next/static"],
                    "Nuxt.js":    ["__nuxt","_nuxt"],
                    "Bootstrap":  ["bootstrap.min.css","bootstrap.bundle"],
                    "jQuery":     ["jquery.min.js","jquery.js"],
                    "Shopify":    ["cdn.shopify.com","shopify"],
                    "Wix":        ["wix.com","wixsite"],
                    "Squarespace":["squarespace.com","sqsp"],
                    "Ghost":      ["ghost.io","ghost-theme"],
                }.items():
                    if any(s in body for s in sigs):
                        result["tech"]["cms"] = cms
                        break
                if not self.quiet:
                    console.print(f"  [green]✓[/green]  Tech: {result['tech'].get('server','')}  {result['tech'].get('cms','')}")
                break

        try:
            import ssl
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
            conn.settimeout(5)
            conn.connect((domain, 443))
            cert = conn.getpeercert()
            conn.close()
            result["ssl"] = {
                "subject":   dict(x[0] for x in cert.get("subject",[])),
                "issuer":    dict(x[0] for x in cert.get("issuer",[])),
                "not_after": cert.get("notAfter",""),
                "san":       [x[1] for x in cert.get("subjectAltName",[])],
            }
            if not self.quiet:
                console.print(f"  [green]✓[/green]  SSL: expires {result['ssl']['not_after']}")
        except Exception:
            pass

        console.print(f"\n  [*] Subdomain enumeration...")
        found_subs = []
        r4 = self._req(f"https://crt.sh/?q=%.{domain}&output=json")
        if r4 and r4.status_code == 200:
            try:
                subs = set()
                for entry in r4.json():
                    for name in entry.get("name_value","").split("\n"):
                        name = name.strip().lower()
                        if name.endswith(f".{domain}") and "*" not in name and name != domain:
                            subs.add(name)
                for s in list(subs)[:limit]:
                    try:
                        ip3 = socket.gethostbyname(s)
                        found_subs.append({"sub": s, "ip": ip3, "source": "crt.sh"})
                        if not self.quiet:
                            console.print(f"  [green]✓[/green]  {s:45}  {ip3}")
                    except Exception:
                        pass
            except Exception:
                pass

        q2   = Queue()
        lock = threading.Lock()
        for word in SUBDOMAIN_WORDLIST:
            fqdn = f"{word}.{domain}"
            if not any(s["sub"] == fqdn for s in found_subs):
                q2.put(fqdn)

        def sub_worker():
            while True:
                try:
                    fqdn = q2.get_nowait()
                except Empty:
                    break
                try:
                    ip4 = socket.gethostbyname(fqdn)
                    with lock:
                        found_subs.append({"sub": fqdn, "ip": ip4, "source": "bruteforce"})
                        if not self.quiet:
                            console.print(f"  [green]✓[/green]  {fqdn:45}  {ip4}")
                except Exception:
                    pass
                finally:
                    q2.task_done()

        sw = [threading.Thread(target=sub_worker, daemon=True) for _ in range(min(self.threads, 50))]
        for w in sw:
            w.start()
        for w in sw:
            w.join()

        result["subdomains"] = found_subs[:limit]

        emails = set()
        r5 = self._req(f"https://www.google.com/search?q=site:{domain}+email")
        if r5:
            for email in re.findall(r"[\w.+-]+@" + re.escape(domain), r5.text):
                emails.add(email)
        result["emails"] = list(emails)[:20]

        return result

    def _ip_scan(self, ip: str) -> dict:
        result = {"ip": ip}
        r = self._req(
            f"http://ip-api.com/json/{ip}?"
            f"fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
        )
        if r and r.status_code == 200:
            result.update(r.json())

        r2 = self._req(f"https://ipwhois.app/json/{ip}")
        if r2 and r2.status_code == 200:
            try:
                d = r2.json()
                result["abuse_contact"] = d.get("org","")
            except Exception:
                pass

        try:
            result["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        if not self.quiet:
            console.print(f"  [green]✓[/green]  {ip}  {result.get('city','')} {result.get('country','')}  {result.get('isp','')[:40]}")

        return result

    def run(self, username=None, email=None, phone=None,
            domain=None, ip=None, name=None,
            limit=50, output_dir="results", save_json=False):
        from core.security import guard

        results = {"tool": "CypherX", "scan_time": datetime.now().isoformat()}

        if username:
            username = guard.sanitize(username, "username")
            console.print(f"\n  [*] Username: {username}  limit={limit}")
            data = self._username_scan(username, limit)
            results["username"] = {"target": username, "found": data, "count": len(data)}
            t = Table(title=f"Profiles found: {len(data)}", box=box.SIMPLE)
            t.add_column("Platform", style="cyan",  width=22)
            t.add_column("URL",      style="white")
            for d in data:
                t.add_row(d["platform"], d["url"])
            console.print(t)

        if email:
            email = guard.sanitize(email, "email")
            console.print(f"\n  [*] Email: {email}")
            data = self._email_scan(email)
            results["email"] = data
            t = Table(title="Email Analysis", box=box.SIMPLE, show_header=False)
            t.add_column("", style="cyan", width=18)
            t.add_column("", style="white")
            for k, v in data.items():
                if v and not isinstance(v, (dict, list)):
                    t.add_row(k, str(v))
            console.print(t)

        if phone:
            phone = guard.sanitize(phone, "phone")
            console.print(f"\n  [*] Phone: {phone}")
            data = self._phone_scan(phone)
            results["phone"] = data
            t = Table(title="Phone Analysis", box=box.SIMPLE, show_header=False)
            t.add_column("", style="cyan", width=18)
            t.add_column("", style="white")
            for k, v in data.items():
                t.add_row(k, str(v))
            console.print(t)

        if domain:
            domain = guard.sanitize(domain, "domain")
            console.print(f"\n  [*] Domain: {domain}  limit={limit}")
            data = self._domain_scan(domain, limit)
            results["domain"] = data
            if data["subdomains"]:
                t = Table(title=f"Subdomains: {len(data['subdomains'])}", box=box.SIMPLE)
                t.add_column("Subdomain", style="cyan",  width=45)
                t.add_column("IP",        style="white", width=16)
                t.add_column("Source",    style="dim",   width=12)
                for s in data["subdomains"][:30]:
                    t.add_row(s["sub"], s["ip"], s["source"])
                console.print(t)

        if ip:
            ip = guard.sanitize(ip, "ip")
            console.print(f"\n  [*] IP: {ip}")
            data = self._ip_scan(ip)
            results["ip"] = data
            t = Table(title="IP Intelligence", box=box.SIMPLE, show_header=False)
            t.add_column("", style="cyan", width=18)
            t.add_column("", style="white")
            for k, v in data.items():
                if v and not isinstance(v, (dict, list)):
                    t.add_row(k, str(v)[:80])
            console.print(t)

        if save_json:
            os.makedirs(output_dir, exist_ok=True)
            target = (username or email or phone or domain or ip or "target")
            target = target.replace("@","_at_").replace(".","_").replace("/","_")
            path   = os.path.join(output_dir, f"osint_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False, default=str)
            console.print(f"\n  [green]✓[/green]  Saved → {path}")

        target_str = " | ".join(filter(None, [username, email, phone, domain, ip]))
        console.print(f"\n  CypherX  |  {target_str}\n")
        return results
