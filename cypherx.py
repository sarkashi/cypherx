#!/usr/bin/env python3

import os
import sys
import signal
import platform

__version__ = "1.0.0"
__project__ = "CypherX"

if __project__ != "CypherX":
    print("\n  FATAL: Integrity check failed.\n")
    sys.exit(1)

import click
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

SHORT = {
    "-os": "osint",
    "-sc": "scan",
    "-n":  "network",
    "-m":  "monitor",
    "-r":  "recon",
    "-b":  "brute",
    "-v":  "vuln",
    "-a":  "audit",
    "-f":  "forensics",
    "-h2": "hardening",
    "-fc": "filecheck",
    "-rp": "report",
    "-u":  "update",
}

def _check_update():
    try:
        import requests
        r = requests.get(
            "https://raw.githubusercontent.com/sarkashi/cypherx/main/version.txt",
            timeout=3
        )
        latest = r.text.strip()
        if latest != __version__:
            console.print(f"  [yellow]⚠  Update available: v{latest}  →  run: git pull[/yellow]\n")
    except Exception:
        pass

def _help():
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}\n")
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    t.add_column("Command",     width=12)
    t.add_column("Short",       width=6)
    t.add_column("Description", width=40)
    t.add_column("Example",     width=46)
    rows = [
        ("osint",     "-os",  "Username/email/phone/domain/ip OSINT",  "cypherx osint --username sarkashi --limit 20"),
        ("recon",     "-r",   "Full target reconnaissance",            "cypherx recon --target example.com"),
        ("scan",      "-sc",  "Fast deep port scan + service detect",  "cypherx scan 192.168.1.1 --ports 1-65535"),
        ("network",   "-n",   "Host discovery + fingerprint",          "cypherx network 192.168.1.0/24"),
        ("monitor",   "-m",   "Live traffic monitor",                  "cypherx monitor --iface eth0"),
        ("brute",     "-b",   "Bruteforce SSH/FTP/HTTP/MySQL/RDP",     "cypherx brute ssh 192.168.1.1"),
        ("vuln",      "-v",   "Deep vulnerability detection",          "cypherx vuln --target 192.168.1.1"),
        ("audit",     "-a",   "Full system security audit",            "cypherx audit --full"),
        ("forensics", "-f",   "Log analysis + IOC extraction",         "cypherx forensics --log /var/log/auth.log"),
        ("hardening", "-h2",  "System hardening guide",                "cypherx hardening"),
        ("filecheck", "-fc",  "Deep file safety analysis",             "cypherx filecheck suspicious.exe"),
        ("report",    "-rp",  "HTML/PDF/TXT report generator",         "cypherx report --last --format html"),
        ("update",    "-u",   "Check and apply updates",               "cypherx update"),
    ]
    for cmd, short, desc, ex in rows:
        t.add_row(cmd, short, desc, ex)
    console.print(t)
    console.print("  [dim]Global flags: --limit / --output / --json / --quiet / --timeout / --proxy / --threads[/dim]\n")

@click.group(invoke_without_command=True, context_settings={"help_option_names": ["--help"]})
@click.option("--version", is_flag=True)
@click.pass_context
def cli(ctx, version):
    if version:
        console.print(f"CypherX v{__version__}")
        sys.exit(0)
    if ctx.invoked_subcommand is None:
        console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
        _check_update()
        _help()

@cli.command()
@click.option("--username", default=None)
@click.option("--email",    default=None)
@click.option("--phone",    default=None)
@click.option("--domain",   default=None)
@click.option("--ip",       default=None)
@click.option("--name",     default=None)
@click.option("--limit",    default=50,   help="Result limit")
@click.option("--output",   default="results")
@click.option("--json",     "save_json", is_flag=True)
@click.option("--quiet",    is_flag=True)
@click.option("--timeout",  default=10)
@click.option("--proxy",    default=None)
@click.option("--threads",  default=50)
def osint(username, email, phone, domain, ip, name, limit, output, save_json, quiet, timeout, proxy, threads):
    """OSINT: username / email / phone / domain / ip / name"""
    if not any([username, email, phone, domain, ip, name]):
        console.print("  [red]Error:[/red] Provide at least one target flag.\n  Example: cypherx osint --username ali")
        sys.exit(1)
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    _check_update()
    from modules.osint import OSINTEngine
    OSINTEngine(timeout=timeout, proxy=proxy, quiet=quiet, threads=threads).run(
        username=username, email=email, phone=phone,
        domain=domain, ip=ip, name=name,
        limit=limit, output_dir=output, save_json=save_json
    )

@cli.command()
@click.argument("target")
@click.option("--limit",   default=50)
@click.option("--output",  default="results")
@click.option("--json",    "save_json", is_flag=True)
@click.option("--quiet",   is_flag=True)
@click.option("--timeout", default=10)
@click.option("--proxy",   default=None)
@click.option("--threads", default=50)
def recon(target, limit, output, save_json, quiet, timeout, proxy, threads):
    """Full target reconnaissance"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    _check_update()
    from modules.recon import ReconEngine
    ReconEngine(timeout=timeout, proxy=proxy, quiet=quiet, threads=threads).run(
        target, limit=limit, output_dir=output, save_json=save_json
    )

@cli.command()
@click.argument("target")
@click.option("--ports",   default="1-1024")
@click.option("--limit",   default=200)
@click.option("--output",  default="results")
@click.option("--json",    "save_json", is_flag=True)
@click.option("--quiet",   is_flag=True)
@click.option("--timeout", default=1.0)
@click.option("--threads", default=500)
@click.option("--banner",  is_flag=True, default=True)
def scan(target, ports, limit, output, save_json, quiet, timeout, threads, banner):
    """Fast deep port scan + service detection"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    _check_update()
    from modules.scanner import PortScanner
    PortScanner(timeout=timeout, quiet=quiet, threads=threads, grab_banner=banner).run(
        target, ports=ports, limit=limit, output_dir=output, save_json=save_json
    )

@cli.command()
@click.argument("target")
@click.option("--limit",   default=254)
@click.option("--output",  default="results")
@click.option("--json",    "save_json", is_flag=True)
@click.option("--quiet",   is_flag=True)
@click.option("--timeout", default=1.0)
@click.option("--threads", default=100)
def network(target, limit, output, save_json, quiet, timeout, threads):
    """Host discovery + OS fingerprint"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    _check_update()
    from modules.network import NetworkEngine
    NetworkEngine(timeout=timeout, quiet=quiet, threads=threads).run(
        target, limit=limit, output_dir=output, save_json=save_json
    )

@cli.command()
@click.option("--iface",    default=None)
@click.option("--duration", default=0)
@click.option("--limit",    default=500)
@click.option("--output",   default="results")
@click.option("--quiet",    is_flag=True)
def monitor(iface, duration, limit, output, quiet):
    """Live traffic monitor"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    from modules.monitor import TrafficMonitor
    TrafficMonitor(quiet=quiet).run(iface=iface, duration=duration, limit=limit, output_dir=output)

@cli.command()
@click.argument("protocol", type=click.Choice(["ssh","ftp","http","smtp","rdp","mysql","postgres","telnet"]))
@click.argument("target")
@click.option("--port",     default=None, type=int)
@click.option("--userlist", default=None)
@click.option("--passlist", default=None)
@click.option("--user",     default="admin")
@click.option("--limit",    default=1000)
@click.option("--threads",  default=20)
@click.option("--output",   default="results")
@click.option("--json",     "save_json", is_flag=True)
@click.option("--quiet",    is_flag=True)
@click.option("--timeout",  default=10)
def brute(protocol, target, port, userlist, passlist, user, limit, threads, output, save_json, quiet, timeout):
    """Bruteforce SSH/FTP/HTTP/SMTP/RDP/MySQL/Postgres/Telnet"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    _check_update()
    from modules.bruteforce import BruteForce
    BruteForce(timeout=timeout, quiet=quiet).run(
        protocol=protocol, target=target, port=port,
        userlist=userlist, passlist=passlist, user=user,
        limit=limit, threads=threads, output_dir=output, save_json=save_json
    )

@cli.command()
@click.option("--target",  required=True)
@click.option("--limit",   default=50)
@click.option("--output",  default="results")
@click.option("--json",    "save_json", is_flag=True)
@click.option("--quiet",   is_flag=True)
@click.option("--timeout", default=10)
@click.option("--threads", default=50)
def vuln(target, limit, output, save_json, quiet, timeout, threads):
    """Deep vulnerability detection"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    _check_update()
    from modules.vuln import VulnScanner
    VulnScanner(timeout=timeout, quiet=quiet, threads=threads).run(
        target, limit=limit, output_dir=output, save_json=save_json
    )

@cli.command()
@click.option("--full",    is_flag=True)
@click.option("--limit",   default=100)
@click.option("--output",  default="results")
@click.option("--json",    "save_json", is_flag=True)
@click.option("--quiet",   is_flag=True)
def audit(full, limit, output, save_json, quiet):
    """Full system security audit"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    from modules.audit import SystemAudit
    SystemAudit(quiet=quiet).run(full=full, limit=limit, output_dir=output, save_json=save_json)

@cli.command()
@click.option("--log",     default=None)
@click.option("--limit",   default=500)
@click.option("--output",  default="results")
@click.option("--json",    "save_json", is_flag=True)
@click.option("--quiet",   is_flag=True)
def forensics(log, limit, output, save_json, quiet):
    """Log analysis + IOC extraction"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    from modules.forensics import ForensicsEngine
    ForensicsEngine(quiet=quiet).run(log_path=log, limit=limit, output_dir=output, save_json=save_json)

@cli.command()
@click.option("--output",  default="results")
@click.option("--json",    "save_json", is_flag=True)
@click.option("--quiet",   is_flag=True)
def hardening(output, save_json, quiet):
    """System hardening guide"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    from modules.hardening import HardeningEngine
    HardeningEngine(quiet=quiet).run(output_dir=output, save_json=save_json)

@cli.command()
@click.argument("filepath")
@click.option("--output",  default="results")
@click.option("--json",    "save_json", is_flag=True)
@click.option("--quiet",   is_flag=True)
def filecheck(filepath, output, save_json, quiet):
    """Deep file safety analysis"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    from modules.filecheck import FileChecker
    FileChecker(quiet=quiet).run(filepath, output_dir=output, save_json=save_json)

@cli.command()
@click.option("--last",    is_flag=True)
@click.option("--input",   "input_file", default=None)
@click.option("--format",  "fmt", default="html", type=click.Choice(["html","txt","pdf"]))
@click.option("--output",  default="reports")
@click.option("--quiet",   is_flag=True)
def report(last, input_file, fmt, output, quiet):
    """Generate HTML/PDF/TXT report"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    from utils.reporter import ReportGenerator
    gen = ReportGenerator(output_dir=output)
    src = gen.find_last("results") if last else input_file
    if not src:
        console.print("  [red]Error:[/red] No input. Use --last or --input <file>")
        sys.exit(1)
    out = gen.generate(src, fmt=fmt)
    console.print(f"  [green]✓[/green]  Report → {out}")

@cli.command()
def update():
    """Check and apply updates"""
    console.print(f"\n  [bold cyan]CypherX[/bold cyan] v{__version__}")
    from core.updater import Updater
    Updater(__version__).run()

def _sigint(sig, frame):
    console.print(f"\n  Interrupted.\n")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, _sigint)
    if len(sys.argv) > 1 and sys.argv[1] in SHORT:
        sys.argv[1] = SHORT[sys.argv[1]]
    try:
        cli()
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"\n  [red]Fatal: {e}[/red]")
        sys.exit(1)
