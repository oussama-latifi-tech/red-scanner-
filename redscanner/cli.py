"""Command line interface of The Red Scanner."""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import socket
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from rich.console import Console
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn)
from rich.table import Table
from rich.text import Text

from . import __version__
from .banner import show_banner
from .discovery import discover_hosts
from .output import SUPPORTED_FORMATS, ScanReport, write_output
from .scanner import HostResult, ResourceLimitError, tcp_connect_scan
from .theme import get_console_with_theme, print_disclaimer

# ~100 commonly exposed TCP ports.
COMMON_PORTS = (
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
)

PORT_PRESETS = {
    "common": COMMON_PORTS,
    "well-known": range(1, 1025),
    "all": range(1, 65536),
}

# speed -> (concurrency, timeout in seconds)
SPEED_PRESETS = {"slow": (10, 5.0), "normal": (50, 3.0), "fast": (200, 1.0)}

DEFAULT_MAX_HOSTS = 65536


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------
def _to_port(text: str) -> int:
    try:
        number = int(text)
    except ValueError:
        raise ValueError(f"invalid port '{text}'") from None
    if not 1 <= number <= 65535:
        raise ValueError(f"port out of range (1-65535): {number}")
    return number


def parse_ports(spec: str) -> List[int]:
    """Turn '22,80,1-1024,common' into a sorted list of valid ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part in PORT_PRESETS:
            ports.update(PORT_PRESETS[part])
        elif "-" in part:
            start_text, _, end_text = part.partition("-")
            start, end = _to_port(start_text), _to_port(end_text)
            if start > end:
                raise ValueError(f"invalid range '{part}' (start is after end)")
            ports.update(range(start, end + 1))
        else:
            ports.add(_to_port(part))
    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)


def expand_single_target(target: str, max_hosts: int = DEFAULT_MAX_HOSTS) -> List[str]:
    """Expand one IP, CIDR network or hostname into IP addresses."""
    target = target.strip()
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise ValueError(f"invalid network: {target}") from None
        if network.num_addresses > max_hosts:
            raise ValueError(
                f"network {target} is too large "
                f"({network.num_addresses} addresses, limit {max_hosts}; see --max-hosts)"
            )
        return [str(host) for host in network.hosts()]
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        pass
    try:
        info = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"cannot resolve host: {target}") from None
    addresses: List[str] = []
    for entry in info:
        ip = entry[4][0]
        if ip not in addresses:
            addresses.append(ip)
    return addresses


def expand_targets(spec: str, max_hosts: int = DEFAULT_MAX_HOSTS) -> Tuple[List[str], List[str]]:
    """Expand a target spec (IP, CIDR, hostname or file) -> (targets, errors)."""
    lines = [spec]
    path = Path(spec)
    if path.is_file():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            return [], [f"cannot read {spec}: {exc}"]

    targets: List[str] = []
    errors: List[str] = []
    seen = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            addresses = expand_single_target(line, max_hosts)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        for ip in addresses:
            if ip not in seen:
                seen.add(ip)
                targets.append(ip)

    if len(targets) > max_hosts:
        return [], [f"too many targets ({len(targets)}, limit {max_hosts})"]
    return targets, errors


def is_private_ip(ip_str: str) -> bool:
    """True for private, loopback and link-local addresses (IPv4 and IPv6)."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redscanner",
        description="The Red Scanner - asynchronous TCP port scanner",
    )
    parser.add_argument("targets", nargs="?",
                        help="target(s): IP, hostname, CIDR (192.168.1.0/24) or a file")
    parser.add_argument("-p", "--ports", default="common",
                        help="ports: 22,80,1-1024 or presets common / well-known / all "
                             "(default: common)")
    parser.add_argument("--speed", choices=list(SPEED_PRESETS), default="normal")
    parser.add_argument("--concurrency", type=_positive_int, default=None,
                        help="simultaneous connections (overrides --speed)")
    parser.add_argument("--timeout", type=_positive_float, default=None,
                        help="connection timeout in seconds (overrides --speed)")
    parser.add_argument("--service-detect", action="store_true",
                        help="grab banners and identify services on open ports")
    parser.add_argument("--no-host-discovery", action="store_true",
                        help="skip host discovery and scan every target")
    parser.add_argument("--show-all", action="store_true",
                        help="also show closed and filtered ports")
    parser.add_argument("--max-hosts", type=_positive_int, default=DEFAULT_MAX_HOSTS,
                        help=f"maximum number of targets (default: {DEFAULT_MAX_HOSTS})")
    parser.add_argument("-o", "--output", help="write the results to this file")
    parser.add_argument("--format", choices=SUPPORTED_FORMATS, default="json",
                        help="output file format (default: json)")
    parser.add_argument("--i-have-permission", action="store_true",
                        help="confirm you are allowed to scan non-private targets")
    parser.add_argument("--no-banner", action="store_true", help="do not show the banner")
    parser.add_argument("--no-disclaimer", action="store_true",
                        help="do not show the disclaimer")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


# --------------------------------------------------------------------------
# Scan steps
# --------------------------------------------------------------------------
def confirm_permission(console: Console, public_targets: Sequence[str]) -> bool:
    console.print("\n[critical]WARNING: Scanning non-private targets![/critical]")
    console.print(f"[warning]{len(public_targets)} target(s) are not on a private network. "
                  "You must have explicit permission to scan these systems.[/warning]")
    try:
        answer = input("Type 'yes' to confirm you have permission: ")
    except EOFError:
        answer = ""
    return answer.strip().lower() == "yes"


async def run_discovery(console: Console, targets: List[str],
                        concurrency: int, timeout: float) -> List[str]:
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        progress.add_task("Discovering hosts...", total=None)
        return await discover_hosts(targets, concurrency=concurrency, timeout=timeout)


async def run_scan(console: Console, hosts: List[str], ports: List[int],
                   concurrency: int, timeout: float, service_detect: bool,
                   errors: Counter) -> List[HostResult]:
    sem = asyncio.Semaphore(concurrency)
    results: List[HostResult] = []

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Scanning ports...", total=len(hosts) * len(ports))

        async def scan_one(host: str, port: int):
            try:
                async with sem:
                    return await tcp_connect_scan(host, port, timeout, service_detect)
            except ResourceLimitError:
                errors["resource-limit"] += 1
            except Exception as exc:  # keep scanning, but report it at the end
                errors[type(exc).__name__] += 1
            finally:
                progress.advance(task)
            return None

        for host in hosts:
            scanned = await asyncio.gather(*(scan_one(host, p) for p in ports))
            ports_found = sorted((r for r in scanned if r is not None),
                                 key=lambda r: r.port)
            results.append(HostResult(host=host, is_up=True, ports=ports_found))
    return results


def render_results(console: Console, report: ScanReport, show_all: bool) -> None:
    table = Table(title="[header]Scan Results[/header]", border_style="border")
    for name, style in (("Host", "info"), ("Port", "info"), ("Proto", "muted"),
                        ("State", "info"), ("Service", "info"), ("Banner", "muted")):
        table.add_column(name, style=style)

    rows = 0
    for host in report.hosts:
        for result in host.ports:
            if result.state != "open" and not show_all:
                continue
            banner = result.banner if len(result.banner) <= 50 else result.banner[:50] + "..."
            table.add_row(host.host, str(result.port), result.protocol,
                          Text(result.state, style=result.state),
                          result.service, Text(banner))
            rows += 1

    if rows:
        console.print(table)
    else:
        console.print("[warning]No open ports found.[/warning]")


def print_summary(console: Console, report: ScanReport) -> None:
    console.print(f"\n[info]Scan completed in {report.duration:.2f}s[/info]")
    console.print(f"[open]Open ports: {report.open_count}[/open]")
    if report.errors:
        console.print(f"[warning]{sum(report.errors.values())} port(s) could not be "
                      "scanned:[/warning]")
        for name, count in report.errors.items():
            console.print(f"[warning]  - {name}: {count}[/warning]")
        if "resource-limit" in report.errors:
            console.print("[warning]The system ran out of sockets. Lower --concurrency "
                          "or raise the open-files limit (ulimit -n).[/warning]")


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------
async def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.no_banner:
        show_banner()
    console = get_console_with_theme()
    if not args.no_disclaimer:
        print_disclaimer(console)

    if not args.targets:
        console.print("[warning]No targets specified. Use --help for usage.[/warning]")
        return 2

    targets, target_errors = expand_targets(args.targets, args.max_hosts)
    for message in target_errors:
        console.print(f"[warning]Skipped: {message}[/warning]")
    if not targets:
        console.print("[warning]No valid targets found.[/warning]")
        return 2

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        console.print(f"[warning]Error: {exc}[/warning]")
        return 2

    public = [t for t in targets if not is_private_ip(t)]
    if public and not args.i_have_permission:
        if not confirm_permission(console, public):
            console.print("[info]Scan cancelled.[/info]")
            return 1

    default_concurrency, default_timeout = SPEED_PRESETS[args.speed]
    concurrency = args.concurrency or default_concurrency
    timeout = args.timeout or default_timeout

    start_time = datetime.now()
    live_hosts = targets
    if not args.no_host_discovery:
        live_hosts = await run_discovery(console, targets, concurrency, timeout)
        console.print(f"[info]Hosts up: {len(live_hosts)}[/info]")
        if not live_hosts:
            console.print("[warning]No live hosts found. If you are sure they are up "
                          "(ICMP/common ports filtered), retry with "
                          "--no-host-discovery.[/warning]")
            return 0

    errors: Counter = Counter()
    host_results = await run_scan(console, live_hosts, ports, concurrency,
                                  timeout, args.service_detect, errors)
    report = ScanReport(host_results, start_time, datetime.now(), dict(errors))

    render_results(console, report, args.show_all)
    print_summary(console, report)

    if args.output:
        try:
            write_output(report, args.output, args.format, args.show_all)
        except (OSError, ValueError) as exc:
            console.print(f"[warning]Could not write {args.output}: {exc}[/warning]")
            return 1
        console.print(f"[info]Results written to {args.output}[/info]")
    return 0


def asyncio_main() -> None:
    """Console-script entry point (see pyproject.toml)."""
    try:
        code = asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    asyncio_main()
