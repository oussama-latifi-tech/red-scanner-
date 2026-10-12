"""Host discovery (ping sweep): ICMP first, then TCP probes."""
from __future__ import annotations

import asyncio
import ipaddress
import math
import platform
import shutil
from typing import List, Optional, Sequence, Tuple

DEFAULT_TCP_PORTS: Tuple[int, ...] = (80, 443, 22, 445)


def ip_sort_key(host: str) -> Tuple[int, int, str]:
    """Sort IPs numerically (10.0.0.2 before 10.0.0.10)."""
    try:
        ip = ipaddress.ip_address(host)
        return (ip.version, int(ip), host)
    except ValueError:
        return (99, 0, host)


def _ping_command(host: str, timeout: float) -> Optional[List[str]]:
    """Build the system ping command, or None if ICMP is unavailable.

    The timeout flag differs per OS: Windows -w (ms), macOS -W (ms),
    Linux -W (seconds). IPv6 is left to the TCP probes.
    """
    ping = shutil.which("ping")
    if ping is None or ":" in host:
        return None
    system = platform.system().lower()
    if system == "windows":
        return [ping, "-n", "1", "-w", str(int(timeout * 1000)), host]
    if system == "darwin":
        return [ping, "-c", "1", "-W", str(int(timeout * 1000)), host]
    return [ping, "-c", "1", "-W", str(max(1, math.ceil(timeout))), host]


async def icmp_ping(host: str, timeout: float = 2.0) -> bool:
    """ICMP echo through the system `ping` command (no root needed)."""
    command = _ping_command(host, timeout)
    if command is None:
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return False
    try:
        await asyncio.wait_for(proc.wait(), timeout + 1)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return False
    return proc.returncode == 0


async def tcp_ping(host: str, port: int = 80, timeout: float = 2.0) -> bool:
    """A host is alive if it accepts OR actively refuses the connection."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
    except ConnectionRefusedError:
        return True  # an RST packet proves the host answered
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def discover_hosts(targets: Sequence[str], use_icmp: bool = True,
                         use_tcp: bool = True, concurrency: int = 50,
                         timeout: float = 2.0,
                         tcp_ports: Sequence[int] = DEFAULT_TCP_PORTS) -> List[str]:
    """Return the targets that look alive, sorted numerically."""
    sem = asyncio.Semaphore(concurrency)

    async def check(host: str) -> bool:
        async with sem:
            if use_icmp and await icmp_ping(host, timeout):
                return True
            if use_tcp:
                for port in tcp_ports:
                    if await tcp_ping(host, port, timeout):
                        return True
            return False

    results = await asyncio.gather(*(check(t) for t in targets),
                                   return_exceptions=True)
    live = [t for t, up in zip(targets, results) if up is True]
    return sorted(live, key=ip_sort_key)
