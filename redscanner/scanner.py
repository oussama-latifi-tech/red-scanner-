"""Core scanning engine: TCP connect scan with raw (non-blocking) sockets."""
from __future__ import annotations

import asyncio
import errno
import socket
from dataclasses import dataclass, field
from typing import List

from .services import grab_banner, identify_service

# Errors meaning "this machine ran out of resources", NOT "the port is closed".
RESOURCE_ERRNOS = {
    code
    for code in (
        getattr(errno, "EMFILE", None),
        getattr(errno, "ENFILE", None),
        getattr(errno, "ENOBUFS", None),
        10024,  # WSAEMFILE (Windows)
    )
    if code is not None
}


class ResourceLimitError(Exception):
    """Raised when the OS refuses more sockets (lower --concurrency)."""


@dataclass
class ScanResult:
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "closed"  # open, closed, filtered
    service: str = "unknown"
    banner: str = ""


@dataclass
class HostResult:
    host: str
    is_up: bool = True
    ports: List[ScanResult] = field(default_factory=list)

    def count(self, state: str) -> int:
        return sum(1 for p in self.ports if p.state == state)


async def _connect(host: str, port: int) -> socket.socket:
    """Open a TCP connection with a raw non-blocking socket.

    1. socket()            -> create the endpoint (IPv4 or IPv6)
    2. setblocking(False)  -> never freeze the program while waiting
    3. sock_connect()      -> start the TCP handshake; the event loop awaits it
                              so thousands of connections can run concurrently

    The caller owns the returned socket and must close it. If anything fails
    (or the attempt is cancelled by a timeout) the socket is closed here.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        await asyncio.get_running_loop().sock_connect(sock, (host, port))
    except BaseException:
        sock.close()
        raise
    return sock


async def tcp_connect_scan(host: str, port: int, timeout: float = 3.0,
                           service_detect: bool = False) -> ScanResult:
    """Perform a TCP connect scan on a single port.

    - connection accepted            -> open
    - connection refused (RST)       -> closed
    - timeout / network unreachable  -> filtered
    - out of file descriptors        -> ResourceLimitError (not a port state)
    """
    result = ScanResult(host=host, port=port)
    banner = ""

    try:
        sock = await asyncio.wait_for(_connect(host, port), timeout)
    except asyncio.TimeoutError:
        result.state = "filtered"
    except ConnectionRefusedError:
        result.state = "closed"
    except OSError as exc:
        if exc.errno in RESOURCE_ERRNOS:
            raise ResourceLimitError(str(exc)) from exc
        result.state = "filtered"
    else:
        result.state = "open"
        sock.close()  # a connect scan only needs the handshake to succeed
        if service_detect:
            banner = await grab_banner(host, port, timeout)

    result.banner = banner
    result.service = identify_service(port, banner)
    return result
