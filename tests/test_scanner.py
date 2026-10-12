import asyncio
import errno
import socket
import types

import pytest

from redscanner import scanner
from redscanner.scanner import ResourceLimitError, tcp_connect_scan

from helpers import free_port, start_server

# Windows can take ~2 s to report a refused connection, so closed-port tests
# use a generous timeout (it is only an upper limit, not a fixed wait).
SLOW_OS_TIMEOUT = 5


def test_open_port_with_service_detection():
    async def scenario():
        server, port, _ = await start_server(b"SSH-2.0-OpenSSH_9.6\r\n")
        async with server:
            return port, await tcp_connect_scan("127.0.0.1", port, 2, service_detect=True)

    port, result = asyncio.run(scenario())
    assert result.state == "open"
    assert result.port == port
    assert result.service == "ssh"
    assert result.banner == "SSH-2.0-OpenSSH_9.6"


def test_open_port_without_service_detection_has_no_banner():
    async def scenario():
        server, port, _ = await start_server(b"SSH-2.0-OpenSSH_9.6\r\n")
        async with server:
            return await tcp_connect_scan("127.0.0.1", port, 2)

    result = asyncio.run(scenario())
    assert result.state == "open"
    assert result.banner == ""


def test_closed_port():
    result = asyncio.run(tcp_connect_scan("127.0.0.1", free_port(), SLOW_OS_TIMEOUT))
    assert result.state == "closed"


def test_real_socket_is_closed_after_scan(monkeypatch):
    """The scanner must not leak sockets (it would hit the fd limit)."""
    created = []
    real_socket = socket.socket

    class TrackedSocket(real_socket):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

    fake_module = types.SimpleNamespace(
        socket=TrackedSocket, AF_INET=socket.AF_INET,
        AF_INET6=socket.AF_INET6, SOCK_STREAM=socket.SOCK_STREAM,
    )
    monkeypatch.setattr(scanner, "socket", fake_module)

    async def scenario():
        server, port, _ = await start_server()
        async with server:
            await tcp_connect_scan("127.0.0.1", port, 2)
        await tcp_connect_scan("127.0.0.1", free_port(), SLOW_OS_TIMEOUT)

    asyncio.run(scenario())
    assert len(created) == 2
    assert all(s.fileno() == -1 for s in created)  # -1 means closed


def test_timeout_is_filtered(monkeypatch):
    async def never(*args, **kwargs):
        await asyncio.sleep(10)

    monkeypatch.setattr(scanner, "_connect", never)
    result = asyncio.run(tcp_connect_scan("10.255.255.1", 80, 0.05))
    assert result.state == "filtered"


def test_unreachable_network_is_filtered(monkeypatch):
    async def unreachable(*args, **kwargs):
        raise OSError(errno.ENETUNREACH, "Network is unreachable")

    monkeypatch.setattr(scanner, "_connect", unreachable)
    result = asyncio.run(tcp_connect_scan("10.255.255.1", 80, 1))
    assert result.state == "filtered"


def test_out_of_file_descriptors_is_not_reported_as_closed(monkeypatch):
    """socket() itself fails with EMFILE when the process has no free descriptor."""
    def too_many(*args, **kwargs):
        raise OSError(errno.EMFILE, "Too many open files")

    fake_module = types.SimpleNamespace(
        socket=too_many, AF_INET=socket.AF_INET,
        AF_INET6=socket.AF_INET6, SOCK_STREAM=socket.SOCK_STREAM,
    )
    monkeypatch.setattr(scanner, "socket", fake_module)
    with pytest.raises(ResourceLimitError):
        asyncio.run(tcp_connect_scan("127.0.0.1", 80, 1))


def test_host_result_counts():
    host = scanner.HostResult("1.2.3.4", ports=[
        scanner.ScanResult("1.2.3.4", 1, state="open"),
        scanner.ScanResult("1.2.3.4", 2, state="closed"),
        scanner.ScanResult("1.2.3.4", 3, state="closed"),
    ])
    assert host.count("open") == 1 and host.count("closed") == 2
