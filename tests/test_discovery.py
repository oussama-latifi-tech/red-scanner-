import asyncio

from redscanner.discovery import discover_hosts, ip_sort_key, tcp_ping

from helpers import free_port, start_server

# Windows can take ~2 s to report a refused connection (upper limit only).
SLOW_OS_TIMEOUT = 5


def test_tcp_ping_open_port():
    async def scenario():
        server, port, _ = await start_server()
        async with server:
            return await tcp_ping("127.0.0.1", port, 1)

    assert asyncio.run(scenario()) is True


def test_refused_connection_still_proves_host_is_up():
    assert asyncio.run(tcp_ping("127.0.0.1", free_port(), SLOW_OS_TIMEOUT)) is True


def test_discover_hosts_finds_localhost():
    live = asyncio.run(discover_hosts(["127.0.0.1"], use_icmp=False,
                                      tcp_ports=(free_port(),), timeout=SLOW_OS_TIMEOUT))
    assert live == ["127.0.0.1"]


def test_ip_sort_is_numeric():
    ips = ["10.0.0.10", "10.0.0.2", "10.0.0.1"]
    assert sorted(ips, key=ip_sort_key) == ["10.0.0.1", "10.0.0.2", "10.0.0.10"]
