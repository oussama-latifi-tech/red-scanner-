"""Shared helpers: tiny local TCP servers (no internet needed)."""
import asyncio
import socket


async def start_server(banner: bytes = b""):
    """Start a local server. Returns (server, port, received_chunks)."""
    received = []

    async def handle(reader, writer):
        if banner:
            writer.write(banner)
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(100), 0.5)
        except asyncio.TimeoutError:
            data = b""
        received.append(data)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port, received


def free_port() -> int:
    """A port nobody listens on (connection will be refused)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
