"""Service identification and banner grabbing."""
from __future__ import annotations

import asyncio
import json
import re
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

SIGNATURES_PATH = Path(__file__).parent / "data" / "signatures.json"

# Best guess from the port number alone (used when no banner confirms it).
PORT_MAP: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis", 8080: "http-proxy", 8443: "https",
}


@lru_cache(maxsize=1)
def load_signatures() -> Dict[str, dict]:
    """Load and compile the signatures. Warns (once) if the file is unusable."""
    try:
        with open(SIGNATURES_PATH, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        warnings.warn(
            f"Could not load {SIGNATURES_PATH}: {exc}. "
            "Banner-based service detection is disabled.",
            RuntimeWarning,
            stacklevel=2,
        )
        return {}

    signatures: Dict[str, dict] = {}
    for name, data in raw.items():
        patterns = []
        for pattern in data.get("regex", []):
            try:
                patterns.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
            except re.error as exc:
                warnings.warn(f"Invalid regex for '{name}': {exc}", RuntimeWarning)
        signatures[name] = {
            "ports": data.get("ports", []),
            "probes": data.get("probes", []),
            "patterns": patterns,
        }
    return signatures


def probes_for_port(port: int) -> List[str]:
    """Return the probes to send on this port (empty = just listen)."""
    for data in load_signatures().values():
        if port in data["ports"]:
            return data["probes"]
    return []


def identify_service(port: int, banner: str = "") -> str:
    """Identify a service from its banner, falling back to the port number.

    Signatures declared for the scanned port are tested first, which avoids
    confusing services that share a greeting format (FTP/SMTP both use 220).
    """
    guess = PORT_MAP.get(port, "unknown")
    if not banner:
        return guess

    signatures = load_signatures()
    ordered = sorted(signatures.items(), key=lambda item: port not in item[1]["ports"])
    for name, data in ordered:
        if any(pattern.search(banner) for pattern in data["patterns"]):
            return name
    return guess


def _clean(text: str) -> str:
    """Make a banner safe and single-line (no control characters)."""
    printable = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(printable.split())


async def grab_banner(host: str, port: int, timeout: float = 3.0,
                      read_timeout: float = 1.0) -> str:
    """Connect to a TCP service and return its (cleaned) banner, or ''."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
        for probe in probes_for_port(port):
            writer.write(probe.encode("utf-8"))
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(4096), min(read_timeout, timeout))
        except asyncio.TimeoutError:
            data = b""
        return _clean(data.decode("utf-8", errors="replace"))
    except (OSError, asyncio.TimeoutError):
        return ""
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
