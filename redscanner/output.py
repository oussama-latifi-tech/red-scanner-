"""Report formatters (JSON, CSV, TXT)."""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .scanner import HostResult, ScanResult

SUPPORTED_FORMATS = ("json", "csv", "txt")


@dataclass
class ScanReport:
    hosts: List[HostResult]
    start_time: datetime
    end_time: datetime
    errors: Dict[str, int] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    @property
    def open_count(self) -> int:
        return sum(h.count("open") for h in self.hosts)


def _visible(host: HostResult, show_all: bool) -> List[ScanResult]:
    """By default only open ports are reported (closed/filtered are noise)."""
    return [p for p in host.ports if show_all or p.state == "open"]


def _csv_safe(value: str) -> str:
    """Neutralise spreadsheet formulas (CSV injection) coming from banners."""
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


def format_json(report: ScanReport, show_all: bool = False) -> str:
    data = {
        "scan_info": {
            "start_time": report.start_time.isoformat(),
            "end_time": report.end_time.isoformat(),
            "duration_seconds": round(report.duration, 2),
            "hosts_scanned": len(report.hosts),
            "open_ports": report.open_count,
            "errors": report.errors,
        },
        "hosts": [
            {
                "host": h.host,
                "is_up": h.is_up,
                "summary": {s: h.count(s) for s in ("open", "closed", "filtered")},
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service": p.service,
                        "banner": p.banner,
                    }
                    for p in _visible(h, show_all)
                ],
            }
            for h in report.hosts
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def format_csv(report: ScanReport, show_all: bool = False) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["host", "port", "protocol", "state", "service", "banner"])
    for h in report.hosts:
        for p in _visible(h, show_all):
            writer.writerow([h.host, p.port, p.protocol, p.state, p.service,
                             _csv_safe(p.banner)])
    return buffer.getvalue()


def format_txt(report: ScanReport, show_all: bool = False) -> str:
    lines = [
        "The Red Scanner Report",
        "======================",
        f"Duration: {report.duration:.2f}s",
        f"Hosts scanned: {len(report.hosts)}",
        f"Open ports: {report.open_count}",
        "",
    ]
    for h in report.hosts:
        lines.append(
            f"Host: {h.host} (open: {h.count('open')}, "
            f"closed: {h.count('closed')}, filtered: {h.count('filtered')})"
        )
        for p in _visible(h, show_all):
            lines.append(f"  {p.port}/{p.protocol} {p.state:>8} {p.service}")
        lines.append("")
    return "\n".join(lines)


_FORMATTERS = {"json": format_json, "csv": format_csv, "txt": format_txt}


def write_output(report: ScanReport, filename: str, fmt: str,
                 show_all: bool = False) -> None:
    """Write the report to `filename`. Raises ValueError for unknown formats."""
    formatter = _FORMATTERS.get(fmt.lower())
    if formatter is None:
        raise ValueError(
            f"Unsupported format '{fmt}' (choose from: {', '.join(SUPPORTED_FORMATS)})"
        )
    Path(filename).write_text(formatter(report, show_all), encoding="utf-8")
