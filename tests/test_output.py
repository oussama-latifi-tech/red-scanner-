import csv
import io
import json
from datetime import datetime, timedelta

import pytest

from redscanner.output import (ScanReport, format_csv, format_json, format_txt,
                               write_output)
from redscanner.scanner import HostResult, ScanResult


@pytest.fixture
def report():
    start = datetime(2026, 1, 1, 12, 0, 0)
    host = HostResult("127.0.0.1", ports=[
        ScanResult("127.0.0.1", 22, state="open", service="ssh",
                   banner='SSH-2.0-Test, "quoted"'),
        ScanResult("127.0.0.1", 80, state="open", service="http", banner="=cmd|calc"),
        ScanResult("127.0.0.1", 81, state="closed"),
    ])
    return ScanReport([host], start, start + timedelta(seconds=2.5), {"OSError": 1})


def test_json_only_open_ports_by_default(report):
    data = json.loads(format_json(report))
    assert data["scan_info"]["duration_seconds"] == 2.5
    assert data["scan_info"]["open_ports"] == 2
    assert [p["port"] for p in data["hosts"][0]["ports"]] == [22, 80]
    assert data["hosts"][0]["summary"] == {"open": 2, "closed": 1, "filtered": 0}


def test_json_show_all(report):
    data = json.loads(format_json(report, show_all=True))
    assert len(data["hosts"][0]["ports"]) == 3


def test_csv_escapes_commas_and_quotes(report):
    rows = list(csv.reader(io.StringIO(format_csv(report))))
    assert rows[0] == ["host", "port", "protocol", "state", "service", "banner"]
    assert rows[1][5] == 'SSH-2.0-Test, "quoted"'  # survives the round trip


def test_csv_neutralises_formulas(report):
    rows = list(csv.reader(io.StringIO(format_csv(report))))
    assert rows[2][5].startswith("'=")


def test_txt_contains_summary(report):
    text = format_txt(report)
    assert "Open ports: 2" in text and "22/tcp" in text
    assert "81/tcp" not in text


def test_write_output_and_unknown_format(report, tmp_path):
    target = tmp_path / "out.json"
    write_output(report, str(target), "json")
    assert json.loads(target.read_text())["hosts"]
    with pytest.raises(ValueError):
        write_output(report, str(tmp_path / "out.xml"), "xml")
