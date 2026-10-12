import pytest

from redscanner.cli import COMMON_PORTS, parse_ports


def test_single_ports_and_lists():
    assert parse_ports("80") == [80]
    assert parse_ports("443, 22,80") == [22, 80, 443]


def test_ranges_and_dedup():
    assert parse_ports("20-22,21") == [20, 21, 22]


def test_presets():
    assert parse_ports("common") == sorted(COMMON_PORTS)
    assert len(COMMON_PORTS) == 100
    assert parse_ports("well-known") == list(range(1, 1025))
    assert len(parse_ports("all")) == 65535


@pytest.mark.parametrize("bad", ["0", "70000", "-5", "abc", "100-20", "1-", "", ",,"])
def test_invalid_ports_raise(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)
