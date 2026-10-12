import pytest

from redscanner.cli import expand_single_target, expand_targets, is_private_ip


def test_single_ip():
    assert expand_single_target("192.168.1.5") == ["192.168.1.5"]


def test_cidr_expansion():
    assert expand_single_target("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_cidr_too_large():
    with pytest.raises(ValueError):
        expand_single_target("10.0.0.0/8")


def test_invalid_network_and_host():
    with pytest.raises(ValueError):
        expand_single_target("999.1.1.1/24")
    with pytest.raises(ValueError):
        expand_single_target("this-host-does-not-exist.invalid")


def test_targets_from_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# comment\n127.0.0.1\n\n192.168.1.0/30\n127.0.0.1\nnot a host!!\n")
    targets, errors = expand_targets(str(f))
    assert targets == ["127.0.0.1", "192.168.1.1", "192.168.1.2"]  # deduplicated
    assert len(errors) == 1


def test_max_hosts_limit():
    targets, errors = expand_targets("192.168.0.0/24", max_hosts=10)
    assert targets == [] and errors


@pytest.mark.parametrize("ip,expected", [
    ("192.168.1.1", True), ("10.0.0.1", True), ("127.0.0.1", True),
    ("::1", True), ("8.8.8.8", False), ("2001:4860:4860::8888", False),
    ("garbage", False),
])
def test_is_private_ip(ip, expected):
    assert is_private_ip(ip) is expected
