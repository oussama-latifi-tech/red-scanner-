import asyncio

from redscanner.services import (grab_banner, identify_service, load_signatures,
                                 probes_for_port)

from helpers import start_server


def test_signatures_file_loads():
    sigs = load_signatures()
    assert "ssh" in sigs and "http" in sigs
    assert "mysqld" not in sigs  # names must match PORT_MAP ("mysql")


def test_identify_by_banner():
    assert identify_service(22, "SSH-2.0-OpenSSH_9.6") == "ssh"
    assert identify_service(8080, "HTTP/1.1 200 OK Server: nginx") == "http"
    assert identify_service(3306, "5.7.1 mysql_native_password") == "mysql"


def test_ftp_and_smtp_are_not_confused():
    ftp = "220 (vsFTPd 3.0.5)"
    smtp = "220 mail.example.com ESMTP Postfix"
    assert identify_service(21, ftp) == "ftp"
    assert identify_service(25, smtp) == "smtp"
    # Even on a non-standard port the greeting decides, not the order of the file.
    assert identify_service(2525, smtp) == "smtp"
    assert identify_service(2121, ftp) == "ftp"


def test_port_guess_without_banner():
    assert identify_service(443, "") == "https"
    assert identify_service(54321, "") == "unknown"
    assert identify_service(54321, "random bytes") == "unknown"


def test_probes_only_for_matching_port():
    assert probes_for_port(80) and "HEAD" in probes_for_port(80)[0]
    assert probes_for_port(22) == []
    assert probes_for_port(5432) == []
    assert probes_for_port(54321) == []


def test_no_http_probe_sent_on_non_http_port():
    """Regression: HTTP probes used to be sent to every port."""
    async def scenario():
        server, port, received = await start_server(b"SSH-2.0-Test\r\n")
        async with server:
            banner = await grab_banner("127.0.0.1", port, timeout=2)
            await asyncio.sleep(0.2)
        return banner, received

    banner, received = asyncio.run(scenario())
    assert banner == "SSH-2.0-Test"
    assert received == [b""]  # the server received nothing from us
