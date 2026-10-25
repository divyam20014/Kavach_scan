"""Phase 06: Nmap argv construction, flag validation, version and XML parsing."""

from __future__ import annotations

import pytest

from app.integrations.nmap import (
    NmapOutputError,
    NmapPolicyError,
    NmapSpec,
    parse_version,
    parse_xml,
    validate_argv,
)


def test_argv_is_fixed_safe_and_shell_free() -> None:
    spec = NmapSpec("/usr/bin/nmap")
    argv = spec.argv(["192.0.2.10"], [443, 80, 80], max_rate=999, host_timeout=9999)
    assert isinstance(argv, list) and argv[0] == "/usr/bin/nmap"
    assert argv[1:5] == ["-sT", "-Pn", "-n", "--unprivileged"]
    assert argv[argv.index("-p") + 1] == "80,443"  # explicit, de-duplicated, sorted
    assert argv[argv.index("--max-rate") + 1] == "50"  # capped
    assert argv[argv.index("--host-timeout") + 1] == "300s"  # capped
    assert argv[argv.index("-oX") + 1] == "-" and argv[-1] == "192.0.2.10"
    for unsafe in ("-sS", "-sU", "-A", "-O", "-sV", "--script", "-sC", "-p-", "-T4", "-T5", "-D"):
        assert unsafe not in argv


@pytest.mark.parametrize(
    "args",
    [
        ["-sS", "-p", "80", "192.0.2.1"],
        ["-sT", "-sU", "-p", "80", "192.0.2.1"],
        ["-A", "192.0.2.1"],
        ["-O", "192.0.2.1"],
        ["--script", "default", "192.0.2.1"],
        ["-sT", "-p", "1-65535", "192.0.2.1"],
        ["-sT", "-p", "-", "192.0.2.1"],
        ["-sT", "-oX", "/tmp/out.xml", "192.0.2.1"],
        ["-sT", "--max-rate", "5000", "192.0.2.1"],
        ["-sT", "-p", "80", "example.com"],  # hostname: nmap would resolve DNS itself
        ["-sT", "-p", "80"],  # no target
    ],
)
def test_validator_rejects_unsafe_argv(args: list[str]) -> None:
    with pytest.raises(NmapPolicyError):
        validate_argv(args)


def test_target_and_port_bounds() -> None:
    spec = NmapSpec("/x")
    with pytest.raises(NmapPolicyError):
        spec.argv(["192.0.2.1"], list(range(1, 1200)))  # too many ports (cap is 1000)
    with pytest.raises(NmapPolicyError):
        spec.argv([], [80])  # no targets
    with pytest.raises(NmapPolicyError):
        spec.argv([f"10.0.0.{i}" for i in range(70)], [80])  # too many targets


def test_up_to_1000_explicit_ports_are_accepted() -> None:
    """Widened from 100 ports (TBD-077) so an operator can run an Nmap-'top ports'-scale
    scan; still a fixed, explicit, no-ranges list — never -p-."""
    spec = NmapSpec("/x")
    argv = spec.argv(["192.0.2.1"], list(range(1, 1001)))
    port_list = argv[argv.index("-p") + 1]
    assert port_list.count(",") == 999  # exactly 1000 explicit ports, comma separated
    assert "-" not in port_list  # never a range


def test_version_parsing() -> None:
    assert parse_version(b"Nmap version 7.94 ( https://nmap.org )") == "Nmap 7.94"
    assert parse_version(b"garbage") == ""


VALID_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -p 80,22 192.0.2.10" version="7.94">
 <host>
  <address addr="192.0.2.10" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port>
   <port protocol="tcp" portid="80"><state state="closed" reason="reset"/></port>
   <port protocol="udp" portid="53"><state state="open"/></port>
  </ports>
 </host>
</nmaprun>"""


def test_parse_valid_xml() -> None:
    result = parse_xml(VALID_XML)
    assert result.version == "7.94"
    ports = {p.port: p for p in result.hosts["192.0.2.10"]}
    assert ports[22].state == "open" and ports[22].service == "ssh"
    assert ports[80].state == "closed"
    assert 53 not in ports  # udp entries are ignored


def test_parse_rejects_dtd_and_entities() -> None:
    xxe = (
        b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b"<nmaprun><host><address addr='192.0.2.1' addrtype='ipv4'/></host></nmaprun>"
    )
    with pytest.raises(NmapOutputError):
        parse_xml(xxe)


@pytest.mark.parametrize(
    "raw", [b"", b"not xml", b"<other/>", b"<nmaprun><host></host></nmaprun>x"]
)
def test_parse_rejects_malformed(raw: bytes) -> None:
    if raw == b"<nmaprun><host></host></nmaprun>x":
        with pytest.raises(NmapOutputError):
            parse_xml(raw)
    else:
        with pytest.raises(NmapOutputError):
            parse_xml(raw)


def test_parse_rejects_oversized_output() -> None:
    with pytest.raises(NmapOutputError):
        parse_xml(b"<nmaprun>" + b" " * (9 * 1024 * 1024) + b"</nmaprun>")
