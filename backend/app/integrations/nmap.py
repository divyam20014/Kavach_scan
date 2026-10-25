"""Optional Nmap integration for bounded TCP port checks (MASTER_SPEC Module 6.2 / 11).

This module builds and validates argument arrays and parses XML; it runs nothing itself.
The surface runner executes the argv via `JobContext.run_process` (allowlisted executable,
no shell, timeout, output cap, process-tree kill) after `ScopeGuard` authorized every
host:port, and passes only guard-pinned IP literals (so Nmap does not resolve DNS).

Allowed flags (and nothing else; `validate_argv` enforces it):
  -sT              TCP connect scan (no raw packets, no SYN/stealth)
  -Pn              no host discovery pings (targets are already authorized)
  -n               no reverse DNS
  --unprivileged   never use raw sockets even if run with privileges
  --max-retries 1, --host-timeout <=300s, --max-rate <=50
  -p <explicit comma list, at most 1000 ports, no ranges, no "-">
  -oX -            XML to stdout
Never: -sS/-sU/-sN/-sF/-sX/-sA, -A, -O, -sV, --script/-sC, -p-, -T4/-T5, decoys (-D),
spoofing (-S, --spoof-mac), fragmentation (-f, --mtu), source port (-g), proxies.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET  # noqa: S405 - input is size-capped and DTDs are rejected
from dataclasses import dataclass, field

from app.integrations.process import find_executable

MAX_PORTS = 1000
MAX_TARGETS = 64
MAX_XML_BYTES = 8 * 1024 * 1024
MAX_HOST_TIMEOUT = 300
MAX_RATE = 50
_FLAG_WITH_VALUE = {"--max-retries", "--host-timeout", "--max-rate", "-p", "-oX"}
_BARE_FLAGS = {"-sT", "-Pn", "-n", "--unprivileged"}
_IP = re.compile(r"^[0-9a-fA-F:.]{2,45}$")
_VERSION = re.compile(r"Nmap version (\d+(?:\.\d+)+)")


class NmapPolicyError(ValueError):
    """The argv would violate the Nmap safety policy (never executed)."""


class NmapOutputError(ValueError):
    """Nmap output could not be interpreted; no port states may be claimed from it."""


@dataclass(frozen=True)
class NmapSpec:
    executable: str
    prefix: tuple[str, ...] = ()  # interpreter args (tests run a fixture script)

    def version_argv(self) -> list[str]:
        return [self.executable, *self.prefix, "--version"]

    def argv(
        self, ips: list[str], ports: list[int], *, host_timeout: int = 120, max_rate: int = 10
    ) -> list[str]:
        if not ips or len(ips) > MAX_TARGETS:
            raise NmapPolicyError(f"between 1 and {MAX_TARGETS} target addresses are required")
        if not ports or len(ports) > MAX_PORTS:
            raise NmapPolicyError(f"between 1 and {MAX_PORTS} explicit ports are required")
        argv = [
            self.executable,
            *self.prefix,
            "-sT",
            "-Pn",
            "-n",
            "--unprivileged",
            "--max-retries",
            "1",
            "--host-timeout",
            f"{min(max(host_timeout, 10), MAX_HOST_TIMEOUT)}s",
            "--max-rate",
            str(min(max(max_rate, 1), MAX_RATE)),
            "-p",
            ",".join(str(p) for p in sorted(set(ports))),
            "-oX",
            "-",
            *ips,
        ]
        validate_argv(argv[1 + len(self.prefix) :])
        return argv


def validate_argv(args: list[str]) -> None:
    """Accept only the allowlisted flag set followed by IP literals."""
    i = 0
    seen_targets = False
    while i < len(args):
        arg = args[i]
        if arg in _BARE_FLAGS and not seen_targets:
            i += 1
            continue
        if arg in _FLAG_WITH_VALUE and not seen_targets:
            if i + 1 >= len(args):
                raise NmapPolicyError(f"{arg} needs a value")
            value = args[i + 1]
            _check_value(arg, value)
            i += 2
            continue
        if arg.startswith("-"):
            raise NmapPolicyError(f"flag {arg!r} is not allowed")
        if not _IP.fullmatch(arg):
            raise NmapPolicyError("targets must be guard-pinned IP literals")
        seen_targets = True
        i += 1
    if not seen_targets:
        raise NmapPolicyError("no targets")


def _check_value(flag: str, value: str) -> None:
    if flag == "-p":
        parts = value.split(",")
        if not 1 <= len(parts) <= MAX_PORTS or not all(
            p.isdigit() and 1 <= int(p) <= 65535 for p in parts
        ):
            raise NmapPolicyError(
                "-p must be an explicit comma-separated list of ports (no ranges)"
            )
    elif flag == "-oX":
        if value != "-":
            raise NmapPolicyError("XML output goes to stdout only")
    elif flag == "--max-retries":
        if value not in ("0", "1"):
            raise NmapPolicyError("--max-retries must be 0 or 1")
    elif flag == "--host-timeout":
        if not re.fullmatch(r"\d{1,3}s", value) or int(value[:-1]) > MAX_HOST_TIMEOUT:
            raise NmapPolicyError("--host-timeout is capped")
    elif flag == "--max-rate":
        if not value.isdigit() or not 1 <= int(value) <= MAX_RATE:
            raise NmapPolicyError("--max-rate is capped")


def parse_version(output: bytes) -> str:
    m = _VERSION.search(output.decode("utf-8", "replace"))
    return f"Nmap {m.group(1)}" if m else ""


@dataclass
class NmapPort:
    port: int
    state: str  # open | closed | filtered | open|filtered | ...
    service: str = ""
    reason: str = ""


@dataclass
class NmapResult:
    hosts: dict[str, list[NmapPort]] = field(default_factory=dict)  # ip -> ports
    scanner_args: str = ""
    version: str = ""


def parse_xml(data: bytes) -> NmapResult:
    if not data:
        raise NmapOutputError("empty Nmap output")
    if len(data) > MAX_XML_BYTES:
        raise NmapOutputError("Nmap output exceeds the size cap")
    head = data[:4096].upper()
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in head:
        raise NmapOutputError("DTD/entity declarations are not accepted")
    try:
        root = ET.fromstring(data)  # noqa: S314 - DTDs rejected above; size-capped
    except ET.ParseError as exc:
        raise NmapOutputError(f"malformed Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapOutputError("not an Nmap XML report")
    result = NmapResult(
        scanner_args=root.get("args", "")[:500], version=root.get("version", "")[:40]
    )
    for host in root.findall("host"):
        address = next(
            (
                a.get("addr", "")
                for a in host.findall("address")
                if a.get("addrtype") in ("ipv4", "ipv6")
            ),
            "",
        )
        if not address or not _IP.fullmatch(address):
            continue
        ports: list[NmapPort] = []
        for port in host.findall("./ports/port"):
            if port.get("protocol") != "tcp":
                continue
            try:
                number = int(port.get("portid", ""))
            except ValueError:
                continue
            state = port.find("state")
            service = port.find("service")
            ports.append(
                NmapPort(
                    port=number,
                    state=(state.get("state", "") if state is not None else "")[:20],
                    service=(service.get("name", "") if service is not None else "")[:40],
                    reason=(state.get("reason", "") if state is not None else "")[:40],
                )
            )
        result.hosts[address] = ports
    return result


def detect_nmap() -> NmapSpec | None:
    found = find_executable(["nmap"])
    return NmapSpec(found) if found else None
