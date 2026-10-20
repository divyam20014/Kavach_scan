"""Optional external TLS analysis tools: sslyze and testssl.sh (Module 5.3 / Module 11).

This module builds argument arrays and parses output; it never runs anything itself.
The web runner executes the argv through `JobContext.run_process` (allowlisted
executable, timeout, output cap, process-tree kill) after `ScopeGuard.authorize_connect`
approved the host/port, and passes the guard-pinned IP to the tool so the tool does not
resolve DNS on its own:
- sslyze:     `HOST:PORT{IP}` target syntax;
- testssl.sh: `--ip IP`.

Conservative options only: protocol-version enumeration and certificate info. No
vulnerability/exploit checks (e.g. Heartbleed, ROBOT, renegotiation) are requested.
A tool that is missing, fails, times out or returns unparseable output yields NO protocol
claims: the related checks are reported as skipped/error, never as passed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.integrations.process import find_executable

PROTOCOLS = ("SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
LEGACY = frozenset({"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"})
TOOL_TIMEOUT_SECONDS = 300.0
MAX_TOOL_OUTPUT = 4 * 1024 * 1024


class ToolOutputError(ValueError):
    """The tool's output could not be interpreted; nothing may be claimed from it."""


@dataclass
class TlsToolReport:
    tool: str
    version: str
    protocols: dict[str, bool] = field(default_factory=dict)  # only protocols actually tested
    notes: list[str] = field(default_factory=list)

    @property
    def legacy_offered(self) -> list[str]:
        return [p for p in PROTOCOLS if p in LEGACY and self.protocols.get(p)]


@dataclass(frozen=True)
class TlsToolSpec:
    name: str  # "sslyze" | "testssl.sh"
    executable: str  # absolute path; also the allowlist entry
    prefix: tuple[str, ...] = ()  # interpreter arguments (tests run a fixture script)
    output_file: str = ""  # testssl.sh only: work-dir file name for --jsonfile

    def version_args(self) -> list[str]:
        return [*self.prefix, "--version"]

    def argv(self, host: str, port: int, ip: str, *, json_path: str = "") -> list[str]:
        if self.name == "sslyze":
            return [
                self.executable,
                *self.prefix,
                "--quiet",
                "--json_out=-",
                "--certinfo",
                "--sslv2",
                "--sslv3",
                "--tlsv1",
                "--tlsv1_1",
                "--tlsv1_2",
                "--tlsv1_3",
                f"{host}:{port}{{{ip}}}",
            ]
        if self.name == "testssl.sh":
            return [
                self.executable,
                *self.prefix,
                "--quiet",
                "--warnings",
                "batch",
                "--protocols",
                "--ip",
                ip,
                "--jsonfile",
                json_path,
                f"{host}:{port}",
            ]
        raise ValueError(f"unsupported TLS tool {self.name}")

    def parse(self, output: bytes, version: str) -> TlsToolReport:
        try:
            data: Any = json.loads(output.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ToolOutputError(f"{self.name} output is not valid JSON") from exc
        if self.name == "sslyze":
            return _parse_sslyze(data, version)
        return _parse_testssl(data, version)


_SSLYZE_KEYS = {
    "ssl_2_0_cipher_suites": "SSLv2",
    "ssl_3_0_cipher_suites": "SSLv3",
    "tls_1_0_cipher_suites": "TLS 1.0",
    "tls_1_1_cipher_suites": "TLS 1.1",
    "tls_1_2_cipher_suites": "TLS 1.2",
    "tls_1_3_cipher_suites": "TLS 1.3",
}


def _parse_sslyze(data: Any, version: str) -> TlsToolReport:
    if not isinstance(data, dict) or not isinstance(data.get("server_scan_results"), list):
        raise ToolOutputError("sslyze JSON has no server_scan_results")
    results = data["server_scan_results"]
    if not results:
        raise ToolOutputError("sslyze returned no results")
    first = results[0]
    if not isinstance(first, dict) or first.get("scan_status") not in (None, "COMPLETED"):
        raise ToolOutputError(
            f"sslyze scan status: {first.get('scan_status') if isinstance(first, dict) else '?'}"
        )
    scan = first.get("scan_result")
    if not isinstance(scan, dict):
        raise ToolOutputError("sslyze JSON has no scan_result")
    report = TlsToolReport(tool="sslyze", version=version)
    for key, label in _SSLYZE_KEYS.items():
        entry = scan.get(key)
        if not isinstance(entry, dict) or entry.get("status") not in (None, "COMPLETED"):
            report.notes.append(f"{label}: not tested")
            continue
        result = entry.get("result")
        accepted = result.get("accepted_cipher_suites") if isinstance(result, dict) else None
        if not isinstance(accepted, list):
            report.notes.append(f"{label}: no result")
            continue
        report.protocols[label] = bool(accepted)
    if not report.protocols:
        raise ToolOutputError("sslyze reported no protocol results")
    return report


_TESTSSL_IDS = {
    "SSLv2": "SSLv2",
    "SSLv3": "SSLv3",
    "TLS1": "TLS 1.0",
    "TLS1_1": "TLS 1.1",
    "TLS1_2": "TLS 1.2",
    "TLS1_3": "TLS 1.3",
}


def _parse_testssl(data: Any, version: str) -> TlsToolReport:
    items = data.get("scanResult", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ToolOutputError("testssl.sh JSON is not a list of findings")
    report = TlsToolReport(tool="testssl.sh", version=version)
    for item in items:
        if not isinstance(item, dict):
            continue
        label = _TESTSSL_IDS.get(str(item.get("id", "")))
        if label is None:
            continue
        finding = str(item.get("finding", "")).lower()
        if "not offered" in finding:
            report.protocols[label] = False
        elif "offered" in finding:
            report.protocols[label] = True
        else:
            report.notes.append(f"{label}: {finding[:80] or 'unknown'}")
    if not report.protocols:
        raise ToolOutputError("testssl.sh reported no protocol results")
    return report


def detect_tls_tools() -> list[TlsToolSpec]:
    """Installed tools in preference order (sslyze first). Only PATH lookups, no execution."""
    found: list[TlsToolSpec] = []
    sslyze = find_executable(["sslyze"])
    if sslyze:
        found.append(TlsToolSpec("sslyze", sslyze))
    testssl = find_executable(["testssl.sh", "testssl"])
    if testssl:
        found.append(TlsToolSpec("testssl.sh", testssl, output_file="testssl.json"))
    return found
