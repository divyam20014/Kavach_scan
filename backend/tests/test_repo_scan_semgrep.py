"""Semgrep adapter: argv construction/validation and JSON-report parsing (roadmap Phase 2
increment 1, TBD-084).

`REAL_SEMGREP_OUTPUT` below is the genuine JSON produced by a real local Semgrep 1.182.1
run (`semgrep scan --config p/security-audit --json --metrics=off <dir>`) against a
throwaway two-line Python file (a shell-invoking `subprocess.call(x, ...)` call and
`eval(expr)`) in this session -- not a hand-invented shape. Every field name and value matches that real run
exactly (see TBD-084); only the verbose `time`/profiling block was trimmed, since this
adapter never reads it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.common import Confidence, Severity
from app.scanners.repo_scan.semgrep_adapter import (
    ALLOWED_CONFIGS,
    SemgrepArgvError,
    SemgrepReportError,
    build_scan_argv,
    parse_semgrep_json,
    report_errors,
)

REAL_SEMGREP_OUTPUT = b"""
{
  "version": "1.182.1",
  "results": [
    {
      "check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
      "path": "vuln.py",
      "start": {"line": 4, "col": 39, "offset": 91},
      "end": {"line": 4, "col": 43, "offset": 95},
      "extra": {
        "message": "Found 'subprocess' function 'call' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead.",
        "fix": "False",
        "metadata": {
          "owasp": ["A01:2017 - Injection", "A03:2021 - Injection", "A05:2025 - Injection"],
          "cwe": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"],
          "references": ["https://stackoverflow.com/questions/3172470/actual-meaning-of-shell-true-in-subprocess", "https://docs.python.org/3/library/subprocess.html"],
          "category": "security",
          "technology": ["python"],
          "likelihood": "HIGH",
          "impact": "LOW",
          "confidence": "MEDIUM",
          "vulnerability_class": ["Command Injection"],
          "source": "https://semgrep.dev/r/python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
          "shortlink": "https://sg.run/J92w"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "python.lang.security.audit.eval-detected.eval-detected",
      "path": "vuln.py",
      "start": {"line": 7, "col": 12, "offset": 129},
      "end": {"line": 7, "col": 22, "offset": 139},
      "extra": {
        "message": "Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.",
        "metadata": {
          "cwe": ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"],
          "owasp": ["A03:2021 - Injection", "A05:2025 - Injection"],
          "category": "security",
          "technology": ["python"],
          "references": ["https://owasp.org/Top10/A03_2021-Injection"],
          "likelihood": "LOW",
          "impact": "HIGH",
          "confidence": "LOW",
          "vulnerability_class": ["Code Injection"],
          "source": "https://semgrep.dev/r/python.lang.security.audit.eval-detected.eval-detected",
          "shortlink": "https://sg.run/ZvrD"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    }
  ],
  "errors": [],
  "paths": {"scanned": ["vuln.py"]},
  "engine_requested": "OSS",
  "skipped_rules": [],
  "profiling_results": []
}
"""


def test_parses_the_real_captured_output_correctly() -> None:
    findings = parse_semgrep_json(REAL_SEMGREP_OUTPUT)
    assert len(findings) == 2
    shell_true, eval_use = findings

    assert (
        shell_true.check_id
        == "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
    )
    assert shell_true.path == "vuln.py"
    assert shell_true.start_line == 4 and shell_true.end_line == 4
    assert "shell=True" in shell_true.message
    assert shell_true.severity == Severity.HIGH  # ERROR
    assert (
        shell_true.confidence == Confidence.POTENTIAL
    )  # MEDIUM -> never higher than probable overall
    assert shell_true.cwe_ids == [78]
    assert "https://docs.python.org/3/library/subprocess.html" in shell_true.references
    assert shell_true.source_url.startswith("https://semgrep.dev/r/")
    # Semgrep CE's own fingerprint/lines fields require a login and must never be trusted
    assert shell_true.fingerprint_key == f"{shell_true.check_id}|vuln.py|4"

    assert eval_use.severity == Severity.MEDIUM  # WARNING
    assert eval_use.confidence == Confidence.POTENTIAL  # LOW
    assert eval_use.cwe_ids == [95]


def test_confidence_is_never_confirmed_even_for_semgreps_own_high_confidence() -> None:
    data = b'{"results": [{"check_id": "x", "path": "a.py", "start": {"line": 1}, "end": {"line": 1}, "extra": {"severity": "ERROR", "metadata": {"confidence": "HIGH"}}}]}'
    finding = parse_semgrep_json(data)[0]
    assert finding.confidence == Confidence.PROBABLE  # the highest this adapter ever reports
    assert finding.confidence != Confidence.CONFIRMED


def test_unknown_severity_or_confidence_degrades_safely_not_crash() -> None:
    data = b'{"results": [{"check_id": "x", "path": "a.py", "start": {}, "end": {}, "extra": {"severity": "CRITICAL", "metadata": {"confidence": "VERY_HIGH"}}}]}'
    finding = parse_semgrep_json(data)[0]
    assert finding.severity == Severity.INFORMATIONAL  # safe default, never a guess up
    assert finding.confidence == Confidence.NEEDS_REVIEW


@pytest.mark.parametrize(
    "raw",
    [
        b"not json at all",
        b"[]",
        b'{"no_results_key": true}',
        b'{"results": "not a list"}',
    ],
)
def test_malformed_output_is_rejected_never_silently_empty(raw: bytes) -> None:
    with pytest.raises(SemgrepReportError):
        parse_semgrep_json(raw)


def test_non_dict_entries_are_skipped_not_fatal() -> None:
    data = b'{"results": ["not a dict", {"check_id": "x", "path": "a.py", "start": {}, "end": {}, "extra": {}}]}'
    findings = parse_semgrep_json(data)
    assert len(findings) == 1


def test_report_errors_surfaces_semgreps_own_error_list() -> None:
    data = b'{"results": [], "errors": ["Could not parse broken.py"]}'
    assert report_errors(data) == ["Could not parse broken.py"]
    assert report_errors(b"not json") == []
    assert report_errors(b'{"results": []}') == []  # no errors key at all


def test_build_scan_argv_matches_the_confirmed_working_invocation(tmp_path: Path) -> None:
    argv = build_scan_argv("/usr/bin/semgrep", tmp_path)
    assert argv == [
        "/usr/bin/semgrep",
        "scan",
        "--config",
        "p/security-audit",
        "--json",
        "--metrics=off",
        "--timeout",
        "300",
        "--max-target-bytes",
        "5000000",
        str(tmp_path),
    ]


def test_build_scan_argv_rejects_an_unlisted_config(tmp_path: Path) -> None:
    with pytest.raises(SemgrepArgvError, match="config must be one of"):
        build_scan_argv("/usr/bin/semgrep", tmp_path, config="file:///etc/passwd")


def test_build_scan_argv_rejects_out_of_range_timeout(tmp_path: Path) -> None:
    with pytest.raises(SemgrepArgvError, match="timeout_seconds"):
        build_scan_argv("/usr/bin/semgrep", tmp_path, timeout_seconds=0)
    with pytest.raises(SemgrepArgvError, match="timeout_seconds"):
        build_scan_argv("/usr/bin/semgrep", tmp_path, timeout_seconds=99999)


def test_build_scan_argv_rejects_out_of_range_max_target_bytes(tmp_path: Path) -> None:
    with pytest.raises(SemgrepArgvError, match="max_target_bytes"):
        build_scan_argv("/usr/bin/semgrep", tmp_path, max_target_bytes=1)


def test_every_allowed_config_builds_a_valid_argv(tmp_path: Path) -> None:
    for config in ALLOWED_CONFIGS:
        argv = build_scan_argv("/usr/bin/semgrep", tmp_path, config=config)
        assert "--config" in argv and config in argv
