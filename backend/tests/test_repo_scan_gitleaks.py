"""Gitleaks adapter: argv construction/validation and JSON-report parsing (roadmap Phase 2
increment 2, TBD-085).

`REAL_GITLEAKS_OUTPUT` below is the genuine JSON produced by a real local Gitleaks 8.30.1
run (`gitleaks dir <dir> --report-format json --report-path - --exit-code 0 --no-banner
--redact --log-level error`) against a throwaway file containing a fake GitHub-PAT-shaped
token in this session -- not a hand-invented shape. Every field name and value matches that
real run exactly (see TBD-085), including gitleaks' own `--redact` flag already having
replaced `Match`/`Secret` with the literal string `"REDACTED"` in the report itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.common import Confidence, Severity
from app.scanners.repo_scan.gitleaks_adapter import (
    GitleaksArgvError,
    GitleaksReportError,
    build_scan_argv,
    parse_gitleaks_json,
)

REAL_GITLEAKS_OUTPUT = b"""
[
 {
  "RuleID": "generic-api-key",
  "Description": "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
  "StartLine": 2,
  "EndLine": 2,
  "StartColumn": 2,
  "EndColumn": 62,
  "Match": "github_token = \\"REDACTED\\"",
  "Secret": "REDACTED",
  "File": "sample/config.py",
  "SymlinkFile": "",
  "Commit": "",
  "Entropy": 3.64125,
  "Author": "",
  "Email": "",
  "Date": "",
  "Message": "",
  "Tags": [],
  "Fingerprint": "sample/config.py:generic-api-key:2"
 },
 {
  "RuleID": "github-pat",
  "Description": "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
  "StartLine": 2,
  "EndLine": 2,
  "StartColumn": 18,
  "EndColumn": 57,
  "Match": "REDACTED",
  "Secret": "REDACTED",
  "File": "sample/config.py",
  "SymlinkFile": "",
  "Commit": "",
  "Entropy": 3.6464393,
  "Author": "",
  "Email": "",
  "Date": "",
  "Message": "",
  "Tags": [],
  "Fingerprint": "sample/config.py:github-pat:2"
 }
]
"""


def test_parses_the_real_captured_output_correctly() -> None:
    findings = parse_gitleaks_json(REAL_GITLEAKS_OUTPUT)
    assert len(findings) == 2
    generic_key, github_pat = findings

    assert generic_key.rule_id == "generic-api-key"
    assert generic_key.path == "sample/config.py"
    assert generic_key.start_line == 2 and generic_key.end_line == 2
    assert "Generic API Key" in generic_key.description
    assert generic_key.fingerprint_key == "sample/config.py:generic-api-key:2"
    assert generic_key.severity == Severity.HIGH
    assert generic_key.confidence == Confidence.POTENTIAL
    assert generic_key.confidence != Confidence.CONFIRMED

    assert github_pat.rule_id == "github-pat"
    assert github_pat.fingerprint_key == "sample/config.py:github-pat:2"


def test_never_captures_the_raw_or_redacted_secret_text() -> None:
    """Defense in depth: even though gitleaks' own `--redact` flag already replaced the
    secret with the literal string "REDACTED" in the fixture above, this adapter's dataclass
    must never have a field that could carry secret-shaped text through at all."""
    finding = parse_gitleaks_json(REAL_GITLEAKS_OUTPUT)[0]
    field_names = {f for f in finding.__dataclass_fields__}
    assert "Match" not in field_names
    assert "Secret" not in field_names
    assert "match" not in field_names
    assert "secret" not in field_names


def test_no_leaks_found_parses_as_an_empty_list() -> None:
    assert parse_gitleaks_json(b"[]") == []


@pytest.mark.parametrize(
    "raw",
    [
        b"not json at all",
        b"{}",
        b'{"results": []}',
        b'"just a string"',
    ],
)
def test_malformed_output_is_rejected_never_silently_empty(raw: bytes) -> None:
    with pytest.raises(GitleaksReportError):
        parse_gitleaks_json(raw)


def test_non_dict_entries_are_skipped_not_fatal() -> None:
    data = b'["not a dict", {"RuleID": "x", "File": "a.py"}]'
    findings = parse_gitleaks_json(data)
    assert len(findings) == 1


def test_missing_optional_fields_degrade_safely() -> None:
    finding = parse_gitleaks_json(b'[{"RuleID": "x", "File": "a.py"}]')[0]
    assert finding.start_line == 0
    assert finding.end_line == 0
    assert finding.tags == []
    assert finding.commit == ""
    assert finding.fingerprint_key == "x|a.py|0"


def test_build_scan_argv_matches_the_confirmed_working_invocation(tmp_path: Path) -> None:
    argv = build_scan_argv("/usr/bin/gitleaks", tmp_path)
    assert argv == [
        "/usr/bin/gitleaks",
        "dir",
        str(tmp_path),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--exit-code",
        "0",
        "--no-banner",
        "--redact",
        "--log-level",
        "error",
        "--timeout",
        "300",
        "--max-target-megabytes",
        "50",
    ]


def test_build_scan_argv_always_includes_redact_and_exit_code_zero(tmp_path: Path) -> None:
    """These two flags must never be omittable by a caller -- see the module docstring."""
    argv = build_scan_argv("/usr/bin/gitleaks", tmp_path)
    assert "--redact" in argv
    redact_idx = argv.index("--exit-code")
    assert argv[redact_idx + 1] == "0"


def test_build_scan_argv_rejects_out_of_range_timeout(tmp_path: Path) -> None:
    with pytest.raises(GitleaksArgvError, match="timeout_seconds"):
        build_scan_argv("/usr/bin/gitleaks", tmp_path, timeout_seconds=0)
    with pytest.raises(GitleaksArgvError, match="timeout_seconds"):
        build_scan_argv("/usr/bin/gitleaks", tmp_path, timeout_seconds=99999)


def test_build_scan_argv_rejects_out_of_range_max_target_megabytes(tmp_path: Path) -> None:
    with pytest.raises(GitleaksArgvError, match="max_target_megabytes"):
        build_scan_argv("/usr/bin/gitleaks", tmp_path, max_target_megabytes=0)
    with pytest.raises(GitleaksArgvError, match="max_target_megabytes"):
        build_scan_argv("/usr/bin/gitleaks", tmp_path, max_target_megabytes=99999)
