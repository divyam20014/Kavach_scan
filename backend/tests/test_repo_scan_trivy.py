"""Trivy adapter: argv construction/validation and JSON-report parsing (roadmap Phase 2
increment 3, TBD-086).

`REAL_TRIVY_OUTPUT` below is trimmed from the genuine JSON produced by a real local Trivy
0.76.1 run (`trivy fs <dir> --scanners vuln --format json --output <file> --cache-dir <dir>
--disable-telemetry`) against a throwaway `requirements.txt` pinning a deliberately old,
vulnerable Django version in this session -- not a hand-invented shape. Every field name
and value matches that real run exactly (see TBD-086); the full run returned 30
vulnerabilities, trimmed here to three representative severities.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models.common import Confidence, Severity
from app.scanners.repo_scan.trivy_adapter import (
    TrivyArgvError,
    TrivyReportError,
    build_scan_argv,
    parse_trivy_json,
)

REAL_TRIVY_OUTPUT = b"""
{
  "SchemaVersion": 2,
  "Trivy": {"Version": "0.76.1"},
  "ReportID": "01a175e5-4315-7e59-beff-9dc749c88ed5",
  "ArtifactName": "sample",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "requirements.txt",
      "Class": "lang-pkgs",
      "Type": "pip",
      "Packages": [
        {"Name": "django", "Version": "1.11.0"}
      ],
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2019-14234",
          "PkgName": "django",
          "InstalledVersion": "1.11.0",
          "FixedVersion": "1.11.23, 2.1.11, 2.2.4",
          "Status": "fixed",
          "Title": "Django: SQL injection possibility in key and index lookups for JSONField/HStoreField",
          "Severity": "CRITICAL",
          "CweIDs": ["CWE-89"],
          "References": [
            "https://github.com/django/django",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-14234"
          ],
          "Fingerprint": "sha256:398eee643b5b41387a6093cbd1fa9d4807e9a8abca7e0546facebc9fb590396e"
        },
        {
          "VulnerabilityID": "CVE-2021-33203",
          "PkgName": "django",
          "InstalledVersion": "1.11.0",
          "FixedVersion": "2.2.24, 3.1.12, 3.2.4",
          "Status": "fixed",
          "Title": "django: potential path traversal via django.contrib.admindocs",
          "Severity": "MEDIUM",
          "CweIDs": ["CWE-22"],
          "References": ["https://nvd.nist.gov/vuln/detail/CVE-2021-33203"]
        },
        {
          "VulnerabilityID": "CVE-2017-12794",
          "PkgName": "django",
          "InstalledVersion": "1.11.0",
          "FixedVersion": "1.10.8, 1.11.5",
          "Status": "fixed",
          "Title": "django: XSS possibility in traceback section of technical 500 debug page",
          "Severity": "LOW",
          "CweIDs": ["CWE-79"],
          "References": []
        }
      ]
    }
  ]
}
"""


def test_parses_the_real_captured_output_correctly() -> None:
    findings = parse_trivy_json(REAL_TRIVY_OUTPUT)
    assert len(findings) == 3
    critical, medium, low = findings

    assert critical.vulnerability_id == "CVE-2019-14234"
    assert critical.pkg_name == "django"
    assert critical.installed_version == "1.11.0"
    assert critical.fixed_version == "1.11.23, 2.1.11, 2.2.4"
    assert critical.target == "requirements.txt"
    assert critical.status == "fixed"
    assert "SQL injection" in critical.title
    assert critical.severity == Severity.CRITICAL
    assert critical.confidence == Confidence.PROBABLE
    assert critical.confidence != Confidence.CONFIRMED
    assert critical.cwe_ids == [89]
    assert "https://nvd.nist.gov/vuln/detail/CVE-2019-14234" in critical.references
    assert critical.fingerprint_key.startswith("sha256:")

    assert medium.severity == Severity.MEDIUM
    assert medium.cwe_ids == [22]
    # no "Fingerprint" field on this entry -- falls back to the locally-built shape
    assert medium.fingerprint_key == "CVE-2021-33203|django|requirements.txt"

    assert low.severity == Severity.LOW
    assert low.references == []


def test_unknown_severity_degrades_safely_not_crash() -> None:
    data = b'{"Results": [{"Target": "a", "Vulnerabilities": [{"VulnerabilityID": "x", "Severity": "WHO_KNOWS"}]}]}'
    finding = parse_trivy_json(data)[0]
    assert finding.severity == Severity.INFORMATIONAL


def test_results_null_is_a_clean_scan_not_an_error() -> None:
    """Trivy's own documented schema allows `Results` to be entirely absent or null for a
    filesystem with nothing to analyze -- this must never be confused with a malformed
    report."""
    assert parse_trivy_json(b'{"Results": null}') == []
    assert parse_trivy_json(b'{"SchemaVersion": 2}') == []


def test_a_result_with_no_vulnerabilities_key_contributes_no_findings() -> None:
    data = b'{"Results": [{"Target": "a", "Class": "lang-pkgs", "Packages": []}]}'
    assert parse_trivy_json(data) == []


@pytest.mark.parametrize(
    "raw",
    [
        b"not json at all",
        b"[]",
        b'{"Results": "not a list"}',
        b'"just a string"',
    ],
)
def test_malformed_output_is_rejected_never_silently_empty(raw: bytes) -> None:
    with pytest.raises(TrivyReportError):
        parse_trivy_json(raw)


def test_non_dict_results_entries_are_skipped_not_fatal() -> None:
    data = b'{"Results": ["not a dict", {"Target": "a", "Vulnerabilities": [{"VulnerabilityID": "x"}]}]}'
    assert len(parse_trivy_json(data)) == 1


def test_build_scan_argv_defaults_to_skip_db_update(tmp_path: Path) -> None:
    """The safest default: never trigger Trivy's own (potentially multi-gigabyte) automatic
    vulnerability-database download unless a caller explicitly opts in -- see the module
    docstring."""
    argv = build_scan_argv(
        "/usr/bin/trivy", tmp_path / "repo", tmp_path / "report.json", tmp_path / "cache"
    )
    assert "--skip-db-update" in argv


def test_build_scan_argv_allows_opting_into_the_db_update(tmp_path: Path) -> None:
    argv = build_scan_argv(
        "/usr/bin/trivy",
        tmp_path / "repo",
        tmp_path / "report.json",
        tmp_path / "cache",
        skip_db_update=False,
    )
    assert "--skip-db-update" not in argv


def test_build_scan_argv_always_restricts_scanners_to_vuln_only(tmp_path: Path) -> None:
    """Trivy's own default `--scanners` value is `vuln,secret`, which would overlap with
    the dedicated Gitleaks adapter -- this adapter always forces `vuln` only."""
    argv = build_scan_argv(
        "/usr/bin/trivy", tmp_path / "repo", tmp_path / "report.json", tmp_path / "cache"
    )
    idx = argv.index("--scanners")
    assert argv[idx + 1] == "vuln"


def test_build_scan_argv_matches_the_confirmed_working_shape(tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    report_path = tmp_path / "report.json"
    cache_dir = tmp_path / "cache"
    argv = build_scan_argv("/usr/bin/trivy", repo_path, report_path, cache_dir)
    assert argv == [
        "/usr/bin/trivy",
        "fs",
        str(repo_path),
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--output",
        str(report_path),
        "--cache-dir",
        str(cache_dir),
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
        "--timeout",
        "300s",
        "--skip-db-update",
    ]


def test_build_scan_argv_rejects_out_of_range_timeout(tmp_path: Path) -> None:
    with pytest.raises(TrivyArgvError, match="timeout_seconds"):
        build_scan_argv(
            "/usr/bin/trivy",
            tmp_path / "repo",
            tmp_path / "report.json",
            tmp_path / "cache",
            timeout_seconds=0,
        )
    with pytest.raises(TrivyArgvError, match="timeout_seconds"):
        build_scan_argv(
            "/usr/bin/trivy",
            tmp_path / "repo",
            tmp_path / "report.json",
            tmp_path / "cache",
            timeout_seconds=99999,
        )
