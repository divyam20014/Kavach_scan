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
    LICENSE_ACTIONABLE_CATEGORIES,
    TrivyArgvError,
    TrivyReportError,
    build_download_checks_argv,
    build_scan_argv,
    parse_trivy_json,
    parse_trivy_license_json,
    parse_trivy_misconfig_json,
    parse_trivy_packages_json,
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


# ---------------------------------------------------------------- IaC/misconfiguration (TBD-111)

# Trimmed directly from a real local Trivy 0.76.1 run (`trivy fs <dir> --scanners misconfig
# ...` against a throwaway Dockerfile and Terraform file with known misconfigurations, run
# via the official `aquasec/trivy` Docker image pulled from Docker Hub -- GitHub's own
# binary-release CDN was blocked in this environment, see TBD-111), not hand-invented.
REAL_TRIVY_MISCONFIG_OUTPUT = b"""
{
  "SchemaVersion": 2,
  "Trivy": {"Version": "0.76.1"},
  "ArtifactName": "/work/iac",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": ".",
      "Class": "config",
      "Type": "terraform",
      "MisconfSummary": {"Successes": 69, "Failures": 0}
    },
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {"Successes": 23, "Failures": 2},
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS-0001",
          "Title": "':latest' tag used",
          "Description": "When using a 'FROM' statement you should use a specific tag.",
          "Message": "Specify a tag in the 'FROM' statement for image 'ubuntu'",
          "Resolution": "Add a tag to the image in the 'FROM' statement",
          "Severity": "MEDIUM",
          "References": ["https://avd.aquasec.com/misconfig/ds-0001"],
          "Status": "FAIL",
          "CauseMetadata": {"Provider": "Dockerfile", "Service": "general", "StartLine": 1, "EndLine": 1}
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS-0002",
          "Title": "Image user should not be 'root'",
          "Description": "Running containers with 'root' user can lead to a container escape.",
          "Message": "Last USER command in Dockerfile should not be 'root'",
          "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
          "Severity": "HIGH",
          "References": ["https://avd.aquasec.com/misconfig/ds-0002"],
          "Status": "FAIL",
          "CauseMetadata": {"Provider": "Dockerfile", "Service": "general", "StartLine": 2, "EndLine": 2}
        }
      ]
    },
    {
      "Target": "main.tf",
      "Class": "config",
      "Type": "terraform",
      "MisconfSummary": {"Successes": 0, "Failures": 1},
      "Misconfigurations": [
        {
          "Type": "Terraform Security Check",
          "ID": "AWS-0107",
          "Title": "Security groups should not allow unrestricted ingress to SSH or RDP.",
          "Description": "It is recommended that no security group allows unrestricted ingress.",
          "Message": "Security group rule allows unrestricted ingress from any IP address.",
          "Resolution": "Set a more restrictive CIDR range",
          "Severity": "HIGH",
          "References": ["https://avd.aquasec.com/misconfig/aws-0107"],
          "Status": "FAIL",
          "CauseMetadata": {
            "Resource": "aws_security_group.bad_sg",
            "Provider": "AWS",
            "Service": "ec2",
            "StartLine": 12,
            "EndLine": 12
          }
        }
      ]
    }
  ]
}
"""


def test_parse_trivy_misconfig_json_reads_only_misconfigurations_not_vulnerabilities() -> None:
    findings = parse_trivy_misconfig_json(REAL_TRIVY_MISCONFIG_OUTPUT)
    assert len(findings) == 3
    ids = {f.check_id for f in findings}
    assert ids == {"DS-0001", "DS-0002", "AWS-0107"}


def test_parse_trivy_misconfig_json_maps_severity_and_never_confirms() -> None:
    findings = parse_trivy_misconfig_json(REAL_TRIVY_MISCONFIG_OUTPUT)
    by_id = {f.check_id: f for f in findings}
    assert by_id["DS-0002"].severity == Severity.HIGH
    assert by_id["DS-0001"].severity == Severity.MEDIUM
    assert all(f.confidence == Confidence.PROBABLE for f in findings)  # never CONFIRMED


def test_parse_trivy_misconfig_json_captures_file_resource_and_lines() -> None:
    findings = parse_trivy_misconfig_json(REAL_TRIVY_MISCONFIG_OUTPUT)
    by_id = {f.check_id: f for f in findings}
    assert by_id["DS-0001"].target == "Dockerfile"
    assert by_id["DS-0001"].start_line == 1
    assert by_id["AWS-0107"].target == "main.tf"
    assert by_id["AWS-0107"].resource == "aws_security_group.bad_sg"
    assert by_id["AWS-0107"].start_line == 12


def test_parse_trivy_misconfig_json_fingerprint_differs_per_finding() -> None:
    findings = parse_trivy_misconfig_json(REAL_TRIVY_MISCONFIG_OUTPUT)
    keys = {f.fingerprint_key for f in findings}
    assert len(keys) == len(findings)  # no two distinct findings collide


def test_parse_trivy_json_ignores_misconfig_only_results() -> None:
    """The combined-report shape (TBD-111): a pure-`config`-class result with zero
    `Vulnerabilities` must contribute nothing to the vulnerability finding list."""
    assert parse_trivy_json(REAL_TRIVY_MISCONFIG_OUTPUT) == []


def test_build_scan_argv_with_misconfig_adds_skip_check_update(tmp_path: Path) -> None:
    argv = build_scan_argv(
        "/usr/bin/trivy",
        tmp_path / "repo",
        tmp_path / "report.json",
        tmp_path / "cache",
        scanners=("vuln", "misconfig"),
    )
    idx = argv.index("--scanners")
    assert argv[idx + 1] == "vuln,misconfig"
    assert "--skip-check-update" in argv


def test_build_scan_argv_vuln_only_has_no_skip_check_update(tmp_path: Path) -> None:
    argv = build_scan_argv(
        "/usr/bin/trivy", tmp_path / "repo", tmp_path / "report.json", tmp_path / "cache"
    )
    assert "--skip-check-update" not in argv


def test_build_download_checks_argv_matches_the_confirmed_working_shape(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    argv = build_download_checks_argv("/usr/bin/trivy", cache_dir)
    assert argv == [
        "/usr/bin/trivy",
        "fs",
        ".",
        "--scanners",
        "misconfig",
        "--cache-dir",
        str(cache_dir),
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
    ]


# ---------------------------------------------------------------- SBOM / license (TBD-112)

# Trimmed directly from a real local Trivy 0.76.1 run (`trivy fs <dir> --scanners
# vuln,license --license-full ...` against a throwaway npm/pip/LICENSE fixture, run via the
# official `aquasec/trivy` Docker image pulled from Docker Hub -- GitHub's own binary-
# release CDN was blocked in this environment, see TBD-112), not hand-invented. The pip
# result's missing `Licenses` key on its own package (no `site-packages` directory found)
# is the real, confirmed behavior, not an simplification for the test.
REAL_TRIVY_SBOM_LICENSE_OUTPUT = b"""
{
  "SchemaVersion": 2,
  "Trivy": {"Version": "0.76.1"},
  "ArtifactName": "/work/all",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "node/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Packages": [
        {
          "ID": "lodash@4.17.21",
          "Name": "lodash",
          "Identifier": {"PURL": "pkg:npm/lodash@4.17.21", "UID": "d8b5f60846330939"},
          "Version": "4.17.21",
          "Licenses": ["MIT"],
          "Relationship": "direct"
        }
      ]
    },
    {
      "Target": "requirements.txt",
      "Class": "lang-pkgs",
      "Type": "pip",
      "Packages": [
        {
          "Name": "Django",
          "Identifier": {"PURL": "pkg:pypi/django@4.2.0", "UID": "9c6b5407efd73222"},
          "Version": "4.2.0"
        }
      ]
    },
    {
      "Target": "Loose File License(s)",
      "Class": "license-file",
      "Licenses": [
        {
          "Severity": "LOW",
          "Category": "notice",
          "PkgName": "",
          "FilePath": "LICENSE",
          "Name": "MIT",
          "Text": "",
          "Confidence": 1,
          "Link": "https://spdx.org/licenses/MIT.html"
        },
        {
          "Severity": "HIGH",
          "Category": "restricted",
          "PkgName": "",
          "FilePath": "vendor/COPYING",
          "Name": "GPL-3.0",
          "Text": "",
          "Confidence": 0.95,
          "Link": "https://spdx.org/licenses/GPL-3.0-only.html"
        }
      ]
    }
  ]
}
"""


def test_parse_trivy_packages_json_reads_every_ecosystem_regardless_of_license_data() -> None:
    packages = parse_trivy_packages_json(REAL_TRIVY_SBOM_LICENSE_OUTPUT)
    assert len(packages) == 2
    by_name = {p.name: p for p in packages}
    assert by_name["lodash"].ecosystem == "npm"
    assert by_name["lodash"].licenses == ["MIT"]
    assert by_name["lodash"].purl == "pkg:npm/lodash@4.17.21"
    # pip, with no installed environment: no license data at all -- confirmed real behavior,
    # never a fabricated empty-list-means-"no license" claim beyond what Trivy itself says.
    assert by_name["Django"].ecosystem == "pip"
    assert by_name["Django"].licenses == []


def test_parse_trivy_license_json_reads_only_the_license_file_class() -> None:
    findings = parse_trivy_license_json(REAL_TRIVY_SBOM_LICENSE_OUTPUT)
    assert len(findings) == 2
    names = {f.name for f in findings}
    assert names == {"MIT", "GPL-3.0"}


def test_parse_trivy_license_json_never_reads_packages_licenses() -> None:
    """`Packages[].Licenses` (plain strings) must never be misread as a license-file
    classifier match (dicts) -- the two share a field name at different nesting levels."""
    only_packages = (
        b'{"Results": [{"Target": "x", "Packages": [{"Name": "p", "Licenses": ["MIT"]}]}]}'
    )
    assert parse_trivy_license_json(only_packages) == []


def test_license_finding_actionability_matches_the_real_classifier_taxonomy() -> None:
    findings = parse_trivy_license_json(REAL_TRIVY_SBOM_LICENSE_OUTPUT)
    by_name = {f.name: f for f in findings}
    assert by_name["MIT"].category == "notice"
    assert by_name["MIT"].is_actionable is False  # permissive-family -- inventory only
    assert by_name["GPL-3.0"].category == "restricted"
    assert by_name["GPL-3.0"].is_actionable is True
    assert by_name["GPL-3.0"].severity == Severity.MEDIUM
    assert set(LICENSE_ACTIONABLE_CATEGORIES) == {"forbidden", "restricted"}


def test_license_finding_confidence_level_is_never_confirmed() -> None:
    findings = parse_trivy_license_json(REAL_TRIVY_SBOM_LICENSE_OUTPUT)
    assert all(f.confidence_level == Confidence.PROBABLE for f in findings)


def test_build_scan_argv_with_license_adds_license_full(tmp_path: Path) -> None:
    argv = build_scan_argv(
        "/usr/bin/trivy",
        tmp_path / "repo",
        tmp_path / "report.json",
        tmp_path / "cache",
        scanners=("vuln", "license"),
    )
    idx = argv.index("--scanners")
    assert argv[idx + 1] == "vuln,license"
    assert "--license-full" in argv


def test_build_scan_argv_without_license_has_no_license_full(tmp_path: Path) -> None:
    argv = build_scan_argv(
        "/usr/bin/trivy", tmp_path / "repo", tmp_path / "report.json", tmp_path / "cache"
    )
    assert "--license-full" not in argv
