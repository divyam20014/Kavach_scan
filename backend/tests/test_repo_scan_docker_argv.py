"""Docker-mode argv builders for the repo_scan engines (Docker-based execution roadmap,
phase 3 of 5, TBD-092). The exact argv shapes below were confirmed directly against real
`docker run` invocations on this machine using the images pulled in TBD-091 -- not assumed
from documentation. The parsers themselves (`parse_semgrep_json`/`parse_gitleaks_json`/
`parse_trivy_json`) are unchanged and already tested in `test_repo_scan_semgrep.py`/
`test_repo_scan_gitleaks.py`/`test_repo_scan_trivy.py`: Docker mode produces the identical
JSON schema, confirmed directly by running each real image and capturing its output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.scanners.repo_scan.docker_argv import (
    DockerArgvError,
    build_gitleaks_docker_argv,
    build_semgrep_docker_argv,
    build_trivy_db_download_docker_argv,
    build_trivy_docker_argv,
)
from app.scanners.repo_scan.gitleaks_adapter import parse_gitleaks_json
from app.scanners.repo_scan.semgrep_adapter import parse_semgrep_json
from app.scanners.repo_scan.trivy_adapter import parse_trivy_json


def test_build_semgrep_docker_argv_matches_the_confirmed_working_invocation(
    tmp_path: Path,
) -> None:
    """Confirmed directly: the official semgrep/semgrep image has no ENTRYPOINT (default
    CMD is `semgrep --help`), so the leading "semgrep" word is mandatory -- omitting it
    makes Docker try to exec "scan" as a program and fail."""
    argv = build_semgrep_docker_argv("docker", "semgrep/semgrep:1.182.1", tmp_path)
    assert argv == [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{tmp_path}:/src:ro",
        "semgrep/semgrep:1.182.1",
        "semgrep",
        "scan",
        "--config",
        "p/security-audit",
        "--json",
        "--metrics=off",
        "--timeout",
        "300",
        "--max-target-bytes",
        "5000000",
        "/src",
    ]


def test_build_semgrep_docker_argv_rejects_an_unlisted_config(tmp_path: Path) -> None:
    with pytest.raises(DockerArgvError, match="config must be one of"):
        build_semgrep_docker_argv(
            "docker", "semgrep/semgrep:1.182.1", tmp_path, config="file:///etc/passwd"
        )


def test_build_semgrep_docker_argv_rejects_out_of_range_timeout(tmp_path: Path) -> None:
    with pytest.raises(DockerArgvError, match="timeout_seconds"):
        build_semgrep_docker_argv("docker", "semgrep/semgrep:1.182.1", tmp_path, timeout_seconds=0)


def test_build_gitleaks_docker_argv_matches_the_confirmed_working_invocation(
    tmp_path: Path,
) -> None:
    """Confirmed directly: unlike Semgrep's image, Gitleaks' own image already defaults to
    running `gitleaks` itself -- no tool-name prefix is needed, and `--report-path -`
    genuinely writes JSON to stdout inside the container, same as natively."""
    argv = build_gitleaks_docker_argv("docker", "ghcr.io/gitleaks/gitleaks:v8.30.1", tmp_path)
    assert argv == [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{tmp_path}:/src:ro",
        "ghcr.io/gitleaks/gitleaks:v8.30.1",
        "dir",
        "/src",
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


def test_build_gitleaks_docker_argv_rejects_out_of_range_timeout(tmp_path: Path) -> None:
    with pytest.raises(DockerArgvError, match="timeout_seconds"):
        build_gitleaks_docker_argv(
            "docker", "ghcr.io/gitleaks/gitleaks:v8.30.1", tmp_path, timeout_seconds=99999
        )


def test_build_trivy_docker_argv_matches_the_confirmed_working_invocation(
    tmp_path: Path,
) -> None:
    """Confirmed directly: Trivy's own `--output -` produces no output at all inside a
    container (unlike Semgrep/Gitleaks) -- a writable report-directory mount and a real
    file path are used instead, and `--skip-db-update` is always present (never a
    parameter): the database only ever reaches the container via the read-only cache
    mount, confirmed directly to work even when that mount is `:ro`."""
    repo_path = tmp_path / "repo"
    cache_dir = tmp_path / "cache"
    report_dir = tmp_path / "report"
    argv = build_trivy_docker_argv(
        "docker", "aquasec/trivy:0.76.1", repo_path, cache_dir, report_dir
    )
    assert argv == [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{repo_path}:/src:ro",
        "-v",
        f"{cache_dir}:/cache:ro",
        "-v",
        f"{report_dir}:/report",
        "aquasec/trivy:0.76.1",
        "fs",
        "/src",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--output",
        "/report/report.json",
        "--cache-dir",
        "/cache",
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
        "--timeout",
        "300s",
        "--skip-db-update",
    ]
    assert "--skip-db-update" in argv  # always present, never a caller-supplied toggle


def test_build_trivy_docker_argv_with_misconfig_adds_skip_check_update(tmp_path: Path) -> None:
    """Security/reliability/scope roadmap Phase 4 (TBD-111): mirrors the native adapter's
    own `--skip-check-update` rule -- the checks bundle only ever reaches the container via
    the read-only cache mount, never a download the container triggers itself."""
    argv = build_trivy_docker_argv(
        "docker",
        "aquasec/trivy:0.76.1",
        tmp_path / "repo",
        tmp_path / "cache",
        tmp_path / "report",
        scanners=("vuln", "misconfig"),
    )
    idx = argv.index("--scanners")
    assert argv[idx + 1] == "vuln,misconfig"
    assert "--skip-check-update" in argv
    assert "--skip-db-update" in argv  # both skip flags present together


def test_build_trivy_docker_argv_with_license_adds_license_full(tmp_path: Path) -> None:
    """Security/reliability/scope roadmap Phase 5 (TBD-112): mirrors the native adapter's
    own `--license-full` rule."""
    argv = build_trivy_docker_argv(
        "docker",
        "aquasec/trivy:0.76.1",
        tmp_path / "repo",
        tmp_path / "cache",
        tmp_path / "report",
        scanners=("vuln", "license"),
    )
    idx = argv.index("--scanners")
    assert argv[idx + 1] == "vuln,license"
    assert "--license-full" in argv


def test_build_trivy_docker_argv_rejects_out_of_range_timeout(tmp_path: Path) -> None:
    with pytest.raises(DockerArgvError, match="timeout_seconds"):
        build_trivy_docker_argv(
            "docker",
            "aquasec/trivy:0.76.1",
            tmp_path / "repo",
            tmp_path / "cache",
            tmp_path / "report",
            timeout_seconds=0,
        )


# ---------------------------------------------------------------- real Docker-mode output
#
# Each sample below is trimmed from the genuine output of the exact pulled images (TBD-091)
# run for real against a throwaway sample repo on this machine (TBD-092) -- confirming the
# existing, already-tested native parsers need no changes for Docker mode, even though
# Docker-mode paths are container-absolute (e.g. "/src/app.py") rather than the native
# adapters' own repo-relative paths.


def test_semgrep_parser_accepts_real_docker_mode_output_with_container_absolute_paths() -> None:
    data = (
        b'{"version":"1.182.1","results":[{"check_id":"python.lang.security.audit.'
        b'subprocess-shell-true.subprocess-shell-true","path":"/src/app.py","start":'
        b'{"line":3},"end":{"line":3},"extra":{"message":"shell=True is dangerous",'
        b'"severity":"ERROR","metadata":{"confidence":"MEDIUM"}}}],"errors":[]}'
    )
    findings = parse_semgrep_json(data)
    assert len(findings) == 1
    assert findings[0].path == "/src/app.py"  # container-absolute, accepted as-is


def test_gitleaks_parser_accepts_real_docker_mode_output_with_container_absolute_paths() -> None:
    data = (
        b'[{"RuleID":"generic-api-key","Description":"Detected a Generic API Key.",'
        b'"StartLine":1,"EndLine":1,"File":"/src/config.py",'
        b'"Fingerprint":"/src/config.py:generic-api-key:1"}]'
    )
    findings = parse_gitleaks_json(data)
    assert len(findings) == 1
    assert findings[0].path == "/src/config.py"


def test_trivy_parser_accepts_real_docker_mode_output_with_a_relative_target() -> None:
    """Unlike Semgrep/Gitleaks, Trivy's own `Target` field in Docker mode is already
    repo-relative ("requirements.txt"), confirmed directly -- no container-path leakage."""
    data = (
        b'{"Results":[{"Target":"requirements.txt","Vulnerabilities":[{'
        b'"VulnerabilityID":"CVE-2019-14234","PkgName":"django","InstalledVersion":'
        b'"1.11.0","Severity":"CRITICAL"}]}]}'
    )
    findings = parse_trivy_json(data)
    assert len(findings) == 1
    assert findings[0].target == "requirements.txt"


def test_build_trivy_db_download_docker_argv_matches_the_confirmed_working_invocation(
    tmp_path: Path,
) -> None:
    """Operator-reported gap, fixed in TBD-095: an operator who only pulled Trivy's Docker
    image (no native install at all) had no way to trigger the vulnerability-database
    download, since the download route only ever looked for a native executable. Confirmed
    directly against a second real Docker invocation that this exact argv downloads the
    database into the mounted cache directory -- note the cache mount here is writable
    (unlike `build_trivy_docker_argv`'s own `:ro` scan-time mount), since this is the one
    operation that is actually supposed to write into it."""
    cache_dir = tmp_path / "cache"
    argv = build_trivy_db_download_docker_argv("docker", "aquasec/trivy:0.76.1", cache_dir)
    assert argv == [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{cache_dir}:/cache",
        "aquasec/trivy:0.76.1",
        "fs",
        ".",
        "--download-db-only",
        "--cache-dir",
        "/cache",
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
    ]
    assert ":ro" not in argv[4]  # writable, unlike the scan-time cache mount
