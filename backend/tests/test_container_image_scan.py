"""Container image vulnerability scanner (module `container_image`, security/reliability/
scope roadmap Phase 3, TBD-110). Mirrors `tests/test_repo_scan_job.py`'s own pattern: every
subprocess is mocked (no real trivy/docker binary is required to run the suite), but every
other line of code -- argv building, process dispatch, report reading, parsing, and finding
creation -- is real.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.core.settings import RuntimeSettings
from app.jobs.manager import JobManager, StartScanRequest
from app.models.common import ScanModule, ScanState, new_id
from app.models.project import AuthorizationRecord, ScanPolicy
from app.scanners.container_image.profile import IMAGE_REF_PATTERN, validate_parameters
from app.scanners.container_image.runner import ContainerImageRunner
from app.scanners.container_image.trivy_argv import TrivyArgvError, build_image_scan_argv
from app.storage.repository import StorageRepository
from tests.conftest import make_project
from tests.jobhelpers import terminal, wait_for

_TRIVY_OUTPUT = {
    "ArtifactName": "alpine:3.18",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.12)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-99999",
                    "PkgName": "busybox",
                    "InstalledVersion": "1.36.1-r7",
                    "FixedVersion": "1.36.1-r8",
                    "Status": "fixed",
                    "Title": "busybox: a made-up vulnerability for this test fixture",
                    "Severity": "CRITICAL",
                    "CweIDs": ["CWE-78"],
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2024-99999"],
                }
            ],
        }
    ],
}


def _project(repo: StorageRepository, **policy_overrides: object):
    now = datetime.now(UTC)
    auth = AuthorizationRecord(
        organization="o",
        target_owner="t",
        authorized_by="a",
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(days=5),
        attestation_event_id=new_id("event"),
    )
    policy = ScanPolicy(allowed_modules=[ScanModule.CONTAINER_IMAGE], **policy_overrides)
    return repo.create_project(make_project(authorization=auth, scan_policy=policy))


def _manager(
    repo: StorageRepository, settings: RuntimeSettings, runner: ContainerImageRunner
) -> JobManager:
    return JobManager(repo, settings, runners={ScanModule.CONTAINER_IMAGE: runner})


# ---------------------------------------------------------------------- parameter validation


def test_image_is_required() -> None:
    errors = validate_parameters({}, ScanPolicy())
    assert any("image is required" in e for e in errors)


@pytest.mark.parametrize(
    "image",
    [
        "alpine:3.18",
        "alpine",
        "library/alpine:3.18",
        "myregistry.local:5000/team/app:1.2.3",
        "app@sha256:" + "a" * 64,
        "ALPINE",  # uppercase repo components are rejected (Docker itself lowercases these)
        "alpine:3.18; rm -rf /",
        "../../etc/passwd",
        "alpine:" + "x" * 200,  # tag too long
    ],
)
def test_image_reference_validation_matches_the_pattern_directly(image: str) -> None:
    errors = validate_parameters({"image": image}, ScanPolicy())
    matched = bool(IMAGE_REF_PATTERN.match(image)) and len(image) <= 255
    assert (not errors) == matched, (image, errors)


def test_unknown_parameter_is_rejected() -> None:
    errors = validate_parameters({"image": "alpine:3.18", "bogus": True}, ScanPolicy())
    assert any("unknown parameter" in e for e in errors)


def test_timeout_minutes_out_of_range_is_rejected() -> None:
    errors = validate_parameters({"image": "alpine:3.18", "timeout_minutes": 999}, ScanPolicy())
    assert any("timeout_minutes" in e for e in errors)


# ---------------------------------------------------------------------- argv builder


def test_build_image_scan_argv_matches_the_confirmed_working_shape(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    cache_dir = tmp_path / "cache"
    argv = build_image_scan_argv("/usr/bin/trivy", "alpine:3.18", report_path, cache_dir)
    assert argv == [
        "/usr/bin/trivy",
        "image",
        "alpine:3.18",
        "--image-src",
        "docker",
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
        "--skip-db-update",
        "--timeout",
        "300s",
    ]


def test_build_image_scan_argv_always_restricts_to_the_local_docker_daemon(
    tmp_path: Path,
) -> None:
    argv = build_image_scan_argv(
        "/usr/bin/trivy", "alpine:3.18", tmp_path / "r.json", tmp_path / "cache"
    )
    i = argv.index("--image-src")
    assert argv[i + 1] == "docker"  # never containerd/podman/remote -- see module docstring


def test_build_image_scan_argv_rejects_out_of_range_timeout(tmp_path: Path) -> None:
    with pytest.raises(TrivyArgvError, match="timeout_seconds"):
        build_image_scan_argv(
            "/usr/bin/trivy",
            "alpine:3.18",
            tmp_path / "r.json",
            tmp_path / "cache",
            timeout_seconds=0,
        )


# ---------------------------------------------------------------------- end-to-end job


def test_container_image_scan_creates_findings_from_a_real_trivy_report(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    runner = ContainerImageRunner(
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: True,
    )
    jm = _manager(repo, settings, runner)
    project = _project(repo)
    scan, _created = jm.submit(
        project.project_id,
        StartScanRequest(
            module=ScanModule.CONTAINER_IMAGE,
            targets=["container-image-scan"],
            parameters={"image": "alpine:3.18"},
            confirmed=True,
        ),
    )
    # Pre-seed Trivy's report at the exact path the runner reads back (file-based output).
    report_dir = repo.scan_work_subdir(project.project_id, scan.scan_id, "trivy_report")
    (report_dir / "report.json").write_bytes(json.dumps(_TRIVY_OUTPUT).encode())

    import app.scanners.container_image.runner as runner_mod

    def fake_argv(executable, image, report_path, cache_dir, **kw):  # noqa: ANN001, ANN201
        return [sys.executable, "-c", "pass"]

    mp = pytest.MonkeyPatch()
    mp.setattr(runner_mod, "build_image_scan_argv", fake_argv)
    try:
        jm.start()
        try:
            done = wait_for(repo, project.project_id, scan.scan_id, terminal, timeout=30)
        finally:
            jm.stop()
    finally:
        mp.undo()

    assert done.state == ScanState.COMPLETED, (done.state, done.errors, done.warnings)
    findings = repo.list_findings(project.project_id, limit=50).items
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "container_image_trivy"
    assert finding.rule_id == "CVE-2024-99999"
    assert finding.severity == "critical"
    assert finding.component == "busybox@1.36.1-r7"
    assert "alpine:3.18" in finding.technical_detail
    summary = json.loads(
        repo.read_scan_output(project.project_id, scan.scan_id, "container_image_summary.json")
    )
    assert summary["image"] == "alpine:3.18" and summary["findings_created"] == 1


def test_container_image_scan_rejected_when_trivy_not_available(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    runner = ContainerImageRunner(trivy_availability=lambda: "", trivy_db_ready=lambda: True)
    jm = _manager(repo, settings, runner)
    project = _project(repo)
    from app.core.errors import ValidationFailedError

    with pytest.raises(ValidationFailedError):
        jm.submit(
            project.project_id,
            StartScanRequest(
                module=ScanModule.CONTAINER_IMAGE,
                targets=["container-image-scan"],
                parameters={"image": "alpine:3.18"},
                confirmed=True,
            ),
        )


def test_container_image_scan_rejected_when_trivy_db_not_downloaded(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    runner = ContainerImageRunner(
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: False,  # never downloaded
    )
    jm = _manager(repo, settings, runner)
    project = _project(repo)
    from app.core.errors import ValidationFailedError

    with pytest.raises(ValidationFailedError) as exc_info:
        jm.submit(
            project.project_id,
            StartScanRequest(
                module=ScanModule.CONTAINER_IMAGE,
                targets=["container-image-scan"],
                parameters={"image": "alpine:3.18"},
                confirmed=True,
            ),
        )
    assert any("database has not been downloaded" in d.message for d in exc_info.value.details)


def test_container_image_scan_fails_cleanly_when_trivy_exits_non_zero(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    runner = ContainerImageRunner(
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: True,
    )
    jm = _manager(repo, settings, runner)
    project = _project(repo)
    scan, _created = jm.submit(
        project.project_id,
        StartScanRequest(
            module=ScanModule.CONTAINER_IMAGE,
            targets=["container-image-scan"],
            # No pre-seeded report; the image genuinely doesn't exist locally in this test.
            parameters={"image": "this-image-does-not-exist-locally:999"},
            confirmed=True,
        ),
    )

    import app.scanners.container_image.runner as runner_mod

    def fake_argv(executable, image, report_path, cache_dir, **kw):  # noqa: ANN001, ANN201
        return [sys.executable, "-c", "import sys; sys.exit(1)"]

    mp = pytest.MonkeyPatch()
    mp.setattr(runner_mod, "build_image_scan_argv", fake_argv)
    try:
        jm.start()
        try:
            done = wait_for(repo, project.project_id, scan.scan_id, terminal, timeout=30)
        finally:
            jm.stop()
    finally:
        mp.undo()

    assert done.state == ScanState.FAILED
    assert repo.list_findings(project.project_id, limit=50).items == []
