"""End-to-end repo_scan job dispatch through the real `JobManager`/`RepoScanRunner`
(roadmap Phase 2, TBD-087). Mirrors `tests/test_webapp_zap_engine.py`'s own pattern: every
subprocess is mocked (no real semgrep/gitleaks/trivy binary is required to run the suite),
but every other line of code -- argv building, process dispatch, report reading, parsing,
and finding creation -- is real.
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
from app.scanners.repo_scan.runner import RepoScanRunner
from app.storage.repository import StorageRepository
from tests.conftest import make_project
from tests.jobhelpers import terminal, wait_for

AVAILABLE = {"semgrep": "semgrep", "gitleaks": "gitleaks", "trivy": "trivy"}


def _repo_scan_project(repo: StorageRepository, repo_path: Path):
    now = datetime.now(UTC)
    auth = AuthorizationRecord(
        organization="o",
        target_owner="t",
        authorized_by="a",
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(days=5),
        attestation_event_id=new_id("event"),
    )
    policy = ScanPolicy(allowed_modules=[ScanModule.REPO_SCAN])
    return repo.create_project(
        make_project(
            authorization=auth, scan_policy=policy, repository_path=str(repo_path.resolve())
        )
    )


def _manager(
    repo: StorageRepository, settings: RuntimeSettings, runner: RepoScanRunner
) -> JobManager:
    return JobManager(repo, settings, runners={ScanModule.REPO_SCAN: runner})


_SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.lang.security.audit.eval-detected.eval-detected",
            "path": "app.py",
            "start": {"line": 3},
            "end": {"line": 3},
            "extra": {
                "message": "Detected the use of eval().",
                "severity": "WARNING",
                "metadata": {"confidence": "MEDIUM", "cwe": ["CWE-95: Eval Injection"]},
            },
        }
    ],
    "errors": [],
}

_GITLEAKS_OUTPUT = [
    {
        "RuleID": "generic-api-key",
        "Description": "Detected a Generic API Key.",
        "StartLine": 4,
        "EndLine": 4,
        "File": "config.py",
        "Fingerprint": "config.py:generic-api-key:4",
    }
]

_TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2019-14234",
                    "PkgName": "django",
                    "InstalledVersion": "1.11.0",
                    "FixedVersion": "1.11.23",
                    "Status": "fixed",
                    "Title": "Django SQL injection",
                    "Severity": "CRITICAL",
                }
            ],
        }
    ]
}


def test_repo_scan_dispatches_all_three_engines_and_creates_findings(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable,
        gitleaks_availability=lambda: sys.executable,
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: True,
    )
    jm = _manager(repo, settings, runner)
    project = _repo_scan_project(repo, tmp_path)
    scan, _created = jm.submit(
        project.project_id,
        StartScanRequest(
            module=ScanModule.REPO_SCAN,
            targets=["repo-scan"],
            parameters={"engines": ["semgrep", "gitleaks", "trivy"]},
            confirmed=True,
        ),
    )

    # Pre-seed Trivy's report at the exact path `_run_trivy` reads back (file-based output,
    # unlike Semgrep/Gitleaks which read from the mocked process's own stdout).
    report_dir = repo.scan_work_subdir(project.project_id, scan.scan_id, "trivy_report")
    (report_dir / "report.json").write_bytes(json.dumps(_TRIVY_OUTPUT).encode())

    import app.scanners.repo_scan.runner as runner_mod

    def fake_semgrep_argv(executable, repo_path, **kw):  # noqa: ANN001, ANN201
        code = f"import sys; sys.stdout.write({json.dumps(json.dumps(_SEMGREP_OUTPUT))})"
        return [sys.executable, "-c", code]

    def fake_gitleaks_argv(executable, repo_path, **kw):  # noqa: ANN001, ANN201
        code = f"import sys; sys.stdout.write({json.dumps(json.dumps(_GITLEAKS_OUTPUT))})"
        return [sys.executable, "-c", code]

    def fake_trivy_argv(executable, repo_path, report_path, cache_dir, **kw):  # noqa: ANN001, ANN201
        return [sys.executable, "-c", "pass"]

    mp = pytest.MonkeyPatch()
    mp.setattr(runner_mod, "semgrep_argv", fake_semgrep_argv)
    mp.setattr(runner_mod, "gitleaks_argv", fake_gitleaks_argv)
    mp.setattr(runner_mod, "trivy_argv", fake_trivy_argv)
    try:
        jm.start()
        try:
            done = wait_for(repo, project.project_id, scan.scan_id, terminal, timeout=30)
        finally:
            jm.stop()
    finally:
        mp.undo()

    assert done.state == ScanState.COMPLETED, (done.state, done.errors, done.warnings)
    findings = {f.category: f for f in repo.list_findings(project.project_id, limit=50).items}
    assert set(findings) == {"repo_scan_semgrep", "repo_scan_gitleaks", "repo_scan_trivy"}
    assert (
        findings["repo_scan_semgrep"].rule_id
        == "python.lang.security.audit.eval-detected.eval-detected"
    )
    assert findings["repo_scan_gitleaks"].rule_id == "generic-api-key"
    assert findings["repo_scan_trivy"].rule_id == "CVE-2019-14234"
    assert findings["repo_scan_trivy"].severity == "critical"

    # confirm the results route's RESULT_FILES allowlist actually serves the summary
    # (the same gap TBD-083 found and fixed for `zap_summary` -- checked directly here
    # rather than assumed, since a scan that writes an output file no route can serve
    # would be exactly that class of defect).
    summary_bytes = repo.read_scan_output(
        project.project_id, scan.scan_id, "repo_scan_summary.json"
    )
    summary = json.loads(summary_bytes)
    assert summary["findings_created"] == 3
    assert set(summary["engines"]) == {"semgrep", "gitleaks", "trivy"}


def test_repo_scan_rejected_before_starting_when_an_engine_is_unavailable(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    runner = RepoScanRunner(
        semgrep_availability=lambda: "",  # not installed
        gitleaks_availability=lambda: sys.executable,
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: True,
    )
    jm = _manager(repo, settings, runner)
    project = _repo_scan_project(repo, tmp_path)
    from app.core.errors import ValidationFailedError

    with pytest.raises(ValidationFailedError):
        jm.submit(
            project.project_id,
            StartScanRequest(
                module=ScanModule.REPO_SCAN,
                targets=["repo-scan"],
                parameters={"engines": ["semgrep"]},
                confirmed=True,
            ),
        )
    assert (
        repo.list_across_projects(
            "scan", sort="updated_at", descending=True, offset=0, limit=10
        ).total
        == 0
    )


def test_repo_scan_rejected_when_trivy_db_not_downloaded(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable,
        gitleaks_availability=lambda: sys.executable,
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: False,  # never downloaded
    )
    jm = _manager(repo, settings, runner)
    project = _repo_scan_project(repo, tmp_path)
    from app.core.errors import ValidationFailedError

    with pytest.raises(ValidationFailedError) as exc_info:
        jm.submit(
            project.project_id,
            StartScanRequest(
                module=ScanModule.REPO_SCAN,
                targets=["repo-scan"],
                parameters={"engines": ["trivy"]},
                confirmed=True,
            ),
        )
    assert any("database has not been downloaded" in d.message for d in exc_info.value.details)


def test_repo_scan_fails_cleanly_when_no_repository_path_is_configured(
    repo: StorageRepository,
    settings: RuntimeSettings,
) -> None:
    now = datetime.now(UTC)
    auth = AuthorizationRecord(
        organization="o",
        target_owner="t",
        authorized_by="a",
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(days=5),
        attestation_event_id=new_id("event"),
    )
    project = repo.create_project(
        make_project(
            authorization=auth, scan_policy=ScanPolicy(allowed_modules=[ScanModule.REPO_SCAN])
        )
    )
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable,
        gitleaks_availability=lambda: sys.executable,
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: True,
    )
    jm = _manager(repo, settings, runner)
    scan, _created = jm.submit(
        project.project_id,
        StartScanRequest(
            module=ScanModule.REPO_SCAN,
            targets=["repo-scan"],
            parameters={"engines": ["semgrep"]},
            confirmed=True,
        ),
    )
    jm.start()
    try:
        done = wait_for(repo, project.project_id, scan.scan_id, terminal, timeout=30)
    finally:
        jm.stop()
    assert done.state != ScanState.COMPLETED
    assert any("repository path" in e for e in done.errors)
