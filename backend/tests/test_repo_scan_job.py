"""End-to-end repo_scan job dispatch through the real `JobManager`/`RepoScanRunner`
(roadmap Phase 2, TBD-087). Mirrors `tests/test_webapp_zap_engine.py`'s own pattern: every
subprocess is mocked (no real semgrep/gitleaks/trivy binary is required to run the suite),
but every other line of code -- argv building, process dispatch, report reading, parsing,
and finding creation -- is real.
"""

from __future__ import annotations

import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.core.settings import RuntimeSettings
from app.jobs.manager import JobManager, StartScanRequest
from app.models.common import ScanModule, ScanState, new_id
from app.models.project import AuthorizationRecord, Project, ScanPolicy
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


# ---------------------------------------------------------------- IaC/misconfiguration (TBD-111)

_TRIVY_COMBINED_OUTPUT = {
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
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS-0002",
                    "Title": "Image user should not be 'root'",
                    "Message": "Last USER command in Dockerfile should not be 'root'",
                    "Description": "Running containers with 'root' user can lead to a container escape.",
                    "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
                    "Severity": "HIGH",
                    "CauseMetadata": {"StartLine": 2, "EndLine": 2},
                }
            ],
        },
    ]
}


def test_repo_scan_with_trivy_iac_creates_both_vuln_and_misconfig_findings(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    runner = RepoScanRunner(
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: True,
        trivy_checks_ready=lambda: True,
    )
    jm = _manager(repo, settings, runner)
    project = _repo_scan_project(repo, tmp_path)
    scan, _created = jm.submit(
        project.project_id,
        StartScanRequest(
            module=ScanModule.REPO_SCAN,
            targets=["repo-scan"],
            parameters={"engines": ["trivy"], "trivy_iac": True},
            confirmed=True,
        ),
    )
    report_dir = repo.scan_work_subdir(project.project_id, scan.scan_id, "trivy_report")
    (report_dir / "report.json").write_bytes(json.dumps(_TRIVY_COMBINED_OUTPUT).encode())

    import app.scanners.repo_scan.runner as runner_mod

    def fake_trivy_argv(executable, repo_path, report_path, cache_dir, **kw):  # noqa: ANN001, ANN201
        return [sys.executable, "-c", "pass"]

    mp = pytest.MonkeyPatch()
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
    assert set(findings) == {"repo_scan_trivy", "repo_scan_trivy_iac"}
    assert findings["repo_scan_trivy"].rule_id == "CVE-2019-14234"
    iac_finding = findings["repo_scan_trivy_iac"]
    assert iac_finding.rule_id == "DS-0002"
    assert iac_finding.severity == "high"
    assert iac_finding.cwe_ids == []  # Trivy gives no CWE mapping for misconfigurations
    summary = json.loads(
        repo.read_scan_output(project.project_id, scan.scan_id, "repo_scan_summary.json")
    )
    assert summary["engines"]["trivy"]["findings"] == 2


def test_repo_scan_rejected_when_trivy_iac_enabled_without_trivy_engine(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Path
) -> None:
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable,
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: True,
        trivy_checks_ready=lambda: True,
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
                parameters={"engines": ["semgrep"], "trivy_iac": True},
                confirmed=True,
            ),
        )
    assert any("trivy_iac requires" in d.message for d in exc_info.value.details)


def test_repo_scan_rejected_when_trivy_iac_checks_bundle_not_downloaded(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Path
) -> None:
    runner = RepoScanRunner(
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: True,
        trivy_checks_ready=lambda: False,  # never downloaded
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
                parameters={"engines": ["trivy"], "trivy_iac": True},
                confirmed=True,
            ),
        )
    assert any("checks bundle has not been downloaded" in d.message for d in exc_info.value.details)


# ---------------------------------------------------------------- SBOM / license (TBD-112)

_TRIVY_SBOM_LICENSE_OUTPUT = {
    "Results": [
        {
            "Target": "node/package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Packages": [
                {
                    "Name": "lodash",
                    "Identifier": {"PURL": "pkg:npm/lodash@4.17.21"},
                    "Version": "4.17.21",
                    "Licenses": ["MIT"],
                }
            ],
        },
        {
            "Target": "Loose File License(s)",
            "Class": "license-file",
            "Licenses": [
                {
                    "Category": "notice",
                    "PkgName": "",
                    "FilePath": "LICENSE",
                    "Name": "MIT",
                    "Confidence": 1,
                    "Link": "https://spdx.org/licenses/MIT.html",
                },
                {
                    "Category": "restricted",
                    "PkgName": "",
                    "FilePath": "vendor/COPYING",
                    "Name": "GPL-3.0",
                    "Confidence": 0.95,
                    "Link": "https://spdx.org/licenses/GPL-3.0-only.html",
                },
            ],
        },
    ]
}


def test_repo_scan_with_trivy_sbom_writes_inventory_and_only_the_restricted_license_finding(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    runner = RepoScanRunner(
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
            parameters={"engines": ["trivy"], "trivy_sbom": True},
            confirmed=True,
        ),
    )
    report_dir = repo.scan_work_subdir(project.project_id, scan.scan_id, "trivy_report")
    (report_dir / "report.json").write_bytes(json.dumps(_TRIVY_SBOM_LICENSE_OUTPUT).encode())

    import app.scanners.repo_scan.runner as runner_mod

    def fake_trivy_argv(executable, repo_path, report_path, cache_dir, **kw):  # noqa: ANN001, ANN201
        return [sys.executable, "-c", "pass"]

    mp = pytest.MonkeyPatch()
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

    # Only the "restricted" GPL-3.0 match becomes a Finding -- "notice"-category MIT never does.
    findings = {f.rule_id: f for f in repo.list_findings(project.project_id, limit=50).items}
    assert set(findings) == {"GPL-3.0"}
    assert findings["GPL-3.0"].category == "repo_scan_trivy_license"
    assert findings["GPL-3.0"].severity == "medium"

    sbom = json.loads(repo.read_scan_output(project.project_id, scan.scan_id, "sbom.json"))
    assert len(sbom["packages"]) == 1
    assert sbom["packages"][0]["name"] == "lodash"
    assert sbom["packages"][0]["licenses"] == ["MIT"]

    # Full license inventory -- both matches, including the non-actionable MIT one.
    licenses = json.loads(repo.read_scan_output(project.project_id, scan.scan_id, "licenses.json"))
    names = {entry["name"]: entry["actionable"] for entry in licenses["licenses"]}
    assert names == {"MIT": False, "GPL-3.0": True}


def test_repo_scan_without_trivy_sbom_writes_no_sbom_or_license_outputs(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    from app.storage.errors import RecordNotFoundError

    runner = RepoScanRunner(
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
            parameters={"engines": ["trivy"]},
            confirmed=True,
        ),
    )
    report_dir = repo.scan_work_subdir(project.project_id, scan.scan_id, "trivy_report")
    (report_dir / "report.json").write_bytes(json.dumps({"Results": []}).encode())

    import app.scanners.repo_scan.runner as runner_mod

    def fake_trivy_argv(executable, repo_path, report_path, cache_dir, **kw):  # noqa: ANN001, ANN201
        return [sys.executable, "-c", "pass"]

    mp = pytest.MonkeyPatch()
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
    with pytest.raises(RecordNotFoundError):
        repo.read_scan_output(project.project_id, scan.scan_id, "sbom.json")


def test_repo_scan_rejected_when_trivy_sbom_enabled_without_trivy_engine(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Path
) -> None:
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable,
        trivy_availability=lambda: sys.executable,
        trivy_db_ready=lambda: True,
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
                parameters={"engines": ["semgrep"], "trivy_sbom": True},
                confirmed=True,
            ),
        )
    assert any("trivy_sbom requires" in d.message for d in exc_info.value.details)


def test_semgreps_own_errors_list_is_surfaced_not_silently_dropped(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    """Roadmap Phase 2 increment 6 (TBD-089): Semgrep's own `errors` list (e.g. a file it
    could not parse) was parsed since TBD-084 but never wired into the summary or the
    scan's own warnings -- a partial scan must never look identical to a clean one."""
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
            parameters={"engines": ["semgrep"]},
            confirmed=True,
        ),
    )

    semgrep_output = {
        "results": [],
        "errors": ["Could not parse broken.py: syntax error at line 3"],
    }

    import app.scanners.repo_scan.runner as runner_mod

    def fake_semgrep_argv(executable, repo_path, **kw):  # noqa: ANN001, ANN201
        code = f"import sys; sys.stdout.write({json.dumps(json.dumps(semgrep_output))})"
        return [sys.executable, "-c", code]

    mp = pytest.MonkeyPatch()
    mp.setattr(runner_mod, "semgrep_argv", fake_semgrep_argv)
    try:
        jm.start()
        try:
            done = wait_for(repo, project.project_id, scan.scan_id, terminal, timeout=30)
        finally:
            jm.stop()
    finally:
        mp.undo()

    # A tool-reported error must never look identical to a cleanly completed scan -- the
    # job system's own warning-escalation rule already enforces this once `ctx.warn()` runs.
    assert done.state == ScanState.COMPLETED_WITH_WARNINGS, (done.state, done.errors, done.warnings)
    assert any("Could not parse broken.py" in w for w in done.warnings)
    summary_bytes = repo.read_scan_output(
        project.project_id, scan.scan_id, "repo_scan_summary.json"
    )
    summary = json.loads(summary_bytes)
    assert "Could not parse broken.py" in summary["engines"]["semgrep"]["errors"][0]


def test_repo_scan_dispatches_a_mix_of_native_and_docker_engines(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    """Roadmap Docker-based execution, phase 4 of 5 (TBD-093): per-engine Docker mode --
    Semgrep runs via Docker while Gitleaks runs natively in the same scan, confirming the
    operator-confirmed "per-engine, not global" design actually works end to end."""
    runner = RepoScanRunner(
        gitleaks_availability=lambda: sys.executable,
        docker_availability=lambda: sys.executable,
        docker_image_ready=lambda engine: True,
    )
    jm = _manager(repo, settings, runner)
    project = _repo_scan_project(repo, tmp_path)
    scan, _created = jm.submit(
        project.project_id,
        StartScanRequest(
            module=ScanModule.REPO_SCAN,
            targets=["repo-scan"],
            parameters={"engines": ["semgrep", "gitleaks"], "docker_engines": ["semgrep"]},
            confirmed=True,
        ),
    )

    import app.scanners.repo_scan.runner as runner_mod

    def fake_semgrep_docker_argv(executable, image, repo_path, **kw):  # noqa: ANN001, ANN201
        code = f"import sys; sys.stdout.write({json.dumps(json.dumps(_SEMGREP_OUTPUT))})"
        return [sys.executable, "-c", code]

    def fake_gitleaks_argv(executable, repo_path, **kw):  # noqa: ANN001, ANN201
        code = f"import sys; sys.stdout.write({json.dumps(json.dumps(_GITLEAKS_OUTPUT))})"
        return [sys.executable, "-c", code]

    mp = pytest.MonkeyPatch()
    mp.setattr(runner_mod, "build_semgrep_docker_argv", fake_semgrep_docker_argv)
    mp.setattr(runner_mod, "gitleaks_argv", fake_gitleaks_argv)
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
    assert set(findings) == {"repo_scan_semgrep", "repo_scan_gitleaks"}


def test_repo_scan_rejected_when_docker_engine_selected_but_docker_unavailable(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    runner = RepoScanRunner(docker_availability=lambda: "", docker_image_ready=lambda e: True)
    jm = _manager(repo, settings, runner)
    project = _repo_scan_project(repo, tmp_path)
    from app.core.errors import ValidationFailedError

    with pytest.raises(ValidationFailedError) as exc_info:
        jm.submit(
            project.project_id,
            StartScanRequest(
                module=ScanModule.REPO_SCAN,
                targets=["repo-scan"],
                parameters={"engines": ["semgrep"], "docker_engines": ["semgrep"]},
                confirmed=True,
            ),
        )
    assert any("docker is not available" in d.message for d in exc_info.value.details)


def test_repo_scan_rejected_when_docker_engine_selected_but_image_not_pulled(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Path,
) -> None:
    runner = RepoScanRunner(
        docker_availability=lambda: sys.executable, docker_image_ready=lambda e: False
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
                parameters={"engines": ["semgrep"], "docker_engines": ["semgrep"]},
                confirmed=True,
            ),
        )
    assert any("has not been pulled" in d.message for d in exc_info.value.details)


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


# ---------------------------------------------------------------------------------------
# Git-clone-from-URL roadmap, phase 5 of 6 (TBD-100): job-system wiring for
# `repository_url`. The SSRF-guard and unresolved-credential cases need no real git binary
# or network access (both fail before any clone is attempted); the successful-clone case
# needs a real `git` binary and real network access to GitHub's own tiny public demo repo
# (`octocat/Hello-World`, never a scan target -- the same repo phases 2/3 verified against).


def _repo_url_project(repo: StorageRepository, **overrides: object) -> Project:
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
        make_project(authorization=auth, scan_policy=policy, **overrides)  # type: ignore[arg-type]
    )


def test_repo_scan_fails_cleanly_when_the_repository_url_resolves_to_a_blocked_host(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    project = _repo_url_project(repo, repository_url="https://localhost/x/y.git")
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable, git_availability=lambda: sys.executable
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
    assert any("blocked" in e for e in done.errors)


def test_repo_scan_fails_cleanly_when_git_is_not_available(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    project = _repo_url_project(repo, repository_url="https://github.com/octocat/Hello-World.git")
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable, git_availability=lambda: ""
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
    assert any("git is not available" in e for e in done.errors)


def test_repo_scan_fails_cleanly_when_the_credential_alias_cannot_be_resolved(
    repo: StorageRepository, settings: RuntimeSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("KAVACH_TEST_PHASE5_MISSING_TOKEN", raising=False)
    project = _repo_url_project(
        repo,
        repository_url="https://github.com/octocat/Hello-World.git",
        repository_credential_alias="env:KAVACH_TEST_PHASE5_MISSING_TOKEN",
    )
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable, git_availability=lambda: sys.executable
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
    assert any("could not resolve credential alias" in e for e in done.errors)


@pytest.mark.skipif(shutil.which("git") is None, reason="git binary not available")
def test_repo_scan_clones_a_real_public_repository_and_scans_it(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    """The one real, network-touching test in this phase: proves the SSRF guard, the
    (absent-credential) env wiring, and `build_clone_argv` all work together against a
    real `git clone` of GitHub's own tiny public demo repo, with the result actually
    readable by the (mocked) next stage -- not merely that `git clone` exits 0 in
    isolation."""
    project = _repo_url_project(repo, repository_url="https://github.com/octocat/Hello-World.git")
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable, git_availability=lambda: shutil.which("git")
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

    import app.scanners.repo_scan.runner as runner_mod

    def fake_semgrep_argv(executable, repo_path, **kw):  # noqa: ANN001, ANN201
        code = 'import sys; sys.stdout.write(\'{"results": [], "errors": []}\')'
        return [sys.executable, "-c", code]

    mp = pytest.MonkeyPatch()
    mp.setattr(runner_mod, "semgrep_argv", fake_semgrep_argv)
    try:
        jm.start()
        try:
            done = wait_for(repo, project.project_id, scan.scan_id, terminal, timeout=60)
        finally:
            jm.stop()
    finally:
        mp.undo()

    assert done.state == ScanState.COMPLETED, (done.state, done.errors, done.warnings)
    cloned = repo.scan_work_subdir(project.project_id, scan.scan_id, "git_clone_repo")
    assert (cloned / "README").is_file() or (cloned / "README.md").is_file()


@pytest.mark.skipif(shutil.which("git") is None, reason="git binary not available")
def test_repo_scan_writes_the_askpass_helper_when_a_credential_alias_is_configured(
    repo: StorageRepository, settings: RuntimeSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The actual mechanics of Git invoking the askpass helper for a real authentication
    challenge were already proven for real in TBD-098 (phase 3); this test proves phase 5's
    own new risk surface -- that the production code path actually writes the helper (and,
    on Windows, its launcher) into the scan's own work directory with the expected content,
    through the storage layer, before the clone attempt -- rather than assuming the wiring
    that connects the two phases is correct."""
    monkeypatch.setenv("KAVACH_TEST_PHASE5_REAL_TOKEN", "does-not-need-to-be-a-real-secret")
    project = _repo_url_project(
        repo,
        repository_url="https://github.com/octocat/Hello-World.git",
        repository_credential_alias="env:KAVACH_TEST_PHASE5_REAL_TOKEN",
    )
    runner = RepoScanRunner(
        semgrep_availability=lambda: sys.executable, git_availability=lambda: shutil.which("git")
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

    import app.scanners.repo_scan.runner as runner_mod

    def fake_semgrep_argv(executable, repo_path, **kw):  # noqa: ANN001, ANN201
        code = 'import sys; sys.stdout.write(\'{"results": [], "errors": []}\')'
        return [sys.executable, "-c", code]

    mp = pytest.MonkeyPatch()
    mp.setattr(runner_mod, "semgrep_argv", fake_semgrep_argv)
    try:
        jm.start()
        try:
            done = wait_for(repo, project.project_id, scan.scan_id, terminal, timeout=60)
        finally:
            jm.stop()
    finally:
        mp.undo()

    assert done.state == ScanState.COMPLETED, (done.state, done.errors, done.warnings)
    work_dir = repo.scan_work_dir(project.project_id, scan.scan_id)
    helper = (work_dir / "git_askpass_helper.py").read_text("utf-8")
    assert "KAVACH_GIT_CREDENTIAL" in helper
    # the real secret is never written into the helper's own (fixed) source text
    assert "does-not-need-to-be-a-real-secret" not in helper
    if sys.platform.startswith("win"):
        launcher = (work_dir / "git_askpass_helper.cmd").read_text("utf-8")
        assert "git_askpass_helper.py" in launcher
        assert "does-not-need-to-be-a-real-secret" not in launcher
