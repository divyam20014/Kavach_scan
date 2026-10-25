"""`engine=zap` on the existing `web_app` module (roadmap Phase 1 increment 3, TBD-081).

ZAP is an execution engine *within* the existing Web Application Security Scanner, not a
separate `ScanModule` -- see TBD-081 for the design decision this implements. Covers:
backward compatibility (old/omitted `engine`), engine selection, invalid engine values,
an unavailable ZAP runtime being rejected before a job starts, and a full job-dispatch
round trip (mocked process -- no real ZAP/JVM is launched by this test suite) producing
real canonical findings.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.errors import ValidationFailedError
from app.core.settings import RuntimeSettings
from app.integrations.zap import ZapAvailability, ZapInstallation
from app.jobs.manager import JobManager, StartScanRequest
from app.models.common import ScanModule, ScanState
from app.models.project import ScanPolicy
from app.scanners.webapp.profile import (
    DEFAULT_ENGINE,
    ENGINES,
    build_profile,
    validate_parameters,
)
from app.scanners.webapp.runner import WebAppRunner
from app.storage.repository import StorageRepository
from tests.jobhelpers import terminal, wait_for
from tests.webfixtures import lab_project, lab_servers

AVAILABLE = ZapAvailability(
    True,
    "",
    ZapInstallation(jar_path="/opt/zap/zap-2.17.0.jar", version="2.17.0", install_dir="/opt/zap"),
)
UNAVAILABLE = ZapAvailability(False, "ZAP is not installed or configured")


@pytest.fixture
def ports() -> Iterator[tuple[int, int]]:
    with lab_servers() as p:
        yield p


def _policy() -> ScanPolicy:
    return ScanPolicy()


# ---------------------------------------------------------------- backward compatibility


def test_engine_defaults_to_native_when_omitted() -> None:
    profile = build_profile({}, _policy())
    assert profile.engine == "native" == DEFAULT_ENGINE


def test_an_older_persisted_profile_with_no_engine_key_loads_as_native() -> None:
    """A `WebScanProfile` written to disk before this increment existed has no `engine` key
    at all in its JSON -- Pydantic must fill in the backward-compatible default, not fail
    to load."""
    from app.scanners.webapp.profile import WebScanProfile

    old_json = {
        "profile_version": 1,
        "catalog_version": "1.1.0",
        "safe_mode": True,
        "auth_profile": None,
        "respect_robots": True,
        "tls_verify": True,
        "seed_paths": [],
        "budgets": {
            "max_pages": 200,
            "max_depth": 3,
            "requests_per_second": 2.0,
            "max_concurrency": 2,
            "max_requests_per_target": 2000,
            "max_duration_seconds": 1800,
            "max_response_bytes": 2_000_000,
            "max_redirects": 5,
        },
        "checks": [],
        "limitations": [],
        # deliberately no "engine", "zap_spider_max_minutes" or "zap_wait_max_minutes" key
    }
    profile = WebScanProfile.model_validate(old_json)
    assert profile.engine == "native"
    assert profile.zap_spider_max_minutes == 2
    assert profile.zap_wait_max_minutes == 2


def test_existing_web_scan_requests_without_an_engine_parameter_are_unaffected() -> None:
    """Every parameter combination already accepted before this increment must still be
    accepted identically -- omitting `engine` must never change validation outcomes."""
    assert validate_parameters({"check_cors": False}, _policy()) == []
    assert validate_parameters({"max_pages": 10}, _policy()) == []


# ---------------------------------------------------------------- engine selection / validation


def test_engine_native_is_accepted_explicitly() -> None:
    assert validate_parameters({"engine": "native"}, _policy()) == []
    assert build_profile({"engine": "native"}, _policy()).engine == "native"


def test_engine_zap_is_accepted_and_selected() -> None:
    assert validate_parameters({"engine": "zap"}, _policy()) == []
    profile = build_profile({"engine": "zap"}, _policy())
    assert profile.engine == "zap"


@pytest.mark.parametrize("bad", ["ZAP", "nuclei", "", "native ", 123, True])
def test_invalid_engine_values_are_rejected(bad: object) -> None:
    problems = validate_parameters({"engine": bad}, _policy())
    assert problems, f"expected a validation error for engine={bad!r}"


def test_zap_duration_parameters_are_bounded() -> None:
    assert validate_parameters({"zap_spider_max_minutes": 0}, _policy())
    assert validate_parameters({"zap_spider_max_minutes": 61}, _policy())
    assert validate_parameters({"zap_wait_max_minutes": 0}, _policy())
    assert validate_parameters({"zap_spider_max_minutes": 5}, _policy()) == []


def test_engines_tuple_has_exactly_the_two_supported_values() -> None:
    assert ENGINES == ("native", "zap")


# ---------------------------------------------------------------- unavailable ZAP runtime


def test_engine_zap_rejected_at_validation_when_zap_is_unavailable() -> None:
    runner = WebAppRunner(zap_availability=lambda: UNAVAILABLE)
    problems = runner.validate_parameters({"engine": "zap"}, _policy())
    assert problems and "not available" in problems[0]
    assert "ZAP is not installed" in problems[0]


def test_engine_native_is_never_blocked_by_an_unavailable_zap_runtime() -> None:
    runner = WebAppRunner(zap_availability=lambda: UNAVAILABLE)
    assert runner.validate_parameters({}, _policy()) == []
    assert runner.validate_parameters({"engine": "native"}, _policy()) == []


def test_engine_zap_accepted_at_validation_when_zap_is_available() -> None:
    runner = WebAppRunner(zap_availability=lambda: AVAILABLE)
    assert runner.validate_parameters({"engine": "zap"}, _policy()) == []


# ---------------------------------------------------------------- job dispatch (mocked process)


def _manager(
    repo: StorageRepository, settings: RuntimeSettings, runner: WebAppRunner
) -> JobManager:
    from tests.webfixtures import MapResolver

    return JobManager(
        repo, settings, runners={ScanModule.WEB_APP: runner}, resolver_factory=MapResolver
    )


_SAMPLE_REPORT = {
    "site": [
        {
            "@name": "{origin}",
            "alerts": [
                {
                    "pluginid": "10038",
                    "alert": "Content Security Policy (CSP) Header Not Set",
                    "riskcode": "2",
                    "confidence": "3",
                    "desc": "<p>CSP is missing.</p>",
                    "solution": "<p>Set the header.</p>",
                    "reference": "",
                    "cweid": "693",
                    "instances": [{"uri": "{origin}/", "method": "GET", "param": ""}],
                }
            ],
        }
    ]
}


def test_engine_zap_dispatches_through_the_existing_job_system_and_creates_findings(
    repo: StorageRepository,
    settings: RuntimeSettings,
    ports: tuple[int, int],
    tmp_path: Path,
    client: TestClient,
) -> None:
    """End to end through the real `JobManager`/`WebAppRunner`, with the ZAP *process*
    mocked (no real JVM/ZAP is launched by the automated test suite -- see TBD-080/081):
    the report file is pre-seeded at the exact path the real code looks for, and the
    mocked argv is a no-op command that exits 0 immediately."""
    lab, _victim = ports
    target = f"http://lab.test:{lab}/"
    origin = f"http://lab.test:{lab}"

    runner = WebAppRunner(zap_availability=lambda: AVAILABLE)
    jm = _manager(repo, settings, runner)
    pid = repo.create_project(lab_project([lab])).project_id
    scan, _created = jm.submit(
        pid,
        StartScanRequest(
            module=ScanModule.WEB_APP,
            targets=[target],
            parameters={"engine": "zap"},
            confirmed=True,
        ),
    )

    # Pre-seed the report at the exact path `_run_zap` will read back, then make the
    # mocked ZAP "process" a true no-op (python -c pass): this proves the plan/argv/
    # report-reading/parsing/finding-writing wiring without needing a real JVM.
    report_dir = repo.scan_work_subdir(pid, scan.scan_id, "zap_report")
    report = json.loads(json.dumps(_SAMPLE_REPORT).replace("{origin}", origin))
    (report_dir / "zap-report.json").write_bytes(json.dumps(report).encode())

    import app.scanners.webapp.runner as runner_mod

    def fake_baseline_argv(java: str, jar_path: str, plan_path: Path, home_dir: Path) -> list[str]:
        return [java, "-c", "pass"]

    orig_find_executable = runner_mod.find_executable

    def fake_find_executable(names: list[str]) -> str | None:
        if names == ["java"]:
            return sys.executable
        return orig_find_executable(names)

    mp = pytest.MonkeyPatch()
    mp.setattr(runner_mod, "baseline_argv", fake_baseline_argv)
    mp.setattr(runner_mod, "find_executable", fake_find_executable)
    try:
        jm.start()
        try:
            done = wait_for(repo, pid, scan.scan_id, terminal, timeout=30)
        finally:
            jm.stop()
    finally:
        mp.undo()

    assert done.state == ScanState.COMPLETED, (done.state, done.errors, done.warnings)
    findings = repo.list_findings(pid, limit=50).items
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Content Security Policy (CSP) Header Not Set"
    assert finding.rule_id == "ZAP-10038"
    assert finding.sources[0].tool == "OWASP ZAP"
    assert finding.cwe_ids == [693]
    assert finding.severity.value == "medium"
    # a passive engine never reports CONFIRMED, even though ZAP's own confidence was "High"
    assert finding.confidence.value == "probable"

    summary = json.loads(repo.read_scan_output(pid, scan.scan_id, "zap_summary.json"))
    assert summary["engine"] == "zap"
    assert summary["alerts_found"] == 1
    assert summary["findings_created"] == 1

    # The frontend reads this through the generic results route, not a direct file read --
    # confirm the route's RESULT_FILES allowlist actually serves it (a scan detail page gap
    # found while auditing the UI: the native "summary" kind never exists for a ZAP scan).
    api_response = client.get(f"/api/projects/{pid}/scans/{scan.scan_id}/results/zap_summary")
    assert api_response.status_code == 200
    assert api_response.json()["engine"] == "zap"
    assert (
        client.get(f"/api/projects/{pid}/scans/{scan.scan_id}/results/summary").status_code == 404
    )


def test_native_web_scan_is_completely_unaffected_by_the_zap_engine_addition(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    """Regression guard: a plain native scan (no `engine` parameter at all) behaves exactly
    as it did before this increment -- same module dispatch, same runner, no ZAP code path
    is ever touched."""
    lab, _victim = ports
    runner = WebAppRunner(zap_availability=lambda: UNAVAILABLE)  # must never be consulted
    jm = _manager(repo, settings, runner)
    pid = repo.create_project(lab_project([lab])).project_id
    scan, _ = jm.submit(
        pid,
        StartScanRequest(
            module=ScanModule.WEB_APP,
            targets=[f"http://lab.test:{lab}/"],
            parameters={},
            confirmed=True,
        ),
    )
    jm.start()
    try:
        done = wait_for(repo, pid, scan.scan_id, terminal, timeout=90)
    finally:
        jm.stop()
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
    assert repo.list_findings(pid, limit=200).items  # the native scanner still runs normally


def test_submitting_zap_engine_with_an_unavailable_runtime_is_rejected_before_any_job_starts(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _victim = ports
    runner = WebAppRunner(zap_availability=lambda: UNAVAILABLE)
    jm = _manager(repo, settings, runner)
    pid = repo.create_project(lab_project([lab])).project_id
    with pytest.raises(ValidationFailedError):
        jm.submit(
            pid,
            StartScanRequest(
                module=ScanModule.WEB_APP,
                targets=[f"http://lab.test:{lab}/"],
                parameters={"engine": "zap"},
                confirmed=True,
            ),
        )
    assert repo.list_scans(pid).total == 0  # nothing was created
