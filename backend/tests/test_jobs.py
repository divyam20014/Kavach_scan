"""Phase 04: job state machine, manager, cancellation, recovery, budgets, kill switch, redaction."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from app.core.settings import RuntimeSettings
from app.jobs.context import JobContext, RunResult
from app.jobs.manager import JobRejectedError
from app.jobs.selftest import SelfTestRunner
from app.jobs.states import TERMINAL, TRANSITIONS, InvalidTransitionError, check_transition
from app.models.common import ScanModule, ScanState
from app.storage.repository import StorageRepository
from tests.jobhelpers import (
    Clock,
    LoopRunner,
    attested_project,
    manager,
    selftest_settings,
    start_req,
    terminal,
    wait_for,
)

S = ScanState


# ------------------------------------------------------------------ state machine


def test_every_state_has_a_transition_entry_and_terminals_are_final() -> None:
    assert set(TRANSITIONS) == set(ScanState)
    for state in TERMINAL:
        assert TRANSITIONS[state] == frozenset()


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (S.QUEUED, S.VALIDATING),
        (S.VALIDATING, S.RUNNING),
        (S.RUNNING, S.COMPLETED),
        (S.RUNNING, S.CANCELLED),
        (S.RUNNING, S.INTERRUPTED),
        (S.VALIDATING, S.BLOCKED_SCOPE),
        (S.QUEUED, S.CANCELLED),
        (S.RUNNING, S.EXPIRED_AUTHORIZATION),
        (S.RUNNING, S.COMPLETED_WITH_WARNINGS),
    ],
)
def test_valid_transitions(a: ScanState, b: ScanState) -> None:
    check_transition(a, b)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (S.QUEUED, S.RUNNING),
        (S.QUEUED, S.COMPLETED),
        (S.COMPLETED, S.RUNNING),
        (S.CANCELLED, S.QUEUED),
        (S.FAILED, S.RUNNING),
        (S.INTERRUPTED, S.RUNNING),
        (S.RUNNING, S.QUEUED),
        (S.RUNNING, S.VALIDATING),
        (S.VALIDATING, S.COMPLETED),
    ],
)
def test_invalid_transitions_rejected(a: ScanState, b: ScanState) -> None:
    with pytest.raises(InvalidTransitionError):
        check_transition(a, b)


# ------------------------------------------------------------------ end-to-end with the self-test runner


def test_selftest_job_runs_and_progress_persists(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, selftest_settings(settings))
    jm.start()
    try:
        scan, created = jm.submit(
            pid,
            start_req(
                targets=["https://app.example.com/", "https://api.example.com/x"],
                steps=3,
                step_seconds=0.05,
                warn_at_step=2,
            ),
        )
        assert created and scan.state == S.QUEUED and scan.correlation_id
        done = wait_for(repo, pid, scan.scan_id, terminal)
    finally:
        jm.stop()
    assert done.state == S.COMPLETED_WITH_WARNINGS
    assert done.progress.percent == 100.0 and done.progress.stage == "report"
    assert (
        done.progress.counters["steps_done"] == 3
        and done.progress.counters["simulated_requests"] == 6
    )
    assert done.output_refs == ["work/selftest-summary.json"]
    assert done.started_at and done.finished_at and done.finished_at >= done.started_at
    assert (
        done.scope_hash
        and done.policy_snapshot
        and done.authorized_targets == ["https://app.example.com/", "https://api.example.com/x"]
    )
    events, corrupt, _ = repo.scan_events(pid, scan.scan_id).read_newest(limit=200)
    types = [e["type"] for e in reversed(events)]
    assert corrupt == 0 and types[0] == "queued" and "stage" in types and types[-1] == "state"
    assert {e["correlation_id"] for e in events} == {scan.correlation_id}
    console = repo.scan_console(pid, scan.scan_id).tail(500)
    assert any("stage: simulate" in line for line in console) and any(
        "completed_with_warnings" in line for line in console
    )


def test_failure_requested_by_runner_marks_failed(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, selftest_settings(settings))
    jm.start()
    try:
        scan, _ = jm.submit(pid, start_req(steps=4, step_seconds=0.01, fail_at_step=2))
        done = wait_for(repo, pid, scan.scan_id, terminal)
    finally:
        jm.stop()
    assert done.state == S.FAILED and done.errors and done.progress.counters["steps_done"] == 2


# ------------------------------------------------------------------ duplicate start / claims / caps


def test_idempotency_key_prevents_duplicate_jobs(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, selftest_settings(settings))  # not started: nothing is dispatched
    req = start_req()
    req = req.model_copy(update={"idempotency_key": "tab-1-request-0001"})
    first, created1 = jm.submit(pid, req)
    second, created2 = jm.submit(pid, req)
    assert created1 and not created2 and first.scan_id == second.scan_id
    assert repo.list_scans(pid).total == 1 and len(repo.spool_entries()) == 1


def test_concurrent_claims_run_a_job_exactly_once(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    runner = LoopRunner(steps=3, pause=0.01)
    jm = manager(
        repo, selftest_settings(settings, max_active_jobs=4), {ScanModule.SELF_TEST: runner}
    )
    scan, _ = jm.submit(pid, start_req())
    results: list[bool] = []
    barrier = threading.Barrier(8)

    def claim() -> None:
        barrier.wait()
        results.append(jm._claim_and_start(pid, scan.scan_id))  # noqa: SLF001

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1
    done = wait_for(repo, pid, scan.scan_id, terminal)
    assert done.state == S.COMPLETED and runner.done_steps == 3


def test_queue_cap(repo: StorageRepository, settings: RuntimeSettings) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, selftest_settings(settings, max_queued_jobs=2))
    jm.submit(pid, start_req())
    jm.submit(pid, start_req())
    with pytest.raises(JobRejectedError) as info:
        jm.submit(pid, start_req())
    assert info.value.code == "queue_full" and repo.list_scans(pid).total == 2


def test_worker_concurrency_cap_is_respected(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    peak = {"value": 0}
    jm_ref: list = []

    def track(_ctx: JobContext, _i: int) -> None:
        peak["value"] = max(peak["value"], len(jm_ref[0].status().active_jobs))

    jm = manager(
        repo,
        selftest_settings(settings, max_active_jobs=2),
        {ScanModule.SELF_TEST: LoopRunner(steps=15, pause=0.02, on_step=track)},
    )
    jm_ref.append(jm)
    ids = [jm.submit(pid, start_req())[0].scan_id for _ in range(5)]
    jm.start()
    try:
        for sid in ids:
            wait_for(repo, pid, sid, terminal, timeout=60)
    finally:
        jm.stop()
    assert peak["value"] == 2


# ------------------------------------------------------------------ cancellation


def test_cancel_running_job_stops_new_work_and_keeps_partial_output(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    runner = LoopRunner(pause=0.02)
    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: runner})
    jm.start()
    try:
        scan, _ = jm.submit(pid, start_req())
        assert runner.started.wait(10)
        wait_for(repo, pid, scan.scan_id, lambda s: s.progress.counters.get("steps", 0) >= 3)
        jm.cancel(pid, scan.scan_id)
        done = wait_for(repo, pid, scan.scan_id, terminal)
        steps_at_stop = runner.done_steps
        time.sleep(0.3)
    finally:
        jm.stop()
    assert done.state == S.CANCELLED and done.cancel_requested
    assert runner.done_steps == steps_at_stop  # no new work after cancellation
    assert "work/partial.txt" in done.output_refs  # partial output preserved
    assert (
        (repo.scan_dir(pid, scan.scan_id) / "work" / "partial.txt")
        .read_bytes()
        .startswith(b"partial")
    )
    actions = [e.action for e in repo.audit.list(project_id=pid).items]
    assert "scan_cancelled" in actions and "scan_started" in actions


def test_cancel_queued_job_never_starts(repo: StorageRepository, settings: RuntimeSettings) -> None:
    pid = attested_project(repo).project_id
    runner = LoopRunner(steps=1)
    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: runner})
    scan, _ = jm.submit(pid, start_req())
    cancelled = jm.cancel(pid, scan.scan_id)
    assert cancelled.state == S.CANCELLED and repo.spool_entries() == []
    jm.start()
    time.sleep(0.5)
    jm.stop()
    assert runner.done_steps == 0 and not runner.started.is_set()
    with pytest.raises(Exception, match="already cancelled"):
        jm.cancel(pid, scan.scan_id)


# ------------------------------------------------------------------ restart recovery


def test_restart_marks_orphaned_jobs_interrupted_and_requeues_queued(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm1 = manager(repo, selftest_settings(settings))
    running, _ = jm1.submit(pid, start_req())
    queued, _ = jm1.submit(pid, start_req(steps=1, step_seconds=0))
    # Simulate a crash while `running` was in flight: state on disk says running, spool lost.
    repo.update_scan(
        pid, running.scan_id, {"state": "running", "started_at": datetime.now(UTC).isoformat()}
    )
    repo.spool_remove(running.scan_id)
    repo.spool_remove(queued.scan_id)
    repo.spool_add(pid, "scn_" + "f" * 32)  # orphan spool entry
    (repo.root / "jobs" / "claims" / f"{running.scan_id}.lock").write_text(
        "stale"
    )  # leftover lock file

    jm2 = manager(repo, selftest_settings(settings))
    report = jm2.start()
    try:
        assert report.interrupted == [running.scan_id]
        assert report.requeued == [queued.scan_id]
        assert report.spool_removed == ["scn_" + "f" * 32]
        interrupted = repo.get_scan(pid, running.scan_id)
        assert interrupted.state == S.INTERRUPTED and "NOT replayed" in interrupted.final_reason
        assert wait_for(repo, pid, queued.scan_id, terminal).state == S.COMPLETED
        assert repo.get_scan(pid, running.scan_id).state == S.INTERRUPTED  # never re-run
    finally:
        jm2.stop()
    # Recovery is deterministic: running it again changes nothing.
    assert manager(repo, selftest_settings(settings)).recover().model_dump() == {
        "requeued": [],
        "interrupted": [],
        "spool_removed": [],
    }


def test_shutdown_interrupts_running_job(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    runner = LoopRunner()
    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: runner})
    jm.start()
    scan, _ = jm.submit(pid, start_req())
    assert runner.started.wait(10)
    jm.stop()
    done = repo.get_scan(pid, scan.scan_id)
    assert done.state == S.INTERRUPTED


# ------------------------------------------------------------------ budgets, duration, authorization, scope


def test_request_budget_and_rate_limit(repo: StorageRepository, settings: RuntimeSettings) -> None:
    pid = attested_project(repo, requests_per_second=4.0, max_requests_per_target=6).project_id

    class Burst:
        name = "burst"
        elapsed = 0.0

        def run(self, ctx: JobContext) -> RunResult:
            start = time.monotonic()
            for _ in range(5):
                ctx.acquire_request("app.example.com")
            Burst.elapsed = time.monotonic() - start
            for _ in range(5):
                ctx.acquire_request("app.example.com")  # 7th request exceeds the budget of 6
            return RunResult()

    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: Burst()})
    jm.start()
    try:
        scan, _ = jm.submit(pid, start_req())
        done = wait_for(repo, pid, scan.scan_id, terminal)
    finally:
        jm.stop()
    # 4 tokens available at once, then 4/s: request #5 waits ~0.25s
    assert Burst.elapsed >= 0.2
    assert done.state == S.COMPLETED_WITH_WARNINGS
    assert any("request budget of 6" in w for w in done.warnings)


def test_max_duration_stops_job_with_warning(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    clock = Clock()
    pid = attested_project(repo, max_duration_seconds=60).project_id

    def advance(_ctx: JobContext, i: int) -> None:
        if i == 2:
            clock.offset = timedelta(seconds=61)

    jm = manager(
        repo,
        selftest_settings(settings),
        {ScanModule.SELF_TEST: LoopRunner(on_step=advance)},
        clock=clock,
    )
    jm.start()
    try:
        scan, _ = jm.submit(pid, start_req())
        done = wait_for(repo, pid, scan.scan_id, terminal)
    finally:
        jm.stop()
    assert done.state == S.COMPLETED_WITH_WARNINGS and any(
        "maximum duration" in w for w in done.warnings
    )


def test_authorization_expiring_while_queued_blocks_the_job(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    clock = Clock()
    project = attested_project(repo, end=datetime.now(UTC) + timedelta(hours=1))
    jm = manager(repo, selftest_settings(settings), clock=clock)
    scan, _ = jm.submit(project.project_id, start_req())
    clock.offset = timedelta(hours=2)
    jm.start()
    try:
        done = wait_for(repo, project.project_id, scan.scan_id, terminal)
    finally:
        jm.stop()
    assert done.state == S.EXPIRED_AUTHORIZATION


def test_authorization_expiring_mid_run(repo: StorageRepository, settings: RuntimeSettings) -> None:
    clock = Clock()
    project = attested_project(repo, end=datetime.now(UTC) + timedelta(hours=1))

    def expire(_ctx: JobContext, i: int) -> None:
        if i == 2:
            clock.offset = timedelta(hours=2)

    jm = manager(
        repo,
        selftest_settings(settings),
        {ScanModule.SELF_TEST: LoopRunner(on_step=expire)},
        clock=clock,
    )
    jm.start()
    try:
        scan, _ = jm.submit(project.project_id, start_req())
        done = wait_for(repo, project.project_id, scan.scan_id, terminal)
    finally:
        jm.stop()
    assert done.state == S.EXPIRED_AUTHORIZATION


def test_tampered_targets_are_blocked_at_validation(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    runner = LoopRunner(steps=1)
    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: runner})
    scan, _ = jm.submit(pid, start_req())
    repo.update_scan(pid, scan.scan_id, {"authorized_targets": ["https://evil.test/"]})
    jm.start()
    try:
        done = wait_for(repo, pid, scan.scan_id, terminal)
    finally:
        jm.stop()
    assert (
        done.state == S.BLOCKED_SCOPE
        and "evil.test" in done.final_reason
        and runner.done_steps == 0
    )


def test_runner_crash_fails_job_with_redacted_error(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id

    class Crash:
        name = "crash"

        def run(self, ctx: JobContext) -> RunResult:
            raise RuntimeError("boom with password=hunter2 and Bearer abcdefghijklmnop")

    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: Crash()})
    jm.start()
    try:
        scan, _ = jm.submit(pid, start_req())
        done = wait_for(repo, pid, scan.scan_id, terminal)
    finally:
        jm.stop()
    assert done.state == S.FAILED
    blob = done.model_dump_json() + (repo.scan_dir(pid, scan.scan_id) / "events.jsonl").read_text()
    assert (
        "hunter2" not in blob
        and "abcdefghijklmnop" not in blob
        and "RuntimeError" in done.final_reason
    )


def test_event_and_console_logs_are_redacted(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id

    class Leaky:
        name = "leaky"

        def run(self, ctx: JobContext) -> RunResult:
            ctx.emit(
                "note",
                "request headers: {'Authorization': 'Bearer tok_abcdefghijkl', 'Cookie': 'sid=s3cr3t'}",
                headers={"Authorization": "Bearer tok_abcdefghijkl", "Set-Cookie": "sid=s3cr3t"},
                url="https://app.example.com/?api_key=AKIAIOSFODNN7EXAMPLE",
            )
            ctx.warn("retrying with password=hunter2")
            return RunResult()

    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: Leaky()})
    jm.start()
    try:
        scan, _ = jm.submit(pid, start_req())
        wait_for(repo, pid, scan.scan_id, terminal)
    finally:
        jm.stop()
    d = repo.scan_dir(pid, scan.scan_id)
    text = (
        (d / "events.jsonl").read_text()
        + (d / "console.log").read_text()
        + (d / "scan.json").read_text()
    )
    for secret in ("tok_abcdefghijkl", "s3cr3t", "AKIAIOSFODNN7EXAMPLE", "hunter2"):
        assert secret not in text, secret


# ------------------------------------------------------------------ kill switch


def test_kill_switch_blocks_new_jobs_cancels_active_and_persists(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    runner = LoopRunner()
    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: runner})
    jm.start()
    try:
        running, _ = jm.submit(pid, start_req())
        assert runner.started.wait(10)
        queued, _ = jm.submit(pid, start_req())
        jm.set_kill_switch(True, "incident: stop everything")
        assert wait_for(repo, pid, running.scan_id, terminal).state == S.CANCELLED
        assert wait_for(repo, pid, queued.scan_id, terminal).state == S.CANCELLED
        with pytest.raises(JobRejectedError) as info:
            jm.submit(pid, start_req())
        assert info.value.code == "kill_switch_engaged"
    finally:
        jm.stop()
    # persisted across a restart
    jm2 = manager(repo, selftest_settings(settings))
    assert jm2.kill_switch_engaged()
    with pytest.raises(JobRejectedError):
        jm2.submit(pid, start_req())
    jm2.set_kill_switch(False, "incident resolved")
    jm2.submit(pid, start_req())
    actions = [e.action for e in repo.audit.list(action="kill_switch_changed").items]  # type: ignore[arg-type]
    assert len(actions) == 2


def test_unreadable_kill_switch_fails_safe(repo: StorageRepository) -> None:
    (repo.root / "control" / "kill_switch.json").write_text("{garbage")
    assert repo.get_kill_switch().engaged is True


# ------------------------------------------------------------------ submit validation


def test_submit_rejections_create_nothing(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    project = attested_project(repo)
    pid = project.project_id
    jm = manager(repo, selftest_settings(settings), runners={})
    with pytest.raises(JobRejectedError) as info:
        jm.submit(pid, start_req(module=ScanModule.SELF_TEST))
    assert info.value.code == "module_unavailable"
    jm = manager(repo, selftest_settings(settings))
    with pytest.raises(Exception, match="outside the project scope"):
        jm.submit(pid, start_req(targets=["https://app.example.com/", "https://evil.test/"]))
    repo.update_project(pid, {"authorization": None})
    with pytest.raises(JobRejectedError) as info:
        jm.submit(pid, start_req())
    assert info.value.code == "authorization_missing"
    assert repo.list_scans(pid).total == 0 and repo.spool_entries() == []


def test_selftest_unavailable_unless_enabled(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, settings, {ScanModule.SELF_TEST: SelfTestRunner()})  # flag off
    assert ScanModule.SELF_TEST not in {m.module for m in jm.availability()}
    with pytest.raises(JobRejectedError):
        jm.submit(pid, start_req())
    reasons = {m.module: m.reason for m in jm.availability()}
    assert "Phase 05" in reasons[ScanModule.WEB_APP]
