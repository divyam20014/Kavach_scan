"""Phase 04 verification: races, restart edge cases, child-process cleanup, log tailing bounds."""

from __future__ import annotations

import json
import sys
import threading
import time
import tracemalloc
from typing import Any

import pytest

from app.core.settings import RuntimeSettings
from app.integrations.process import ProcessResult
from app.jobs.context import JobContext, RunResult
from app.models.common import ScanModule, ScanState
from app.storage.repository import StorageRepository
from tests.jobhelpers import (
    LoopRunner,
    attested_project,
    manager,
    selftest_settings,
    start_req,
    terminal,
    wait_for,
)
from tests.test_process import SPAWN_GRANDCHILD, _wait_dead, pid_alive

S = ScanState


# ------------------------------------------------------------------ duplicate submission races


def test_concurrent_submits_with_same_idempotency_key_create_one_job(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, selftest_settings(settings))
    req = start_req().model_copy(update={"idempotency_key": "two-tabs-same-key-01"})
    barrier = threading.Barrier(10)
    results: list[tuple[str, bool]] = []

    def submit() -> None:
        barrier.wait()
        scan, created = jm.submit(pid, req)
        results.append((scan.scan_id, created))

    threads = [threading.Thread(target=submit) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len({sid for sid, _ in results}) == 1, results
    assert sum(created for _, created in results) == 1
    assert repo.list_scans(pid).total == 1 and len(repo.spool_entries()) == 1


# ------------------------------------------------------------------ cancel racing the claim


def test_cancel_during_claim_window_is_honoured(
    repo: StorageRepository, settings: RuntimeSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = attested_project(repo).project_id
    runner = LoopRunner(steps=200, pause=0.02)
    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: runner})
    scan, _ = jm.submit(pid, start_req())
    in_window = threading.Event()
    proceed = threading.Event()
    real_transition = jm._transition  # noqa: SLF001

    def slow_transition(
        project_id: str, scan_id: str, target: ScanState, extra: dict[str, Any]
    ) -> Any:
        result = real_transition(project_id, scan_id, target, extra)
        if target == S.VALIDATING:  # claimed + validating, but not yet registered as active
            in_window.set()
            proceed.wait(5)
        return result

    monkeypatch.setattr(jm, "_transition", slow_transition)
    worker = threading.Thread(target=jm._claim_and_start, args=(pid, scan.scan_id))  # noqa: SLF001
    worker.start()
    assert in_window.wait(5)
    canceller = threading.Thread(target=jm.cancel, args=(pid, scan.scan_id))
    canceller.start()
    time.sleep(0.3)  # cancel arrives while the job is between claim and registration
    proceed.set()
    worker.join(5)
    canceller.join(10)
    done = wait_for(repo, pid, scan.scan_id, terminal)
    assert done.state == S.CANCELLED, done.state
    assert runner.done_steps < 200


# ------------------------------------------------------------------ restart edge cases


def test_restart_during_validating_and_with_cancel_flag(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm1 = manager(repo, selftest_settings(settings))
    validating, _ = jm1.submit(pid, start_req())
    cancel_flagged, _ = jm1.submit(pid, start_req())
    repo.update_scan(pid, validating.scan_id, {"state": "validating"})
    repo.spool_remove(validating.scan_id)
    repo.update_scan(
        pid, cancel_flagged.scan_id, {"cancel_requested": True}
    )  # crash between flag and finish
    runner = LoopRunner(steps=1)
    jm2 = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: runner})
    report = jm2.start()
    try:
        assert report.interrupted == [validating.scan_id]
        assert wait_for(repo, pid, cancel_flagged.scan_id, terminal).state == S.CANCELLED
    finally:
        jm2.stop()
    assert runner.done_steps == 0  # the flagged job never ran


def test_corrupt_spool_entry_does_not_break_dispatch(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, selftest_settings(settings))
    scan, _ = jm.submit(pid, start_req(steps=1, step_seconds=0))
    (repo.root / "jobs" / "spool" / "scn_garbage.json").write_text("{not json")
    jm.start()
    try:
        assert wait_for(repo, pid, scan.scan_id, terminal).state == S.COMPLETED
    finally:
        jm.stop()


def test_corrupt_scan_record_does_not_stop_other_jobs(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, selftest_settings(settings))
    bad, _ = jm.submit(pid, start_req())
    good, _ = jm.submit(pid, start_req(steps=1, step_seconds=0))
    (repo.scan_dir(pid, bad.scan_id) / "scan.json").write_text("{truncated")
    jm.start()
    try:
        assert wait_for(repo, pid, good.scan_id, terminal).state == S.COMPLETED
    finally:
        jm.stop()
    assert all(e.scan_id != bad.scan_id for e in repo.spool_entries())


# ------------------------------------------------------------------ child process cleanup via the job system


class ProcRunner:
    name = "proc"

    def __init__(self) -> None:
        self.result: ProcessResult | None = None
        self.started = threading.Event()

    def run(self, ctx: JobContext) -> RunResult:
        self.started.set()
        try:
            ctx.run_process(
                [sys.executable, "-c", SPAWN_GRANDCHILD],
                allowed_executables=[sys.executable],
                timeout=120,
            )
        finally:
            self.result = ctx.last_process  # set even when run_process raises on cancellation
        return RunResult()


def _child_pids(runner: ProcRunner) -> list[int]:
    assert runner.result is not None
    return [int(x) for x in runner.result.stdout.split()]


@pytest.mark.parametrize("how", ["cancel", "kill_switch", "shutdown"])
def test_job_stop_kills_child_process_tree(
    repo: StorageRepository, settings: RuntimeSettings, how: str
) -> None:
    pid = attested_project(repo).project_id
    runner = ProcRunner()
    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: runner})
    jm.start()
    scan, _ = jm.submit(pid, start_req())
    assert runner.started.wait(10)
    time.sleep(1.5)  # let the child spawn its grandchild
    if how == "cancel":
        jm.cancel(pid, scan.scan_id)
    elif how == "kill_switch":
        jm.set_kill_switch(True, "verification")
    else:
        jm.stop()
    expected = {"cancel": S.CANCELLED, "kill_switch": S.CANCELLED, "shutdown": S.INTERRUPTED}[how]
    done = wait_for(repo, pid, scan.scan_id, terminal, timeout=30)
    if how != "shutdown":
        jm.stop()
    assert done.state == expected
    assert runner.result is not None and runner.result.cancelled and runner.result.killed_tree
    for child in _child_pids(runner):
        assert _wait_dead(child), f"child {child} survived ({how})"
    assert all(not pid_alive(c) for c in _child_pids(runner))


# ------------------------------------------------------------------ log tailing: bounded memory, no secrets


def test_console_tail_is_memory_bounded_on_huge_logs(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, selftest_settings(settings))
    scan, _ = jm.submit(pid, start_req())
    d = repo.scan_dir(pid, scan.scan_id)
    with open(d / "console.log", "ab") as fh:  # ~60 MB of lines plus one 5 MB line with no newline
        line = b"x" * 1000 + b"\n"
        for _ in range(60_000):
            fh.write(line)
        fh.write(b"y" * 5_000_000)
    tracemalloc.start()
    lines = repo.scan_console(pid, scan.scan_id).tail(200)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(lines) == 200 and peak < 20 * 1024 * 1024, peak


def test_event_page_is_byte_bounded(repo: StorageRepository, settings: RuntimeSettings) -> None:
    pid = attested_project(repo).project_id
    jm = manager(repo, selftest_settings(settings))
    scan, _ = jm.submit(pid, start_req())
    log = repo.scan_events(pid, scan.scan_id)
    big = {
        "type": "note",
        "scan_id": scan.scan_id,
        "message": "m" * 2000,
        "data": {"blob": "z" * 200_000},
    }
    for _ in range(80):  # ~16 MB of events
        log.append(big)
    items, _, more = log.read_newest(limit=500, max_bytes=4 * 1024 * 1024)
    assert more and 0 < len(items) < 80
    assert sum(len(json.dumps(i)) for i in items) <= 5 * 1024 * 1024


def test_tail_endpoints_redact_secrets_even_if_written_raw(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    from fastapi.testclient import TestClient

    from app.main import create_app
    from tests.conftest import LOCAL_BASE_URL, LOCAL_CLIENT

    pid = attested_project(repo).project_id
    repo.settings = selftest_settings(settings)
    jm = manager(repo, repo.settings)
    scan, _ = jm.submit(pid, start_req())
    d = repo.scan_dir(pid, scan.scan_id)
    # Simulate a log written by an older/buggy writer that bypassed redaction.
    with open(d / "console.log", "ab") as fh:
        fh.write(
            b"Authorization: Bearer abcdefghijklmnopqrst\ncalling https://u:hunter2@app.example.com/?token=tok_123456\n"
        )
    raw_event = {
        "schema_version": 1,
        "event_id": "evt_" + "1" * 32,
        "ts": "2026-11-01T00:00:00Z",
        "scan_id": scan.scan_id,
        "type": "note",
        "level": "info",
        "stage": "",
        "message": "Cookie: sid=s3cr3tcookie",
        "data": {"password": "plain-pass"},
        "correlation_id": None,
    }
    repo.scan_events(pid, scan.scan_id).append(raw_event)
    app = create_app(repo.settings, repository=repo, job_runners={})
    with TestClient(app, base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT) as c:
        console = c.get(f"/api/projects/{pid}/scans/{scan.scan_id}/console").text
        events = c.get(f"/api/projects/{pid}/scans/{scan.scan_id}/events").text
        too_many = c.get(f"/api/projects/{pid}/scans/{scan.scan_id}/events", params={"limit": 5000})
    for secret in ("abcdefghijklmnopqrst", "hunter2", "tok_123456", "s3cr3tcookie", "plain-pass"):
        assert secret not in console and secret not in events, secret
    assert too_many.status_code == 422


# ------------------------------------------------------------------ kill switch end to end


def test_kill_switch_stops_dispatch_of_jobs_queued_before_it(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = attested_project(repo).project_id
    runner = LoopRunner(steps=1)
    jm = manager(repo, selftest_settings(settings), {ScanModule.SELF_TEST: runner})
    queued = [jm.submit(pid, start_req())[0] for _ in range(3)]
    jm.set_kill_switch(True, "freeze")
    jm.start()
    time.sleep(1.0)
    jm.stop()
    assert runner.done_steps == 0
    assert {repo.get_scan(pid, q.scan_id).state for q in queued} == {S.CANCELLED}
