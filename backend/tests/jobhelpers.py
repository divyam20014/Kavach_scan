"""Helpers shared by the Phase 04 job tests."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.settings import RuntimeSettings
from app.jobs.context import JobContext, RunResult
from app.jobs.manager import JobManager, Runner, StartScanRequest
from app.jobs.selftest import SelfTestRunner
from app.models import new_id
from app.models.common import ScanModule
from app.models.project import AuthorizationRecord, Project, ScanPolicy, ScopeDefinition
from app.models.scan import ScanJob
from app.storage.repository import StorageRepository
from tests.conftest import make_project


def attested_project(
    repo: StorageRepository, *, end: datetime | None = None, **policy: Any
) -> Project:
    now = datetime.now(UTC)
    auth = AuthorizationRecord(
        organization="o",
        target_owner="t",
        authorized_by="a",
        window_start=now - timedelta(days=1),
        window_end=end or now + timedelta(days=5),
        attestation_event_id=new_id("event"),
    )
    scope = ScopeDefinition(hosts=["app.example.com", "api.example.com"], path_prefixes=["/"])
    pol = ScanPolicy(allowed_modules=["web_app"], **policy)
    return repo.create_project(make_project(authorization=auth, scope=scope, scan_policy=pol))


def selftest_settings(settings: RuntimeSettings, **kw: Any) -> RuntimeSettings:
    return settings.model_copy(update={"enable_selftest_jobs": True, **kw})


class Clock:
    def __init__(self) -> None:
        self.offset = timedelta()

    def __call__(self) -> datetime:
        return datetime.now(UTC) + self.offset


class LoopRunner:
    """Runs until cancelled (or `steps` reached); records how many steps happened."""

    name = "loop"

    def __init__(
        self,
        steps: int = 10_000,
        pause: float = 0.02,
        on_step: Callable[[JobContext, int], None] | None = None,
    ):
        self.steps = steps
        self.pause = pause
        self.on_step = on_step
        self.started = threading.Event()
        self.done_steps = 0

    def run(self, ctx: JobContext) -> RunResult:
        ctx.stage("looping")
        ctx.write_output("partial.txt", b"partial output written before cancellation")
        self.started.set()
        for i in range(self.steps):
            ctx.checkpoint()
            if self.on_step:
                self.on_step(ctx, i)
            self.done_steps += 1
            ctx.incr("steps")
            ctx.sleep(self.pause)
        return RunResult()


def manager(
    repo: StorageRepository,
    settings: RuntimeSettings,
    runners: dict[ScanModule, Runner] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> JobManager:
    runners = runners if runners is not None else {ScanModule.SELF_TEST: SelfTestRunner()}
    kwargs: dict[str, Any] = {"runners": runners}
    if clock is not None:
        kwargs["clock"] = clock
    return JobManager(repo, settings, **kwargs)


def start_req(
    module: ScanModule = ScanModule.SELF_TEST, targets: list[str] | None = None, **params: Any
) -> StartScanRequest:
    return StartScanRequest(
        module=module,
        targets=targets or ["https://app.example.com/"],
        parameters=params,
        confirmed=True,
    )


def wait_for(
    repo: StorageRepository,
    pid: str,
    sid: str,
    predicate: Callable[[ScanJob], bool],
    timeout: float = 20.0,
) -> ScanJob:
    deadline = time.monotonic() + timeout
    scan = repo.get_scan(pid, sid)
    while time.monotonic() < deadline:
        scan = repo.get_scan(pid, sid)
        if predicate(scan):
            return scan
        time.sleep(0.05)
    raise AssertionError(
        f"timed out waiting; last state {scan.state.value}, progress {scan.progress}"
    )


def terminal(scan: ScanJob) -> bool:
    from app.jobs.states import is_terminal

    return is_terminal(scan.state)
