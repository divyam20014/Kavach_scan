"""Shared job context handed to every scanner/runner (MASTER_SPEC Module 4).

Scanners never touch storage, the network or processes directly. They use:
- `checkpoint()`           cancellation / kill switch / deadline / authorization re-check
- `acquire_request(host)`  per-host token bucket + per-target request budget (interruptible)
- `slot()`                 per-job concurrency cap (BoundedSemaphore)
- `requester(transport)`   GuardedRequester with a budgeted transport (scope + budgets per hop)
- `run_process(...)`       subprocess adapter bound to the job's cancel event and work dir
- `stage/incr/warn/error`    progress, counters and messages, persisted (throttled) to scan.json
- `emit(...)`                structured JSONL event + concise console line, both redacted
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import Field

from app.core.redaction import redact, redact_text
from app.integrations.process import ProcessResult, run_process
from app.models.common import ShortText, StrictModel, UtcDatetime, new_id, utc_now
from app.models.project import Project, ScanPolicy
from app.models.scan import ScanJob
from app.scope import (
    AuthorizedTarget,
    GuardedRequester,
    RequestOptions,
    ScopeGuard,
    Transport,
    TransportResponse,
)
from app.scope.engine import Decision, Reason
from app.storage.repository import StorageRepository

log = logging.getLogger("app.jobs")
Level = Literal["debug", "info", "warning", "error"]

PROGRESS_FLUSH_SECONDS = 1.0
GUARD_REFRESH_SECONDS = 5.0


class JobStop(Exception):  # noqa: N818 - control-flow signal, not an error
    """Base for signals that end a run early. `state_hint` picks the terminal state."""

    state_hint = "cancelled"


class JobCancelled(JobStop):
    def __init__(self, why: str = "cancel requested") -> None:
        super().__init__(why)
        self.why = why


class JobInterrupted(JobStop):
    state_hint = "interrupted"


class AuthorizationLapsed(JobStop):
    state_hint = "expired_authorization"


class BudgetExhausted(JobStop):
    state_hint = "completed_with_warnings"


class DurationExceeded(JobStop):
    state_hint = "completed_with_warnings"


class JobEvent(StrictModel):
    schema_version: Literal[1] = 1
    event_id: str = Field(default_factory=lambda: new_id("event"))
    ts: UtcDatetime = Field(default_factory=utc_now)
    scan_id: str
    type: str
    level: Level = "info"
    stage: ShortText = ""
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None


@dataclass
class _Bucket:
    rate: float
    capacity: float
    tokens: float
    updated: float


@dataclass
class RunResult:
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    failed: bool = False


class _DecisionSink:
    def __init__(self, ctx: JobContext) -> None:
        self.ctx = ctx

    def record(self, decision: Decision) -> None:
        if decision.allowed:
            self.ctx.incr("scope_allowed")
            return
        self.ctx.incr("scope_blocked")
        self.ctx.emit(
            "scope_blocked",
            f"{decision.reason.value}: {decision.message}",
            level="warning",
            check=decision.check,
            input=decision.input,
            rule=decision.rule,
            decision_id=decision.decision_id,
        )


class _BudgetedTransport:
    def __init__(self, ctx: JobContext, inner: Transport) -> None:
        self.ctx = ctx
        self.inner = inner

    def send(
        self, method: str, authorized: AuthorizedTarget, options: RequestOptions | None = None
    ) -> TransportResponse:
        self.ctx.acquire_request(authorized.target.host)
        with self.ctx.slot():
            response = self.inner.send(method, authorized, options)
        self.ctx.incr("requests_sent")
        return response


class JobContext:
    def __init__(
        self,
        *,
        repo: StorageRepository,
        scan: ScanJob,
        project: Project,
        cancel_event: threading.Event,
        kill_switch: Callable[[], bool],
        resolver: Any,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.repo = repo
        self.scan = scan
        self.scan_id = scan.scan_id
        self.project_id = scan.project_id
        self.policy: ScanPolicy = scan.policy_snapshot or project.scan_policy
        self.cancel_event = cancel_event
        self.kill_switch = kill_switch
        self.resolver = resolver
        self.clock = clock
        self.stop_reason: str | None = None  # "shutdown" -> interrupted
        self.last_process: ProcessResult | None = None
        self.deadline = clock() + timedelta(seconds=self.policy.max_duration_seconds)
        self._lock = threading.RLock()
        self._counters: dict[str, int] = dict(scan.progress.counters)
        self._stage = scan.progress.stage
        self._percent = scan.progress.percent
        self._warnings: list[str] = list(scan.warnings)
        self._errors: list[str] = list(scan.errors)
        self._outputs: list[str] = list(scan.output_refs)
        self._last_flush = 0.0
        self._dirty = False
        self._per_target: dict[str, int] = defaultdict(int)
        self._buckets: dict[str, _Bucket] = {}
        self._slots = threading.BoundedSemaphore(self.policy.max_concurrency)
        self._events = repo.scan_events(self.project_id, self.scan_id)
        self._console = repo.scan_console(self.project_id, self.scan_id)
        self._project = project
        self._guard_built = 0.0
        self.guard = self._build_guard(project)

    # ------------------------------------------------------------------ guard

    def _build_guard(self, project: Project) -> ScopeGuard:
        snapshot = project.model_copy(update={"scope": self.scan.scope_snapshot or project.scope})
        self._guard_built = time.monotonic()
        return ScopeGuard(
            snapshot,
            resolver=self.resolver,
            sink=_DecisionSink(self),
            clock=self.clock,
            kill_switch=self.kill_switch,
        )

    def _refresh_guard(self) -> None:
        """Re-read the project so revoked authorization or archiving applies mid-run (TBD-046)."""
        try:
            project = self.repo.get_project(self.project_id)
        except Exception as exc:  # noqa: BLE001 - any failure to load the project stops the job safely
            raise JobCancelled("project is no longer available") from exc
        self._project = project
        self.guard = self._build_guard(project)

    # ------------------------------------------------------------------ control

    def checkpoint(self) -> None:
        if self.cancel_event.is_set():
            if self.stop_reason == "shutdown":
                raise JobInterrupted("application shutting down")
            raise JobCancelled(self.stop_reason or "cancel requested")
        if self.kill_switch():
            raise JobCancelled("global kill switch engaged")
        # Authorization is checked before the duration budget: a lapsed authorization is
        # the more serious condition and must be reported as such.
        if time.monotonic() - self._guard_built >= GUARD_REFRESH_SECONDS:
            self._refresh_guard()
        auth = self.guard.policy.authorization()
        if not auth.allowed:
            if auth.reason == Reason.AUTHORIZATION_EXPIRED:
                raise AuthorizationLapsed(auth.message)
            raise JobCancelled(f"{auth.reason.value}: {auth.message}")
        if self.clock() >= self.deadline:
            raise DurationExceeded(
                f"maximum duration of {self.policy.max_duration_seconds}s reached"
            )

    def sleep(self, seconds: float) -> None:
        """Interruptible sleep: returns early (and raises) on cancellation."""
        end = time.monotonic() + seconds
        while (remaining := end - time.monotonic()) > 0:
            if self.cancel_event.wait(min(remaining, 0.1)):
                break
            self.checkpoint()
        self.checkpoint()

    def acquire_request(self, host: str) -> None:
        """Account one request to `host`: request budget, then per-host token bucket."""
        self.checkpoint()
        with self._lock:
            self._per_target[host] += 1
            if self._per_target[host] > self.policy.max_requests_per_target:
                raise BudgetExhausted(
                    f"request budget of {self.policy.max_requests_per_target} for {host} exhausted"
                )
            rate = self.policy.requests_per_second
            bucket = self._buckets.setdefault(
                host, _Bucket(rate, max(1.0, rate), max(1.0, rate), time.monotonic())
            )
        while True:
            with self._lock:
                now = time.monotonic()
                bucket.tokens = min(
                    bucket.capacity, bucket.tokens + (now - bucket.updated) * bucket.rate
                )
                bucket.updated = now
                if bucket.tokens >= 1.0:
                    bucket.tokens -= 1.0
                    return
                wait = (1.0 - bucket.tokens) / bucket.rate
            if self.cancel_event.wait(min(wait, 0.25)):
                self.checkpoint()
            self.checkpoint()

    @contextmanager
    def slot(self) -> Iterator[None]:
        while not self._slots.acquire(timeout=0.25):
            self.checkpoint()
        try:
            yield
        finally:
            self._slots.release()

    def requester(
        self, transport: Transport, *, max_redirects: int | None = None
    ) -> GuardedRequester:
        redirects = self.policy.max_redirects if max_redirects is None else max_redirects
        return GuardedRequester(
            self.guard, _BudgetedTransport(self, transport), max_redirects=redirects
        )

    def run_process(
        self,
        argv: Sequence[str],
        *,
        allowed_executables: Sequence[str],
        timeout: float,
        max_output_bytes: int = 4 * 1024 * 1024,
        extra_env: dict[str, str] | None = None,
    ) -> ProcessResult:
        """`extra_env` is never logged (only `argv` is, in the `process_started` event below)
        -- this is the only way a caller may hand the subprocess a value (e.g. a resolved
        credential, see `app.scanners.repo_scan.git_credentials`) that must never appear in
        this job's own event stream."""
        self.checkpoint()
        remaining = max(1.0, (self.deadline - self.clock()).total_seconds())
        effective = min(timeout, remaining)
        self.emit(
            "process_started", f"running {argv[0]} (timeout {effective:.0f}s)", argv=list(argv)
        )
        result = run_process(
            argv,
            allowed_executables=allowed_executables,
            cwd=self.repo.scan_work_dir(self.project_id, self.scan_id),
            timeout=effective,
            cancelled=self.cancel_event.is_set,
            correlation_id=self.scan.correlation_id,
            max_output_bytes=max_output_bytes,
            temp_dir=self.repo.scan_temp_dir(self.project_id, self.scan_id),
            extra_env=extra_env,
        )
        level: Level = "info" if result.ok else "warning"
        self.emit(
            "process_finished",
            f"{argv[0]} exit={result.exit_code} timed_out={result.timed_out} "
            f"cancelled={result.cancelled} killed_tree={result.killed_tree}",
            level=level,
            duration=result.duration_seconds,
            stdout_truncated=result.stdout_truncated,
        )
        self.last_process = result
        if result.cancelled:
            self.checkpoint()  # raises the appropriate stop signal
        return result

    # ------------------------------------------------------------------ progress and messages

    def stage(self, name: str, percent: float | None = None) -> None:
        with self._lock:
            self._stage = name[:200]
            self._percent = percent
        self.emit("stage", f"stage: {name}")
        self.flush(force=True)

    def set_percent(self, percent: float | None) -> None:
        with self._lock:
            self._percent = None if percent is None else max(0.0, min(100.0, percent))
            self._dirty = True
        self.flush()

    def incr(self, counter: str, n: int = 1) -> None:
        with self._lock:
            self._counters[counter] = self._counters.get(counter, 0) + n
            self._dirty = True
        self.flush()

    def warn(self, message: str) -> None:
        text = redact_text(message, max_chars=480)
        with self._lock:
            if len(self._warnings) < 500:
                self._warnings.append(text)
        self.emit("warning", text, level="warning")
        self.flush(force=True)

    def error(self, message: str) -> None:
        text = redact_text(message, max_chars=480)
        with self._lock:
            if len(self._errors) < 500:
                self._errors.append(text)
        self.emit("error", text, level="error")
        self.flush(force=True)

    def write_output(self, name: str, data: bytes) -> str:
        ref = self.repo.write_scan_output(self.project_id, self.scan_id, name, data)
        with self._lock:
            if ref not in self._outputs:
                self._outputs.append(ref)
        self.emit("output", f"saved {ref} ({len(data)} bytes)")
        self.flush(force=True)
        return ref

    def emit(self, type_: str, message: str, *, level: Level = "info", **data: Any) -> None:
        event = JobEvent(
            scan_id=self.scan_id,
            type=type_,
            level=level,
            stage=self._stage,
            message=redact_text(message, max_chars=2000),
            data=redact(data),
            correlation_id=self.scan.correlation_id,
        )
        try:
            self._events.append(event.model_dump(mode="json"))
            self._console.append(
                f"{event.ts.isoformat()} {level.upper():7} [{self._stage or '-'}] {event.message}"
            )
        except Exception:  # noqa: BLE001 - logging must never crash a scan; state is persisted separately
            log.warning("could not write job event for %s", self.scan_id)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "progress": {
                    "stage": self._stage,
                    "percent": self._percent,
                    "counters": dict(self._counters),
                },
                "warnings": list(self._warnings),
                "errors": list(self._errors),
                "output_refs": list(self._outputs),
            }

    def flush(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (not self._dirty or now - self._last_flush < PROGRESS_FLUSH_SECONDS):
            return
        changes = self.snapshot()
        self._last_flush = now
        self._dirty = False
        self.repo.update_scan(self.project_id, self.scan_id, changes)
