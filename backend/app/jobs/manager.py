"""Filesystem-backed job manager (MASTER_SPEC §2 "Scan job execution", Module 4).

Persistence (no broker, no database):
  projects/<pid>/scans/<sid>/scan.json   canonical job record (state, progress, snapshot...)
  projects/<pid>/scans/<sid>/events.jsonl + console.log   redacted event stream / human log
  jobs/spool/<sid>.json                  queue entry (FIFO by enqueued_at)
  jobs/claims/<sid>.lock                 claim lock held by the worker for the whole run
  control/kill_switch.json               persisted global kill switch

Concurrency: one dispatcher thread + at most `max_active_jobs` worker threads (hard cap 4);
queue length is capped by `max_queued_jobs`. A job runs only after its claim lock is
acquired AND its record is re-read in state `queued`, so it can never run twice.

Startup recovery (deterministic, see docs/STORAGE_FORMATS.md "Job recovery"):
  1. queued      -> stays queued; a missing spool entry is re-created (FIFO by queued_at)
  2. validating/running -> interrupted (partial results kept; NEVER replayed automatically)
  3. terminal    -> any leftover spool entry is removed
  4. spool entries with no matching queued job are removed
  5. leftover claim-lock files are harmless (OS locks die with their process)
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from pydantic import Field, model_validator

from app import __version__
from app.core.correlation import get_correlation_id
from app.core.errors import (
    AppError,
    ConflictError,
    ErrorDetail,
    ValidationFailedError,
)
from app.core.redaction import redact_text
from app.core.settings import RuntimeSettings
from app.integrations.dns import default_resolver_factory
from app.jobs.context import JobContext, JobStop, RunResult
from app.jobs.states import ACTIVE, InvalidTransitionError, check_transition, is_terminal
from app.models.audit import AuditAction
from app.models.common import Name, ScanModule, ScanState, StrictModel, new_id, utc_now
from app.models.scan import CounterName, ParamValue, ScanJob
from app.scope.canonical import normalize_target
from app.scope.engine import (
    AuthorizationError,
    ScopePolicy,
    require_active_authorization,
    scope_hash,
)
from app.scope.guard import ResolutionError
from app.storage.errors import StorageError
from app.storage.repository import StorageRepository

log = logging.getLogger("app.jobs")

S = ScanState
DISPATCH_INTERVAL = 0.25
WORKER_JOIN_SECONDS = 15.0


class Runner(Protocol):
    name: str

    def run(self, ctx: JobContext) -> RunResult: ...


class JobRejectedError(AppError):
    status_code = 409
    code = "job_rejected"

    def __init__(self, code: str, message: str, details: list[ErrorDetail] | None = None) -> None:
        super().__init__(message, details=details)
        self.code = code


class NoResolver:
    """Resolver that fails every lookup closed (tests and network-free modules)."""

    def resolve(self, host: str) -> list[str]:
        raise ResolutionError("DNS resolution is not available in this build")


class StartScanRequest(StrictModel):
    module: ScanModule
    targets: list[str] = Field(min_length=1, max_length=50)
    profile: Name = "default"
    parameters: dict[CounterName, ParamValue] = Field(default_factory=dict, max_length=20)
    idempotency_key: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{8,64}$")
    confirmed: bool = False

    @model_validator(mode="after")
    def _confirmed(self) -> StartScanRequest:
        if not self.confirmed:
            raise ValueError(
                "Explicit confirmation of targets, scope and limits is required to start a job"
            )
        return self


class ModuleAvailability(StrictModel):
    module: ScanModule
    label: str
    available: bool
    reason: str = ""


class ManagerStatus(StrictModel):
    running: bool
    active_jobs: list[str]
    queued_jobs: int
    max_active_jobs: int
    max_queued_jobs: int
    kill_switch_engaged: bool


class RecoveryReport(StrictModel):
    requeued: list[str] = Field(default_factory=list)
    interrupted: list[str] = Field(default_factory=list)
    spool_removed: list[str] = Field(default_factory=list)


MODULE_LABELS = {
    ScanModule.WEB_APP: "Web application scanner (Option A)",
    ScanModule.ATTACK_SURFACE: "Attack surface mapper (Option B)",
    ScanModule.API_SECURITY: "API security testing (Option C)",
    ScanModule.REPO_SCAN: "Repository scanner (Semgrep / Gitleaks / Trivy)",
    ScanModule.SELF_TEST: "Job system self-test (no network traffic)",
}
MODULE_PHASE = {
    ScanModule.WEB_APP: "05",
    ScanModule.ATTACK_SURFACE: "06",
    ScanModule.API_SECURITY: "07",
    ScanModule.REPO_SCAN: "roadmap-phase-2",
}


@dataclass
class _Active:
    scan: ScanJob
    cancel: threading.Event
    thread: threading.Thread | None = None
    ctx: JobContext | None = None
    stop_reason: str | None = None


@dataclass
class JobManager:
    repo: StorageRepository
    settings: RuntimeSettings
    runners: dict[ScanModule, Runner] = field(default_factory=dict)
    resolver_factory: Callable[[], Any] = default_resolver_factory
    clock: Callable[[], datetime] = utc_now

    def __post_init__(self) -> None:
        self._lock = threading.RLock()
        self._submit_lock = threading.Lock()  # makes idempotency check + create atomic
        self._wake = threading.Condition(self._lock)
        self._active: dict[str, _Active] = {}
        self._shutdown = threading.Event()
        self._dispatcher: threading.Thread | None = None
        self.max_active = min(self.settings.max_active_jobs, 4)
        self.last_recovery: RecoveryReport | None = None

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> RecoveryReport:
        report = self.recover()
        self._shutdown.clear()
        self._dispatcher = threading.Thread(
            target=self._dispatch_loop, name="vapt-job-dispatcher", daemon=True
        )
        self._dispatcher.start()
        return report

    def stop(self, timeout: float = WORKER_JOIN_SECONDS) -> None:
        """Stop dispatching and interrupt running jobs (they finish as `interrupted`)."""
        self._shutdown.set()
        with self._wake:
            for active in self._active.values():
                active.stop_reason = "shutdown"
                if active.ctx is not None:
                    active.ctx.stop_reason = "shutdown"
                active.cancel.set()
            self._wake.notify_all()
        threads = [a.thread for a in list(self._active.values()) if a.thread is not None]
        for thread in threads:
            thread.join(timeout)
        if self._dispatcher is not None:
            self._dispatcher.join(timeout)

    @property
    def running(self) -> bool:
        return (
            self._dispatcher is not None
            and self._dispatcher.is_alive()
            and not self._shutdown.is_set()
        )

    # ------------------------------------------------------------------ recovery

    def recover(self) -> RecoveryReport:
        report = RecoveryReport()
        queued_ids: set[str] = set()
        spooled = {e.scan_id for e in self.repo.spool_entries()}
        rows = sorted(
            self.repo.all_scan_summaries(), key=lambda r: str(r[2].get("queued_at") or "")
        )
        for pid, sid, entry in rows:
            state = str(entry.get("state"))
            if state == S.QUEUED.value:
                queued_ids.add(sid)
                if sid not in spooled:
                    self.repo.spool_add(pid, sid)
                    report.requeued.append(sid)
            elif state in (S.VALIDATING.value, S.RUNNING.value):
                claim = self.repo.claim_lock(sid)
                if not claim.try_acquire():
                    log.warning("job %s is claimed by a live worker; leaving it untouched", sid)
                    continue
                try:
                    self._finish(
                        pid,
                        sid,
                        S.INTERRUPTED,
                        "The application stopped while this job was active. Partial results "
                        "are kept; the job was NOT replayed automatically. Review and start "
                        "a new job if needed.",
                    )
                    report.interrupted.append(sid)
                finally:
                    claim.release()
        for spool in self.repo.spool_entries():
            if spool.scan_id not in queued_ids:
                self.repo.spool_remove(spool.scan_id)
                report.spool_removed.append(spool.scan_id)
        self.last_recovery = report
        if report.requeued or report.interrupted or report.spool_removed:
            log.info(
                "job recovery: requeued=%d interrupted=%d spool_removed=%d",
                len(report.requeued),
                len(report.interrupted),
                len(report.spool_removed),
            )
        return report

    # ------------------------------------------------------------------ availability and status

    def availability(self) -> list[ModuleAvailability]:
        out: list[ModuleAvailability] = []
        for module in ScanModule:
            if module == ScanModule.SELF_TEST and not self.settings.enable_selftest_jobs:
                continue
            runner = self.runners.get(module)
            if runner is not None:
                out.append(
                    ModuleAvailability(module=module, label=MODULE_LABELS[module], available=True)
                )
            else:
                out.append(
                    ModuleAvailability(
                        module=module,
                        label=MODULE_LABELS[module],
                        available=False,
                        reason="Scanner not implemented yet "
                        f"(Phase {MODULE_PHASE.get(module, '?')})",
                    )
                )
        return out

    def kill_switch_engaged(self) -> bool:
        return self.repo.get_kill_switch().engaged

    def status(self) -> ManagerStatus:
        with self._lock:
            active = sorted(self._active)
        return ManagerStatus(
            running=self.running,
            active_jobs=active,
            queued_jobs=len(self.repo.spool_entries()),
            max_active_jobs=self.max_active,
            max_queued_jobs=self.settings.max_queued_jobs,
            kill_switch_engaged=self.kill_switch_engaged(),
        )

    # ------------------------------------------------------------------ submit / cancel / retry

    def submit(
        self,
        project_id: str,
        req: StartScanRequest,
        *,
        actor: str = "local-operator",
        retry_of: str | None = None,
    ) -> tuple[ScanJob, bool]:
        """Validate and enqueue. Returns (scan, created). Nothing is created when a check fails.

        Serialized so two concurrent requests with the same idempotency key (two tabs, a
        double click) can never both pass the duplicate check. Single instance per data root.
        """
        with self._submit_lock:
            return self._submit_locked(project_id, req, actor=actor, retry_of=retry_of)

    def _submit_locked(
        self,
        project_id: str,
        req: StartScanRequest,
        *,
        actor: str,
        retry_of: str | None,
    ) -> tuple[ScanJob, bool]:
        project = self.repo.get_project(project_id)
        if req.idempotency_key:
            for sid, summary in self.repo.summaries("scan", project_id)[0].items():
                if summary.get("idempotency_key") == req.idempotency_key:
                    return self.repo.get_scan(project_id, sid), False
        if self.kill_switch_engaged():
            raise JobRejectedError(
                "kill_switch_engaged", "The global kill switch is engaged; no new jobs can start"
            )
        if self._shutdown.is_set():
            raise JobRejectedError("shutting_down", "The job manager is shutting down")
        runner = self.runners.get(req.module)
        if runner is None or (
            req.module == ScanModule.SELF_TEST and not self.settings.enable_selftest_jobs
        ):
            raise JobRejectedError(
                "module_unavailable", f"Module {req.module.value} is not available in this build"
            )
        try:
            require_active_authorization(project, self.clock())
        except AuthorizationError as exc:
            raise JobRejectedError(exc.decision.reason.value, exc.decision.message) from exc
        policy = ScopePolicy(project, clock=self.clock)
        if not policy.valid:
            raise JobRejectedError("scope_invalid", "; ".join(policy.errors)[:480])
        if (
            req.module.value not in {m.value for m in project.scan_policy.allowed_modules}
            and req.module != ScanModule.SELF_TEST
        ):
            raise JobRejectedError(
                "module_not_allowed", f"Module {req.module.value} is not allowed for this project"
            )
        validate = getattr(runner, "validate_parameters", None)
        if validate is not None:
            problems = validate(dict(req.parameters), project.scan_policy)
            if problems:
                raise ValidationFailedError(
                    "The scan parameters are invalid; nothing was started",
                    details=[
                        ErrorDetail(loc=["parameters"], message=p[:480], type="invalid_parameter")
                        for p in problems
                    ],
                )
        target_check = getattr(runner, "check_targets", None)
        if target_check is not None:
            # Modules whose targets are not URLs (e.g. root domains, hosts) validate them here.
            canonical_targets, problems = target_check(list(req.targets), policy)
            if problems:
                raise ValidationFailedError(
                    "One or more targets are outside the project scope; nothing was started",
                    details=[
                        ErrorDetail(loc=["targets", i], message=msg[:480], type="target_rejected")
                        for i, msg in problems
                    ],
                )
            decisions = []
        else:
            decisions = [policy.is_target_in_scope(t) for t in req.targets]
        blocked = [d for d in decisions if not d.allowed]
        if blocked:
            raise ValidationFailedError(
                "One or more targets are outside the project scope; nothing was started",
                details=[
                    ErrorDetail(
                        loc=["targets", i],
                        message=f"{d.reason.value}: {d.message}"[:480],
                        type=d.reason.value,
                    )
                    for i, d in enumerate(decisions)
                    if not d.allowed
                ],
            )
        if len(self.repo.spool_entries()) >= self.settings.max_queued_jobs:
            raise JobRejectedError(
                "queue_full", f"The job queue is full ({self.settings.max_queued_jobs} jobs)"
            )
        canonical = (
            canonical_targets
            if target_check is not None
            else list(dict.fromkeys(normalize_target(t).url for t in req.targets))
        )
        correlation = get_correlation_id() or new_id("event")[4:]
        scan = ScanJob(
            scan_id=new_id("scan"),
            project_id=project_id,
            module=req.module,
            profile=req.profile,
            targets=[t[:2048] for t in req.targets],
            authorized_targets=canonical,
            parameters={k: v for k, v in req.parameters.items() if isinstance(k, str)},
            state=S.QUEUED,
            queued_at=utc_now(),
            actor=actor,
            idempotency_key=req.idempotency_key,
            scope_snapshot=project.scope,
            scope_hash=scope_hash(project.scope),
            policy_snapshot=project.scan_policy,
            app_version=__version__,
            correlation_id=correlation,
            retry_of=retry_of,
        )
        created = self.repo.create_scan(scan)
        self.repo.audit.record(
            AuditAction.SCAN_STARTED,
            project_id=project_id,
            target_ids=[created.scan_id],
            metadata={
                "module": req.module.value,
                "targets": canonical,
                "confirmed": True,
                "scope_hash": created.scope_hash,
                "retry_of": retry_of,
                "parameters": dict(req.parameters),
            },
        )
        self.repo.spool_add(project_id, created.scan_id)
        self._event(
            created, "queued", f"job queued ({req.module.value}, {len(canonical)} target(s))"
        )
        with self._wake:
            self._wake.notify_all()
        return created, True

    def cancel(
        self,
        project_id: str,
        scan_id: str,
        *,
        actor: str = "local-operator",
        why: str = "cancel requested",
    ) -> ScanJob:
        scan = self.repo.get_scan(project_id, scan_id)
        if is_terminal(scan.state):
            raise ConflictError(f"Job is already {scan.state.value}")
        self.repo.update_scan(project_id, scan_id, {"cancel_requested": True})
        with self._wake:
            active = self._active.get(scan_id)
            if active is not None:
                active.stop_reason = why
                if active.ctx is not None:
                    active.ctx.stop_reason = why
                active.cancel.set()
        if active is None:
            # Not claimed by a worker: cancel it while holding the claim so no worker can start it.
            claim = self.repo.claim_lock(scan_id)
            if not claim.try_acquire():
                # A worker is claiming it right now: signal it as soon as it registers.
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    with self._wake:
                        active = self._active.get(scan_id)
                        if active is not None:
                            active.stop_reason = why
                            active.cancel.set()
                            break
                    time.sleep(0.02)
            elif claim.held:
                try:
                    current = self.repo.get_scan(project_id, scan_id)
                    if current.state == S.QUEUED:
                        self.repo.spool_remove(scan_id)
                        self._finish(
                            project_id, scan_id, S.CANCELLED, f"Cancelled before start ({why})"
                        )
                finally:
                    claim.release()
        self.repo.audit.record(
            AuditAction.SCAN_CANCELLED,
            project_id=project_id,
            target_ids=[scan_id],
            metadata={"reason": why},
            actor=actor,
        )
        self._event(scan, "cancel_requested", f"cancellation requested: {why}", level="warning")
        return self.repo.get_scan(project_id, scan_id)

    def retry(
        self, project_id: str, scan_id: str, *, idempotency_key: str | None = None
    ) -> ScanJob:
        """Start a NEW job with the same module/targets/parameters (never resumes the old one)."""
        old = self.repo.get_scan(project_id, scan_id)
        if old.state not in (
            S.FAILED,
            S.INTERRUPTED,
            S.CANCELLED,
            S.EXPIRED_AUTHORIZATION,
            S.BLOCKED_SCOPE,
            S.COMPLETED_WITH_WARNINGS,
        ):
            raise ConflictError(
                "Only finished jobs that did not complete cleanly can be retried "
                f"(state {old.state.value})"
            )
        req = StartScanRequest(
            module=old.module,
            targets=old.targets,
            profile=old.profile,
            parameters=dict(old.parameters),
            idempotency_key=idempotency_key,
            confirmed=True,
        )
        scan, _ = self.submit(project_id, req, retry_of=scan_id)
        return scan

    def set_kill_switch(self, engaged: bool, reason: str, actor: str = "local-operator") -> Any:
        state = self.repo.set_kill_switch(engaged, reason, actor)
        self.repo.audit.record(
            AuditAction.KILL_SWITCH_CHANGED,
            metadata={"engaged": engaged, "reason": reason},
            actor=actor,
        )
        if engaged:
            for pid, sid, entry in self.repo.all_scan_summaries():
                if str(entry.get("state")) in (S.QUEUED.value, S.VALIDATING.value, S.RUNNING.value):
                    try:
                        self.cancel(pid, sid, actor=actor, why="global kill switch engaged")
                    except (ConflictError, StorageError):
                        continue
        with self._wake:
            self._wake.notify_all()
        return state

    # ------------------------------------------------------------------ dispatch

    def _dispatch_loop(self) -> None:
        while not self._shutdown.is_set():
            try:
                self._dispatch_once()
            except Exception:  # noqa: BLE001 - the dispatcher must survive transient storage errors
                log.exception("dispatcher iteration failed")
            with self._wake:
                self._wake.wait(DISPATCH_INTERVAL)

    def _dispatch_once(self) -> None:
        if self.kill_switch_engaged():
            return
        for entry in self.repo.spool_entries():
            with self._lock:
                if len(self._active) >= self.max_active or self._shutdown.is_set():
                    return
                if entry.scan_id in self._active:
                    continue
            self._claim_and_start(entry.project_id, entry.scan_id)

    def _claim_and_start(self, project_id: str, scan_id: str) -> bool:
        claim = self.repo.claim_lock(scan_id)
        if not claim.try_acquire():
            return False  # another worker owns it
        try:
            scan = self.repo.get_scan(project_id, scan_id)
        except StorageError:
            claim.release()
            self.repo.spool_remove(scan_id)
            return False
        if scan.state != S.QUEUED or scan.cancel_requested:
            if scan.state == S.QUEUED and scan.cancel_requested:
                self._finish(project_id, scan_id, S.CANCELLED, "Cancelled before start")
            self.repo.spool_remove(scan_id)
            claim.release()
            return False
        scan = self._transition(project_id, scan_id, S.VALIDATING, {"started_at": utc_now()})
        self.repo.spool_remove(scan_id)
        active = _Active(scan=scan, cancel=threading.Event())
        thread = threading.Thread(
            target=self._run, args=(active, claim), name=f"vapt-job-{scan_id[-8:]}", daemon=True
        )
        active.thread = thread
        with self._lock:
            self._active[scan_id] = active
        thread.start()
        return True

    # ------------------------------------------------------------------ worker

    def _run(self, active: _Active, claim: Any) -> None:
        scan = active.scan
        pid, sid = scan.project_id, scan.scan_id
        final_state, reason = S.FAILED, "internal error"
        ctx: JobContext | None = None
        try:
            # A cancel may have been persisted between our claim and our registration.
            if self.repo.get_scan(pid, sid).cancel_requested:
                active.cancel.set()
            project = self.repo.get_project(pid)
            try:
                require_active_authorization(project, self.clock())
            except AuthorizationError as exc:
                final_state, reason = S.EXPIRED_AUTHORIZATION, exc.decision.message
                return
            policy = ScopePolicy(
                project.model_copy(update={"scope": scan.scope_snapshot or project.scope}),
                clock=self.clock,
            )
            runner = self.runners.get(scan.module)
            if runner is None:
                final_state, reason = S.FAILED, f"module {scan.module.value} is not available"
                return
            target_check = getattr(runner, "check_targets", None)
            if target_check is not None:
                _, problems = target_check(list(scan.authorized_targets), policy)
                blocked_msgs = [msg for _, msg in problems]
            else:
                blocked_msgs = [
                    f"{d.input}: {d.message}"
                    for d in (policy.is_target_in_scope(t) for t in scan.authorized_targets)
                    if not d.allowed
                ]
            if blocked_msgs or not policy.valid:
                final_state = S.BLOCKED_SCOPE
                reason = "; ".join(blocked_msgs)[:480] or "scope is invalid"
                return
            ctx = JobContext(
                repo=self.repo,
                scan=scan,
                project=project,
                cancel_event=active.cancel,
                kill_switch=self.kill_switch_engaged,
                resolver=self.resolver_factory(),
                clock=self.clock,
            )
            ctx.stop_reason = active.stop_reason
            active.ctx = ctx
            if active.cancel.is_set():
                raise_stop = ctx.checkpoint
                raise_stop()
            self._transition(pid, sid, S.RUNNING, {})
            self._event(scan, "state", "job running")
            result = runner.run(ctx)
            ctx.flush(force=True)
            snap = ctx.snapshot()
            if result.failed or result.errors:
                final_state, reason = S.FAILED, "runner reported failure"
            elif result.warnings or snap["warnings"]:
                final_state, reason = S.COMPLETED_WITH_WARNINGS, "completed with warnings"
            else:
                final_state, reason = S.COMPLETED, "completed"
        except JobStop as stop:
            final_state = S(stop.state_hint)
            reason = str(stop) or stop.state_hint
            if final_state == S.COMPLETED_WITH_WARNINGS and ctx is not None:
                ctx.warn(f"stopped early: {reason}")
        except Exception as exc:  # noqa: BLE001 - any runner bug fails the job, never the app
            final_state, reason = (
                S.FAILED,
                f"{type(exc).__name__}: {redact_text(str(exc), max_chars=300)}",
            )
            log.error("job %s failed: %s", sid, type(exc).__name__)
            if ctx is not None:
                ctx.error(reason)
        finally:
            try:
                if ctx is not None:
                    ctx.flush(force=True)
                self._finish(pid, sid, final_state, reason)
            except Exception:  # noqa: BLE001
                log.exception("could not record final state for job %s", sid)
            finally:
                claim.release()
                with self._wake:
                    self._active.pop(sid, None)
                    self._wake.notify_all()

    # ------------------------------------------------------------------ state helpers

    def _transition(
        self, project_id: str, scan_id: str, target: ScanState, extra: dict[str, Any]
    ) -> ScanJob:
        def apply(current: ScanJob) -> ScanJob:
            check_transition(current.state, target)
            return current.model_copy(update={"state": target, **extra})

        return self.repo.update_scan(project_id, scan_id, apply)

    def _finish(self, project_id: str, scan_id: str, target: ScanState, reason: str) -> None:
        """Move to a terminal state (no-op if already terminal); records event and human log."""

        def apply(current: ScanJob) -> ScanJob:
            if is_terminal(current.state):
                return current
            if target not in (S.CANCELLED,) or current.state != S.QUEUED:
                check_transition(current.state, target)
            return current.model_copy(
                update={
                    "state": target,
                    "finished_at": utc_now(),
                    "final_reason": redact_text(reason, max_chars=480),
                }
            )

        try:
            updated = self.repo.update_scan(project_id, scan_id, apply)
        except InvalidTransitionError:
            log.error("refused invalid final transition for %s -> %s", scan_id, target.value)
            return
        self._event(
            updated,
            "state",
            f"job {updated.state.value}: {reason}",
            level="info" if updated.state in (S.COMPLETED,) else "warning",
        )

    def _event(self, scan: ScanJob, type_: str, message: str, level: str = "info") -> None:
        try:
            from app.jobs.context import JobEvent

            event = JobEvent(
                scan_id=scan.scan_id,
                type=type_,
                level=level,  # type: ignore[arg-type]
                stage=scan.progress.stage,
                message=redact_text(message, max_chars=2000),
                correlation_id=scan.correlation_id,
            )
            self.repo.scan_events(scan.project_id, scan.scan_id).append(
                event.model_dump(mode="json")
            )
            self.repo.scan_console(scan.project_id, scan.scan_id).append(
                f"{event.ts.isoformat()} {level.upper():7} "
                f"[{scan.progress.stage or '-'}] {event.message}"
            )
        except Exception:  # noqa: BLE001 - logging failures must not break state handling
            log.warning("could not write event for %s", scan.scan_id)


def default_runners(
    settings: RuntimeSettings, repo: StorageRepository | None = None
) -> dict[ScanModule, Runner]:
    from app.cve.matcher import StoredCveCatalog
    from app.integrations.zap import ZapAvailability, check_availability
    from app.jobs.selftest import SelfTestRunner
    from app.scanners.apisec.runner import ApiSecRunner
    from app.scanners.repo_scan.availability import find_tool
    from app.scanners.repo_scan.runner import RepoScanRunner
    from app.scanners.surface.runner import SurfaceRunner
    from app.scanners.webapp.runner import WebAppRunner

    cve_catalog = StoredCveCatalog(repo) if repo is not None else None

    def zap_availability() -> ZapAvailability:
        # Re-read the operator's configured path on every call, never cached: Settings can
        # change between one scan submission and the next.
        if repo is None:
            return check_availability("")
        return check_availability(repo.get_settings().integrations.zap_path)

    def semgrep_availability() -> str:
        if repo is None:
            return find_tool("", ["semgrep"])
        return find_tool(repo.get_settings().integrations.semgrep_path, ["semgrep"])

    def gitleaks_availability() -> str:
        if repo is None:
            return find_tool("", ["gitleaks"])
        return find_tool(repo.get_settings().integrations.gitleaks_path, ["gitleaks"])

    def trivy_availability() -> str:
        if repo is None:
            return find_tool("", ["trivy"])
        return find_tool(repo.get_settings().integrations.trivy_path, ["trivy"])

    def trivy_db_ready() -> bool:
        if repo is None:
            return False
        return repo.get_trivy_db_status() is not None

    def docker_availability() -> str:
        if repo is None:
            return find_tool("", ["docker"])
        return find_tool(repo.get_settings().integrations.docker_path, ["docker"])

    def docker_image_ready(engine: str) -> bool:
        if repo is None:
            return False
        return repo.get_docker_image_status(engine) is not None

    runners: dict[ScanModule, Runner] = {
        ScanModule.WEB_APP: WebAppRunner(
            cve_catalog=cve_catalog, zap_availability=zap_availability
        ),
        ScanModule.ATTACK_SURFACE: SurfaceRunner(),
        ScanModule.API_SECURITY: ApiSecRunner(),
        ScanModule.REPO_SCAN: RepoScanRunner(
            semgrep_availability=semgrep_availability,
            gitleaks_availability=gitleaks_availability,
            trivy_availability=trivy_availability,
            trivy_db_ready=trivy_db_ready,
            docker_availability=docker_availability,
            docker_image_ready=docker_image_ready,
        ),
    }
    if settings.enable_selftest_jobs:
        runners[ScanModule.SELF_TEST] = SelfTestRunner()
    return runners


ACTIVE_STATES = ACTIVE
