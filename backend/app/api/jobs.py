"""Job routes (Phase 04): start/cancel/retry scans, job detail, events, console, kill switch.

Starting a job requires explicit confirmation, an active attested authorization, a valid
scope, in-scope targets, an available module and a free queue slot; otherwise nothing is
created. The job itself is executed by the filesystem-backed JobManager.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, Response
from pydantic import Field

from app.api.deps import Repository
from app.core.errors import ServiceUnavailableError
from app.core.redaction import redact, redact_text
from app.jobs.context import JobEvent
from app.jobs.manager import JobManager, ManagerStatus, ModuleAvailability, StartScanRequest
from app.jobs.states import is_terminal
from app.models.common import ShortText, StrictModel, utc_now
from app.models.scan import ScanJob
from app.storage.repository import KillSwitchState

router = APIRouter(prefix="/api", tags=["jobs"])


def get_manager(request: Request) -> JobManager:
    manager = getattr(request.app.state, "jobs", None)
    if manager is None:
        raise ServiceUnavailableError("The job manager is not running")
    return manager  # type: ignore[no-any-return]


class ScanDetail(StrictModel):
    scan: ScanJob
    active: bool
    terminal: bool
    elapsed_seconds: float | None


class EventPage(StrictModel):
    items: list[JobEvent]
    offset: int
    limit: int
    has_more: bool
    corrupt_lines: int


class ConsoleView(StrictModel):
    lines: list[str]


class KillSwitchRequest(StrictModel):
    engaged: bool
    reason: ShortText = Field(min_length=3)


class RetryRequest(StrictModel):
    confirmed: bool
    idempotency_key: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{8,64}$")


def _elapsed(scan: ScanJob, now: datetime) -> float | None:
    if scan.started_at is None:
        return None
    end = scan.finished_at or now
    return round((end - scan.started_at).total_seconds(), 1)


@router.get("/jobs/modules", response_model=list[ModuleAvailability])
def modules(request: Request) -> list[ModuleAvailability]:
    return get_manager(request).availability()


@router.get("/jobs/status", response_model=ManagerStatus)
def job_status(request: Request) -> ManagerStatus:
    return get_manager(request).status()


@router.get("/kill-switch", response_model=KillSwitchState)
def get_kill_switch(repo: Repository) -> KillSwitchState:
    return repo.get_kill_switch()


@router.put("/kill-switch", response_model=KillSwitchState)
def set_kill_switch(body: KillSwitchRequest, request: Request) -> Any:
    return get_manager(request).set_kill_switch(body.engaged, body.reason)


@router.post(
    "/projects/{project_id}/scans",
    response_model=ScanJob,
    status_code=202,
    responses={200: {"model": ScanJob, "description": "Existing job for this idempotency key"}},
)
def start_scan(
    project_id: str, body: StartScanRequest, request: Request, response: Response
) -> ScanJob:
    scan, created = get_manager(request).submit(project_id, body)
    if not created:
        response.status_code = 200
    return scan


@router.get("/projects/{project_id}/scans/{scan_id}", response_model=ScanDetail)
def scan_detail(project_id: str, scan_id: str, request: Request, repo: Repository) -> ScanDetail:
    scan = repo.get_scan(project_id, scan_id)
    manager = getattr(request.app.state, "jobs", None)
    active = manager is not None and scan_id in manager.status().active_jobs
    return ScanDetail(
        scan=scan,
        active=active,
        terminal=is_terminal(scan.state),
        elapsed_seconds=_elapsed(scan, utc_now()),
    )


@router.get("/projects/{project_id}/scans/{scan_id}/events", response_model=EventPage)
def scan_events(
    project_id: str,
    scan_id: str,
    repo: Repository,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> EventPage:
    repo.get_scan(project_id, scan_id)  # 404 / invalid id handling
    items, corrupt, more = repo.scan_events(project_id, scan_id).read_newest(
        offset=offset, limit=limit, parse=JobEvent.model_validate
    )
    # Defence in depth: writers redact already; re-redact on the way out too.
    safe = [
        e.model_copy(
            update={"message": redact_text(e.message, max_chars=2000), "data": redact(e.data)}
        )
        for e in items
    ]
    return EventPage(items=safe, offset=offset, limit=limit, has_more=more, corrupt_lines=corrupt)


@router.get("/projects/{project_id}/scans/{scan_id}/console", response_model=ConsoleView)
def scan_console(
    project_id: str,
    scan_id: str,
    repo: Repository,
    lines: Annotated[int, Query(ge=1, le=2000)] = 200,
) -> ConsoleView:
    repo.get_scan(project_id, scan_id)
    tail = repo.scan_console(project_id, scan_id).tail(lines)
    return ConsoleView(
        lines=[redact_text(line, max_chars=4000) for line in tail]
    )  # re-redacted on read


@router.post(
    "/projects/{project_id}/scans/{scan_id}/cancel", response_model=ScanJob, status_code=202
)
def cancel_scan(project_id: str, scan_id: str, request: Request) -> ScanJob:
    return get_manager(request).cancel(project_id, scan_id)


@router.post(
    "/projects/{project_id}/scans/{scan_id}/retry", response_model=ScanJob, status_code=202
)
def retry_scan(project_id: str, scan_id: str, body: RetryRequest, request: Request) -> ScanJob:
    if not body.confirmed:
        from app.core.errors import ValidationFailedError

        raise ValidationFailedError("Explicit confirmation is required to start a new job")
    return get_manager(request).retry(project_id, scan_id, idempotency_key=body.idempotency_key)
