"""System endpoints: liveness, readiness, version, storage diagnostics.

API versioning: the API is unversioned under `/api` because the only client is the
bundled UI shipped with the same build; `/api/version` reports `api_version` so a
future breaking change can be detected (see TBD-039).
"""

from __future__ import annotations

import platform
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import __version__
from app.api.deps import Repository
from app.core.config import PRODUCT_NAME
from app.models.audit import AuditAction
from app.storage.diagnostics import StorageDiagnostics, diagnose
from app.storage.integrity import IntegrityReport, check_integrity
from app.storage.migrations import STORAGE_VERSION

API_VERSION = "1"

router = APIRouter(prefix="/api", tags=["system"])


class HealthResponse(BaseModel):
    status: Literal["ok"]


class VersionResponse(BaseModel):
    name: str
    version: str
    api_version: str
    storage_version: int
    python: str
    scanning_available: bool


class ReadinessResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    storage_ready: bool
    integrity_ok: bool | None
    warnings: list[str]


class StorageDiagnosticsResponse(BaseModel):
    storage: StorageDiagnostics
    last_integrity_check: IntegrityReport | None


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness only: no filesystem access."""
    return HealthResponse(status="ok")


@router.get("/version", response_model=VersionResponse)
def version() -> VersionResponse:
    # scanning_available is a fact, not a toggle: no scanner exists yet.
    return VersionResponse(
        name=PRODUCT_NAME,
        version=__version__,
        api_version=API_VERSION,
        storage_version=STORAGE_VERSION,
        python=platform.python_version(),
        scanning_available=False,
    )


@router.get(
    "/readiness", response_model=ReadinessResponse, responses={503: {"model": ReadinessResponse}}
)
def readiness(request: Request, repo: Repository) -> JSONResponse:
    diag = diagnose(repo.root, repo.settings, lock_held_here=repo.instance_lock.held)
    last: IntegrityReport | None = getattr(request.app.state, "last_integrity", None)
    ready = diag.ready and repo.instance_lock.held
    body = ReadinessResponse(
        status="ready" if ready else "not_ready",
        storage_ready=diag.ready,
        integrity_ok=None if last is None else last.ok,
        warnings=diag.warnings,
    )
    return JSONResponse(status_code=200 if ready else 503, content=body.model_dump(mode="json"))


@router.get("/diagnostics/storage", response_model=StorageDiagnosticsResponse)
def storage_diagnostics(request: Request, repo: Repository) -> StorageDiagnosticsResponse:
    return StorageDiagnosticsResponse(
        storage=diagnose(repo.root, repo.settings, lock_held_here=repo.instance_lock.held),
        last_integrity_check=getattr(request.app.state, "last_integrity", None),
    )


@router.post("/diagnostics/integrity-check", response_model=IntegrityReport)
def run_integrity_check(request: Request, repo: Repository) -> IntegrityReport:
    """Re-run the integrity check; repairs only derivable state (indexes, temp files)."""
    report = check_integrity(repo, repair=True)
    request.app.state.last_integrity = report
    repo.audit.record(
        AuditAction.INTEGRITY_CHECKED,
        outcome="success" if report.ok else "failure",
        metadata={"issues": len(report.issues), "indexes_rebuilt": report.indexes_rebuilt},
    )
    return report
