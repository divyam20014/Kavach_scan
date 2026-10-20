"""Project, scope-preview, dashboard, record-listing and audit routes (Phase 02).

Routers only parse/validate, call a service or the repository, and serialize.
No route starts, schedules or simulates a scan.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, status

from app.api.deps import Repository
from app.models.asset import Asset
from app.models.audit import AuditAction
from app.models.common import (
    AnalystStatus,
    AssetType,
    Confidence,
    Page,
    ProjectStatus,
    ScanState,
    Severity,
)
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import ScanJob
from app.services.dashboard import DashboardSummary, build_summary
from app.services.projects import (
    DeletionImpact,
    ProjectCreate,
    ProjectOverview,
    ProjectService,
    ProjectUpdate,
)
from app.services.scope_preview import ScopePreviewRequest, ScopePreviewResponse, preview_scope
from app.storage.audit import AuditPage

router = APIRouter(prefix="/api", tags=["projects"])

Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Order = Annotated[Literal["asc", "desc"], Query()]


def _set(values: list[Any] | None) -> set[str] | None:
    return {v.value if hasattr(v, "value") else str(v) for v in values} if values else None


# ------------------------------------------------------------------ projects


@router.get("/projects", response_model=Page[ProjectOverview])
def list_projects(
    repo: Repository,
    q: Annotated[str | None, Query(max_length=200)] = None,
    status_filter: Annotated[ProjectStatus | None, Query(alias="status")] = None,
    sort: Literal["updated_at", "created_at", "name"] = "updated_at",
    order: Order = "desc",
    offset: Offset = 0,
    limit: Limit = 25,
) -> Page[ProjectOverview]:
    return ProjectService(repo).list(
        status=status_filter.value if status_filter else None,
        search=q,
        sort=sort,
        descending=order == "desc",
        offset=offset,
        limit=limit,
    )


@router.post("/projects", response_model=Project, status_code=status.HTTP_201_CREATED)
def create_project(body: ProjectCreate, repo: Repository) -> Project:
    return ProjectService(repo).create(body)


@router.get("/projects/{project_id}", response_model=ProjectOverview)
def get_project(project_id: str, repo: Repository) -> ProjectOverview:
    service = ProjectService(repo)
    return service.overview(repo.get_project(project_id))


@router.patch("/projects/{project_id}", response_model=Project)
def update_project(project_id: str, body: ProjectUpdate, repo: Repository) -> Project:
    return ProjectService(repo).update(project_id, body)


@router.get("/projects/{project_id}/deletion-impact", response_model=DeletionImpact)
def deletion_impact(project_id: str, repo: Repository) -> DeletionImpact:
    return ProjectService(repo).deletion_impact(project_id)


@router.delete("/projects/{project_id}", response_model=DeletionImpact)
def delete_project(
    project_id: str,
    repo: Repository,
    confirm: Annotated[str, Query(min_length=1, max_length=200, description="Exact project name")],
) -> DeletionImpact:
    return ProjectService(repo).delete(project_id, confirm)


# --------------------------------------------------- scope preview (no network access)


@router.post("/scope/preview", response_model=ScopePreviewResponse)
def scope_preview(body: ScopePreviewRequest) -> ScopePreviewResponse:
    return preview_scope(body)


# ------------------------------------------------------------------ dashboard


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    repo: Repository,
    project_id: Annotated[str | None, Query(max_length=64)] = None,
) -> DashboardSummary:
    return build_summary(repo, project_id)


# ------------------------------------------------ read-only record views (KPI drill-down)


@router.get("/findings", response_model=Page[Finding])
def list_findings(
    repo: Repository,
    project_id: Annotated[str | None, Query(max_length=64)] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    analyst_status: Annotated[list[AnalystStatus] | None, Query()] = None,
    confidence: Annotated[list[Confidence] | None, Query()] = None,
    sort: Literal["updated_at", "created_at", "severity", "title"] = "updated_at",
    order: Order = "desc",
    offset: Offset = 0,
    limit: Limit = 25,
) -> Page[Any]:
    return repo.list_across_projects(
        "finding",
        project_id=project_id,
        filters={
            "severity": _set(severity),
            "analyst_status": _set(analyst_status),
            "confidence": _set(confidence),
        },
        sort=sort,
        descending=order == "desc",
        offset=offset,
        limit=limit,
    )


@router.get("/assets", response_model=Page[Asset])
def list_assets(
    repo: Repository,
    project_id: Annotated[str | None, Query(max_length=64)] = None,
    asset_type: Annotated[list[AssetType] | None, Query()] = None,
    sort: Literal["updated_at", "created_at", "last_seen", "locator"] = "updated_at",
    order: Order = "desc",
    offset: Offset = 0,
    limit: Limit = 25,
) -> Page[Any]:
    return repo.list_across_projects(
        "asset",
        project_id=project_id,
        filters={"asset_type": _set(asset_type)},
        sort=sort,
        descending=order == "desc",
        offset=offset,
        limit=limit,
    )


@router.get("/scans", response_model=Page[ScanJob])
def list_scans(
    repo: Repository,
    project_id: Annotated[str | None, Query(max_length=64)] = None,
    state: Annotated[list[ScanState] | None, Query()] = None,
    sort: Literal["updated_at", "created_at", "queued_at"] = "updated_at",
    order: Order = "desc",
    offset: Offset = 0,
    limit: Limit = 25,
) -> Page[Any]:
    return repo.list_across_projects(
        "scan",
        project_id=project_id,
        filters={"state": _set(state)},
        sort=sort,
        descending=order == "desc",
        offset=offset,
        limit=limit,
    )


# ------------------------------------------------------------------ audit log


@router.get("/audit", response_model=AuditPage)
def list_audit(
    repo: Repository,
    project_id: Annotated[str | None, Query(max_length=64)] = None,
    action: AuditAction | None = None,
    offset: Offset = 0,
    limit: Limit = 50,
) -> AuditPage:
    return repo.audit.list(offset=offset, limit=limit, project_id=project_id, action=action)
