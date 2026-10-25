"""Central findings workbench routes (MASTER_SPEC Module 9, Phase 09).

`GET /api/findings` is the cross-project workbench list (search/filter/sort/pagination).
Everything that mutates a finding is scoped under its project, like every other
project-owned resource in this app (`/api/projects/{id}/findings/...`).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, TypeVar

from fastapi import APIRouter, Query
from pydantic import StringConstraints

from app.api.deps import Repository
from app.api.projects import Limit, Offset, Order
from app.core.errors import ValidationFailedError
from app.models.common import (
    AnalystStatus,
    Confidence,
    LongText,
    Page,
    Severity,
    ShortText,
    StrictModel,
)
from app.models.finding import BusinessPriority
from app.services import findings as svc
from app.services.risk import formula_description
from app.standards import CATALOGS

router = APIRouter(prefix="/api", tags=["findings"])

T = TypeVar("T")


def _set(values: list[T] | None) -> set[T] | None:
    return set(values) if values else None


@router.get("/findings", response_model=Page[svc.FindingListItem])
def list_findings(
    repo: Repository,
    project_id: Annotated[str | None, Query(max_length=64)] = None,
    q: Annotated[str, Query(max_length=200)] = "",
    severity: Annotated[list[Severity] | None, Query()] = None,
    confidence: Annotated[list[Confidence] | None, Query()] = None,
    analyst_status: Annotated[list[AnalystStatus] | None, Query()] = None,
    scan_id: Annotated[str | None, Query(max_length=64, pattern=r"^scn_[0-9a-f]{32}$")] = None,
    module: Annotated[list[str] | None, Query()] = None,
    source: Annotated[list[str] | None, Query()] = None,
    asset_id: Annotated[str | None, Query(max_length=64, pattern=r"^ast_[0-9a-f]{32}$")] = None,
    cwe: Annotated[int | None, Query(ge=1, le=100_000)] = None,
    mapping_catalog: Annotated[str | None, Query(max_length=32)] = None,
    mapping_entry: Annotated[str | None, Query(max_length=32)] = None,
    reviewed: bool | None = None,
    include_merged: bool = False,
    first_seen_from: datetime | None = None,
    first_seen_to: datetime | None = None,
    last_seen_from: datetime | None = None,
    last_seen_to: datetime | None = None,
    sort: svc.SortField = "updated_at",
    order: Order = "desc",
    offset: Offset = 0,
    limit: Limit = 25,
) -> Page[svc.FindingListItem]:
    filters = svc.FindingListFilters(
        project_id=project_id,
        q=q,
        severity=_set(severity),
        confidence=_set(confidence),
        analyst_status=_set(analyst_status),
        scan_id=scan_id,
        module=_set(module),
        source=_set(source),
        asset_id=asset_id,
        cwe=cwe,
        mapping_catalog=mapping_catalog,
        mapping_entry=mapping_entry,
        reviewed=reviewed,
        include_merged=include_merged,
        first_seen_from=first_seen_from,
        first_seen_to=first_seen_to,
        last_seen_from=last_seen_from,
        last_seen_to=last_seen_to,
    )
    return svc.list_findings(
        repo, filters=filters, sort=sort, descending=order == "desc", offset=offset, limit=limit
    )


@router.get("/projects/{project_id}/findings/{finding_id}", response_model=svc.FindingDetailView)
def finding_detail(project_id: str, finding_id: str, repo: Repository) -> svc.FindingDetailView:
    return svc.get_finding_detail(repo, project_id, finding_id)


class FindingUpdateRequest(StrictModel):
    expected_revision: int
    analyst_status: AnalystStatus | None = None
    business_impact: LongText | None = None
    business_priority: BusinessPriority | None = None
    remediation: LongText | None = None


@router.patch("/projects/{project_id}/findings/{finding_id}", response_model=svc.FindingDetailView)
def update_finding(
    project_id: str, finding_id: str, body: FindingUpdateRequest, repo: Repository
) -> svc.FindingDetailView:
    changes = {
        k: v
        for k, v in body.model_dump(mode="json", exclude={"expected_revision"}).items()
        if v is not None
    }
    if not changes:
        raise ValidationFailedError("at least one editable field must be provided")
    svc.update_finding(
        repo, project_id, finding_id, changes=changes, expected_revision=body.expected_revision
    )
    return svc.get_finding_detail(repo, project_id, finding_id)


class CommentRequest(StrictModel):
    text: Annotated[str, StringConstraints(min_length=1, max_length=20_000)]
    expected_revision: int


@router.post(
    "/projects/{project_id}/findings/{finding_id}/comments", response_model=svc.FindingDetailView
)
def add_comment(
    project_id: str, finding_id: str, body: CommentRequest, repo: Repository
) -> svc.FindingDetailView:
    svc.add_comment(
        repo, project_id, finding_id, text=body.text, expected_revision=body.expected_revision
    )
    return svc.get_finding_detail(repo, project_id, finding_id)


class MergeRequest(StrictModel):
    into_finding_id: Annotated[str, StringConstraints(pattern=r"^fnd_[0-9a-f]{32}$")]
    expected_revision: int
    note: ShortText = ""


@router.post(
    "/projects/{project_id}/findings/{finding_id}/merge", response_model=svc.FindingDetailView
)
def merge_finding(
    project_id: str, finding_id: str, body: MergeRequest, repo: Repository
) -> svc.FindingDetailView:
    svc.merge_finding(
        repo,
        project_id,
        finding_id,
        into_finding_id=body.into_finding_id,
        expected_revision=body.expected_revision,
        note=body.note,
    )
    return svc.get_finding_detail(repo, project_id, finding_id)


class UnmergeRequest(StrictModel):
    expected_revision: int


@router.post(
    "/projects/{project_id}/findings/{finding_id}/unmerge", response_model=svc.FindingDetailView
)
def unmerge_finding(
    project_id: str, finding_id: str, body: UnmergeRequest, repo: Repository
) -> svc.FindingDetailView:
    svc.unmerge_finding(repo, project_id, finding_id, expected_revision=body.expected_revision)
    return svc.get_finding_detail(repo, project_id, finding_id)


# ------------------------------------------------------------- risk formula & catalogs


class CatalogView(StrictModel):
    catalog: str
    version: str
    label: str
    source: str
    imported_at: str
    entry_count: int
    coverage_note: str


@router.get("/standards/catalogs", response_model=list[CatalogView])
def list_catalogs() -> list[CatalogView]:
    return [
        CatalogView(
            catalog=c.catalog,
            version=c.version,
            label=c.label,
            source=c.source,
            imported_at=c.imported_at,
            entry_count=c.entry_count,
            coverage_note=c.coverage_note,
        )
        for c in CATALOGS.values()
    ]


@router.get("/risk-formula")
def risk_formula() -> dict[str, object]:
    return formula_description()
