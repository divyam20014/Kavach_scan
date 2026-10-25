"""Central findings workbench service (MASTER_SPEC Module 9, Phase 09).

Scale note: like `app/imports/service.py`, this iterates full `Finding` records in Python
rather than extending the on-disk equality index — the richer filters here (free-text
search, CWE/mapping/asset membership, date ranges) are not simple per-field equality, and
this is a filesystem-only, single-operator tool, not a web-scale service. Iteration is
bounded by the same `MAX_LIST_PAGES` pattern used elsewhere.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.core.errors import ConflictError, ValidationFailedError
from app.models.asset import Asset
from app.models.audit import AuditAction
from app.models.common import (
    AnalystStatus,
    Confidence,
    Page,
    Severity,
    StrictModel,
    new_id,
)
from app.models.finding import DedupEvent, Finding, FindingComment
from app.services.risk import RiskBreakdown, max_asset_criticality, score_finding
from app.storage.repository import StorageRepository

MAX_LIST_PAGE = 200
MAX_LIST_PAGES = 200  # hard stop: at most 40,000 findings considered per request

_MODULE_PREFIXES: dict[str, str] = {
    "WEB-": "web_app",
    "SURF-": "attack_surface",
    "API-": "api_security",
}

SortField = Literal["updated_at", "created_at", "severity", "risk_score", "title", "analyst_status"]


def module_for(finding: Finding) -> str:
    """Derived module classification. Scanner-native findings use a documented rule_id
    prefix convention (WEB-/SURF-/API-, see app/scanners/*/rules.py); anything else came
    from an import (Phase 08) or predates the convention."""
    for prefix, module in _MODULE_PREFIXES.items():
        if finding.rule_id.startswith(prefix):
            return module
    if any(s.import_id for s in finding.sources):
        return "import"
    return "unknown"


def source_tools(finding: Finding) -> list[str]:
    seen: list[str] = []
    for s in finding.sources:
        if s.tool not in seen:
            seen.append(s.tool)
    return seen


def _iter_project_findings(repo: StorageRepository, project_id: str) -> list[Finding]:
    out: list[Finding] = []
    offset = 0
    for _ in range(MAX_LIST_PAGES):
        page = repo.list_findings(project_id, offset=offset, limit=MAX_LIST_PAGE)
        out.extend(page.items)
        offset += MAX_LIST_PAGE
        if offset >= page.total:
            break
    return out


def _iter_all_findings(repo: StorageRepository, project_id: str | None) -> list[Finding]:
    if project_id is not None:
        repo.get_project(project_id)  # 404 for an unknown project
        return _iter_project_findings(repo, project_id)
    entries, _errors = repo.project_summaries()
    out: list[Finding] = []
    for pid in sorted(entries):
        out.extend(_iter_project_findings(repo, pid))
    return out


def _load_assets(repo: StorageRepository, project_id: str, asset_ids: Iterable[str]) -> list[Asset]:
    out = []
    for aid in asset_ids:
        try:
            out.append(repo.get_asset(project_id, aid))
        except Exception:  # noqa: BLE001, S112 - a stale/deleted asset reference is not fatal
            continue
    return out


class FindingListItem(StrictModel):
    finding: Finding
    module: str
    risk_score: float
    risk_tier: str
    asset_criticality: str | None
    reviewed: bool  # analyst_status != NEW


class FindingDetailView(StrictModel):
    finding: Finding
    module: str
    risk: dict[str, Any]
    assets: list[Asset]
    duplicate_of: Finding | None = None  # set when this finding.merged_into points somewhere
    merged_duplicates: list[Finding] = Field(default_factory=list)  # findings merged INTO this one


class FindingListFilters(StrictModel):
    # Deliberately a plain string, not the strict `ProjectId` pattern type: an invalid id
    # here must surface as the same structured `invalid_id` 400 every other project-scoped
    # route raises (via `repo.get_project`'s own validation), not an unhandled pydantic
    # ValidationError from constructing this filter object.
    project_id: str | None = None
    q: str = ""
    severity: set[Severity] | None = None
    confidence: set[Confidence] | None = None
    analyst_status: set[AnalystStatus] | None = None
    scan_id: str | None = None
    module: set[str] | None = None
    source: set[str] | None = None
    asset_id: str | None = None
    cwe: int | None = None
    mapping_catalog: str | None = None
    mapping_entry: str | None = None
    reviewed: bool | None = None
    include_merged: bool = False
    first_seen_from: datetime | None = None
    first_seen_to: datetime | None = None
    last_seen_from: datetime | None = None
    last_seen_to: datetime | None = None


def _matches(item: FindingListItem, f: FindingListFilters) -> bool:
    finding = item.finding
    if f.severity and finding.severity not in f.severity:
        return False
    if f.confidence and finding.confidence not in f.confidence:
        return False
    if f.scan_id and finding.scan_id != f.scan_id:
        return False
    if f.analyst_status and finding.analyst_status not in f.analyst_status:
        return False
    if f.module and item.module not in f.module:
        return False
    if f.source and not (set(source_tools(finding)) & f.source):
        return False
    if f.asset_id and f.asset_id not in finding.affected_asset_ids:
        return False
    if f.cwe is not None and f.cwe not in finding.cwe_ids:
        return False
    if f.mapping_catalog or f.mapping_entry:
        hit = False
        for m in finding.mappings:
            if f.mapping_catalog and m.catalog != f.mapping_catalog:
                continue
            if f.mapping_entry and m.entry_id != f.mapping_entry:
                continue
            hit = True
            break
        if not hit:
            return False
    if f.reviewed is not None and item.reviewed != f.reviewed:
        return False
    if not f.include_merged and finding.merged_into is not None:
        return False
    if f.first_seen_from and finding.created_at < f.first_seen_from:
        return False
    if f.first_seen_to and finding.created_at > f.first_seen_to:
        return False
    if f.last_seen_from and finding.updated_at < f.last_seen_from:
        return False
    if f.last_seen_to and finding.updated_at > f.last_seen_to:
        return False
    if f.q:
        needle = f.q.lower()
        haystack = " ".join(
            [finding.title, finding.summary, finding.component, finding.url or "", finding.category]
        ).lower()
        if needle not in haystack:
            return False
    return True


_SORT_KEYS: dict[str, Any] = {
    "updated_at": lambda it: it.finding.updated_at,
    "created_at": lambda it: it.finding.created_at,
    "title": lambda it: it.finding.title.lower(),
    "analyst_status": lambda it: it.finding.analyst_status.value,
    "severity": lambda it: {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFORMATIONAL: 4,
    }[it.finding.severity],
    "risk_score": lambda it: it.risk_score,
}


def _view(repo: StorageRepository, finding: Finding) -> FindingListItem:
    assets = _load_assets(repo, finding.project_id, finding.affected_asset_ids)
    breakdown = score_finding(finding, assets)
    worst = max_asset_criticality(assets)
    return FindingListItem(
        finding=finding,
        module=module_for(finding),
        risk_score=breakdown.score,
        risk_tier=breakdown.tier,
        asset_criticality=worst,
        reviewed=finding.analyst_status != AnalystStatus.NEW,
    )


def list_findings(
    repo: StorageRepository,
    *,
    filters: FindingListFilters,
    sort: SortField = "updated_at",
    descending: bool = True,
    offset: int = 0,
    limit: int = 25,
) -> Page[FindingListItem]:
    if sort not in _SORT_KEYS:
        raise ValidationFailedError(f"sort must be one of: {', '.join(_SORT_KEYS)}")
    if offset < 0 or not 1 <= limit <= 500:
        raise ValidationFailedError("offset must be >= 0 and limit between 1 and 500")
    raw = _iter_all_findings(repo, filters.project_id)
    views = [_view(repo, f) for f in raw]
    matched = [v for v in views if _matches(v, filters)]
    matched.sort(key=_SORT_KEYS[sort], reverse=descending)
    page_items = matched[offset : offset + limit]
    return Page[FindingListItem](
        items=page_items, total=len(matched), offset=offset, limit=limit, errors=[]
    )


def get_finding_detail(
    repo: StorageRepository, project_id: str, finding_id: str
) -> FindingDetailView:
    finding = repo.get_finding(project_id, finding_id)
    assets = _load_assets(repo, project_id, finding.affected_asset_ids)
    breakdown = score_finding(finding, assets)
    duplicate_of = None
    if finding.merged_into:
        try:
            duplicate_of = repo.get_finding(project_id, finding.merged_into)
        except Exception:  # noqa: BLE001 - a dangling merge target is shown as absent, not fatal
            duplicate_of = None
    merged_duplicates = [
        f for f in _iter_project_findings(repo, project_id) if f.merged_into == finding_id
    ]
    return FindingDetailView(
        finding=finding,
        module=module_for(finding),
        risk=breakdown.as_dict(),
        assets=assets,
        duplicate_of=duplicate_of,
        merged_duplicates=merged_duplicates,
    )


_EDITABLE_FIELDS = {"analyst_status", "business_impact", "business_priority", "remediation"}


def update_finding(
    repo: StorageRepository,
    project_id: str,
    finding_id: str,
    *,
    changes: dict[str, Any],
    expected_revision: int,
) -> Finding:
    """Analyst triage edit. Only the explicitly editable fields may change; everything a
    scanner/import wrote (severity, confidence, sources, evidence, cwe_ids, mappings,
    fingerprint...) is untouched — "without losing original source data" (acceptance
    criterion)."""
    unknown = set(changes) - _EDITABLE_FIELDS
    if unknown:
        raise ValidationFailedError(f"cannot edit field(s): {', '.join(sorted(unknown))}")
    before = repo.get_finding(project_id, finding_id)
    updated = repo.update_finding(
        project_id, finding_id, changes, expected_revision=expected_revision
    )
    metadata: dict[str, Any] = {}
    for field in changes:
        metadata[field] = {"from": str(getattr(before, field)), "to": str(getattr(updated, field))}
    repo.audit.record(
        AuditAction.FINDING_UPDATED,
        project_id=project_id,
        target_ids=[finding_id],
        metadata=metadata,
    )
    return updated


def add_comment(
    repo: StorageRepository,
    project_id: str,
    finding_id: str,
    *,
    text: str,
    expected_revision: int,
) -> Finding:
    comment = FindingComment(comment_id=new_id("comment"), text=text)

    def apply(current: Finding) -> Finding:
        return current.model_copy(update={"comments": (current.comments + [comment])[-500:]})

    updated = repo.update_finding(
        project_id, finding_id, apply, expected_revision=expected_revision
    )
    repo.audit.record(
        AuditAction.FINDING_COMMENT_ADDED,
        project_id=project_id,
        target_ids=[finding_id],
        metadata={"comment_id": comment.comment_id},
    )
    return updated


def merge_finding(
    repo: StorageRepository,
    project_id: str,
    finding_id: str,
    *,
    into_finding_id: str,
    expected_revision: int,
    note: str = "",
) -> tuple[Finding, Finding]:
    """Mark `finding_id` as a confirmed duplicate of `into_finding_id`. Both records are
    kept (never deleted): the duplicate's own sources/evidence stay on its own record for
    rollback, and the canonical record gains a DedupEvent cross-reference. Unmerge reverses
    this exactly."""
    if finding_id == into_finding_id:
        raise ValidationFailedError("a finding cannot be merged into itself")
    duplicate = repo.get_finding(project_id, finding_id)
    repo.get_finding(project_id, into_finding_id)  # 404 if the target does not exist
    if duplicate.merged_into is not None:
        raise ConflictError("this finding is already merged into another finding")

    def apply_dup(current: Finding) -> Finding:
        return current.model_copy(
            update={
                "merged_into": into_finding_id,
                "dedup_history": (
                    current.dedup_history
                    + [DedupEvent(action="merged", other_finding_id=into_finding_id, note=note)]
                )[-500:],
            }
        )

    def apply_target(current: Finding) -> Finding:
        return current.model_copy(
            update={
                "dedup_history": (
                    current.dedup_history
                    + [DedupEvent(action="merged", other_finding_id=finding_id, note=note)]
                )[-500:],
            }
        )

    updated_dup = repo.update_finding(
        project_id, finding_id, apply_dup, expected_revision=expected_revision
    )
    updated_target = repo.update_finding(project_id, into_finding_id, apply_target)
    repo.audit.record(
        AuditAction.FINDING_MERGED,
        project_id=project_id,
        target_ids=[finding_id, into_finding_id],
        metadata={"duplicate_of": into_finding_id, "note": note},
    )
    return updated_dup, updated_target


def unmerge_finding(
    repo: StorageRepository,
    project_id: str,
    finding_id: str,
    *,
    expected_revision: int,
) -> Finding:
    current_record = repo.get_finding(project_id, finding_id)
    if current_record.merged_into is None:
        raise ConflictError("this finding is not currently merged into another finding")
    was_merged_into = current_record.merged_into

    def apply(current: Finding) -> Finding:
        return current.model_copy(
            update={
                "merged_into": None,
                "dedup_history": (
                    current.dedup_history
                    + [DedupEvent(action="unmerged", other_finding_id=was_merged_into)]
                )[-500:],
            }
        )

    updated = repo.update_finding(
        project_id, finding_id, apply, expected_revision=expected_revision
    )
    repo.audit.record(
        AuditAction.FINDING_UNMERGED,
        project_id=project_id,
        target_ids=[finding_id],
        metadata={"was_merged_into": was_merged_into},
    )
    return updated


__all__ = [
    "FindingDetailView",
    "FindingListFilters",
    "FindingListItem",
    "RiskBreakdown",
    "add_comment",
    "get_finding_detail",
    "list_findings",
    "merge_finding",
    "module_for",
    "source_tools",
    "unmerge_finding",
    "update_finding",
]
