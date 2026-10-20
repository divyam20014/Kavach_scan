"""Dashboard aggregation computed from canonical records (via derived indexes).

Every number here is counted from stored records at request time. There are no
cached, sample or synthetic values; empty storage yields honest zeros.
"""

from __future__ import annotations

from collections import Counter

from pydantic import Field

from app.models.audit import AuditEvent
from app.models.common import (
    AnalystStatus,
    AssetType,
    Confidence,
    ScanState,
    Severity,
    StrictModel,
    UtcDatetime,
    utc_now,
)
from app.models.project import Project
from app.services.projects import authorization_status
from app.storage.errors import StorageError
from app.storage.repository import StorageRepository

ACTIVE_SCAN_STATES = {ScanState.QUEUED, ScanState.VALIDATING, ScanState.RUNNING}
FAILED_SCAN_STATES = {ScanState.FAILED}


class ProjectCounts(StrictModel):
    total: int
    active: int
    archived: int
    authorization: dict[str, int]


class ScanCounts(StrictModel):
    total: int
    active: int
    failed: int
    by_state: dict[str, int]
    last_scan_at: str | None
    last_scan_state: str | None


class FindingCounts(StrictModel):
    total: int
    open: int  # not false_positive / accepted_risk / fixed
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_confidence: dict[str, int]


class AssetCounts(StrictModel):
    total: int
    by_type: dict[str, int]


class DashboardSummary(StrictModel):
    generated_at: UtcDatetime = Field(default_factory=utc_now)
    project_id: str | None
    projects: ProjectCounts
    scans: ScanCounts
    findings: FindingCounts
    assets: AssetCounts
    recent_activity: list[AuditEvent]
    unreadable_records: int


CLOSED_STATUSES = {AnalystStatus.FALSE_POSITIVE, AnalystStatus.ACCEPTED_RISK, AnalystStatus.FIXED}


def _zeroed(values: list[str]) -> Counter[str]:
    return Counter(dict.fromkeys(values, 0))


def build_summary(
    repo: StorageRepository, project_id: str | None = None, activity_limit: int = 10
) -> DashboardSummary:
    project_entries, errors = repo.project_summaries()
    if project_id is not None:
        repo.get_project(project_id)  # 400/404 for invalid or unknown ids
        project_entries = {pid: e for pid, e in project_entries.items() if pid == project_id}
    unreadable = len(errors)

    auth = _zeroed(["missing", "not_started", "active", "expiring_soon", "expired"])
    statuses = Counter(str(e.get("status")) for e in project_entries.values())
    scan_states = _zeroed([s.value for s in ScanState])
    severities = _zeroed([s.value for s in Severity])
    finding_status = _zeroed([s.value for s in AnalystStatus])
    confidence = _zeroed([c.value for c in Confidence])
    asset_types = _zeroed([a.value for a in AssetType])
    last_scan: tuple[str, str] | None = None
    findings_total = assets_total = scans_total = 0

    for pid in project_entries:
        try:
            project: Project = repo.get_project(pid)
        except StorageError:
            unreadable += 1
            continue
        auth[authorization_status(project)] += 1
        for kind in ("scan", "finding", "asset"):
            try:
                entries, errs = repo.summaries(kind, pid)
            except StorageError:
                unreadable += 1
                continue
            unreadable += len(errs)
            for entry in entries.values():
                if kind == "scan":
                    scans_total += 1
                    scan_states[str(entry.get("state"))] += 1
                    at = str(entry.get("updated_at") or "")
                    if last_scan is None or at > last_scan[0]:
                        last_scan = (at, str(entry.get("state")))
                elif kind == "finding":
                    findings_total += 1
                    severities[str(entry.get("severity"))] += 1
                    finding_status[str(entry.get("analyst_status"))] += 1
                    confidence[str(entry.get("confidence"))] += 1
                else:
                    assets_total += 1
                    asset_types[str(entry.get("asset_type"))] += 1

    activity = repo.audit.list(limit=activity_limit, project_id=project_id).items
    return DashboardSummary(
        project_id=project_id,
        projects=ProjectCounts(
            total=len(project_entries),
            active=statuses.get("active", 0),
            archived=statuses.get("archived", 0),
            authorization=dict(auth),
        ),
        scans=ScanCounts(
            total=scans_total,
            active=sum(scan_states[s.value] for s in ACTIVE_SCAN_STATES),
            failed=sum(scan_states[s.value] for s in FAILED_SCAN_STATES),
            by_state=dict(scan_states),
            last_scan_at=last_scan[0] if last_scan else None,
            last_scan_state=last_scan[1] if last_scan else None,
        ),
        findings=FindingCounts(
            total=findings_total,
            open=findings_total - sum(finding_status[s.value] for s in CLOSED_STATUSES),
            by_severity=dict(severities),
            by_status=dict(finding_status),
            by_confidence=dict(confidence),
        ),
        assets=AssetCounts(total=assets_total, by_type=dict(asset_types)),
        recent_activity=activity,
        unreadable_records=unreadable,
    )
