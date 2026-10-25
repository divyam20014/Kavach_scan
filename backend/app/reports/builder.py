"""Gather canonical records into a single `ReportData` snapshot that the HTML and PDF
renderers (and the JSON/CSV exporters) all consume identically — this is what guarantees
"the same selected findings appear consistently in preview and files" (Phase 10 acceptance
criterion): the resolution happens exactly once, here.

`Finding`/`EvidenceMetadata` fields are already redacted at write time (TBD-041). This
module applies `redact_text` a **second** time to every free-text field as it builds the
report snapshot — defense in depth, the same "redact at every boundary" posture already
used for audit logs and imports, so a report can never surface a secret even if some future
or third-party write path skipped redaction at the source. Never a raw evidence blob.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.redaction import redact_text
from app.models.asset import Asset
from app.models.common import AnalystStatus, Severity
from app.models.evidence import EvidenceMetadata
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import ScanJob
from app.services.findings import FindingListFilters, list_findings, module_for
from app.storage.errors import StorageError
from app.storage.repository import StorageRepository

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]
MAX_FINDINGS_PER_REPORT = 2000  # a bound, not a claim every finding ever fits one document


@dataclass
class ReportFilters:
    project_id: str
    title: str = "VAPT Assessment Report"
    classification_label: str = "CONFIDENTIAL"
    scan_date_from: datetime | None = None
    scan_date_to: datetime | None = None
    modules: set[str] | None = None
    severity_threshold: Severity = Severity.INFORMATIONAL  # include this severity and worse
    analyst_statuses: set[AnalystStatus] | None = None  # None = all except false_positive
    finding_ids: list[str] | None = None  # explicit override; ignores the filters above
    include_asset_inventory: bool = True
    include_evidence: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "classification_label": self.classification_label,
            "scan_date_from": self.scan_date_from.isoformat() if self.scan_date_from else "",
            "scan_date_to": self.scan_date_to.isoformat() if self.scan_date_to else "",
            "modules": sorted(self.modules) if self.modules else [],
            "severity_threshold": self.severity_threshold.value,
            "analyst_statuses": sorted(s.value for s in self.analyst_statuses)
            if self.analyst_statuses
            else [],
            "finding_ids": list(self.finding_ids) if self.finding_ids else [],
            "include_asset_inventory": self.include_asset_inventory,
            "include_evidence": self.include_evidence,
        }


@dataclass
class ScanSummary:
    scan: ScanJob
    coverage_total: int = 0
    coverage_skipped: int = 0
    coverage_errors: int = 0
    skip_reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class ReportData:
    project: Project
    filters: ReportFilters
    generated_at: datetime
    findings: list[Finding]
    assets: list[Asset]
    scans: list[ScanSummary]
    evidence_by_finding: dict[str, list[EvidenceMetadata]]
    severity_counts: dict[str, int]
    status_counts: dict[str, int]
    module_counts: dict[str, int]
    limitations: list[str]
    tool_versions: dict[str, str]


def _severity_at_or_above(severity: Severity, threshold: Severity) -> bool:
    return _SEVERITY_ORDER.index(severity) <= _SEVERITY_ORDER.index(threshold)


_FINDING_TEXT_FIELDS: dict[str, int] = {
    "title": 200,
    "summary": 20_000,
    "technical_detail": 20_000,
    "remediation": 20_000,
    "parameter": 500,
    "component": 500,
    "business_impact": 20_000,
}


def _redact_finding(f: Finding) -> Finding:
    changes = {
        name: redact_text(getattr(f, name), max_chars=cap)
        for name, cap in _FINDING_TEXT_FIELDS.items()
    }
    return f.model_copy(update=changes)


def _redact_evidence(e: EvidenceMetadata) -> EvidenceMetadata:
    return e.model_copy(
        update={
            "request_excerpt": redact_text(e.request_excerpt, max_chars=8192),
            "response_excerpt": redact_text(e.response_excerpt, max_chars=8192),
        }
    )


def _read_scan_json(
    repo: StorageRepository, project_id: str, scan_id: str, name: str
) -> dict[str, Any]:
    try:
        raw = repo.read_scan_output(project_id, scan_id, name)
    except StorageError:
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _scan_summary(repo: StorageRepository, project_id: str, scan: ScanJob) -> ScanSummary:
    summary_json = _read_scan_json(repo, project_id, scan.scan_id, "summary.json")
    coverage_json = _read_scan_json(repo, project_id, scan.scan_id, "coverage.json")
    raw_results = coverage_json.get("results")
    rows: list[Any] = raw_results if isinstance(raw_results, list) else []
    skipped = [r for r in rows if isinstance(r, dict) and r.get("outcome") == "skipped"]
    errored = [r for r in rows if isinstance(r, dict) and r.get("outcome") == "error"]
    skip_reasons = sorted(
        {str(r.get("rationale", ""))[:300] for r in skipped if r.get("rationale")}
    )[:50]
    limitations = summary_json.get("limitations")
    return ScanSummary(
        scan=scan,
        coverage_total=len(rows),
        coverage_skipped=len(skipped),
        coverage_errors=len(errored),
        skip_reasons=skip_reasons,
        limitations=[str(x) for x in limitations][:50] if isinstance(limitations, list) else [],
    )


def _iter_project_assets(repo: StorageRepository, project_id: str) -> list[Asset]:
    out: list[Asset] = []
    offset = 0
    for _ in range(200):
        page = repo.list_assets(project_id, offset=offset, limit=200)
        out.extend(page.items)
        offset += 200
        if offset >= page.total:
            break
    return out


def _iter_project_scans(repo: StorageRepository, project_id: str) -> list[ScanJob]:
    out: list[ScanJob] = []
    offset = 0
    for _ in range(200):
        page = repo.list_scans(project_id, offset=offset, limit=200)
        out.extend(page.items)
        offset += 200
        if offset >= page.total:
            break
    return out


def build_report_data(repo: StorageRepository, filters: ReportFilters) -> ReportData:
    project = repo.get_project(filters.project_id)
    generated_at = datetime.now(project.created_at.tzinfo)

    if filters.finding_ids:
        findings: list[Finding] = []
        for fid in filters.finding_ids[:MAX_FINDINGS_PER_REPORT]:
            try:
                findings.append(repo.get_finding(filters.project_id, fid))
            except StorageError:
                continue  # a stale/removed id is skipped, not a fatal error for the report
    else:
        statuses = filters.analyst_statuses
        if statuses is None:
            statuses = {s for s in AnalystStatus if s != AnalystStatus.FALSE_POSITIVE}
        page = list_findings(
            repo,
            filters=FindingListFilters(
                project_id=filters.project_id,
                analyst_status=statuses,
                first_seen_from=filters.scan_date_from,
                first_seen_to=filters.scan_date_to,
            ),
            sort="severity",
            descending=False,
            offset=0,
            limit=500,
        )
        findings = [
            item.finding
            for item in page.items
            if _severity_at_or_above(item.finding.severity, filters.severity_threshold)
            and (filters.modules is None or module_for(item.finding) in filters.modules)
        ][:MAX_FINDINGS_PER_REPORT]

    # Defense in depth (see module docstring): redact every free-text field a second time,
    # regardless of whether the write path already did so.
    findings = [_redact_finding(f) for f in findings]

    evidence_by_finding: dict[str, list[EvidenceMetadata]] = {}
    if filters.include_evidence:
        for f in findings:
            items = []
            for eid in f.evidence_ids[:50]:
                try:
                    items.append(_redact_evidence(repo.get_evidence(filters.project_id, eid)))
                except StorageError:
                    continue
            if items:
                evidence_by_finding[f.finding_id] = items

    all_assets = _iter_project_assets(repo, filters.project_id)
    included_asset_ids = {aid for f in findings for aid in f.affected_asset_ids}
    assets = (
        all_assets
        if filters.include_asset_inventory
        else [a for a in all_assets if a.asset_id in included_asset_ids]
    )

    all_scans = _iter_project_scans(repo, filters.project_id)
    selected_scans = all_scans
    if filters.modules is not None:
        selected_scans = [s for s in selected_scans if s.module.value in filters.modules]
    if filters.scan_date_from or filters.scan_date_to:

        def in_range(s: ScanJob) -> bool:
            at = s.finished_at or s.queued_at or s.created_at
            if filters.scan_date_from and at < filters.scan_date_from:
                return False
            return not (filters.scan_date_to and at > filters.scan_date_to)

        selected_scans = [s for s in selected_scans if in_range(s)]
    scan_summaries = [_scan_summary(repo, filters.project_id, s) for s in selected_scans]

    severity_counts = {s.value: 0 for s in Severity}
    status_counts = {s.value: 0 for s in AnalystStatus}
    module_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity.value] += 1
        status_counts[f.analyst_status.value] += 1
        module_counts[module_for(f)] = module_counts.get(module_for(f), 0) + 1

    limitations: list[str] = [
        "This report reflects only the checks that were actually executed, within the "
        "configured scope, rate, and time budgets — it is not a claim of overall security.",
        "A finding's absence in a given area means no issue was detected by the checks run; "
        "it does not mean the area was proven free of weaknesses.",
    ]
    for s in scan_summaries:
        limitations.extend(s.limitations)
        if s.coverage_skipped:
            limitations.append(
                f"Scan {s.scan.scan_id[:12]}… ({s.scan.module.value}): "
                f"{s.coverage_skipped} of {s.coverage_total} check(s) skipped."
            )
        limitations.extend(f"Skipped: {r}" for r in s.skip_reasons[:10])
        limitations.extend(f"Warning: {w}" for w in s.scan.warnings[:10])
    # de-dup while keeping order, bounded
    seen: set[str] = set()
    deduped_limitations = []
    for item in limitations:
        if item not in seen:
            seen.add(item)
            deduped_limitations.append(item)
    deduped_limitations = deduped_limitations[:200]

    tool_versions: dict[str, str] = {}
    for sc in selected_scans:
        tool_versions.update(sc.tool_versions)

    return ReportData(
        project=project,
        filters=filters,
        generated_at=generated_at,
        findings=findings,
        assets=assets,
        scans=scan_summaries,
        evidence_by_finding=evidence_by_finding,
        severity_counts=severity_counts,
        status_counts=status_counts,
        module_counts=module_counts,
        limitations=deduped_limitations,
        tool_versions=tool_versions,
    )
