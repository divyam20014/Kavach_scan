"""Report builder, normalized exports, and project backup/restore routes (Phase 10)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, UploadFile
from fastapi.responses import Response
from pydantic import Field

from app.api.deps import Repository
from app.backup.archive import export_archive, preview_archive, restore_archive
from app.backup.safety import MAX_ARCHIVE_BYTES, ArchiveSafetyError
from app.core.errors import NotFoundError, ValidationFailedError
from app.models.audit import AuditAction
from app.models.common import AnalystStatus, Severity, StrictModel, new_id
from app.models.report import ReportFormat, ReportMetadata
from app.reports.builder import ReportData, ReportFilters, build_report_data
from app.reports.exports import assets_to_csv, assets_to_json, findings_to_csv, findings_to_json
from app.reports.html_render import render_html
from app.reports.pdf_render import render_pdf

router = APIRouter(prefix="/api", tags=["reports"])

_MEDIA_TYPES: dict[ReportFormat, str] = {
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "json": "application/json",
    "csv": "text/csv",
}
_FILE_NAMES: dict[ReportFormat, str] = {
    "html": "report.html",
    "pdf": "report.pdf",
    "json": "findings.json",
    "csv": "findings.csv",
}


class ReportFilterRequest(StrictModel):
    title: str = "VAPT Assessment Report"
    classification_label: str = "CONFIDENTIAL"
    scan_date_from: datetime | None = None
    scan_date_to: datetime | None = None
    modules: list[str] | None = None
    severity_threshold: Severity = Severity.INFORMATIONAL
    analyst_statuses: list[AnalystStatus] | None = None
    finding_ids: list[str] | None = None
    include_asset_inventory: bool = True
    include_evidence: bool = True

    def to_filters(self, project_id: str) -> ReportFilters:
        return ReportFilters(
            project_id=project_id,
            title=self.title,
            classification_label=self.classification_label,
            scan_date_from=self.scan_date_from,
            scan_date_to=self.scan_date_to,
            modules=set(self.modules) if self.modules else None,
            severity_threshold=self.severity_threshold,
            analyst_statuses=set(self.analyst_statuses) if self.analyst_statuses else None,
            finding_ids=self.finding_ids,
            include_asset_inventory=self.include_asset_inventory,
            include_evidence=self.include_evidence,
        )


class ReportPreviewResponse(StrictModel):
    finding_ids: list[str]
    asset_ids: list[str]
    scan_ids: list[str]
    severity_counts: dict[str, int]
    status_counts: dict[str, int]
    module_counts: dict[str, int]
    limitations: list[str]
    tool_versions: dict[str, str]


def _preview_from_data(data: ReportData) -> ReportPreviewResponse:
    return ReportPreviewResponse(
        finding_ids=[f.finding_id for f in data.findings],
        asset_ids=[a.asset_id for a in data.assets],
        scan_ids=[s.scan.scan_id for s in data.scans],
        severity_counts=data.severity_counts,
        status_counts=data.status_counts,
        module_counts=data.module_counts,
        limitations=data.limitations,
        tool_versions=data.tool_versions,
    )


@router.post("/projects/{project_id}/reports/preview", response_model=ReportPreviewResponse)
def preview_report(
    project_id: str, body: ReportFilterRequest, repo: Repository
) -> ReportPreviewResponse:
    """Read-only: resolves exactly the finding/asset set a generated report would use,
    without writing anything (Phase 10: "Preview before generating")."""
    data = build_report_data(repo, body.to_filters(project_id))
    return _preview_from_data(data)


class GenerateReportRequest(ReportFilterRequest):
    formats: list[ReportFormat] = Field(default=["html", "pdf"], min_length=1, max_length=4)


class ReportSummary(StrictModel):
    report_id: str
    project_id: str
    title: str
    classification_label: str
    formats: list[ReportFormat]
    finding_count: int
    asset_count: int
    evidence_included: bool
    created_at: str


def _summary(m: ReportMetadata) -> ReportSummary:
    return ReportSummary(
        report_id=m.report_id,
        project_id=m.project_id,
        title=m.title,
        classification_label=m.classification_label,
        formats=m.formats,
        finding_count=len(m.finding_ids),
        asset_count=len(m.asset_ids),
        evidence_included=m.evidence_included,
        created_at=m.created_at.isoformat(),
    )


@router.post("/projects/{project_id}/reports", response_model=ReportSummary, status_code=201)
def generate_report(
    project_id: str, body: GenerateReportRequest, repo: Repository
) -> ReportSummary:
    filters = body.to_filters(project_id)
    data = build_report_data(repo, filters)
    report_id = new_id("report")
    rendered: dict[ReportFormat, bytes] = {}
    for fmt in body.formats:
        if fmt == "html":
            rendered[fmt] = render_html(data).encode("utf-8")
        elif fmt == "pdf":
            rendered[fmt] = render_pdf(data)
        elif fmt == "json":
            rendered[fmt] = findings_to_json(data)
        elif fmt == "csv":
            rendered[fmt] = findings_to_csv(data)

    metadata = ReportMetadata(
        report_id=report_id,
        project_id=project_id,
        title=filters.title,
        classification_label=filters.classification_label,
        formats=body.formats,
        finding_ids=[f.finding_id for f in data.findings],
        asset_ids=[a.asset_id for a in data.assets],
        evidence_included=filters.include_evidence,
        filters=filters.as_dict(),  # type: ignore[arg-type]
        generator_version="vapt-reports 1.0.0",
    )
    created = repo.save_report_metadata(metadata)
    file_sha: dict[str, str] = {}
    for fmt, content in rendered.items():
        file_sha[fmt] = repo.write_report_file(project_id, report_id, _FILE_NAMES[fmt], content)
    created = repo.update_report_metadata(project_id, report_id, {"file_sha256": file_sha})

    repo.audit.record(
        AuditAction.REPORT_GENERATED,
        project_id=project_id,
        target_ids=[report_id],
        metadata={"formats": body.formats, "finding_count": len(data.findings)},
    )
    return _summary(created)


@router.get("/projects/{project_id}/reports", response_model=list[ReportSummary])
def list_reports(project_id: str, repo: Repository) -> list[ReportSummary]:
    page = repo.list_reports(project_id, offset=0, limit=200)
    return [_summary(m) for m in page.items]


@router.get("/projects/{project_id}/reports/{report_id}", response_model=ReportSummary)
def report_detail(project_id: str, report_id: str, repo: Repository) -> ReportSummary:
    return _summary(repo.get_report_metadata(project_id, report_id))


@router.get("/projects/{project_id}/reports/{report_id}/download/{fmt}")
def download_report(
    project_id: str, report_id: str, fmt: ReportFormat, repo: Repository
) -> Response:
    metadata = repo.get_report_metadata(project_id, report_id)
    if fmt not in metadata.formats:
        raise NotFoundError(f"this report was not generated in the {fmt} format")
    data = repo.read_report_file(project_id, report_id, _FILE_NAMES[fmt])
    repo.audit.record(
        AuditAction.REPORT_DOWNLOADED,
        project_id=project_id,
        target_ids=[report_id],
        metadata={"format": fmt},
    )
    return Response(
        content=data,
        media_type=_MEDIA_TYPES[fmt],
        headers={"Content-Disposition": f'attachment; filename="{_FILE_NAMES[fmt]}"'},
    )


# ------------------------------------------------------------------ standalone exports


@router.get("/projects/{project_id}/export/findings.json")
def export_findings_json(project_id: str, repo: Repository) -> Response:
    data = build_report_data(repo, ReportFilters(project_id=project_id, include_evidence=False))
    return Response(
        content=findings_to_json(data),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="findings.json"'},
    )


@router.get("/projects/{project_id}/export/findings.csv")
def export_findings_csv(project_id: str, repo: Repository) -> Response:
    data = build_report_data(repo, ReportFilters(project_id=project_id, include_evidence=False))
    return Response(
        content=findings_to_csv(data),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="findings.csv"'},
    )


@router.get("/projects/{project_id}/export/assets.json")
def export_assets_json(project_id: str, repo: Repository) -> Response:
    data = build_report_data(repo, ReportFilters(project_id=project_id, include_evidence=False))
    return Response(
        content=assets_to_json(data),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="assets.json"'},
    )


@router.get("/projects/{project_id}/export/assets.csv")
def export_assets_csv(project_id: str, repo: Repository) -> Response:
    data = build_report_data(repo, ReportFilters(project_id=project_id, include_evidence=False))
    return Response(
        content=assets_to_csv(data),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="assets.csv"'},
    )


# ------------------------------------------------------------------ project backup/restore


@router.get("/projects/{project_id}/backup/export")
def backup_export(
    project_id: str,
    repo: Repository,
    include_evidence_blobs: Annotated[bool, Query()] = True,
) -> Response:
    archive = export_archive(repo, project_id, include_evidence_blobs=include_evidence_blobs)
    repo.audit.record(
        AuditAction.BACKUP_CREATED,
        project_id=project_id,
        metadata={"include_evidence_blobs": include_evidence_blobs, "bytes": len(archive)},
    )
    return Response(
        content=archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{project_id}-backup.zip"'},
    )


class BackupPreviewResponse(StrictModel):
    project_id: str
    project_name: str
    exported_at: str
    app_version: str
    storage_version: int
    include_evidence_blobs: bool
    counts: dict[str, int]
    checksum_mismatches: list[str]
    project_already_exists: bool
    warnings: list[str]


@router.post("/backup/preview", response_model=BackupPreviewResponse)
async def backup_preview(repo: Repository, file: UploadFile) -> BackupPreviewResponse:
    raw = await file.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValidationFailedError(f"archive exceeds the {MAX_ARCHIVE_BYTES} byte limit")
    try:
        preview = preview_archive(repo, raw)
    except ArchiveSafetyError as exc:
        raise ValidationFailedError(str(exc)) from exc
    return BackupPreviewResponse(
        project_id=preview.project_id,
        project_name=preview.project_name,
        exported_at=preview.exported_at,
        app_version=preview.app_version,
        storage_version=preview.storage_version,
        include_evidence_blobs=preview.include_evidence_blobs,
        counts=preview.counts,
        checksum_mismatches=preview.checksum_mismatches,
        project_already_exists=preview.project_already_exists,
        warnings=preview.warnings,
    )


class RestoreResponse(StrictModel):
    project_id: str
    counts: dict[str, int]


@router.post("/backup/restore", response_model=RestoreResponse)
async def backup_restore(
    repo: Repository,
    file: UploadFile,
    confirmed: Annotated[bool, Query()] = False,
    overwrite: Annotated[bool, Query()] = False,
) -> RestoreResponse:
    raw = await file.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValidationFailedError(f"archive exceeds the {MAX_ARCHIVE_BYTES} byte limit")
    try:
        result = restore_archive(repo, raw, confirmed=confirmed, overwrite=overwrite)
    except ArchiveSafetyError as exc:
        raise ValidationFailedError(str(exc)) from exc
    repo.audit.record(
        AuditAction.BACKUP_RESTORED,
        project_id=result.project_id,
        metadata={"counts": result.counts, "overwrite": overwrite},
    )
    return RestoreResponse(project_id=result.project_id, counts=result.counts)
