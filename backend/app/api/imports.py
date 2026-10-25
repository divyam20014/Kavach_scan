"""Import Center routes (Phase 08): upload -> dry-run preview -> explicit commit.

Upload and preview are fully offline and read-only against canonical project data: no
`Finding`/`Asset` is written until `POST .../commit`. The raw upload is stored verbatim
(never executed) and re-parsed on each read/commit using the options resolved at upload
time, so what the operator previewed is exactly what gets committed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, get_args

from fastapi import APIRouter, Form, UploadFile
from pydantic import Field

from app.api.deps import Repository
from app.core.errors import ConflictError, ValidationFailedError
from app.imports.safety import MAX_UPLOAD_BYTES, ImportSafetyError
from app.imports.service import ImportPreview, commit, parse_upload, preview
from app.models.audit import AuditAction
from app.models.common import StrictModel, new_id
from app.models.import_artifact import ImportArtifact, ImportSourceType, sanitize_display_filename

router = APIRouter(prefix="/api", tags=["imports"])

_SOURCE_TYPES = frozenset(get_args(ImportSourceType))


def _coerce_source_type(value: str | None) -> ImportSourceType:
    return value if value in _SOURCE_TYPES else "unknown"  # type: ignore[return-value]


class ImportSummary(StrictModel):
    import_id: str
    revision: int
    display_filename: str
    sha256: str
    size_bytes: int
    source_type: str
    source_tool_version: str
    status: str
    uploaded_at: str
    parser_version: str
    warnings: list[str] = Field(default_factory=list)
    record_count: int = 0
    mapped_count: int = 0
    rejected_count: int = 0


class ImportDetail(StrictModel):
    summary: ImportSummary
    preview: ImportPreview | None = None
    error: str = ""


def _summary(artifact: ImportArtifact) -> ImportSummary:
    return ImportSummary(
        import_id=artifact.import_id,
        revision=artifact.revision,
        display_filename=artifact.display_filename,
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        source_type=artifact.source_type,
        source_tool_version=artifact.source_tool_version,
        status=artifact.status,
        uploaded_at=artifact.uploaded_at.isoformat(),
        parser_version=artifact.parser_version,
        warnings=artifact.warnings[:200],
        record_count=artifact.record_count,
        mapped_count=artifact.mapped_count,
        rejected_count=artifact.rejected_count,
    )


def _parse_options(options_json: str | None) -> dict[str, Any]:
    if not options_json:
        return {}
    try:
        parsed = json.loads(options_json)
    except json.JSONDecodeError as exc:
        raise ValidationFailedError(f"options_json is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValidationFailedError("options_json must be a JSON object")
    return parsed


@router.post("/projects/{project_id}/imports", response_model=ImportDetail, status_code=201)
async def upload_import(
    project_id: str,
    repo: Repository,
    file: UploadFile,
    source_type: Annotated[str | None, Form()] = None,
    options_json: Annotated[str | None, Form()] = None,
) -> ImportDetail:
    """Upload a report (offline): detect format, parse bounded records, compute a dry-run
    preview, and store provenance (hash, sanitized filename, parser version, warnings).
    Nothing is written to the project's findings/assets at this step."""
    repo.get_project(project_id)
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ValidationFailedError(f"upload exceeds the {MAX_UPLOAD_BYTES} byte limit")
    options = _parse_options(options_json)
    display = sanitize_display_filename(file.filename or "upload")
    sha256 = hashlib.sha256(raw).hexdigest()
    error = ""
    prev: ImportPreview | None = None
    try:
        adapter, result = parse_upload(display, raw, declared=source_type, options=options)
        prev = preview(repo, project_id, adapter, result)
        artifact = ImportArtifact(
            import_id=new_id("import"),
            project_id=project_id,
            display_filename=display,
            sha256=sha256,
            size_bytes=len(raw),
            source_type=_coerce_source_type(adapter.source_type),
            source_tool_version=result.source_tool_version,
            status="parsed",
            parser_version=adapter.parser_version,
            warnings=result.warnings[:1000],
            record_count=len(result.findings),
            mapped_count=0,
            rejected_count=result.rejected_count,
            source_options=options,
        )
    except ImportSafetyError as exc:
        error = str(exc)
        artifact = ImportArtifact(
            import_id=new_id("import"),
            project_id=project_id,
            display_filename=display,
            sha256=sha256,
            size_bytes=len(raw),
            source_type=_coerce_source_type(source_type),
            status="parse_failed",
            warnings=[error[:500]],
            source_options=options,
        )
    created = repo.create_import(artifact, raw)
    repo.audit.record(
        AuditAction.IMPORT_CREATED,
        project_id=project_id,
        target_ids=[created.import_id],
        metadata={
            "source_type": created.source_type,
            "status": created.status,
            "sha256": created.sha256,
            "size_bytes": created.size_bytes,
        },
    )
    return ImportDetail(summary=_summary(created), preview=prev, error=error)


@router.get("/projects/{project_id}/imports", response_model=list[ImportSummary])
def list_imports(project_id: str, repo: Repository) -> list[ImportSummary]:
    repo.get_project(project_id)
    page = repo.list_imports(project_id, offset=0, limit=200)
    return [_summary(a) for a in page.items]


def _reparse(repo: Repository, project_id: str, import_id: str) -> tuple[ImportArtifact, Any, Any]:
    artifact = repo.get_import(project_id, import_id)
    raw = repo.read_import_raw(project_id, import_id)
    adapter, result = parse_upload(
        artifact.display_filename,
        raw,
        declared=artifact.source_type,
        options=artifact.source_options or None,
    )
    return artifact, adapter, result


@router.get("/projects/{project_id}/imports/{import_id}", response_model=ImportDetail)
def import_detail(project_id: str, import_id: str, repo: Repository) -> ImportDetail:
    """Re-reads the stored upload and re-parses it with the original options, so the
    preview shown here always matches what a commit would do. Still fully offline."""
    repo.get_project(project_id)
    try:
        artifact, adapter, result = _reparse(repo, project_id, import_id)
    except ImportSafetyError as exc:
        artifact = repo.get_import(project_id, import_id)
        return ImportDetail(summary=_summary(artifact), error=str(exc))
    prev = preview(repo, project_id, adapter, result)
    return ImportDetail(summary=_summary(artifact), preview=prev)


class CommitResponse(StrictModel):
    import_id: str
    findings_created: int
    findings_reobserved: int
    assets_created: int
    assets_updated: int


class CommitRequest(StrictModel):
    confirmed: bool
    expected_revision: int = Field(ge=1)


@router.post("/projects/{project_id}/imports/{import_id}/commit", response_model=CommitResponse)
def commit_import(
    project_id: str, import_id: str, body: CommitRequest, repo: Repository
) -> CommitResponse:
    """Normalizes and merges the parsed records into the project's canonical findings/assets.
    Requires explicit confirmation; rejects a second commit of the same import (409)."""
    if not body.confirmed:
        raise ValidationFailedError("Explicit confirmation is required to commit an import")
    artifact = repo.get_import(project_id, import_id)
    if artifact.status == "committed":
        raise ConflictError("This import has already been committed")
    if artifact.revision != body.expected_revision:
        raise ConflictError("The import record changed since it was loaded; reload and retry")
    _artifact, adapter, result = _reparse(repo, project_id, import_id)
    summary = commit(repo, project_id, import_id, adapter, result)
    updated = repo.update_import(
        project_id,
        import_id,
        {
            "status": "committed",
            "mapped_count": summary.findings_created + summary.findings_reobserved,
        },
        expected_revision=body.expected_revision,
    )
    repo.audit.record(
        AuditAction.IMPORT_COMMITTED,
        project_id=project_id,
        target_ids=[import_id],
        metadata={
            "findings_created": summary.findings_created,
            "findings_reobserved": summary.findings_reobserved,
            "assets_created": summary.assets_created,
            "assets_updated": summary.assets_updated,
            "source_type": updated.source_type,
        },
    )
    return CommitResponse(
        import_id=import_id,
        findings_created=summary.findings_created,
        findings_reobserved=summary.findings_reobserved,
        assets_created=summary.assets_created,
        assets_updated=summary.assets_updated,
    )


class SupportedFormat(StrictModel):
    source_type: str
    label: str


class UnsupportedFormat(StrictModel):
    source_type: str
    reason: str


class FormatsResponse(StrictModel):
    supported: list[SupportedFormat]
    unsupported: list[UnsupportedFormat]


@router.get("/imports/formats", response_model=FormatsResponse)
def list_formats() -> FormatsResponse:
    from app.imports.adapters import ADAPTERS, UNSUPPORTED

    return FormatsResponse(
        supported=[SupportedFormat(source_type=a.source_type, label=a.label) for a in ADAPTERS],
        unsupported=[UnsupportedFormat(source_type=k, reason=v) for k, v in UNSUPPORTED.items()],
    )
