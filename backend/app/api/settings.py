"""Settings, integrations status/self-test, and local CVE catalog routes (Phase 11).

Secret handling: `online_lookup_credential_alias` can only ever be a reference such as
`env:NAME`/`keychain:NAME` (enforced by `app.models.settings`'s validator) — never a raw
secret value. That is what makes "secret values are write-only and never returned by the
settings-read API" true by construction: there is never a real secret for this endpoint to
echo back in the first place.
"""

from __future__ import annotations

from fastapi import APIRouter, UploadFile
from pydantic import ValidationError

from app.api.deps import Repository
from app.core.errors import NotFoundError, ValidationFailedError
from app.cve.parser import MAX_CATALOG_BYTES, CveCatalogParseError, parse_catalog_file
from app.models.audit import AuditAction
from app.models.common import StrictModel, utc_now
from app.models.cve_catalog import CveCatalogRecord
from app.models.settings import AppSettings
from app.services.integrations import (
    TOOL_IDS,
    IntegrationStatus,
    UnknownIntegrationError,
    list_integration_statuses,
    run_selftest,
)

router = APIRouter(prefix="/api", tags=["settings"])


# ------------------------------------------------------------------ settings


class IntegrationsSettingsUpdate(StrictModel):
    nmap_path: str | None = None
    sslyze_path: str | None = None
    testssl_path: str | None = None
    online_lookup_credential_alias: str | None = None


class SettingsUpdateRequest(StrictModel):
    product_name: str | None = None
    integrations: IntegrationsSettingsUpdate | None = None
    expected_revision: int | None = None


@router.get("/settings", response_model=AppSettings)
def get_settings(repo: Repository) -> AppSettings:
    return repo.get_settings()


@router.patch("/settings", response_model=AppSettings)
def update_settings(body: SettingsUpdateRequest, repo: Repository) -> AppSettings:
    current = repo.get_settings()
    data = current.model_dump(mode="json")
    changed_fields: list[str] = []
    integration_fields_changed = False
    if body.product_name is not None:
        data["product_name"] = body.product_name
        changed_fields.append("product_name")
    if body.integrations is not None:
        integ = dict(data["integrations"])
        for field_name in (
            "nmap_path", "sslyze_path", "testssl_path", "online_lookup_credential_alias",
        ):
            value = getattr(body.integrations, field_name)
            if value is not None:
                integ[field_name] = value
                changed_fields.append(f"integrations.{field_name}")
                integration_fields_changed = True
        data["integrations"] = integ
    try:
        updated = AppSettings.model_validate(data)
    except ValidationError as exc:
        raise ValidationFailedError(
            f"settings failed validation ({exc.error_count()} error(s))"
        ) from exc
    saved = repo.save_settings(updated, expected_revision=body.expected_revision)
    repo.audit.record(
        AuditAction.TOOL_CONFIG_CHANGED if integration_fields_changed
        else AuditAction.SETTINGS_CHANGED,
        metadata={"fields": changed_fields},
    )
    return saved


# ------------------------------------------------------------------ integrations status/self-test


class ToolUsageResponse(StrictModel):
    project_id: str
    scan_id: str
    at: str
    version: str


class IntegrationStatusResponse(StrictModel):
    id: str
    label: str
    capability: str
    configured_path: str
    detected_path: str
    status: str
    version: str
    last_used: ToolUsageResponse | None
    last_error: str
    troubleshooting: str


def _to_response(s: IntegrationStatus) -> IntegrationStatusResponse:
    return IntegrationStatusResponse(
        id=s.id, label=s.label, capability=s.capability, configured_path=s.configured_path,
        detected_path=s.detected_path, status=s.status, version=s.version,
        last_used=ToolUsageResponse(**s.last_used.__dict__) if s.last_used else None,
        last_error=s.last_error, troubleshooting=s.troubleshooting,
    )


@router.get("/integrations", response_model=list[IntegrationStatusResponse])
def integrations_status(repo: Repository) -> list[IntegrationStatusResponse]:
    """Detection only (PATH/path-existence lookup) — no subprocess is run to build this list."""
    return [_to_response(s) for s in list_integration_statuses(repo)]


@router.post("/integrations/{tool_id}/selftest", response_model=IntegrationStatusResponse)
def integration_selftest(tool_id: str, repo: Repository) -> IntegrationStatusResponse:
    """Runs `<tool> --version` only. No scan target is ever contacted by this route."""
    if tool_id not in TOOL_IDS:
        raise NotFoundError(f"unknown integration {tool_id!r}")
    try:
        result = run_selftest(repo, tool_id)
    except UnknownIntegrationError as exc:
        raise NotFoundError(f"unknown integration {exc}") from exc
    repo.audit.record(
        AuditAction.INTEGRATION_SELFTEST_RUN,
        metadata={"tool": tool_id, "status": result.status},
    )
    return _to_response(result)


# ------------------------------------------------------------------ CVE catalog


class CveCatalogMetadataResponse(StrictModel):
    source: str
    catalog_version: str
    imported_at: str
    file_sha256: str
    file_name: str
    parser_version: str
    entry_count: int
    stale_after_days: int
    is_stale: bool
    warnings: list[str]


def _catalog_response(record: CveCatalogRecord) -> CveCatalogMetadataResponse:
    age_days = (utc_now() - record.imported_at).days
    return CveCatalogMetadataResponse(
        source=record.source, catalog_version=record.catalog_version,
        imported_at=record.imported_at.isoformat(), file_sha256=record.file_sha256,
        file_name=record.file_name, parser_version=record.parser_version,
        entry_count=len(record.entries), stale_after_days=record.stale_after_days,
        is_stale=age_days > record.stale_after_days, warnings=record.warnings,
    )


@router.get("/cve-catalog", response_model=CveCatalogMetadataResponse | None)
def get_cve_catalog(repo: Repository) -> CveCatalogMetadataResponse | None:
    record = repo.get_cve_catalog()
    return _catalog_response(record) if record else None


@router.post("/cve-catalog/import", response_model=CveCatalogMetadataResponse, status_code=201)
async def import_cve_catalog(
    repo: Repository, file: UploadFile
) -> CveCatalogMetadataResponse:
    raw = await file.read(MAX_CATALOG_BYTES + 1)
    if len(raw) > MAX_CATALOG_BYTES:
        raise ValidationFailedError(f"catalog file exceeds the {MAX_CATALOG_BYTES} byte limit")
    try:
        record = parse_catalog_file(raw, file_name=file.filename or "")
    except CveCatalogParseError as exc:
        raise ValidationFailedError(str(exc)) from exc
    saved = repo.save_cve_catalog(record)
    repo.audit.record(
        AuditAction.CVE_CATALOG_IMPORTED,
        metadata={
            "source": saved.source, "catalog_version": saved.catalog_version,
            "entry_count": len(saved.entries), "file_sha256": saved.file_sha256,
        },
    )
    return _catalog_response(saved)


@router.delete("/cve-catalog", status_code=204)
def remove_cve_catalog(repo: Repository) -> None:
    repo.delete_cve_catalog()
    repo.audit.record(AuditAction.CVE_CATALOG_REMOVED)
