"""Settings, integrations status/self-test, and local CVE catalog routes (Phase 11).

Secret handling: `online_lookup_credential_alias` can only ever be a reference such as
`env:NAME`/`keychain:NAME` (enforced by `app.models.settings`'s validator) — never a raw
secret value. That is what makes "secret values are write-only and never returned by the
settings-read API" true by construction: there is never a real secret for this endpoint to
echo back in the first place.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, UploadFile
from pydantic import ValidationError

from app.api.deps import Repository
from app.core.errors import NotFoundError, ValidationFailedError
from app.cve.parser import MAX_CATALOG_BYTES, CveCatalogParseError, parse_catalog_file
from app.integrations.process import ProcessPolicyError, run_process
from app.models.audit import AuditAction
from app.models.common import StrictModel, utc_now
from app.models.cve_catalog import CveCatalogRecord
from app.models.docker_image import DockerImageStatusRecord
from app.models.settings import AppSettings
from app.models.trivy_db import TrivyDbStatusRecord
from app.scanners.repo_scan.availability import find_tool
from app.scanners.repo_scan.docker_images import (
    ENGINES as DOCKER_ENGINES,
)
from app.scanners.repo_scan.docker_images import (
    build_pull_argv,
    build_verify_argv,
    image_for,
)
from app.scanners.repo_scan.trivy_adapter import build_download_db_argv
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
    zap_path: str | None = None
    semgrep_path: str | None = None
    gitleaks_path: str | None = None
    trivy_path: str | None = None
    docker_path: str | None = None
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
            "nmap_path",
            "sslyze_path",
            "testssl_path",
            "zap_path",
            "semgrep_path",
            "gitleaks_path",
            "trivy_path",
            "docker_path",
            "online_lookup_credential_alias",
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
        AuditAction.TOOL_CONFIG_CHANGED
        if integration_fields_changed
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
        id=s.id,
        label=s.label,
        capability=s.capability,
        configured_path=s.configured_path,
        detected_path=s.detected_path,
        status=s.status,
        version=s.version,
        last_used=ToolUsageResponse(**s.last_used.__dict__) if s.last_used else None,
        last_error=s.last_error,
        troubleshooting=s.troubleshooting,
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


# ------------------------------------------------------------------ Trivy vulnerability database

TRIVY_DOWNLOAD_TIMEOUT_SECONDS = 600.0  # the real download took ~26s/1.6GB in TBD-087's
# verification on a fast connection; a slow one needs real headroom, not a tight timeout.


class TrivyDbStatusResponse(StrictModel):
    downloaded_at: str
    trivy_version: str
    size_bytes: int


def _db_dir_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


@router.get("/integrations/trivy/db-status", response_model=TrivyDbStatusResponse | None)
def trivy_db_status(repo: Repository) -> TrivyDbStatusResponse | None:
    """`None` means the operator has never explicitly triggered the download -- see
    `app/models/trivy_db.py`. This never checks the filesystem directly: the status record
    is the single source of truth for "was this explicitly triggered," independent of
    whatever Trivy's own cache directory happens to currently contain."""
    record = repo.get_trivy_db_status()
    if record is None:
        return None
    return TrivyDbStatusResponse(
        downloaded_at=record.downloaded_at.isoformat(),
        trivy_version=record.trivy_version,
        size_bytes=record.size_bytes,
    )


@router.post("/integrations/trivy/download-db", response_model=TrivyDbStatusResponse)
def download_trivy_db(repo: Repository) -> TrivyDbStatusResponse:
    """The one explicit, operator-initiated action that is ever allowed to download Trivy's
    vulnerability database (roadmap Phase 2, TBD-087) -- a `repo_scan` job with `trivy`
    selected never downloads it itself (see `app/scanners/repo_scan/trivy_adapter.py`'s own
    module docstring). This blocks for the duration of the real download (observed ~26s for
    1.6 GB on a fast connection in TBD-087's own verification; a slow connection needs real
    minutes) -- an explicit, occasional, operator-watched action, not a request this
    application's ordinary traffic would ever trigger, so a long-held HTTP connection was
    judged acceptable rather than adding background-job infrastructure for a one-time cost."""
    executable = find_tool(repo.get_settings().integrations.trivy_path, ["trivy"])
    if not executable:
        raise ValidationFailedError("Trivy is not installed or configured; set its path first")
    cache_dir = repo.trivy_db_dir()
    argv = build_download_db_argv(executable, cache_dir)
    try:
        result = run_process(
            argv,
            allowed_executables=[executable],
            cwd=repo.diagnostics_temp_dir(),
            timeout=TRIVY_DOWNLOAD_TIMEOUT_SECONDS,
            temp_dir=repo.diagnostics_temp_dir(),
        )
    except ProcessPolicyError as exc:
        raise ValidationFailedError(f"could not run trivy: {exc}") from exc
    if result.timed_out:
        raise ValidationFailedError(
            f"the download did not finish within {TRIVY_DOWNLOAD_TIMEOUT_SECONDS:.0f}s"
        )
    if result.exit_code != 0:
        raise ValidationFailedError(f"trivy exited with status {result.exit_code}")
    version_result = run_process(
        [executable, "--version"],
        allowed_executables=[executable],
        cwd=repo.diagnostics_temp_dir(),
        timeout=20.0,
        temp_dir=repo.diagnostics_temp_dir(),
    )
    version_text = version_result.stdout.decode("utf-8", "replace").strip()
    record = repo.save_trivy_db_status(
        TrivyDbStatusRecord(
            downloaded_at=utc_now(),
            trivy_version=version_text[:200],
            size_bytes=_db_dir_size(cache_dir),
        )
    )
    repo.audit.record(
        AuditAction.TRIVY_DB_DOWNLOADED,
        metadata={"trivy_version": record.trivy_version, "size_bytes": record.size_bytes},
    )
    return TrivyDbStatusResponse(
        downloaded_at=record.downloaded_at.isoformat(),
        trivy_version=record.trivy_version,
        size_bytes=record.size_bytes,
    )


@router.delete("/integrations/trivy/db-status", status_code=204)
def remove_trivy_db_status(repo: Repository) -> None:
    """Clears only this application's own *record* that the download happened -- never
    deletes the cache directory's contents (an operator who wants that back deletes the
    data directory's `diagnostics/trivy_db` folder directly, same as any other cache)."""
    repo.delete_trivy_db_status()
    repo.audit.record(AuditAction.TRIVY_DB_DOWNLOADED, metadata={"action": "status_cleared"})


# ------------------------------------------------------------------ Docker-based engines
# (Docker-based execution roadmap phase 2 of 5, TBD-091: operator-confirmed design --
# per-engine, additive to a native install, pinned image versions.)

DOCKER_PULL_TIMEOUT_SECONDS = 300.0
DOCKER_VERIFY_TIMEOUT_SECONDS = 60.0


class DockerImageStatusResponse(StrictModel):
    image: str
    digest: str
    size_bytes: int
    verified_version: str
    pulled_at: str


def _docker_image_response(record: DockerImageStatusRecord) -> DockerImageStatusResponse:
    return DockerImageStatusResponse(
        image=record.image,
        digest=record.digest,
        size_bytes=record.size_bytes,
        verified_version=record.verified_version,
        pulled_at=record.pulled_at.isoformat(),
    )


@router.get(
    "/integrations/docker/{engine}/image-status",
    response_model=DockerImageStatusResponse | None,
)
def docker_image_status(engine: str, repo: Repository) -> DockerImageStatusResponse | None:
    """`None` means this engine's pinned image has never been explicitly pulled."""
    if engine not in DOCKER_ENGINES:
        raise NotFoundError(f"unknown engine {engine!r}")
    record = repo.get_docker_image_status(engine)
    return _docker_image_response(record) if record else None


@router.post("/integrations/docker/{engine}/pull-image", response_model=DockerImageStatusResponse)
def pull_docker_image(engine: str, repo: Repository) -> DockerImageStatusResponse:
    """The one explicit, operator-initiated action that ever pulls a Docker image for a
    repo_scan engine -- a scan never pulls one itself, the same "never a silent network
    fetch" rule TBD-087 already established for Trivy's own vulnerability database. Pulls
    the pinned image, then runs one bounded verification command inside it (proves the
    image doesn't just exist locally but actually executes in this environment) before
    recording success."""
    if engine not in DOCKER_ENGINES:
        raise NotFoundError(f"unknown engine {engine!r}")
    executable = find_tool(repo.get_settings().integrations.docker_path, ["docker"])
    if not executable:
        raise ValidationFailedError("Docker is not installed or configured; set its path first")
    argv = build_pull_argv(executable, engine)
    try:
        result = run_process(
            argv,
            allowed_executables=[executable],
            cwd=repo.diagnostics_temp_dir(),
            timeout=DOCKER_PULL_TIMEOUT_SECONDS,
            temp_dir=repo.diagnostics_temp_dir(),
        )
    except ProcessPolicyError as exc:
        raise ValidationFailedError(f"could not run docker: {exc}") from exc
    if result.timed_out:
        raise ValidationFailedError(
            f"the pull did not finish within {DOCKER_PULL_TIMEOUT_SECONDS:.0f}s"
        )
    if result.exit_code != 0:
        raise ValidationFailedError(f"docker pull exited with status {result.exit_code}")

    image = image_for(engine)
    inspect_result = run_process(
        [executable, "image", "inspect", image, "--format", "{{.Size}} {{index .RepoDigests 0}}"],
        allowed_executables=[executable],
        cwd=repo.diagnostics_temp_dir(),
        timeout=DOCKER_VERIFY_TIMEOUT_SECONDS,
        temp_dir=repo.diagnostics_temp_dir(),
    )
    size_bytes = 0
    digest = ""
    inspect_text = inspect_result.stdout.decode("utf-8", "replace").strip()
    if inspect_result.exit_code == 0 and inspect_text:
        parts = inspect_text.split(" ", 1)
        if parts[0].isdigit():
            size_bytes = int(parts[0])
        if len(parts) > 1 and "@" in parts[1]:
            digest = parts[1].split("@", 1)[1][:100]

    verify_argv = build_verify_argv(executable, engine)
    try:
        verify_result = run_process(
            verify_argv,
            allowed_executables=[executable],
            cwd=repo.diagnostics_temp_dir(),
            timeout=DOCKER_VERIFY_TIMEOUT_SECONDS,
            temp_dir=repo.diagnostics_temp_dir(),
        )
    except ProcessPolicyError as exc:
        raise ValidationFailedError(f"pulled, but could not verify the image: {exc}") from exc
    if verify_result.exit_code != 0:
        raise ValidationFailedError(
            f"the image was pulled but did not run correctly (exit "
            f"{verify_result.exit_code}); it was not recorded as ready"
        )
    verified_version = verify_result.stdout.decode("utf-8", "replace").strip()[:200]

    record = repo.save_docker_image_status(
        engine,
        DockerImageStatusRecord(
            image=image,
            digest=digest,
            size_bytes=size_bytes,
            verified_version=verified_version,
            pulled_at=utc_now(),
        ),
    )
    repo.audit.record(
        AuditAction.DOCKER_IMAGE_PULLED,
        metadata={"engine": engine, "image": record.image, "size_bytes": record.size_bytes},
    )
    return _docker_image_response(record)


@router.delete("/integrations/docker/{engine}/image-status", status_code=204)
def remove_docker_image_status(engine: str, repo: Repository) -> None:
    """Clears only this application's own record that the pull happened -- never removes
    the image from Docker's own local store (an operator who wants that back runs
    `docker rmi` themselves, same as any other cache)."""
    if engine not in DOCKER_ENGINES:
        raise NotFoundError(f"unknown engine {engine!r}")
    repo.delete_docker_image_status(engine)
    repo.audit.record(
        AuditAction.DOCKER_IMAGE_PULLED, metadata={"engine": engine, "action": "status_cleared"}
    )


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
        source=record.source,
        catalog_version=record.catalog_version,
        imported_at=record.imported_at.isoformat(),
        file_sha256=record.file_sha256,
        file_name=record.file_name,
        parser_version=record.parser_version,
        entry_count=len(record.entries),
        stale_after_days=record.stale_after_days,
        is_stale=age_days > record.stale_after_days,
        warnings=record.warnings,
    )


@router.get("/cve-catalog", response_model=CveCatalogMetadataResponse | None)
def get_cve_catalog(repo: Repository) -> CveCatalogMetadataResponse | None:
    record = repo.get_cve_catalog()
    return _catalog_response(record) if record else None


@router.post("/cve-catalog/import", response_model=CveCatalogMetadataResponse, status_code=201)
async def import_cve_catalog(repo: Repository, file: UploadFile) -> CveCatalogMetadataResponse:
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
            "source": saved.source,
            "catalog_version": saved.catalog_version,
            "entry_count": len(saved.entries),
            "file_sha256": saved.file_sha256,
        },
    )
    return _catalog_response(saved)


@router.delete("/cve-catalog", status_code=204)
def remove_cve_catalog(repo: Repository) -> None:
    repo.delete_cve_catalog()
    repo.audit.record(AuditAction.CVE_CATALOG_REMOVED)
