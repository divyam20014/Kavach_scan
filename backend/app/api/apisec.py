"""API-spec routes (Phase 07): upload/list/detail/validate/inventory and scan-profile preview.

Import and inventory are fully offline (zero network requests). Scans start only through the
gated job routes. The raw upload is stored verbatim and never executed.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Any

from fastapi import APIRouter, Query, UploadFile
from pydantic import Field

from app.api.deps import Repository
from app.core.errors import NotFoundError, ValidationFailedError
from app.models.audit import AuditAction
from app.models.common import StrictModel, new_id
from app.models.import_artifact import ImportArtifact, sanitize_display_filename
from app.models.project import ScopeDefinition
from app.scanners.apisec.inventory import ApiInventory, build_inventory
from app.scanners.apisec.profile import validate_parameters
from app.scanners.apisec.rules import CATALOG_VERSION
from app.scanners.apisec.spec import MAX_SPEC_BYTES, SpecError, load_spec
from app.scope.engine import ScopePolicy

router = APIRouter(prefix="/api", tags=["api-security"])


class ApiSpecSummary(StrictModel):
    import_id: str
    display_filename: str
    sha256: str
    size_bytes: int
    status: str
    uploaded_at: str
    kind: str = ""
    version: str = ""
    title: str = ""
    operation_count: int = 0
    warnings: list[str] = Field(default_factory=list)


class ServerScopeView(StrictModel):
    raw: str
    expanded: str
    in_scope: bool
    reason: str


class ApiSpecDetail(StrictModel):
    summary: ApiSpecSummary
    inventory: dict[str, Any]
    servers: list[ServerScopeView]


def _inventory_for(
    repo: Repository, project_id: str, import_id: str
) -> tuple[ImportArtifact, ApiInventory]:
    artifact = repo.get_import(project_id, import_id)
    if artifact.source_type != "openapi_spec":
        raise NotFoundError("Not an API specification import")
    raw = repo.read_import_raw(project_id, import_id)
    try:
        return artifact, build_inventory(load_spec(raw))
    except SpecError as exc:
        raise ValidationFailedError(f"The stored spec could not be parsed: {exc}") from exc


def _server_views(inventory: ApiInventory, policy: ScopePolicy) -> list[ServerScopeView]:
    views: list[ServerScopeView] = []
    for server in inventory.servers:
        decision = policy.is_target_in_scope(server.expanded)
        views.append(
            ServerScopeView(
                raw=server.raw,
                expanded=server.expanded,
                in_scope=decision.allowed,
                reason=decision.message[:200],
            )
        )
    return views


@router.post("/projects/{project_id}/api-specs", response_model=ApiSpecDetail, status_code=201)
async def upload_spec(project_id: str, repo: Repository, file: UploadFile) -> ApiSpecDetail:
    """Upload and parse an OpenAPI/Swagger spec (offline). Rejects anything unparseable."""
    project = repo.get_project(project_id)
    raw = await file.read(MAX_SPEC_BYTES + 1)
    if len(raw) > MAX_SPEC_BYTES:
        raise ValidationFailedError(f"Spec exceeds the {MAX_SPEC_BYTES // (1024 * 1024)} MB limit")
    try:
        inventory = build_inventory(load_spec(raw))
    except SpecError as exc:
        raise ValidationFailedError(f"Not a valid OpenAPI/Swagger spec: {exc}") from exc
    artifact = ImportArtifact(
        import_id=new_id("import"),
        project_id=project_id,
        display_filename=sanitize_display_filename(file.filename or "spec"),
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        source_type="openapi_spec",
        source_tool_version=f"{inventory.kind} {inventory.version}",
        status="parsed",
        parser_version=CATALOG_VERSION,
        warnings=inventory.warnings[:1000],
        record_count=len(inventory.operations),
    )
    created = repo.create_import(artifact, raw)
    repo.audit.record(
        AuditAction.IMPORT_CREATED,
        project_id=project_id,
        target_ids=[created.import_id],
        metadata={
            "kind": inventory.kind,
            "operations": len(inventory.operations),
            "sha256": created.sha256,
        },
    )
    policy = ScopePolicy(project)
    return ApiSpecDetail(
        summary=_summary(created, inventory),
        inventory=inventory.as_dict(),
        servers=_server_views(inventory, policy),
    )


def _summary(artifact: ImportArtifact, inventory: ApiInventory) -> ApiSpecSummary:
    return ApiSpecSummary(
        import_id=artifact.import_id,
        display_filename=artifact.display_filename,
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        status=artifact.status,
        uploaded_at=artifact.uploaded_at.isoformat(),
        kind=inventory.kind,
        version=inventory.version,
        title=inventory.title,
        operation_count=len(inventory.operations),
        warnings=inventory.warnings[:50],
    )


@router.get("/projects/{project_id}/api-specs", response_model=list[ApiSpecSummary])
def list_specs(project_id: str, repo: Repository) -> list[ApiSpecSummary]:
    repo.get_project(project_id)
    out: list[ApiSpecSummary] = []
    page = repo.list_imports(project_id, offset=0, limit=200)
    for artifact in page.items:
        if artifact.source_type != "openapi_spec":
            continue
        out.append(
            ApiSpecSummary(
                import_id=artifact.import_id,
                display_filename=artifact.display_filename,
                sha256=artifact.sha256,
                size_bytes=artifact.size_bytes,
                status=artifact.status,
                uploaded_at=artifact.uploaded_at.isoformat(),
                version=artifact.source_tool_version,
                operation_count=artifact.record_count,
                warnings=artifact.warnings[:20],
            )
        )
    return out


@router.get("/projects/{project_id}/api-specs/{import_id}", response_model=ApiSpecDetail)
def spec_detail(project_id: str, import_id: str, repo: Repository) -> ApiSpecDetail:
    """Full offline inventory for a stored spec, with server scope classification."""
    project = repo.get_project(project_id)
    artifact, inventory = _inventory_for(repo, project_id, import_id)
    return ApiSpecDetail(
        summary=_summary(artifact, inventory),
        inventory=inventory.as_dict(),
        servers=_server_views(inventory, ScopePolicy(project)),
    )


class ValidateResponse(StrictModel):
    valid: bool
    kind: str
    version: str
    operation_count: int
    warnings: list[str]
    remote_refs: list[str]
    cyclic_refs: list[str]
    in_scope_servers: list[str]
    out_of_scope_servers: list[str]


@router.get(
    "/projects/{project_id}/api-specs/{import_id}/validate", response_model=ValidateResponse
)
def validate_spec(project_id: str, import_id: str, repo: Repository) -> ValidateResponse:
    project = repo.get_project(project_id)
    _artifact, inventory = _inventory_for(repo, project_id, import_id)
    views = _server_views(inventory, ScopePolicy(project))
    return ValidateResponse(
        valid=True,
        kind=inventory.kind,
        version=inventory.version,
        operation_count=len(inventory.operations),
        warnings=inventory.warnings,
        remote_refs=inventory.remote_refs,
        cyclic_refs=inventory.cyclic_refs,
        in_scope_servers=[v.expanded for v in views if v.in_scope],
        out_of_scope_servers=[v.expanded for v in views if not v.in_scope],
    )


class ApiProfilePreview(StrictModel):
    problems: list[str]
    inventory_only: bool
    server_in_scope: bool
    server_reason: str
    operations_total: int


@router.post("/projects/{project_id}/api-security-plan", response_model=ApiProfilePreview)
def api_scan_profile(project_id: str, body: dict[str, Any], repo: Repository) -> ApiProfilePreview:
    """Preview parameter validity and the chosen server's scope (no network)."""
    project = repo.get_project(project_id)
    problems = validate_parameters(body)
    import_id = str(body.get("import_id", ""))
    operations_total = 0
    server_in_scope = False
    server_reason = "no server selected"
    try:
        _artifact, inventory = _inventory_for(repo, project_id, import_id)
        operations_total = len(inventory.operations)
        server_url = str(body.get("server_url", "")).strip()
        if server_url:
            decision = ScopePolicy(project).is_target_in_scope(server_url)
            server_in_scope = decision.allowed
            server_reason = decision.message[:200]
    except (NotFoundError, ValidationFailedError) as exc:
        problems = [*problems, str(exc)]
    return ApiProfilePreview(
        problems=problems,
        inventory_only=bool(body.get("inventory_only", True)),
        server_in_scope=server_in_scope,
        server_reason=server_reason,
        operations_total=operations_total,
    )


# `ScopeDefinition` import keeps mypy aware of the server-URL scope model shape.
_ = ScopeDefinition
_UNUSED = Annotated[int, Query()]
