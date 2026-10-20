"""Attack-surface routes (Phase 06): scan profile preview, asset graph/table with transparent
priority, operator criticality, and explicit approval of discovered hosts.

None of these routes sends network traffic: scans start only through the gated job routes.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import Field

from app.api.deps import Repository
from app.core.errors import ValidationFailedError
from app.models.asset import Asset, Criticality
from app.models.audit import AuditAction
from app.models.common import AssetType, ScopeStatus, StrictModel
from app.models.project import Project
from app.scanners.surface.inventory import iter_assets
from app.scanners.surface.profile import build_profile, validate_parameters
from app.scanners.surface.ranking import rank
from app.scope.engine import ScopePolicy
from app.services.projects import ProjectService

router = APIRouter(prefix="/api", tags=["surface"])
MAX_GRAPH_ASSETS = 5000


class SurfaceProfilePreview(StrictModel):
    profile: dict[str, Any]
    problems: list[str]
    target_problems: list[str]
    nmap: str | None


class SurfaceAsset(StrictModel):
    asset: Asset
    candidate_status: str  # scope status, or "unresolved" when DNS failed
    priority: int
    priority_factors: list[str]
    findings: int


class SurfaceView(StrictModel):
    items: list[SurfaceAsset]
    total: int
    counts: dict[str, dict[str, int]]
    edges: list[tuple[str, str]]
    truncated: bool


class CriticalityRequest(StrictModel):
    expected_revision: int = Field(ge=1)
    criticality: Criticality | None


class ApproveRequest(StrictModel):
    expected_project_revision: int = Field(ge=1)
    confirmed: bool


@router.get("/projects/{project_id}/surface-scan-profile", response_model=SurfaceProfilePreview)
def surface_profile(
    project_id: str,
    repo: Repository,
    targets: Annotated[list[str] | None, Query(max_length=50)] = None,
    hosts: Annotated[str, Query(max_length=200_000)] = "",
    ports: Annotated[str, Query(max_length=1000)] = "",
    port_method: Literal["auto", "connect", "nmap"] = "auto",
    max_hosts: Annotated[int, Query(ge=1, le=1000)] = 50,
    passive_crtsh: bool = False,
    probe_web: bool = True,
    web_max_pages: Annotated[int, Query(ge=1, le=50)] = 5,
    read_banners: bool = True,
    tls_verify: bool = True,
) -> SurfaceProfilePreview:
    from app.integrations.nmap import detect_nmap
    from app.scanners.surface.runner import check_targets

    project = repo.get_project(project_id)
    policy = ScopePolicy(project)
    params: dict[str, Any] = {
        "port_method": port_method,
        "max_hosts": max_hosts,
        "passive_crtsh": passive_crtsh,
        "probe_web": probe_web,
        "web_max_pages": web_max_pages,
        "read_banners": read_banners,
        "tls_verify": tls_verify,
    }
    if hosts:
        params["hosts"] = hosts
    if ports:
        params["ports"] = ports
    problems = validate_parameters(params, project.scan_policy)
    roots, target_problems = check_targets(list(targets or []), policy) if targets else ([], [])
    nmap = detect_nmap()
    profile = build_profile(
        params if not problems else {}, roots, policy, nmap_available=nmap is not None
    )
    return SurfaceProfilePreview(
        profile=profile.model_dump(mode="json"),
        problems=problems,
        target_problems=[f"{(targets or [''])[i]}: {msg}" for i, msg in target_problems],
        nmap=nmap.executable if nmap else None,
    )


def _candidate_status(asset: Asset) -> str:
    if asset.resolution_status == "unresolved" and asset.scope_status in (
        ScopeStatus.IN_SCOPE,
        ScopeStatus.PENDING_APPROVAL,
    ):
        return "unresolved"
    return asset.scope_status.value


@router.get("/projects/{project_id}/surface", response_model=SurfaceView)
def surface_view(
    project_id: str,
    repo: Repository,
    asset_type: Annotated[list[AssetType] | None, Query()] = None,
    status: Annotated[list[str] | None, Query(max_length=10)] = None,
    q: Annotated[str, Query(max_length=200)] = "",
    sort: Literal["priority", "last_seen", "locator", "first_seen"] = "priority",
) -> SurfaceView:
    repo.get_project(project_id)
    assets = list(iter_assets(repo, project_id))
    findings = []
    offset = 0
    while offset < 20_000:
        page = repo.list_findings(project_id, offset=offset, limit=200)
        findings += page.items
        offset += 200
        if offset >= page.total:
            break
    ranks = rank(assets, findings)
    counts: dict[str, dict[str, int]] = {"type": {}, "status": {}}
    rows: list[SurfaceAsset] = []
    for a in assets:
        cand = _candidate_status(a)
        counts["type"][a.asset_type.value] = counts["type"].get(a.asset_type.value, 0) + 1
        counts["status"][cand] = counts["status"].get(cand, 0) + 1
        if asset_type and a.asset_type not in asset_type:
            continue
        if status and cand not in status:
            continue
        if q and q.lower() not in a.locator.lower():
            continue
        rk = ranks[a.asset_id]
        rows.append(
            SurfaceAsset(
                asset=a,
                candidate_status=cand,
                priority=rk["score"],
                priority_factors=rk["factors"],
                findings=rk["findings"],
            )
        )
    key = {
        "priority": lambda r: (-r.priority, r.asset.locator),
        "last_seen": lambda r: (-r.asset.last_seen.timestamp(), r.asset.locator),
        "first_seen": lambda r: (-r.asset.first_seen.timestamp(), r.asset.locator),
        "locator": lambda r: (r.asset.locator,),
    }[sort]
    rows.sort(key=key)
    shown = rows[:MAX_GRAPH_ASSETS]
    ids = {r.asset.asset_id for r in shown}
    edges: list[tuple[str, str]] = []
    for row in shown:
        for parent in [row.asset.parent_asset_id, *row.asset.related_asset_ids]:
            if parent and parent in ids:
                edges.append((parent, row.asset.asset_id))
    return SurfaceView(
        items=shown,
        total=len(rows),
        counts=counts,
        edges=edges,
        truncated=len(rows) > MAX_GRAPH_ASSETS,
    )


@router.patch("/projects/{project_id}/assets/{asset_id}", response_model=Asset)
def set_criticality(
    project_id: str, asset_id: str, body: CriticalityRequest, repo: Repository
) -> Asset:
    before = repo.get_asset(project_id, asset_id)
    updated = repo.update_asset(
        project_id,
        asset_id,
        {"criticality": body.criticality},
        expected_revision=body.expected_revision,
    )
    repo.audit.record(
        AuditAction.ASSET_CRITICALITY_CHANGED,
        project_id=project_id,
        target_ids=[asset_id],
        metadata={"from": before.criticality, "to": body.criticality, "locator": before.locator},
    )
    return updated


@router.post("/projects/{project_id}/assets/{asset_id}/approve", response_model=Project)
def approve_asset(
    project_id: str, asset_id: str, body: ApproveRequest, repo: Repository
) -> Project:
    """Approve a discovered hostname: adds it to the project scope (audited scope change)."""
    if not body.confirmed:
        raise ValidationFailedError("Explicit confirmation is required to add a host to the scope")
    asset = repo.get_asset(project_id, asset_id)
    if asset.asset_type != AssetType.HOSTNAME:
        raise ValidationFailedError("Only discovered hostnames can be approved")
    project = ProjectService(repo).approve_discovered_host(
        project_id, asset.locator, body.expected_project_revision
    )
    repo.update_asset(project_id, asset_id, {"scope_status": ScopeStatus.IN_SCOPE.value})
    return project
