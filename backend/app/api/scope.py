"""Scope policy routes (Phase 03): policy view, dry-run checks, internal-target override.

Nothing here sends traffic or resolves DNS. `/scope/check` evaluates a URL (and,
optionally, addresses the caller says it resolves to) against the policy so the
operator can see exactly what would be allowed or blocked and why.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import Field

from app.api.deps import Repository
from app.models.common import ScopeStatus, StrictModel
from app.models.project import InternalTargetOverride, Project, ScopeDefinition
from app.scope.engine import Decision, ScopePolicy
from app.services.projects import InternalOverrideRequest, ProjectService
from app.services.scope_preview import BlockedRangeView, blocked_ranges_view

router = APIRouter(prefix="/api", tags=["scope"])


class OverrideView(StrictModel):
    override: InternalTargetOverride
    active: bool


class ScopePolicyView(StrictModel):
    project_id: str
    scope: ScopeDefinition
    scope_hash: str
    valid: bool
    authorization: Decision
    can_start_active_work: bool
    internal_override: OverrideView | None
    warnings: list[str]
    blocked_ranges: list[BlockedRangeView]


class ScopeCheckRequest(StrictModel):
    url: str = Field(min_length=1, max_length=4096)
    resolved_ips: list[str] = Field(default_factory=list, max_length=16)


class ScopeCheckResponse(StrictModel):
    allowed: bool
    summary: str
    authorization: Decision
    target: Decision
    resolved_ips: list[Decision]
    dns_note: str | None


class DiscoveredHostRequest(StrictModel):
    host: str = Field(min_length=1, max_length=255)


class DiscoveredHostResponse(StrictModel):
    status: ScopeStatus
    decision: Decision


def _policy(repo: Repository, project_id: str) -> tuple[Project, ScopePolicy]:
    project = repo.get_project(project_id)
    return project, ScopePolicy(project)


@router.get("/scope/blocked-ranges", response_model=list[BlockedRangeView])
def blocked_ranges() -> list[BlockedRangeView]:
    return blocked_ranges_view()


@router.get("/projects/{project_id}/scope/policy", response_model=ScopePolicyView)
def scope_policy(project_id: str, repo: Repository) -> ScopePolicyView:
    project, policy = _policy(repo, project_id)
    auth = policy.authorization()
    override = project.scope.internal_override
    return ScopePolicyView(
        project_id=project.project_id,
        scope=project.scope,
        scope_hash=policy.hash,
        valid=policy.valid,
        authorization=auth,
        can_start_active_work=auth.allowed and policy.valid,
        internal_override=(
            OverrideView(override=override, active=policy.clock() < override.expires_at)
            if override
            else None
        ),
        warnings=policy.warnings(),
        blocked_ranges=blocked_ranges_view(),
    )


@router.post("/projects/{project_id}/scope/check", response_model=ScopeCheckResponse)
def scope_check(project_id: str, body: ScopeCheckRequest, repo: Repository) -> ScopeCheckResponse:
    """Dry run: no DNS lookup and no request is made."""
    _, policy = _policy(repo, project_id)
    auth = policy.authorization()
    target = policy.is_target_in_scope(body.url)
    host = target.target or body.url
    ip_decisions = [policy.validate_resolved_ip(host, ip) for ip in body.resolved_ips]
    is_ip_literal = target.ip is not None
    dns_note = None
    if target.allowed and not is_ip_literal and not body.resolved_ips:
        dns_note = (
            "DNS was not resolved in this dry run. At request time every resolved address is "
            "checked against the blocked ranges and exclusions before any connection."
        )
    allowed = auth.allowed and target.allowed and all(d.allowed for d in ip_decisions)
    if allowed:
        summary = "Would be allowed"
    else:
        first = next(d for d in (target, *ip_decisions, auth) if not d.allowed)
        summary = f"Would be blocked: {first.message}"
    return ScopeCheckResponse(
        allowed=allowed,
        summary=summary[:500],
        authorization=auth,
        target=target,
        resolved_ips=ip_decisions,
        dns_note=dns_note,
    )


@router.post("/projects/{project_id}/scope/classify-host", response_model=DiscoveredHostResponse)
def classify_host(
    project_id: str, body: DiscoveredHostRequest, repo: Repository
) -> DiscoveredHostResponse:
    """How a discovered hostname would be classified (discovery never implies approval)."""
    from app.scope.guard import MemorySink, ScopeGuard

    project, _ = _policy(repo, project_id)

    class _NoDns:
        def resolve(self, host: str) -> list[str]:  # never called: classification is DNS-free
            raise RuntimeError("discovered-host classification must never resolve DNS")

    status, decision = ScopeGuard(
        project, resolver=_NoDns(), sink=MemorySink()
    ).classify_discovered_host(body.host)
    return DiscoveredHostResponse(status=status, decision=decision)


@router.put("/projects/{project_id}/internal-override", response_model=Project)
def set_internal_override(
    project_id: str, body: InternalOverrideRequest, repo: Repository
) -> Project:
    return ProjectService(repo).set_internal_override(project_id, body)


@router.delete("/projects/{project_id}/internal-override", response_model=Project)
def remove_internal_override(
    project_id: str, repo: Repository, expected_revision: Annotated[int, Query(ge=1)]
) -> Project:
    return ProjectService(repo).remove_internal_override(project_id, expected_revision)
