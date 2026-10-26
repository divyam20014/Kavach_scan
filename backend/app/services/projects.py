"""Project use cases: create/update/archive/delete with audit events and authorization status."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import Field, model_validator

from app.core.errors import ValidationFailedError
from app.models.audit import AuditAction
from app.models.common import (
    CredentialAlias,
    LongText,
    Name,
    Page,
    ProjectStatus,
    ShortText,
    StrictModel,
    Tag,
    UtcDatetime,
    new_id,
    utc_now,
)
from app.models.project import (
    AuthorizationRecord,
    InternalTargetOverride,
    Network,
    Project,
    RepositoryPath,
    RepositoryUrl,
    ScanPolicy,
    ScopeDefinition,
)
from app.scope.engine import scope_hash
from app.scope.ip_policy import network_blocked_overlap
from app.storage.repository import StorageRepository

EXPIRING_SOON = timedelta(days=7)
AuthorizationStatus = Literal["missing", "not_started", "active", "expiring_soon", "expired"]


class AuthorizationInput(StrictModel):
    organization: Name
    target_owner: Name
    authorized_by: Name
    reference: ShortText = ""
    window_start: UtcDatetime
    window_end: UtcDatetime
    notes: LongText = ""
    attestation: bool = Field(description="Operator attestation that the authorization is genuine")

    @model_validator(mode="after")
    def _check(self) -> AuthorizationInput:
        if not self.attestation:
            raise ValueError("Operator attestation is required to record an authorization")
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        return self


class ProjectCreate(StrictModel):
    name: Name
    client_name: Name
    description: LongText = ""
    labels: list[Tag] = Field(default_factory=list, max_length=50)
    notes: LongText = ""
    authorization: AuthorizationInput | None = None
    scope: ScopeDefinition = Field(default_factory=ScopeDefinition)
    scope_preview_hash: str | None = Field(
        default=None, description="scope_hash returned by /api/scope/preview for exactly this scope"
    )
    # Not part of `scope` (roadmap Phase 2, TBD-087/088): a local filesystem path for the
    # repo_scan module, structurally unrelated to the network-target fields `scope` holds.
    repository_path: RepositoryPath = ""
    # Additive to, and mutually exclusive with, `repository_path` (git-clone-from-URL
    # roadmap, phase 5, TBD-100): `Project`'s own model validator enforces exclusivity and
    # that an alias requires a URL -- this DTO does not duplicate that check.
    repository_url: RepositoryUrl = ""
    repository_credential_alias: CredentialAlias = ""
    scan_policy: ScanPolicy = Field(default_factory=ScanPolicy)


class ProjectUpdate(StrictModel):
    expected_revision: int = Field(ge=1)
    name: Name | None = None
    client_name: Name | None = None
    description: LongText | None = None
    labels: list[Tag] | None = Field(default=None, max_length=50)
    notes: LongText | None = None
    status: ProjectStatus | None = None
    authorization: AuthorizationInput | None = None
    scope: ScopeDefinition | None = None
    scope_preview_hash: str | None = None
    repository_path: RepositoryPath | None = None
    repository_url: RepositoryUrl | None = None
    repository_credential_alias: CredentialAlias | None = None
    scan_policy: ScanPolicy | None = None


OVERRIDE_MAX_DAYS = 90
OVERRIDE_MIN_PREFIX = {4: 16, 6: 48}


class InternalOverrideRequest(StrictModel):
    expected_revision: int = Field(ge=1)
    ip_ranges: list[Network] = Field(min_length=1, max_length=50)
    reason: ShortText = Field(min_length=10)
    expires_at: UtcDatetime
    attestation: bool

    @model_validator(mode="after")
    def _check(self) -> InternalOverrideRequest:
        if not self.attestation:
            raise ValueError("Operator attestation is required for an internal-target override")
        now = utc_now()
        if self.expires_at <= now:
            raise ValueError("expires_at must be in the future")
        if self.expires_at - now > timedelta(days=OVERRIDE_MAX_DAYS):
            raise ValueError(f"overrides may last at most {OVERRIDE_MAX_DAYS} days")
        for net in self.ip_ranges:
            if net.prefixlen < OVERRIDE_MIN_PREFIX[net.version]:
                raise ValueError(
                    f"{net} is too broad; use /{OVERRIDE_MIN_PREFIX[net.version]} or narrower"
                )
            overlaps = network_blocked_overlap(net)
            if any(not b.overridable for b in overlaps):
                raise ValueError(
                    f"{net} includes cloud metadata addresses, which can never be overridden"
                )
            if not overlaps:
                raise ValueError(f"{net} is not a blocked range; no override is needed")
        return self


class LastScan(StrictModel):
    scan_id: str
    state: str
    at: str | None


class ProjectOverview(StrictModel):
    project: Project
    authorization_status: AuthorizationStatus
    authorization_expires_at: UtcDatetime | None
    last_scan: LastScan | None
    counts: dict[str, int]


class DeletionImpact(StrictModel):
    project_id: str
    name: str
    counts: dict[str, int]
    confirm_with: str = Field(description="Type this exact project name to confirm deletion")


def authorization_status(project: Project, now: datetime | None = None) -> AuthorizationStatus:
    auth = project.authorization
    if auth is None:
        return "missing"
    now = now or utc_now()
    if now < auth.window_start:
        return "not_started"
    if now >= auth.window_end:
        return "expired"
    if auth.window_end - now <= EXPIRING_SOON:
        return "expiring_soon"
    return "active"


class ProjectService:
    COUNTED = ("scan", "finding", "asset", "evidence", "import", "report")

    def __init__(self, repo: StorageRepository) -> None:
        self.repo = repo

    # ------------------------------------------------------------------ reads

    def counts(self, project_id: str) -> dict[str, int]:
        return {kind: len(self.repo.summaries(kind, project_id)[0]) for kind in self.COUNTED}

    def last_scan(self, project_id: str) -> LastScan | None:
        entries, _ = self.repo.summaries("scan", project_id)
        if not entries:
            return None
        scan_id, entry = max(entries.items(), key=lambda kv: str(kv[1].get("updated_at") or ""))
        return LastScan(scan_id=scan_id, state=str(entry.get("state")), at=entry.get("updated_at"))

    def overview(self, project: Project) -> ProjectOverview:
        return ProjectOverview(
            project=project,
            authorization_status=authorization_status(project),
            authorization_expires_at=project.authorization.window_end
            if project.authorization
            else None,
            last_scan=self.last_scan(project.project_id),
            counts=self.counts(project.project_id),
        )

    def list(self, **kwargs: Any) -> Page[ProjectOverview]:
        page = self.repo.list_projects(**kwargs)
        return Page[ProjectOverview](
            items=[self.overview(p) for p in page.items],
            total=page.total,
            offset=page.offset,
            limit=page.limit,
            errors=page.errors,
        )

    # ------------------------------------------------------------------ writes

    def _attest(self, project_id: str, auth: AuthorizationInput) -> AuthorizationRecord:
        event = self.repo.audit.record(
            AuditAction.AUTHORIZATION_ATTESTED,
            project_id=project_id,
            metadata={
                "authorized_by": auth.authorized_by,
                "reference": auth.reference,
                "window_start": auth.window_start.isoformat(),
                "window_end": auth.window_end.isoformat(),
                "label": "operator attestation (not legal verification)",
            },
        )
        data = auth.model_dump(exclude={"attestation"})
        return AuthorizationRecord(**data, attestation_event_id=event.event_id)

    @staticmethod
    def _check_scope_payload(scope: ScopeDefinition, preview_hash: str | None) -> None:
        if scope.internal_override is not None:
            raise ValidationFailedError(
                "internal_override cannot be set through project create/update; "
                "use the dedicated internal-target override endpoint"
            )
        if preview_hash != scope_hash(scope):
            raise ValidationFailedError(
                "Scope must be previewed before saving: scope_preview_hash does not "
                "match this scope "
                "(call /api/scope/preview and send back its scope_hash)"
            )

    def create(self, req: ProjectCreate) -> Project:
        if "scope" in req.model_fields_set:
            self._check_scope_payload(req.scope, req.scope_preview_hash)
        project_id = new_id("project")
        authorization = self._attest(project_id, req.authorization) if req.authorization else None
        project = Project(
            project_id=project_id,
            name=req.name,
            client_name=req.client_name,
            description=req.description,
            labels=req.labels,
            notes=req.notes,
            authorization=authorization,
            scope=req.scope,
            repository_path=req.repository_path,
            repository_url=req.repository_url,
            repository_credential_alias=req.repository_credential_alias,
            scan_policy=req.scan_policy,
        )
        created = self.repo.create_project(project)
        self.repo.audit.record(
            AuditAction.PROJECT_CREATED,
            project_id=project_id,
            target_ids=[project_id],
            metadata={"name": created.name, "scope_hash": scope_hash(created.scope)},
        )
        return created

    def update(self, project_id: str, req: ProjectUpdate) -> Project:
        current = self.repo.get_project(project_id)
        changes: dict[str, Any] = {}
        for field in (
            "name",
            "client_name",
            "description",
            "labels",
            "notes",
            "status",
            "repository_path",
            "repository_url",
            "repository_credential_alias",
            "scan_policy",
        ):
            value = getattr(req, field)
            if value is not None:
                changes[field] = (
                    value.model_dump(mode="json") if hasattr(value, "model_dump") else value
                )
        new_scope = None
        if req.scope is not None:
            self._check_scope_payload(req.scope, req.scope_preview_hash)
            # the override is managed only by its own endpoint; keep the stored one
            new_scope = req.scope.model_copy(
                update={"internal_override": current.scope.internal_override}
            )
            changes["scope"] = new_scope.model_dump(mode="json")
        scope_changed = new_scope is not None and scope_hash(new_scope) != scope_hash(current.scope)
        if req.authorization is not None:
            changes["authorization"] = self._attest(project_id, req.authorization).model_dump(
                mode="json"
            )
        if not changes:
            raise ValidationFailedError("No changes supplied")
        updated = self.repo.update_project(
            project_id, changes, expected_revision=req.expected_revision
        )
        if scope_changed:
            self.repo.audit.record(
                AuditAction.SCOPE_CHANGED,
                project_id=project_id,
                metadata={
                    "old_scope_hash": scope_hash(current.scope),
                    "new_scope_hash": scope_hash(updated.scope),
                },
            )
        if req.status == ProjectStatus.ARCHIVED and current.status != ProjectStatus.ARCHIVED:
            self.repo.audit.record(AuditAction.PROJECT_ARCHIVED, project_id=project_id)
        self.repo.audit.record(
            AuditAction.PROJECT_UPDATED,
            project_id=project_id,
            metadata={"fields": sorted(changes), "revision": updated.revision},
        )
        return updated

    def approve_discovered_host(
        self, project_id: str, host: str, expected_revision: int
    ) -> Project:
        """Add a discovered hostname to the scope's exact hosts (explicit operator action).

        Only candidates that the scope policy classifies as `pending_approval` (subdomains of
        an authorized host/root) can be approved here; anything else needs a scope edit with
        a fresh preview. The change is audited like any scope edit.
        """
        from app.models.common import ScopeStatus
        from app.scope.engine import ScopePolicy

        current = self.repo.get_project(project_id)
        status, _ = ScopePolicy(current).host_status(host)
        if status != ScopeStatus.PENDING_APPROVAL:
            raise ValidationFailedError(
                f"{host} is {status.value}; only pending-approval candidates can be approved here"
            )
        scope = current.scope.model_copy(update={"hosts": [*current.scope.hosts, host]})
        updated = self.repo.update_project(
            project_id,
            {"scope": scope.model_dump(mode="json")},
            expected_revision=expected_revision,
        )
        self.repo.audit.record(
            AuditAction.SCOPE_CHANGED,
            project_id=project_id,
            metadata={
                "old_scope_hash": scope_hash(current.scope),
                "new_scope_hash": scope_hash(updated.scope),
                "reason": f"discovered host approved: {host}",
            },
        )
        self.repo.audit.record(
            AuditAction.ASSET_APPROVED,
            project_id=project_id,
            target_ids=[host],
            metadata={"host": host, "label": "operator approval of a discovered host"},
        )
        return updated

    def set_internal_override(self, project_id: str, req: InternalOverrideRequest) -> Project:
        current = self.repo.get_project(project_id)
        event = self.repo.audit.record(
            AuditAction.INTERNAL_OVERRIDE_SET,
            project_id=project_id,
            metadata={
                "ip_ranges": [str(n) for n in req.ip_ranges],
                "reason": req.reason,
                "expires_at": req.expires_at.isoformat(),
                "label": "operator attestation (not legal verification)",
            },
        )
        override = InternalTargetOverride(
            ip_ranges=req.ip_ranges,
            reason=req.reason,
            expires_at=req.expires_at,
            audit_event_id=event.event_id,
        )
        scope = current.scope.model_copy(update={"internal_override": override})
        try:
            return self.repo.update_project(
                project_id,
                {"scope": scope.model_dump(mode="json")},
                expected_revision=req.expected_revision,
            )
        except Exception:
            self.repo.audit.record(
                AuditAction.INTERNAL_OVERRIDE_SET,
                project_id=project_id,
                outcome="failure",
                metadata={"audit_event_id": event.event_id},
            )
            raise

    def remove_internal_override(self, project_id: str, expected_revision: int) -> Project:
        current = self.repo.get_project(project_id)
        if current.scope.internal_override is None:
            raise ValidationFailedError("This project has no internal-target override")
        scope = current.scope.model_copy(update={"internal_override": None})
        updated = self.repo.update_project(
            project_id,
            {"scope": scope.model_dump(mode="json")},
            expected_revision=expected_revision,
        )
        self.repo.audit.record(AuditAction.INTERNAL_OVERRIDE_REMOVED, project_id=project_id)
        return updated

    def deletion_impact(self, project_id: str) -> DeletionImpact:
        project = self.repo.get_project(project_id)
        return DeletionImpact(
            project_id=project_id,
            name=project.name,
            counts=self.counts(project_id),
            confirm_with=project.name,
        )

    def delete(self, project_id: str, confirm_name: str) -> DeletionImpact:
        impact = self.deletion_impact(project_id)
        if confirm_name != impact.confirm_with:
            raise ValidationFailedError(
                "Confirmation does not match the project name; nothing was deleted"
            )
        self.repo.delete_project(project_id)
        self.repo.audit.record(
            AuditAction.PROJECT_DELETED,
            project_id=project_id,
            target_ids=[project_id],
            metadata={"name": impact.name, "removed": impact.counts},
        )
        return impact
