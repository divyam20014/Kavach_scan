"""Project use cases: create/update/archive/delete with audit events and authorization status."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import Field, model_validator

from app.core.errors import ValidationFailedError
from app.models.audit import AuditAction
from app.models.common import (
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
from app.models.project import AuthorizationRecord, Project, ScanPolicy, ScopeDefinition
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
    scan_policy: ScanPolicy | None = None


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


def scope_hash(scope: ScopeDefinition) -> str:
    return hashlib.sha256(
        json.dumps(scope.model_dump(mode="json"), sort_keys=True).encode()
    ).hexdigest()


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

    def create(self, req: ProjectCreate) -> Project:
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
            "scan_policy",
        ):
            value = getattr(req, field)
            if value is not None:
                changes[field] = (
                    value.model_dump(mode="json") if hasattr(value, "model_dump") else value
                )
        scope_changed = req.scope is not None and scope_hash(req.scope) != scope_hash(current.scope)
        if req.scope is not None:
            changes["scope"] = req.scope.model_dump(mode="json")
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
