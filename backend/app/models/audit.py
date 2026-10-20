"""Append-only audit event. `metadata` is redacted by the storage layer before writing."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field

from app.models.common import EventId, Name, ProjectId, ShortText, StrictModel, UtcDatetime, utc_now

AUDIT_SCHEMA_VERSION: Literal[1] = 1


class AuditAction(StrEnum):
    PROJECT_CREATED = "project_created"
    PROJECT_UPDATED = "project_updated"
    PROJECT_ARCHIVED = "project_archived"
    PROJECT_DELETED = "project_deleted"
    SCOPE_CHANGED = "scope_changed"
    AUTHORIZATION_ATTESTED = "authorization_attested"
    SCAN_STARTED = "scan_started"
    SCAN_CANCELLED = "scan_cancelled"
    KILL_SWITCH_CHANGED = "kill_switch_changed"
    TOOL_CONFIG_CHANGED = "tool_config_changed"
    IMPORT_CREATED = "import_created"
    IMPORT_COMMITTED = "import_committed"
    FINDING_STATE_CHANGED = "finding_state_changed"
    REPORT_GENERATED = "report_generated"
    REPORT_DOWNLOADED = "report_downloaded"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"
    SAFETY_OVERRIDE_ATTEMPTED = "safety_override_attempted"
    SETTINGS_CHANGED = "settings_changed"
    STORAGE_INITIALIZED = "storage_initialized"
    STORAGE_MIGRATED = "storage_migrated"
    INTEGRITY_CHECKED = "integrity_checked"
    INTERNAL_OVERRIDE_SET = "internal_override_set"
    INTERNAL_OVERRIDE_REMOVED = "internal_override_removed"


class AuditEvent(StrictModel):
    schema_version: Literal[1] = AUDIT_SCHEMA_VERSION
    event_id: EventId
    ts: UtcDatetime = Field(default_factory=utc_now)
    actor: Name = "local-operator"
    project_id: ProjectId | None = None
    action: AuditAction
    target_ids: list[ShortText] = Field(default_factory=list, max_length=100)
    outcome: Literal["success", "failure", "blocked", "denied"] = "success"
    metadata: dict[str, Any] = Field(default_factory=dict, max_length=100)
    correlation_id: ShortText | None = None
