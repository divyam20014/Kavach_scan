"""Scan job record. State transitions are enforced by the job manager (Phase 04)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from app.models.common import (
    Locator,
    Name,
    ProjectId,
    Record,
    ScanId,
    ScanModule,
    ScanState,
    Sha256Hex,
    ShortText,
    StrictModel,
    UtcDatetime,
)
from app.models.project import ScanPolicy, ScopeDefinition

SCAN_SCHEMA_VERSION: Literal[1] = 1

CounterName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
ParamValue = str | int | float | bool | None


class ScanProgress(StrictModel):
    stage: ShortText = ""
    percent: float | None = Field(default=None, ge=0, le=100)  # only when meaningful
    counters: dict[CounterName, int] = Field(default_factory=dict, max_length=100)


class ScanJob(Record):
    schema_version: Literal[1] = SCAN_SCHEMA_VERSION
    scan_id: ScanId
    project_id: ProjectId
    module: ScanModule
    profile: Name = "default"
    targets: list[Locator] = Field(default_factory=list, max_length=1000)
    parameters: dict[CounterName, ParamValue] = Field(default_factory=dict, max_length=100)
    state: ScanState = ScanState.QUEUED
    queued_at: UtcDatetime | None = None
    started_at: UtcDatetime | None = None
    finished_at: UtcDatetime | None = None
    progress: ScanProgress = Field(default_factory=ScanProgress)
    cancel_requested: bool = False
    actor: Name = "local-operator"
    idempotency_key: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{8,64}$")] | None = (
        None
    )
    scope_snapshot: ScopeDefinition | None = None
    scope_hash: Sha256Hex | None = None
    policy_snapshot: ScanPolicy | None = None
    app_version: ShortText = ""
    tool_versions: dict[Name, ShortText] = Field(default_factory=dict, max_length=50)
    warnings: list[ShortText] = Field(default_factory=list, max_length=500)
    errors: list[ShortText] = Field(default_factory=list, max_length=500)
