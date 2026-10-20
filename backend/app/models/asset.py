"""Asset inventory record (domain → host → IP → port/service → URL → API operation)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from app.models.common import (
    AssetId,
    AssetType,
    Confidence,
    EvidenceId,
    Locator,
    ProjectId,
    Record,
    ScanId,
    ScopeStatus,
    ShortText,
    Tag,
    UtcDatetime,
    utc_now,
)

ASSET_SCHEMA_VERSION: Literal[1] = 1

AttributeKey = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
AttributeValue = Annotated[str, StringConstraints(max_length=500)] | int | float | bool | None
Criticality = Literal["low", "medium", "high", "critical"]


class Asset(Record):
    schema_version: Literal[1] = ASSET_SCHEMA_VERSION
    asset_id: AssetId
    project_id: ProjectId
    asset_type: AssetType
    locator: Locator  # canonical locator, e.g. "https://app.example.com:443"
    parent_asset_id: AssetId | None = None
    first_seen: UtcDatetime = Field(default_factory=utc_now)
    last_seen: UtcDatetime = Field(default_factory=utc_now)
    source_scan_id: ScanId | None = None
    confidence: Confidence = Confidence.POTENTIAL
    scope_status: ScopeStatus = ScopeStatus.PENDING_APPROVAL
    tags: list[Tag] = Field(default_factory=list, max_length=50)
    observations: list[ShortText] = Field(default_factory=list, max_length=200)
    evidence_ids: list[EvidenceId] = Field(default_factory=list, max_length=500)
    # Phase 06 (optional, backward compatible): graph edges beyond the single parent (an IP
    # can serve several hosts), scanner attributes, DNS outcome, operator criticality.
    related_asset_ids: list[AssetId] = Field(default_factory=list, max_length=200)
    attributes: dict[AttributeKey, AttributeValue] = Field(default_factory=dict, max_length=60)
    resolution_status: Literal["resolved", "unresolved", "not_attempted"] | None = None
    criticality: Criticality | None = None
