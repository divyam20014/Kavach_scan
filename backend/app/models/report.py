"""Generated-report metadata (Phase 10: rendering, export, backup/restore)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.common import (
    AssetId,
    FindingId,
    Name,
    ProjectId,
    Record,
    ReportId,
    Sha256Hex,
    ShortText,
)

REPORT_SCHEMA_VERSION: Literal[1] = 1

ReportFormat = Literal["html", "pdf", "json", "csv"]


class ReportMetadata(Record):
    schema_version: Literal[1] = REPORT_SCHEMA_VERSION
    report_id: ReportId
    project_id: ProjectId
    title: Name
    classification_label: ShortText = "CONFIDENTIAL"
    formats: list[ReportFormat] = Field(min_length=1, max_length=4)
    file_sha256: dict[ReportFormat, Sha256Hex] = Field(default_factory=dict)
    # Resolved at generation time and never recomputed afterward, so a downloaded file always
    # matches exactly what the operator previewed and confirmed (Phase 10 acceptance
    # criterion: "the same selected findings appear consistently in preview and files").
    finding_ids: list[FindingId] = Field(default_factory=list, max_length=10_000)
    asset_ids: list[AssetId] = Field(default_factory=list, max_length=10_000)
    evidence_included: bool = False
    filters: dict[str, ShortText | int | bool | list[ShortText]] = Field(
        default_factory=dict, max_length=50
    )
    generator_version: ShortText = ""
