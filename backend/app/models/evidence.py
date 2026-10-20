"""Evidence metadata. The optional binary blob is stored by the storage layer under an
opaque, ID-derived name; records never carry filesystem paths."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from app.models.common import (
    DataClassification,
    EvidenceId,
    FindingId,
    Name,
    ProjectId,
    Record,
    ScanId,
    Sha256Hex,
    ShortText,
)

EVIDENCE_SCHEMA_VERSION: Literal[1] = 1
MAX_EXCERPT_CHARS = 8192  # TBD-009


class EvidenceMetadata(Record):
    schema_version: Literal[1] = EVIDENCE_SCHEMA_VERSION
    evidence_id: EvidenceId
    project_id: ProjectId
    scan_id: ScanId | None = None
    finding_ids: list[FindingId] = Field(default_factory=list, max_length=200)
    evidence_type: Literal[
        "http_exchange",
        "tls_certificate",
        "dns_record",
        "tool_output",
        "text_excerpt",
        "file_signature",
    ]
    source_stage: ShortText = ""
    source_tool: Name = "vapt-workbench"
    request_excerpt: Annotated[str, StringConstraints(max_length=MAX_EXCERPT_CHARS)] = ""
    response_excerpt: Annotated[str, StringConstraints(max_length=MAX_EXCERPT_CHARS)] = ""
    excerpt_truncated: bool = False
    bytes_observed: int | None = Field(default=None, ge=0)
    sha256: Sha256Hex | None = None  # hash of the observed bytes (pre-truncation)
    classification: DataClassification = DataClassification.CONFIDENTIAL
    has_blob: bool = False
    blob_sha256: Sha256Hex | None = None
    blob_size: int | None = Field(default=None, ge=0)
