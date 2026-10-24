"""Metadata for an uploaded external scan report. The raw upload is stored by the storage
layer as `raw.bin` (never executed); records hold only a sanitized display filename."""

from __future__ import annotations

import re
import unicodedata
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field, StringConstraints

from app.models.common import (
    ImportId,
    ProjectId,
    Record,
    Sha256Hex,
    ShortText,
    UtcDatetime,
    utc_now,
)

IMPORT_SCHEMA_VERSION: Literal[1] = 1


def sanitize_display_filename(name: str) -> str:
    """Reduce an untrusted filename to a display-only string (never used as a path)."""
    name = unicodedata.normalize("NFKC", name)
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[\x00-\x1f\x7f<>:\"|?*]", "_", name).strip(" .")
    return (name or "upload")[:255]


def _display_filename(value: str) -> str:
    if value != sanitize_display_filename(value):
        raise ValueError("display_filename must be pre-sanitized with sanitize_display_filename()")
    return value


ImportSourceType = Literal[
    "nmap_xml",
    "nuclei_jsonl",
    "sarif",
    "zap",
    "burp",
    "nessus",
    "generic_csv",
    "generic_json",
    "pdf_text",
    "openapi_spec",
    "unknown",
]


class ImportArtifact(Record):
    schema_version: Literal[1] = IMPORT_SCHEMA_VERSION
    import_id: ImportId
    project_id: ProjectId
    display_filename: Annotated[
        str, StringConstraints(min_length=1, max_length=255), AfterValidator(_display_filename)
    ]
    sha256: Sha256Hex
    size_bytes: int = Field(ge=0)
    source_type: ImportSourceType = "unknown"
    source_tool_version: ShortText = ""
    uploaded_at: UtcDatetime = Field(default_factory=utc_now)
    status: Literal["uploaded", "parsed", "parse_failed", "committed", "rejected"] = "uploaded"
    parser_version: ShortText = ""
    warnings: list[ShortText] = Field(default_factory=list, max_length=1000)
    record_count: int = Field(default=0, ge=0)
    mapped_count: int = Field(default=0, ge=0)
    rejected_count: int = Field(default=0, ge=0)
    # Phase 08 (optional, backward compatible): the resolved adapter options (e.g. a CSV
    # column_map / JSON field_map override) so a later re-read or commit reproduces the
    # exact same parse as the original dry-run, instead of re-detecting from scratch.
    source_options: dict[str, Any] = Field(default_factory=dict, max_length=20)
