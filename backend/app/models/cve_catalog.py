"""A locally imported CVE catalog (MASTER_SPEC Module 11). Never fetched online — operators
import a file; TBD-028 forbids bundling third-party vulnerability data in this release."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from app.models.common import (
    LongText,
    Name,
    Sha256Hex,
    ShortText,
    StrictModel,
    UtcDatetime,
    utc_now,
)

CVE_CATALOG_SCHEMA_VERSION: Literal[1] = 1
PARSER_VERSION = "vapt-cve-catalog 1.0.0"
MAX_ENTRIES = 20_000

CveId = Annotated[str, StringConstraints(pattern=r"^CVE-\d{4}-\d{4,19}$")]
VersionSpec = Annotated[str, StringConstraints(min_length=1, max_length=200)]


class CveCatalogEntry(StrictModel):
    """One product/version-range -> CVE mapping, exactly as the imported file stated it."""

    product: Name
    version_spec: VersionSpec  # e.g. "<1.12.4" or ">=2.0,<2.3.1" or "==1.0.0"
    cve_id: CveId
    summary: ShortText = ""
    references: list[ShortText] = Field(default_factory=list, max_length=20)


class CveCatalogRecord(StrictModel):
    """The single active, operator-imported CVE catalog. Importing a new one replaces it."""

    schema_version: Literal[1] = CVE_CATALOG_SCHEMA_VERSION
    source: ShortText  # operator-provided label, e.g. "Internal curated export, 2026-10"
    catalog_version: ShortText  # operator-provided version/date label from the file
    imported_at: UtcDatetime = Field(default_factory=utc_now)
    file_sha256: Sha256Hex
    file_name: ShortText = ""
    parser_version: ShortText = PARSER_VERSION
    stale_after_days: int = Field(default=180, ge=1, le=3650)
    entries: list[CveCatalogEntry] = Field(default_factory=list, max_length=MAX_ENTRIES)
    warnings: list[ShortText] = Field(default_factory=list, max_length=50)
    notes: LongText = ""
    revision: int = Field(default=1, ge=1)
