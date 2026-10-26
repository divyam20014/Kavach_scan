"""Status record for Trivy's own vulnerability database (roadmap Phase 2, TBD-087).

Mirrors `app/models/cve_catalog.py`'s own "the operator took an explicit, one-time action;
this record is proof of that" shape: presence of this record means the operator explicitly
triggered the download (via `POST /api/integrations/trivy/download-db`) at least once --
absence means they have not, exactly as `get_cve_catalog() -> None` means "never imported."
Trivy's database is never downloaded silently or automatically by a scan job -- see
`app/scanners/repo_scan/trivy_adapter.py`'s own module docstring for why."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.common import ShortText, StrictModel, UtcDatetime, utc_now

TRIVY_DB_STATUS_SCHEMA_VERSION: Literal[1] = 1


class TrivyDbStatusRecord(StrictModel):
    schema_version: Literal[1] = TRIVY_DB_STATUS_SCHEMA_VERSION
    downloaded_at: UtcDatetime = Field(default_factory=utc_now)
    trivy_version: ShortText = ""
    size_bytes: int = Field(default=0, ge=0)
    revision: int = Field(default=1, ge=1)
