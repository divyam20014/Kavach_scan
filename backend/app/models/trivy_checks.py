"""Status record for Trivy's own misconfiguration/IaC checks bundle (security/reliability/
scope roadmap Phase 4, TBD-111). Mirrors `app/models/trivy_db.py`'s own "the operator took
an explicit, one-time action; this record is proof of that" shape -- presence of this
record means the operator explicitly triggered the download (via `POST
/api/integrations/trivy/download-checks`) at least once.

A separate record from `TrivyDbStatusRecord`, not a shared one: the checks bundle and the
vulnerability database are two independently-fetched artifacts (confirmed directly,
TBD-111 -- the checks bundle lives under `<cache_dir>/policy/`, the vulnerability database
under `<cache_dir>/db/`, both inside the same shared `trivy_db_dir()` cache root but fetched
by entirely different Trivy code paths), so an operator can have one without the other."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.common import ShortText, StrictModel, UtcDatetime, utc_now

TRIVY_CHECKS_STATUS_SCHEMA_VERSION: Literal[1] = 1


class TrivyChecksStatusRecord(StrictModel):
    schema_version: Literal[1] = TRIVY_CHECKS_STATUS_SCHEMA_VERSION
    downloaded_at: UtcDatetime = Field(default_factory=utc_now)
    trivy_version: ShortText = ""
    size_bytes: int = Field(default=0, ge=0)
    revision: int = Field(default=1, ge=1)
