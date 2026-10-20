"""Persisted, operator-editable application settings. Never contains secret values."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.common import Name, StrictModel, UtcDatetime, utc_now
from app.models.project import ScanPolicy

SETTINGS_SCHEMA_VERSION: Literal[1] = 1


class AppSettings(StrictModel):
    schema_version: Literal[1] = SETTINGS_SCHEMA_VERSION
    product_name: Name = "VAPT Workbench"  # TBD-004
    default_scan_policy: ScanPolicy = Field(default_factory=ScanPolicy)
    disk_space_warning_bytes: int = Field(default=2 * 1024**3, ge=0)
    evidence_quota_bytes: int | None = Field(default=None, ge=1)
    report_timezone_label: Literal["UTC"] = "UTC"
    revision: int = Field(default=1, ge=1)
    updated_at: UtcDatetime = Field(default_factory=utc_now)
