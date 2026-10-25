"""Persisted, operator-editable application settings. Never contains secret values."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import AfterValidator, Field

from app.models.common import Name, StrictModel, UtcDatetime, utc_now
from app.models.project import ScanPolicy

SETTINGS_SCHEMA_VERSION: Literal[1] = 1

_CREDENTIAL_ALIAS_RE = re.compile(r"^(env|keychain):[A-Za-z0-9_.-]{1,100}$")


def _validate_tool_path(value: str) -> str:
    """An explicit executable-path override. Never required to exist yet (the operator may
    configure it before installing the tool), but must be an absolute path — never a bare
    command name (which would silently fall back to PATH lookup) and never a relative path
    (ambiguous relative to an unspecified working directory)."""
    if value == "":
        return value
    from pathlib import Path

    p = Path(value)
    if not p.is_absolute():
        raise ValueError("tool path must be an absolute path, or empty to auto-detect from PATH")
    if len(value) > 1024:
        raise ValueError("tool path is too long")
    return value


def _validate_credential_alias(value: str) -> str:
    """Never a raw secret: only a reference to where the real value lives (TBD-058 pattern).
    This is what makes 'write-only, never returned by settings-read API' true by construction
    — the app never stores (or could echo back) the secret itself, only this alias."""
    if value == "":
        return value
    if not _CREDENTIAL_ALIAS_RE.fullmatch(value):
        raise ValueError(
            "credential must be a reference, not a raw secret: 'env:NAME' or 'keychain:NAME'"
        )
    return value


ToolPath = Annotated[str, AfterValidator(_validate_tool_path)]
CredentialAlias = Annotated[str, AfterValidator(_validate_credential_alias)]


class IntegrationsSettings(StrictModel):
    """Optional external-tool/data-source configuration (Phase 11, Module 11/12).

    Executable paths are overrides only: empty means "auto-detect from PATH" (the existing
    Phase 05/06 behavior). `online_lookup_credential_alias` is reserved for a future, explicitly
    opt-in online data source (TBD-068) — no such source is wired to any network call in this
    release; it exists so the configuration surface and its validation can be exercised now."""

    nmap_path: ToolPath = ""
    sslyze_path: ToolPath = ""
    testssl_path: ToolPath = ""
    online_lookup_credential_alias: CredentialAlias = ""


class AppSettings(StrictModel):
    schema_version: Literal[1] = SETTINGS_SCHEMA_VERSION
    product_name: Name = "VAPT Workbench"  # TBD-004
    default_scan_policy: ScanPolicy = Field(default_factory=ScanPolicy)
    disk_space_warning_bytes: int = Field(default=2 * 1024**3, ge=0)
    evidence_quota_bytes: int | None = Field(default=None, ge=1)
    report_timezone_label: Literal["UTC"] = "UTC"
    integrations: IntegrationsSettings = Field(default_factory=IntegrationsSettings)
    revision: int = Field(default=1, ge=1)
    updated_at: UtcDatetime = Field(default_factory=utc_now)
