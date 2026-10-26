"""Project, authorization record, scope definition and scan policy contracts.

Scope fields are validated syntactically here. Canonicalization and allow/deny
matching belong to the scope engine (Phase 03), which must not trust these
values merely because they parsed.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Network, IPv6Network
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from app.models.common import (
    CredentialAlias,
    EventId,
    LongText,
    Name,
    ProjectId,
    ProjectStatus,
    Record,
    ScanModule,
    ShortText,
    StrictModel,
    Tag,
    UtcDatetime,
)

PROJECT_SCHEMA_VERSION: Literal[1] = 1

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOST_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*\.?$")


_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")


def _hostname(value: str) -> str:
    value = value.lower()
    if len(value) > 253 or not _HOST_RE.fullmatch(value):
        raise ValueError("not a valid DNS hostname (use punycode for IDN hosts)")
    value = value.rstrip(".")
    labels = value.split(".")
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        # "127.1", "2130706433", "10.0.0.1": numeric forms belong in ip_ranges, never hosts
        raise ValueError("numeric host: list IP addresses under ip_ranges")
    return value


def _wildcard(value: str) -> str:
    value = value.lower()
    if not value.startswith("*."):
        raise ValueError("wildcard domains must start with '*.'")
    _hostname(value[2:])
    return value.rstrip(".")


def _path_prefix(value: str) -> str:
    if not value.startswith("/") or "\\" in value or "\x00" in value:
        raise ValueError("path prefixes must start with '/' and contain no backslashes")
    return value


def _http_url(value: str) -> str:
    if not re.match(r"^https?://[^\s/@]+(/[^\s]*)?$", value, re.IGNORECASE):
        raise ValueError("must be an http(s) URL without credentials or whitespace")
    return value


def _repository_path(value: str) -> str:
    """An operator-supplied local filesystem path to scan (roadmap Phase 2: repo_scan).
    Mirrors `ToolPath`'s own posture (TBD-domain for integrations settings): must be an
    absolute path, never required to exist *yet* -- the directory may not exist at the
    moment the project is configured, or may be moved/deleted later. Existence and
    "is actually a directory" are runtime checks at scan-start time
    (`RepoScanRunner.validate_parameters`/`run`), never a model-validation-time concern,
    since the filesystem can change between configuration and execution."""
    if value == "":
        return value
    from pathlib import Path

    if not Path(value).is_absolute():
        raise ValueError("repository path must be an absolute path, or empty")
    if len(value) > 2048:
        raise ValueError("repository path is too long")
    return value


def _repository_url(value: str) -> str:
    """An operator-supplied remote repository URL to clone (git-clone-from-URL roadmap,
    phase 5: repo_scan). Mirrors `app.scanners.repo_scan.git_clone.validate_https_url`'s own
    restriction -- plain `https://`, no embedded credentials, no whitespace -- but is
    intentionally a separate, independent check: that module re-validates again,
    immediately before building a clone argv, as defense in depth, never trusting this model
    validator alone (the same posture `ToolPath`/`RepositoryPath` already take relative to
    each other in this codebase)."""
    if value == "":
        return value
    if not re.match(r"^https://[^\s/@]+(/[^\s]*)?$", value, re.IGNORECASE):
        raise ValueError(
            "repository URL must be a plain https:// URL, without embedded credentials or "
            "whitespace"
        )
    if len(value) > 2048:
        raise ValueError("repository URL is too long")
    return value


Hostname = Annotated[str, StringConstraints(max_length=253), AfterValidator(_hostname)]
WildcardDomain = Annotated[str, StringConstraints(max_length=255), AfterValidator(_wildcard)]
PathPrefix = Annotated[
    str, StringConstraints(min_length=1, max_length=1024), AfterValidator(_path_prefix)
]
HttpUrlStr = Annotated[str, StringConstraints(max_length=2048), AfterValidator(_http_url)]
RepositoryPath = Annotated[str, AfterValidator(_repository_path)]
RepositoryUrl = Annotated[str, AfterValidator(_repository_url)]
Port = Annotated[int, Field(ge=1, le=65535)]
Network = IPv4Network | IPv6Network


class AuthorizationRecord(StrictModel):
    organization: Name
    target_owner: Name
    authorized_by: Name
    reference: ShortText = ""
    window_start: UtcDatetime
    window_end: UtcDatetime
    attestation_event_id: EventId | None = None
    notes: LongText = ""

    @model_validator(mode="after")
    def _window_order(self) -> AuthorizationRecord:
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        return self


class ScopeExclusions(StrictModel):
    hosts: list[Hostname] = Field(default_factory=list, max_length=1000)
    wildcard_domains: list[WildcardDomain] = Field(default_factory=list, max_length=200)
    ip_ranges: list[Network] = Field(default_factory=list, max_length=500)
    ports: list[Port] = Field(default_factory=list, max_length=200)
    path_prefixes: list[PathPrefix] = Field(default_factory=list, max_length=500)


class InternalTargetOverride(StrictModel):
    """Explicit, narrow, time-bound permission to reach otherwise blocked ranges."""

    ip_ranges: list[Network] = Field(min_length=1, max_length=50)
    reason: Annotated[str, StringConstraints(min_length=10, max_length=500)]
    expires_at: UtcDatetime
    audit_event_id: EventId


Scheme = Literal["http", "https"]


def _default_schemes() -> list[Scheme]:
    return ["https"]


class ScopeDefinition(StrictModel):
    schemes: list[Scheme] = Field(default_factory=_default_schemes, min_length=1, max_length=2)
    hosts: list[Hostname] = Field(default_factory=list, max_length=1000)
    wildcard_domains: list[WildcardDomain] = Field(default_factory=list, max_length=200)
    ip_ranges: list[Network] = Field(default_factory=list, max_length=500)
    ports: list[Port] = Field(default_factory=lambda: [80, 443], max_length=200)
    path_prefixes: list[PathPrefix] = Field(default_factory=lambda: ["/"], max_length=500)
    api_server_urls: list[HttpUrlStr] = Field(default_factory=list, max_length=100)
    exclusions: ScopeExclusions = Field(default_factory=ScopeExclusions)
    redirect_policy: Literal["same_scope_only"] = "same_scope_only"
    internal_override: InternalTargetOverride | None = None


class ActiveProbeToggles(StrictModel):
    """All active/injection probes are disabled by default (TBD-014, TBD-016)."""

    sqli_error_differential: bool = False
    xss_reflection: bool = False
    api_mutating_operations: bool = False
    api_idor: bool = False
    api_rate_limit_probe: bool = False


class ScanPolicy(StrictModel):
    """Conservative defaults from TBD-011; hard caps from docs/SCAN_SAFETY.md §6."""

    max_concurrency: int = Field(default=2, ge=1, le=8)
    requests_per_second: float = Field(default=2.0, gt=0, le=10)
    connect_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    read_timeout_seconds: float = Field(default=15.0, gt=0, le=60)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_crawl_depth: int = Field(default=3, ge=0, le=10)
    max_pages: int = Field(default=200, ge=1, le=2000)
    max_response_bytes: int = Field(default=1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    max_duration_seconds: int = Field(default=1800, ge=60, le=8 * 3600)
    max_requests_per_target: int = Field(default=2000, ge=1, le=20_000)
    allowed_modules: list[ScanModule] = Field(default_factory=list, max_length=4)
    active_probes: ActiveProbeToggles = Field(default_factory=ActiveProbeToggles)
    evidence_retention_days: int | None = Field(default=None, ge=1, le=3650)


class Project(Record):
    schema_version: Literal[1] = PROJECT_SCHEMA_VERSION
    project_id: ProjectId
    name: Name
    client_name: Name
    description: LongText = ""
    status: ProjectStatus = ProjectStatus.ACTIVE
    authorization: AuthorizationRecord | None = None
    scope: ScopeDefinition = Field(default_factory=ScopeDefinition)
    # Not part of `scope`: that model is strictly network-target-shaped (hosts/ports/
    # schemes), while this is a local filesystem path for the repo_scan module -- a
    # structurally different kind of "where this project's subject lives" (roadmap Phase 2).
    repository_path: RepositoryPath = ""
    # Additive to, and mutually exclusive with, `repository_path` (git-clone-from-URL
    # roadmap, phase 5, TBD-100): an operator-supplied remote URL the repo_scan module
    # clones into an ephemeral per-scan work directory instead of scanning a pre-existing
    # local checkout. `repository_credential_alias` is meaningless without it.
    repository_url: RepositoryUrl = ""
    repository_credential_alias: CredentialAlias = ""
    scan_policy: ScanPolicy = Field(default_factory=ScanPolicy)
    labels: list[Tag] = Field(default_factory=list, max_length=50)
    notes: LongText = ""

    @model_validator(mode="after")
    def _repository_source_is_unambiguous(self) -> Project:
        if self.repository_path and self.repository_url:
            raise ValueError("repository_path and repository_url are mutually exclusive")
        if self.repository_credential_alias and not self.repository_url:
            raise ValueError("repository_credential_alias requires repository_url")
        return self
