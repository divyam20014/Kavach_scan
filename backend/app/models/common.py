"""Shared building blocks for canonical contracts: strict base, IDs, bounded types, enums."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Generic, TypeVar

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
)

# --------------------------------------------------------------------------- base


class StrictModel(BaseModel):
    """Unknown keys are rejected; assignments are re-validated."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


def utc_now() -> datetime:
    return datetime.now(UTC)


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


UtcDatetime = Annotated[AwareDatetime, AfterValidator(_to_utc)]

# --------------------------------------------------------------------------- IDs

ID_PREFIXES = {
    "project": "prj",
    "scan": "scn",
    "asset": "ast",
    "finding": "fnd",
    "evidence": "evd",
    "import": "imp",
    "report": "rpt",
    "event": "evt",
    "comment": "cmt",
}
_ID_RE = {kind: re.compile(rf"^{p}_[0-9a-f]{{32}}$") for kind, p in ID_PREFIXES.items()}
ANY_ID_RE = re.compile(r"^(" + "|".join(ID_PREFIXES.values()) + r")_[0-9a-f]{32}$")


def new_id(kind: str) -> str:
    return f"{ID_PREFIXES[kind]}_{uuid.uuid4().hex}"


def is_valid_id(kind: str, value: str) -> bool:
    return bool(_ID_RE[kind].fullmatch(value))


ProjectId = Annotated[str, StringConstraints(pattern=r"^prj_[0-9a-f]{32}$")]
ScanId = Annotated[str, StringConstraints(pattern=r"^scn_[0-9a-f]{32}$")]
AssetId = Annotated[str, StringConstraints(pattern=r"^ast_[0-9a-f]{32}$")]
FindingId = Annotated[str, StringConstraints(pattern=r"^fnd_[0-9a-f]{32}$")]
EvidenceId = Annotated[str, StringConstraints(pattern=r"^evd_[0-9a-f]{32}$")]
ImportId = Annotated[str, StringConstraints(pattern=r"^imp_[0-9a-f]{32}$")]
ReportId = Annotated[str, StringConstraints(pattern=r"^rpt_[0-9a-f]{32}$")]
EventId = Annotated[str, StringConstraints(pattern=r"^evt_[0-9a-f]{32}$")]
CommentId = Annotated[str, StringConstraints(pattern=r"^cmt_[0-9a-f]{32}$")]

# --------------------------------------------------------------------------- bounded text

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _no_control_chars(value: str) -> str:
    if _CONTROL.search(value):
        raise ValueError("control characters are not allowed")
    return value


Name = Annotated[
    str, StringConstraints(min_length=1, max_length=200), AfterValidator(_no_control_chars)
]
ShortText = Annotated[str, StringConstraints(max_length=500), AfterValidator(_no_control_chars)]
LongText = Annotated[str, StringConstraints(max_length=20_000)]
Tag = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 _.:/-]+$")
]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Locator = Annotated[
    str, StringConstraints(min_length=1, max_length=2048), AfterValidator(_no_control_chars)
]

# Secrets are never stored; only references such as `env:VAPT_TEST_USER_TOKEN` (TBD-010).
SecretRef = Annotated[str, StringConstraints(pattern=r"^env:[A-Z][A-Z0-9_]{1,127}$")]

_CREDENTIAL_ALIAS_RE = re.compile(r"^(env|keychain):[A-Za-z0-9_.-]{1,100}$")


def _validate_credential_alias(value: str) -> str:
    """Never a raw secret: only a reference to where the real value lives (TBD-058 pattern).
    This is what makes 'write-only, never returned by a read API' true by construction --
    the app never stores (or could echo back) the secret itself, only this alias. Shared by
    `IntegrationsSettings.online_lookup_credential_alias` and
    `Project.repository_credential_alias` (TBD-100) -- moved here rather than duplicated so
    both fields are validated by exactly one regex."""
    if value == "":
        return value
    if not _CREDENTIAL_ALIAS_RE.fullmatch(value):
        raise ValueError(
            "credential must be a reference, not a raw secret: 'env:NAME' or 'keychain:NAME'"
        )
    return value


CredentialAlias = Annotated[str, AfterValidator(_validate_credential_alias)]

# --------------------------------------------------------------------------- enums


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(StrEnum):  # TBD-021
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POTENTIAL = "potential"
    NEEDS_REVIEW = "needs_review"


class AnalystStatus(StrEnum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    RETEST_NEEDED = "retest_needed"
    NEEDS_REVIEW = "needs_review"


class ScanModule(StrEnum):
    WEB_APP = "web_app"  # Option A
    ATTACK_SURFACE = "attack_surface"  # Option B
    API_SECURITY = "api_security"  # Option C
    REPO_SCAN = "repo_scan"  # roadmap Phase 2: repository scanning (Semgrep/Gitleaks/Trivy)
    # security/reliability/scope roadmap Phase 3: container image vulnerability scanning
    # (Trivy, native-executable only) against an already-pulled local Docker image.
    CONTAINER_IMAGE = "container_image"
    SELF_TEST = "self_test"  # job-system self-test; no network activity; dev/test only


class ScanState(StrEnum):
    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    BLOCKED_SCOPE = "blocked_scope"
    EXPIRED_AUTHORIZATION = "expired_authorization"


class ProjectStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class AssetType(StrEnum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    URL = "url"
    API_OPERATION = "api_operation"


class ScopeStatus(StrEnum):
    IN_SCOPE = "in_scope"
    PENDING_APPROVAL = "pending_approval"
    OUT_OF_SCOPE = "out_of_scope"
    EXCLUDED = "excluded"
    UNRESOLVED = "unresolved"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# --------------------------------------------------------------------------- record base


class Record(StrictModel):
    """Fields shared by every canonical, individually stored record."""

    revision: int = Field(default=1, ge=1)
    created_at: UtcDatetime = Field(default_factory=utc_now)
    updated_at: UtcDatetime = Field(default_factory=utc_now)


T = TypeVar("T")


class RecordError(StrictModel):
    """A record that could not be loaded; reported instead of crashing the listing."""

    record_id: str | None = None
    project_id: str | None = None
    kind: str
    message: ShortText


class Page(StrictModel, Generic[T]):
    items: list[T]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)
    errors: list[RecordError] = Field(default_factory=list)
