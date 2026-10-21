"""API scan profile and parameters (MASTER_SPEC 7.2-7.6).

Safety posture encoded here:
- `inventory_only` (default True unless the operator selects checks): zero network requests.
- Auth material is referenced by env/keychain ALIAS only (`env:NAME`), never a secret value.
- IDOR/BOLA needs two identities + an object-ownership map + test-safe ops, else skipped.
- Mass-assignment write and any mutating probe need test-safe + fixture + opt-in + cleanup.
- Rate-limit probe runs only on a designated safe operation with a small cap.
Parameters are validated at submit; unknown keys are rejected (422).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, field_validator

from app.models.common import StrictModel

PROFILE_VERSION = 1
MAX_SELECTED_OPS = 500
MAX_IDENTITIES = 4
MAX_OBJECT_IDS = 20
RATE_PROBE_MAX = 20  # hard cap on benign repeated requests
RATE_PROBE_DEFAULT = 8
AliasRef = Annotated[str, StringConstraints(pattern=r"^env:[A-Z][A-Z0-9_]{1,127}$")]


class AuthProfile(StrictModel):
    """Credential material by reference only (resolved from the environment at run time)."""

    alias: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,39}$")]
    scheme: Literal["bearer", "header", "cookie", "basic"] = "bearer"
    header_name: Annotated[str, StringConstraints(max_length=64)] = "Authorization"
    secret_ref: AliasRef  # e.g. env:VAPT_API_TOKEN_A


class TestIdentity(StrictModel):
    label: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,39}$")]
    auth_alias: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,39}$")]


class ObjectOwnership(StrictModel):
    """Which identity owns which object id, for a specific operation/path parameter."""

    operation_key: Annotated[str, StringConstraints(max_length=550)]  # "GET /users/{id}"
    param_name: Annotated[str, StringConstraints(max_length=120)]
    owner_label: Annotated[str, StringConstraints(max_length=40)]
    object_id: Annotated[str, StringConstraints(max_length=200)]


class ApiScanParameters(StrictModel):
    """Typed parameters carried in the scan request (parsed from the generic dict)."""

    import_id: Annotated[str, StringConstraints(pattern=r"^imp_[0-9a-f]{32}$")]
    server_url: Annotated[str, StringConstraints(max_length=2048)] = ""  # chosen in-scope server
    inventory_only: bool = True
    excluded_operations: list[str] = Field(default_factory=list, max_length=MAX_SELECTED_OPS)
    selected_operations: list[str] = Field(default_factory=list, max_length=MAX_SELECTED_OPS)
    auth_profiles: list[AuthProfile] = Field(default_factory=list, max_length=8)
    # checks (all default to the safe side)
    check_unauth_baseline: bool = False
    check_error_leakage: bool = True
    check_config: bool = True
    check_mass_assignment_inventory: bool = True
    # active / gated
    enable_idor: bool = False
    identities: list[TestIdentity] = Field(default_factory=list, max_length=MAX_IDENTITIES)
    ownership: list[ObjectOwnership] = Field(default_factory=list, max_length=MAX_OBJECT_IDS)
    enable_mass_assignment_write: bool = False
    mass_assignment_fixture: str = ""
    cleanup_configured: bool = False
    write_safe_operations: list[str] = Field(default_factory=list, max_length=50)
    enable_rate_probe: bool = False
    rate_probe_operation: str = ""
    rate_probe_count: int = Field(default=RATE_PROBE_DEFAULT, ge=1, le=RATE_PROBE_MAX)
    risk_ack: bool = False

    @field_validator("excluded_operations", "selected_operations", "write_safe_operations")
    @classmethod
    def _op_keys(cls, v: list[str]) -> list[str]:
        for key in v:
            if len(key) > 550:
                raise ValueError("operation key too long")
        return v


def parse_parameters(params: dict[str, Any]) -> ApiScanParameters:
    return ApiScanParameters.model_validate(params)


def validate_parameters(params: dict[str, Any]) -> list[str]:
    """Human-readable problems; empty means acceptable. Unknown keys raise in the model."""
    try:
        parsed = parse_parameters(params)
    except Exception as exc:  # noqa: BLE001 - surfaced as a validation message
        return [f"invalid API scan parameters: {str(exc)[:300]}"]
    problems: list[str] = []
    if parsed.enable_idor:
        labels = {i.label for i in parsed.identities}
        if len(parsed.identities) < 2:
            problems.append("IDOR needs at least two test identities")
        if len(parsed.ownership) < 2:
            problems.append("IDOR needs an object-ownership map (at least two owned objects)")
        for own in parsed.ownership:
            if own.owner_label not in labels:
                problems.append(f"ownership references unknown identity {own.owner_label!r}")
        auth_aliases = {a.alias for a in parsed.auth_profiles}
        for ident in parsed.identities:
            if ident.auth_alias not in auth_aliases:
                problems.append(f"identity {ident.label!r} references unknown auth alias")
    if parsed.enable_mass_assignment_write:
        if not parsed.mass_assignment_fixture:
            problems.append("mass-assignment write needs a disposable test fixture")
        if not parsed.cleanup_configured:
            problems.append("mass-assignment write needs a configured cleanup procedure")
        if not parsed.write_safe_operations:
            problems.append("mass-assignment write needs explicit test-safe operations")
        if not parsed.risk_ack:
            problems.append("active write probe requires risk acknowledgement (risk_ack=true)")
    if parsed.enable_rate_probe and not parsed.rate_probe_operation:
        problems.append("rate-limit probe needs a designated safe operation")
    active = parsed.enable_idor or parsed.enable_mass_assignment_write or parsed.enable_rate_probe
    if active and not parsed.risk_ack:
        problems.append("active checks require risk acknowledgement (risk_ack=true)")
    return problems


class CheckPlan(StrictModel):
    group: str
    label: str
    kind: Literal["passive", "probe", "active", "tool"]
    rule_ids: list[str]
    enabled: bool
    reason: str = ""


class ApiScanProfile(StrictModel):
    profile_version: int = PROFILE_VERSION
    catalog_version: str
    import_id: str
    inventory_only: bool
    server_url: str
    server_in_scope: bool
    operations_total: int
    operations_selected: int
    auth_aliases: list[str]
    checks: list[CheckPlan]
    idor_ready: bool
    idor_skip_reason: str
    mass_write_ready: bool
    mass_write_skip_reason: str
    rate_probe_ready: bool
    limitations: list[str]


LIMITATIONS = [
    "Inventory and validation run fully offline; network checks require an in-scope server URL.",
    "BOLA/IDOR runs only with two test identities and an explicit object-ownership map; no ID "
    "guessing or enumeration, and no mutation of another user's resource.",
    "Mass-assignment writes are disabled unless the operation is test-safe with a fixture, "
    "opt-in and cleanup; by default only request schemas are inventoried.",
    "Rate-limit probing is a small capped benign sequence on one designated safe operation; "
    "not tripping a limit does not prove one is absent.",
    "HTTP status alone is not treated as proof of an access-control outcome.",
    "Remote $ref fetching is disabled; CVE mapping needs an imported catalog (Phase 11).",
]


def _alias(value: str) -> str:
    return value
