"""Web scan profile: which checks run, with which budgets, derived from the project's scan
policy and the start request's parameters. The same object is shown in the UI before the
operator confirms and is written into the job's outputs (the job manifest).

Safe mode is always on in this build: the scanner sends no injection test input
(TBD-049). Injection coverage comes from passive indicators plus imported tool results.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from app.models.common import StrictModel
from app.models.project import ScanPolicy
from app.scanners.webapp.rules import CATALOG_VERSION, RULES, Kind

PROFILE_VERSION = 1
MAX_SEED_PATHS = 20

# parameter name -> (type, default, description). Unknown names are rejected at submit.
PARAMETERS: dict[str, tuple[type, Any, str]] = {
    "seed_paths": (str, "", "Extra in-scope start paths, comma separated"),
    "max_pages": (int, None, "Lower the page limit for this scan"),
    "max_depth": (int, None, "Lower the crawl depth for this scan"),
    "respect_robots": (bool, True, "Honour robots.txt disallow rules while crawling"),
    "tls_verify": (bool, True, "Verify TLS certificates (off: crawl hosts with invalid certs)"),
    "check_cors": (bool, True, "Send one request per origin with a test Origin header"),
    "run_tls_tool": (bool, True, "Run sslyze/testssl.sh when installed"),
}

LIMITATIONS = [
    "Active injection testing is not built in: no SQL injection or XSS test input is sent. "
    "Passive indicators only; import results from a dedicated tool (e.g. OWASP ZAP, Burp "
    "Suite) for injection coverage.",
    "JavaScript is not executed; links created only by scripts are not discovered.",
    "Authenticated crawling is not configured in this build; only unauthenticated pages "
    "are covered.",
    "Content-Security-Policy is checked for presence and basic unsafe patterns only.",
    "Sensitive-file probing is not built in; directory listings, debug and default pages "
    "are detected only on pages the crawler reaches.",
    "Without sslyze or testssl.sh no protocol/cipher coverage is claimed.",
]


class ProfileCheck(StrictModel):
    group: str
    label: str
    kind: Literal["passive", "probe", "active", "tool"]
    rule_ids: list[str]
    enabled: bool
    reason: str = ""


class Budgets(StrictModel):
    max_pages: int
    max_depth: int
    requests_per_second: float
    max_concurrency: int
    max_requests_per_target: int
    max_duration_seconds: int
    max_response_bytes: int
    max_redirects: int


class WebScanProfile(StrictModel):
    profile_version: int = PROFILE_VERSION
    catalog_version: str = CATALOG_VERSION
    safe_mode: bool = True
    auth_profile: str | None = None  # authenticated crawling is not configured in this build
    respect_robots: bool
    tls_verify: bool
    seed_paths: list[str] = Field(default_factory=list)
    budgets: Budgets
    checks: list[ProfileCheck]
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))

    def enabled(self, group: str) -> bool:
        return any(c.group == group and c.enabled for c in self.checks)


GROUPS: list[tuple[str, str, list[str], str | None]] = [
    # group, label, rules, toggle parameter (None = always on)
    (
        "transport",
        "HTTPS availability, redirect and certificate",
        ["WEB-TLS-001", "WEB-TLS-002", "WEB-TLS-003", "WEB-TLS-004"],
        None,
    ),
    (
        "tls_tool",
        "TLS protocol/cipher analysis (sslyze/testssl.sh)",
        ["WEB-TLS-005", "WEB-TLS-006"],
        "run_tls_tool",
    ),
    ("headers", "Security headers", [f"WEB-HDR-00{i}" for i in range(1, 9)], None),
    ("cookies", "Cookie attributes", ["WEB-COOKIE-001", "WEB-COOKIE-002", "WEB-COOKIE-003"], None),
    (
        "disclosure",
        "Version leakage, debug/default pages, directory listing",
        ["WEB-INFO-001", "WEB-INFO-002", "WEB-INFO-003", "WEB-INFO-004"],
        None,
    ),
    ("sensitive_files", "Sensitive-file exposure probing", ["WEB-FILE-001"], None),
    ("redirects", "Unsafe redirect indicators (passive)", ["WEB-REDIR-001"], None),
    ("cors", "CORS policy", ["WEB-CORS-001"], "check_cors"),
    ("caching", "Caching of sensitive-looking responses", ["WEB-CACHE-001"], None),
    ("components", "Component/version detection", ["WEB-COMP-001"], None),
    ("cve", "CVE matching (local catalog)", ["WEB-COMP-002"], None),
    (
        "injection_indicators",
        "Passive injection indicators (reflection, database errors)",
        ["WEB-REFL-001", "WEB-DBERR-001"],
        None,
    ),
    ("active_injection", "Active SQL injection / XSS testing", ["WEB-INJ-000"], None),
]
ALWAYS_SKIPPED = {
    "cve": "Runs only when a local CVE catalog is imported (none imported in this build)",
    "active_injection": "Not built in: use imported results from a dedicated tool",
    "sensitive_files": "Not built in: use imported results from a dedicated tool",
}


def _bool(params: dict[str, Any], name: str) -> bool:
    return bool(params.get(name, PARAMETERS[name][1]))


def _split(text: str) -> list[str]:
    return [p.strip() for p in text.replace("\n", ",").split(",") if p.strip()]


def validate_parameters(params: dict[str, Any], policy: ScanPolicy) -> list[str]:
    """Return human-readable problems; empty means the parameters are acceptable."""
    errors: list[str] = []
    for name, value in params.items():
        if name not in PARAMETERS:
            errors.append(f"unknown parameter {name!r} for the web scanner")
            continue
        kind = PARAMETERS[name][0]
        if value is None:
            continue
        if kind is bool and not isinstance(value, bool):
            errors.append(f"{name} must be true or false")
        elif kind is int and (isinstance(value, bool) or not isinstance(value, int)):
            errors.append(f"{name} must be an integer")
        elif kind is str and not isinstance(value, str):
            errors.append(f"{name} must be text")
    pages = params.get("max_pages")
    if (
        isinstance(pages, int)
        and not isinstance(pages, bool)
        and not 1 <= pages <= policy.max_pages
    ):
        errors.append(f"max_pages must be between 1 and the project limit ({policy.max_pages})")
    depth = params.get("max_depth")
    if (
        isinstance(depth, int)
        and not isinstance(depth, bool)
        and not (0 <= depth <= policy.max_crawl_depth)
    ):
        errors.append(
            f"max_depth must be between 0 and the project limit ({policy.max_crawl_depth})"
        )
    seeds = params.get("seed_paths")
    if isinstance(seeds, str) and seeds:
        paths = _split(seeds)
        if len(paths) > MAX_SEED_PATHS:
            errors.append(f"at most {MAX_SEED_PATHS} seed paths")
        if any(not p.startswith("/") or "://" in p or "\\" in p for p in paths):
            errors.append("seed paths must be relative paths starting with '/'")
    return errors


def build_profile(params: dict[str, Any], policy: ScanPolicy) -> WebScanProfile:
    checks: list[ProfileCheck] = []
    for group, label, rule_ids, toggle in GROUPS:
        kinds = {RULES[r].kind for r in rule_ids}
        kind = next(k for k in (Kind.ACTIVE, Kind.TOOL, Kind.PROBE, Kind.PASSIVE) if k in kinds)
        enabled, reason = True, ""
        if group in ALWAYS_SKIPPED:
            enabled, reason = False, ALWAYS_SKIPPED[group]
        elif toggle is not None and not _bool(params, toggle):
            enabled, reason = False, "Disabled for this scan"
        checks.append(
            ProfileCheck(
                group=group,
                label=label,
                kind=kind.value,
                rule_ids=rule_ids,
                enabled=enabled,
                reason=reason,
            )
        )
    pages = params.get("max_pages")
    depth = params.get("max_depth")
    seeds = params.get("seed_paths")
    return WebScanProfile(
        respect_robots=_bool(params, "respect_robots"),
        tls_verify=_bool(params, "tls_verify"),
        seed_paths=_split(seeds) if isinstance(seeds, str) else [],
        budgets=Budgets(
            max_pages=min(int(pages), policy.max_pages) if pages else policy.max_pages,
            max_depth=policy.max_crawl_depth if depth is None else int(depth),
            requests_per_second=policy.requests_per_second,
            max_concurrency=policy.max_concurrency,
            max_requests_per_target=policy.max_requests_per_target,
            max_duration_seconds=policy.max_duration_seconds,
            max_response_bytes=policy.max_response_bytes,
            max_redirects=policy.max_redirects,
        ),
        checks=checks,
    )
