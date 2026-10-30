"""Web scan profile: which checks run, with which budgets, derived from the project's scan
policy and the start request's parameters. The same object is shown in the UI before the
operator confirms and is written into the job's outputs (the job manifest).

Safe mode is always on in this build: the scanner sends no injection test input
(TBD-049). Injection coverage comes from passive indicators plus imported tool results.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import Field

from app.models.common import StrictModel
from app.models.project import ScanPolicy
from app.scanners.webapp.rules import CATALOG_VERSION, RULES, Kind

PROFILE_VERSION = 1
MAX_SEED_PATHS = 20
#: "none" (default, unauthenticated) or a single operator-configured session credential,
#: resolved only from an environment alias at run time -- never a raw secret value (mirrors
#: `apisec/profile.py`'s `AuthProfile`). See TBD_DECISIONS.md.
AUTH_SCHEMES: tuple[str, ...] = ("none", "bearer", "header", "cookie", "basic")
AUTH_ALIAS_PATTERN = re.compile(r"^env:[A-Z][A-Z0-9_]{1,127}$")

#: the native, built-in scanner stays the backward-compatible default: an older persisted
#: `ScanJob.parameters` with no `engine` key, or an older client that never sends one, gets
#: exactly the behavior it always had. "zap" selects the OWASP ZAP Baseline/Passive engine
#: (`app/scanners/zap_dast/`) instead -- see TBD-081.
ENGINES: tuple[str, ...] = ("native", "zap")
DEFAULT_ENGINE = "native"

# parameter name -> (type, default, description). Unknown names are rejected at submit.
PARAMETERS: dict[str, tuple[type, Any, str]] = {
    "engine": (
        str,
        DEFAULT_ENGINE,
        "Scan engine: 'native' (built-in checks) or 'zap' (OWASP ZAP Baseline/Passive)",
    ),
    "seed_paths": (str, "", "Extra in-scope start paths, comma separated"),
    "max_pages": (int, None, "Lower the page limit for this scan"),
    "max_depth": (int, None, "Lower the crawl depth for this scan"),
    "respect_robots": (bool, True, "Honour robots.txt disallow rules while crawling"),
    "tls_verify": (bool, True, "Verify TLS certificates (off: crawl hosts with invalid certs)"),
    "check_cors": (bool, True, "Send one request per origin with a test Origin header"),
    "run_tls_tool": (bool, True, "Run sslyze/testssl.sh when installed"),
    "check_http_methods": (bool, True, "Send one OPTIONS request per origin to read Allow"),
    "zap_spider_max_minutes": (int, 2, "engine=zap only: bounded spider duration, minutes"),
    "zap_wait_max_minutes": (int, 2, "engine=zap only: bounded passive-scan wait, minutes"),
    "auth_scheme": (
        str,
        "none",
        "Authenticated crawling: 'none' (default), 'bearer', 'header', 'cookie', or 'basic'",
    ),
    "auth_header_name": (
        str,
        "Authorization",
        "Header name for bearer/header schemes, or cookie name for the cookie scheme",
    ),
    "auth_secret_ref": (
        str,
        "",
        "Credential reference, e.g. env:VAPT_SESSION_TOKEN (required unless auth_scheme is "
        "'none'; never a raw secret value)",
    ),
}

LIMITATIONS = [
    "Active SQL injection/XSS confirmation is opt-in and disabled by default (project scan "
    "policy active_probes.sqli_error_differential/xss_reflection, TBD-115): when off, "
    "injection coverage is passive indicators only. When on, each already-crawled "
    "parameter gets exactly one confirmation request per probe type -- never a "
    "payload-fuzzing loop, never blind/time-based injection, never a fresh crawl.",
    "JavaScript is not executed; links created only by scripts are not discovered.",
    "Authenticated crawling supports exactly one operator-configured session credential "
    "(bearer/header/cookie/basic), resolved from an environment alias; it never attempts "
    "login guessing. When engine=zap, this credential is not applied -- ZAP crawls "
    "unauthenticated regardless of auth_scheme.",
    "Content-Security-Policy is checked for presence and basic unsafe patterns only.",
    "Sensitive-file probing is not built in; directory listings, debug and default pages "
    "are detected only on pages the crawler reaches.",
    "Without sslyze or testssl.sh no protocol/cipher coverage is claimed.",
    "HTTP method checks read what the server's own OPTIONS response advertises; they do not "
    "attempt TRACE/PUT/DELETE/CONNECT against any route.",
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
    # Backward compatible by construction: an older persisted profile with no `engine` key
    # (or an older client that never sends one) loads with the same native behavior it
    # always had (TBD-081).
    engine: Literal["native", "zap"] = "native"
    # Never the secret or the env alias name -- only the non-sensitive scheme/header-name
    # metadata is persisted/displayed (mirrors apisec's `auth_aliases` minimization).
    auth_scheme: Literal["none", "bearer", "header", "cookie", "basic"] = "none"
    auth_header_name: str = "Authorization"
    respect_robots: bool
    tls_verify: bool
    seed_paths: list[str] = Field(default_factory=list)
    budgets: Budgets
    checks: list[ProfileCheck]
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))
    zap_spider_max_minutes: int = 2
    zap_wait_max_minutes: int = 2

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
        "Version leakage, debug/default pages, directory listing, sensitive HTML comments",
        ["WEB-INFO-001", "WEB-INFO-002", "WEB-INFO-003", "WEB-INFO-004", "WEB-INFO-005"],
        None,
    ),
    ("sensitive_files", "Sensitive-file exposure probing", ["WEB-FILE-001"], None),
    ("redirects", "Unsafe redirect indicators (passive)", ["WEB-REDIR-001"], None),
    ("cors", "CORS policy", ["WEB-CORS-001"], "check_cors"),
    (
        "http_methods",
        "HTTP method enumeration (OPTIONS)",
        ["WEB-METHOD-001"],
        "check_http_methods",
    ),
    ("caching", "Caching of sensitive-looking responses", ["WEB-CACHE-001"], None),
    ("mixed_content", "Mixed content on HTTPS pages", ["WEB-MIXED-001"], None),
    (
        "subresource_integrity",
        "Third-party script/stylesheet integrity",
        ["WEB-SRI-001"],
        None,
    ),
    ("autocomplete", "Password-field autocomplete", ["WEB-FORM-001"], None),
    ("components", "Component/version detection", ["WEB-COMP-001"], None),
    ("cve", "CVE matching (local catalog)", ["WEB-COMP-002"], None),
    (
        "injection_indicators",
        "Passive injection indicators (reflection, database errors)",
        ["WEB-REFL-001", "WEB-DBERR-001"],
        None,
    ),
    (
        "active_sqli",
        "Active SQL injection confirmation (opt-in, project scan policy)",
        ["WEB-SQLI-001"],
        None,
    ),
    (
        "active_xss",
        "Active XSS reflection confirmation (opt-in, project scan policy)",
        ["WEB-XSS-001"],
        None,
    ),
]
ALWAYS_SKIPPED = {
    "cve": "Runs only when a local CVE catalog is imported (none imported in this build)",
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
    engine = params.get("engine")
    if engine is not None and isinstance(engine, str) and engine not in ENGINES:
        errors.append(f"engine must be one of {ENGINES}, got {engine!r}")
    for minutes_param in ("zap_spider_max_minutes", "zap_wait_max_minutes"):
        minutes = params.get(minutes_param)
        if isinstance(minutes, int) and not isinstance(minutes, bool) and not 1 <= minutes <= 60:
            errors.append(f"{minutes_param} must be between 1 and 60")
    auth_scheme = params.get("auth_scheme")
    scheme = auth_scheme if isinstance(auth_scheme, str) and auth_scheme in AUTH_SCHEMES else None
    if auth_scheme is not None and isinstance(auth_scheme, str) and scheme is None:
        errors.append(f"auth_scheme must be one of {AUTH_SCHEMES}, got {auth_scheme!r}")
    if (scheme or "none") != "none":
        ref = params.get("auth_secret_ref")
        if not isinstance(ref, str) or not AUTH_ALIAS_PATTERN.match(ref):
            errors.append(
                "auth_secret_ref must look like env:NAME (uppercase) when auth_scheme is not 'none'"
            )
    header_name = params.get("auth_header_name")
    if isinstance(header_name, str) and (not header_name or len(header_name) > 64):
        errors.append("auth_header_name must be 1-64 characters")
    return errors


def build_profile(params: dict[str, Any], policy: ScanPolicy) -> WebScanProfile:
    engine_raw = params.get("engine")
    engine: Literal["native", "zap"] = engine_raw if engine_raw in ENGINES else DEFAULT_ENGINE  # type: ignore[assignment]
    checks: list[ProfileCheck] = []
    for group, label, rule_ids, toggle in GROUPS:
        kinds = {RULES[r].kind for r in rule_ids}
        kind = next(k for k in (Kind.ACTIVE, Kind.TOOL, Kind.PROBE, Kind.PASSIVE) if k in kinds)
        enabled, reason = True, ""
        if engine != "native":
            enabled, reason = False, f"engine={engine}: native checks are not run"
        elif group in ALWAYS_SKIPPED:
            enabled, reason = False, ALWAYS_SKIPPED[group]
        elif group == "active_sqli" and not policy.active_probes.sqli_error_differential:
            enabled, reason = (
                False,
                (
                    "Disabled: enable active_probes.sqli_error_differential in the project's "
                    "scan policy to opt in"
                ),
            )
        elif group == "active_xss" and not policy.active_probes.xss_reflection:
            enabled, reason = (
                False,
                (
                    "Disabled: enable active_probes.xss_reflection in the project's scan "
                    "policy to opt in"
                ),
            )
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
    spider_minutes = params.get("zap_spider_max_minutes")
    wait_minutes = params.get("zap_wait_max_minutes")
    auth_scheme_raw = params.get("auth_scheme")
    auth_scheme: Literal["none", "bearer", "header", "cookie", "basic"] = (
        auth_scheme_raw if auth_scheme_raw in AUTH_SCHEMES else "none"
    )
    header_name = params.get("auth_header_name")
    return WebScanProfile(
        engine=engine,
        auth_scheme=auth_scheme,
        auth_header_name=(
            header_name if isinstance(header_name, str) and header_name else "Authorization"
        ),
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
        zap_spider_max_minutes=(int(spider_minutes) if isinstance(spider_minutes, int) else 2),
        zap_wait_max_minutes=int(wait_minutes) if isinstance(wait_minutes, int) else 2,
    )
