"""Passive checks over responses the crawler already fetched (no extra requests).

Results are aggregated per origin for configuration-wide rules (one finding listing the
affected URLs instead of one finding per page), and kept per URL for location-specific
rules (debug page, directory listing, ...). A rule that was evaluated and never failed
yields a PASS with the number of responses examined.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

from app.integrations.http_service import HttpExchange
from app.models.common import Severity
from app.scanners.webapp.crawler import HTML_TYPES, PageRecord
from app.scanners.webapp.evidence import describe_cookie, http_evidence
from app.scanners.webapp.html import HtmlInfo
from app.scanners.webapp.rules import RULES, CheckResult, Outcome

FailFn = Callable[..., None]
HSTS_MIN_AGE = 15552000  # 180 days
MAX_URLS_LISTED = 20
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)
SESSION_COOKIE = re.compile(
    r"(?i)(sess|sid\b|^sid|token|auth|jwt|login|remember|connect\.sid|phpsessid|jsessionid|"
    r"asp\.net_sessionid)"
)
VERSION = re.compile(r"\d+\.\d+")
VERSION_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime-version",
)

DEBUG_SIGNATURES = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Werkzeug debugger", re.compile(r"Werkzeug Debugger|The debugger caught an exception")),
    (
        "Django debug page",
        re.compile(r"You're seeing this error because you have <code>DEBUG = True"),
    ),
    ("Laravel/Ignition error page", re.compile(r"Whoops! There was an error|ignition-")),
    ("ASP.NET error page", re.compile(r"Server Error in '[^']*' Application")),
    ("Java stack trace", re.compile(r"\bat (?:java|javax|org\.springframework)\.[\w.$]+\(")),
    ("PHP fatal error", re.compile(r"<b>Fatal error</b>:|Fatal error: Uncaught")),
    ("Rails exception page", re.compile(r"Action Controller: Exception caught")),
]
DEFAULT_PAGES = [
    (
        "Apache default page",
        re.compile(
            r"Apache2 \w+ Default Page|<h1>It works!</h1>|Test Page for the Apache HTTP Server"
        ),
    ),
    ("nginx default page", re.compile(r"<title>Welcome to nginx!</title>")),
    (
        "IIS default page",
        re.compile(
            r"<title>IIS Windows Server</title>|<title>Internet Information Services</title>"
        ),
    ),
    ("Tomcat default page", re.compile(r"you've successfully installed Tomcat")),
]
DIRECTORY_LISTING = [
    ("Apache/nginx index", re.compile(r"<title>Index of /[^<]*</title>", re.I)),
    ("Python http.server listing", re.compile(r"<title>Directory listing for /", re.I)),
    ("IIS directory browsing", re.compile(r"\[To Parent Directory\]")),
]
DB_ERRORS = [
    (
        "MySQL",
        re.compile(r"You have an error in your SQL syntax|Warning: mysqli?_|com\.mysql\.jdbc"),
    ),
    (
        "PostgreSQL",
        re.compile(
            r"PG::SyntaxError|pg_query\(\): Query failed|org\.postgresql\.util\.PSQLException|"
            r"unterminated quoted string at or near"
        ),
    ),
    (
        "Microsoft SQL Server",
        re.compile(
            r"Unclosed quotation mark after the character string|"
            r"Microsoft OLE DB Provider for SQL Server|\[SQL Server\]"
        ),
    ),
    ("Oracle", re.compile(r"\bORA-\d{5}\b")),
    ("SQLite", re.compile(r"SQLite3::SQLException|sqlite3\.OperationalError|SQLITE_ERROR")),
    ("Generic PDO", re.compile(r"SQLSTATE\[\w+\]")),
]


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


@dataclass
class _Fail:
    result: CheckResult
    urls: list[str] = field(default_factory=list)
    count: int = 0


class Aggregator:
    def __init__(self) -> None:
        self._fails: dict[tuple[str, str, str], _Fail] = {}
        self._evaluated: dict[tuple[str, str], int] = defaultdict(int)
        self._single: dict[tuple[str, str, str], CheckResult] = {}
        self.observations: list[CheckResult] = []

    def evaluated(self, rule_id: str, origin: str) -> None:
        self._evaluated[(rule_id, origin)] += 1

    def fail(self, result: CheckResult, url: str) -> None:
        origin = origin_of(url)
        if not RULES[result.rule_id].aggregate:
            key = (result.rule_id, url, result.parameter)
            self._single.setdefault(key, result)
            return
        key = (result.rule_id, origin, result.parameter)
        entry = self._fails.get(key)
        if entry is None:
            result.subject = origin
            entry = self._fails[key] = _Fail(result)
        entry.count += 1
        if len(entry.urls) < MAX_URLS_LISTED and url not in entry.urls:
            entry.urls.append(url)

    def observe(self, result: CheckResult) -> None:
        self.observations.append(result)

    def results(self) -> list[CheckResult]:
        out: list[CheckResult] = []
        failed_pairs = {(k[0], k[1]) for k in self._fails}
        failed_pairs |= {(k[0], origin_of(k[1])) for k in self._single}
        for entry in self._fails.values():
            listed = "\n".join(f"- {u}" for u in entry.urls)
            more = entry.count - len(entry.urls)
            entry.result.detail = (
                f"{entry.result.detail}\n\nAffected responses ({entry.count}):\n{listed}"
                + (f"\n- … and {more} more" if more > 0 else "")
            ).strip()
            entry.result.data["affected_urls"] = entry.urls
            entry.result.data["affected_count"] = entry.count
            out.append(entry.result)
        out.extend(self._single.values())
        for (rule_id, origin), n in sorted(self._evaluated.items()):
            if (rule_id, origin) not in failed_pairs:
                out.append(
                    CheckResult(
                        rule_id,
                        Outcome.PASS,
                        origin,
                        f"control present in {n} response(s) examined",
                    )
                )
        out.extend(self.observations)
        return out


def _directives(csp: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def csp_weaknesses(csp: str) -> list[str]:
    d = _directives(csp)
    problems: list[str] = []
    scripts = d.get("script-src", d.get("default-src"))
    if scripts is None:
        problems.append("no script-src or default-src directive")
    else:
        has_nonce = any(
            s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in scripts
        )
        if "'unsafe-inline'" in scripts and not has_nonce and "'strict-dynamic'" not in scripts:
            problems.append("script sources allow 'unsafe-inline'")
        if "'unsafe-eval'" in scripts:
            problems.append("script sources allow 'unsafe-eval'")
        if any(s in ("*", "http:", "https:", "data:") for s in scripts):
            problems.append("script sources include a wildcard/scheme-only source")
    if "object-src" not in d and "'none'" not in (d.get("default-src") or []):
        problems.append("object-src is not restricted")
    return problems


class PassiveChecks:
    def __init__(self) -> None:
        self.agg = Aggregator()
        self.reflections: set[tuple[str, str]] = set()

    def observe(self, page: PageRecord, exchange: HttpExchange, info: HtmlInfo | None) -> None:
        response = exchange.response
        if response is None:
            return
        url = exchange.final_url
        origin = origin_of(url)
        ctype = page.content_type
        is_html = ctype in HTML_TYPES
        ok = 200 <= response.status < 300
        https = url.startswith("https://")
        body_text = response.body.decode("utf-8", "replace") if response.body else ""

        def fail(
            rule: str,
            rationale: str,
            *,
            parameter: str = "",
            match: str | None = None,
            detail: str = "",
            severity: Severity | None = None,
        ) -> None:
            self.agg.fail(
                CheckResult(
                    rule,
                    Outcome.FINDING,
                    url,
                    rationale,
                    parameter=parameter,
                    status=response.status,
                    detail=detail,
                    severity=severity,
                    evidence=http_evidence(exchange, body_match=match),
                ),
                url,
            )

        # --- security headers
        if https and response.status < 400:
            self.agg.evaluated("WEB-HDR-001", origin)
            hsts = response.header("Strict-Transport-Security")
            if not hsts:
                fail("WEB-HDR-001", "HTTPS response without Strict-Transport-Security")
            else:
                m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
                age = int(m.group(1)) if m else 0
                if age < HSTS_MIN_AGE:
                    fail(
                        "WEB-HDR-001",
                        f"HSTS max-age={age} is below {HSTS_MIN_AGE}",
                        detail=f"Strict-Transport-Security: {hsts[:200]}",
                        parameter="max-age",
                    )
        if is_html and ok:
            self.agg.evaluated("WEB-HDR-002", origin)
            csp = response.header("Content-Security-Policy")
            if not csp:
                only_ro = response.header("Content-Security-Policy-Report-Only")
                fail(
                    "WEB-HDR-002",
                    "HTML response without an enforced Content-Security-Policy"
                    + (" (only Report-Only is set)" if only_ro else ""),
                )
            else:
                problems = csp_weaknesses(csp)
                if problems:
                    fail(
                        "WEB-HDR-002",
                        "Content-Security-Policy is weak: " + "; ".join(problems),
                        parameter="weak-policy",
                        detail=f"Content-Security-Policy: {csp[:500]}",
                    )
            self.agg.evaluated("WEB-HDR-004", origin)
            ancestors = "frame-ancestors" in _directives(csp or "")
            xfo = (response.header("X-Frame-Options") or "").strip().upper()
            if not ancestors and xfo not in ("DENY", "SAMEORIGIN"):
                fail(
                    "WEB-HDR-004", "neither CSP frame-ancestors nor X-Frame-Options DENY/SAMEORIGIN"
                )
            self.agg.evaluated("WEB-HDR-005", origin)
            if not response.header("Referrer-Policy"):
                fail("WEB-HDR-005", "HTML response without Referrer-Policy")
            self.agg.evaluated("WEB-HDR-006", origin)
            if not response.header("Permissions-Policy"):
                fail("WEB-HDR-006", "HTML response without Permissions-Policy")
        if ok and response.body:
            self.agg.evaluated("WEB-HDR-003", origin)
            if (response.header("X-Content-Type-Options") or "").strip().lower() != "nosniff":
                fail("WEB-HDR-003", "response without X-Content-Type-Options: nosniff")
        self.agg.evaluated("WEB-HDR-007", origin)
        xss = (response.header("X-XSS-Protection") or "").strip()
        if xss.startswith("1"):
            fail(
                "WEB-HDR-007",
                "X-XSS-Protection is enabled (obsolete; can introduce issues)",
                parameter="X-XSS-Protection",
            )
        for obsolete in ("Expect-CT", "Public-Key-Pins"):
            if response.header(obsolete):
                fail("WEB-HDR-007", f"obsolete header {obsolete} is sent", parameter=obsolete)
        self.agg.evaluated("WEB-HDR-008", origin)
        for name in SECURITY_HEADERS:
            values = response.header_all(name)
            if len(values) > 1 and len({v.strip().lower() for v in values}) > 1:
                fail(
                    "WEB-HDR-008",
                    f"{name} sent {len(values)} times with different values",
                    parameter=name,
                    detail="\n".join(f"{name}: {v[:200]}" for v in values),
                )

        # --- cookies
        for raw in response.header_all("Set-Cookie"):
            name = raw.split("=", 1)[0].strip()[:100]
            attrs = {a.strip().split("=", 1)[0].lower(): a.strip() for a in raw.split(";")[1:]}
            described = describe_cookie(raw)
            if https:
                self.agg.evaluated("WEB-COOKIE-001", origin)
                if "secure" not in attrs:
                    fail(
                        "WEB-COOKIE-001",
                        f"cookie {name} set over HTTPS without Secure",
                        parameter=name,
                        detail=f"Set-Cookie (sanitized): {described}",
                    )
            if SESSION_COOKIE.search(name):
                self.agg.evaluated("WEB-COOKIE-002", origin)
                if "httponly" not in attrs:
                    fail(
                        "WEB-COOKIE-002",
                        f"session-like cookie {name} without HttpOnly",
                        parameter=name,
                        detail=f"Set-Cookie (sanitized): {described}",
                    )
            self.agg.evaluated("WEB-COOKIE-003", origin)
            samesite = attrs.get("samesite", "").partition("=")[2].strip().lower()
            if not samesite:
                fail(
                    "WEB-COOKIE-003",
                    f"cookie {name} has no SameSite attribute",
                    parameter=name,
                    detail=f"Set-Cookie (sanitized): {described}",
                )
            elif samesite == "none" and "secure" not in attrs:
                fail(
                    "WEB-COOKIE-003",
                    f"cookie {name} uses SameSite=None without Secure",
                    parameter=name,
                    detail=f"Set-Cookie (sanitized): {described}",
                )

        # --- version disclosure
        self.agg.evaluated("WEB-INFO-001", origin)
        for header in VERSION_HEADERS:
            value = response.header(header)
            if value and VERSION.search(value):
                fail(
                    "WEB-INFO-001",
                    f"{header} discloses a version: {value[:120]}",
                    parameter=header,
                    detail=f"{header}: {value[:200]}",
                )

        # --- body signatures (bounded body, any status)
        if body_text:
            self._signatures(url, origin, body_text, fail, is_html=is_html)
            if response.status < 300:
                self._reflection(page, url, body_text, fail, is_html=is_html)

        # --- caching of sensitive-looking responses
        sensitive = bool(response.header_all("Set-Cookie")) or bool(
            info and any(f.has_password for f in info.forms)
        )
        if sensitive and ok:
            self.agg.evaluated("WEB-CACHE-001", origin)
            cache = (response.header("Cache-Control") or "").lower()
            if "no-store" not in cache and "private" not in cache:
                fail(
                    "WEB-CACHE-001",
                    "sensitive-looking response without Cache-Control no-store/private",
                    detail=f"Cache-Control: {cache or '(absent)'}",
                )

        # --- unsafe redirect indicators (passive; the destination was never requested)
        self._redirect_indicator(page, exchange, fail)

    def _signatures(self, url: str, origin: str, body: str, fail: FailFn, *, is_html: bool) -> None:
        report = fail
        for rule, catalog in (("WEB-INFO-002", DEBUG_SIGNATURES), ("WEB-DBERR-001", DB_ERRORS)):
            self.agg.evaluated(rule, origin)
            for label, pattern in catalog:
                m = pattern.search(body)
                if m:
                    report(
                        rule,
                        f"{label} signature in response body",
                        match=m.group(0),
                        detail=f"Matched signature: {label}",
                    )
                    break
        if is_html:
            self.agg.evaluated("WEB-INFO-003", origin)
            for label, pattern in DEFAULT_PAGES:
                m = pattern.search(body)
                if m:
                    report(
                        "WEB-INFO-003",
                        f"{label} detected",
                        match=m.group(0),
                        detail=f"Matched signature: {label}",
                    )
                    break
            self.agg.evaluated("WEB-INFO-004", origin)
            for label, pattern in DIRECTORY_LISTING:
                m = pattern.search(body)
                if m:
                    report(
                        "WEB-INFO-004",
                        f"{label} detected",
                        match=m.group(0),
                        detail=f"Matched signature: {label}",
                    )
                    break

    def _reflection(
        self, page: PageRecord, url: str, body: str, fail: FailFn, *, is_html: bool
    ) -> None:
        if not is_html:
            return
        origin = origin_of(url)
        for name, value in parse_qsl(urlsplit(page.url).query, keep_blank_values=False):
            decoded = unquote(value)
            if len(decoded) < 4 or (url, name) in self.reflections:
                continue
            if not any(ch in decoded for ch in "<>\"'"):
                continue  # only metacharacter-bearing values say anything about encoding
            self.agg.evaluated("WEB-REFL-001", origin)
            if decoded in body:
                self.reflections.add((url, name))
                fail(
                    "WEB-REFL-001",
                    f"value of parameter {name} reflected with unencoded "
                    "HTML metacharacters (observed passively from a crawled link)",
                    parameter=name,
                    match=decoded,
                )

    def _redirect_indicator(self, page: PageRecord, exchange: HttpExchange, fail: FailFn) -> None:
        for hop in exchange.hops:
            if not hop.location or hop.status not in (301, 302, 303, 307, 308):
                continue
            dest_host = urlsplit(hop.location).hostname
            here = urlsplit(hop.url)
            if not dest_host or dest_host == here.hostname:
                continue
            self.agg.evaluated("WEB-REDIR-001", origin_of(hop.url))
            for name, value in parse_qsl(here.query, keep_blank_values=False):
                candidate = unquote(value)
                if urlsplit(candidate).hostname == dest_host:
                    fail(
                        "WEB-REDIR-001",
                        f"parameter {name} appears to control a redirect to "
                        f"another host ({dest_host})",
                        parameter=name,
                        detail=f"Location: {hop.location[:300]}\n"
                        "The destination was not requested.",
                    )
                    break

    def results(self) -> list[CheckResult]:
        return self.agg.results()
