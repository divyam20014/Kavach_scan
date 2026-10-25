"""Versioned web rule catalog (documented in docs/WEB_RULES.md).

Every check returns exactly one `Outcome` per evaluated subject with a rationale:
- PASS         the control was observed and is in place;
- OBSERVATION  noteworthy but not a weakness on its own (inventory, informational);
- FINDING      a weakness with evidence; becomes a canonical Finding;
- SKIPPED      the check could not run (disabled, tool missing, no applicable subject);
- ERROR        the check tried to run and failed. An error is NEVER a pass.

OWASP mappings use OWASP Top 10:2025 (TBD-020) and are marked "probable": a rule is
related to the category, which is not a claim of one-to-one equivalence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.models.common import Confidence, Severity

CATALOG_ID = "vapt-web-rules"
CATALOG_VERSION = "1.1.0"
OWASP_VERSION = "2025"

OWASP_TITLES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A10": "Mishandling of Exceptional Conditions",
}


class Outcome(StrEnum):
    PASS = "pass"  # noqa: S105 - not a password
    OBSERVATION = "observation"
    FINDING = "finding"
    SKIPPED = "skipped"
    ERROR = "error"


class Kind(StrEnum):
    PASSIVE = "passive"  # uses responses the crawl already fetched
    PROBE = "probe"  # sends a small, bounded number of benign extra requests
    ACTIVE = "active"  # opt-in input tests (disabled by default)
    TOOL = "tool"  # external tool integration


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    kind: Kind
    severity: Severity
    confidence: Confidence
    cwe: tuple[int, ...]
    owasp: str  # Top 10:2025 entry id, "" when no sensible mapping
    summary: str
    remediation: str
    references: tuple[str, ...] = ()
    aggregate: bool = True  # one finding per origin (listing affected URLs) vs per URL


_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"
_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
S, C = Severity, Confidence

RULES: dict[str, Rule] = {
    r.rule_id: r
    for r in [
        Rule(
            "WEB-TLS-001",
            "HTTPS is not available",
            "transport-security",
            Kind.PROBE,
            S.MEDIUM,
            C.CONFIRMED,
            (319,),
            "A04",
            "The site answered over plain HTTP but no HTTPS endpoint answered on the same host.",
            "Serve the application over HTTPS with a valid certificate and redirect HTTP to it.",
            (_CS + "Transport_Layer_Security_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-TLS-002",
            "HTTP does not redirect to HTTPS",
            "transport-security",
            Kind.PROBE,
            S.LOW,
            C.CONFIRMED,
            (319,),
            "A04",
            "HTTPS is available but the HTTP endpoint serves content instead of redirecting.",
            "Redirect every HTTP request to the HTTPS origin (301/308) and enable HSTS.",
            (_CS + "HTTP_Strict_Transport_Security_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-TLS-003",
            "TLS certificate is not valid for this host",
            "transport-security",
            Kind.PROBE,
            S.MEDIUM,
            C.CONFIRMED,
            (295,),
            "A04",
            "Certificate verification failed as seen by a standard client (expired, not yet "
            "valid, untrusted issuer or hostname mismatch).",
            "Install a certificate from a trusted CA that covers the hostname and is in date.",
            (_CS + "Transport_Layer_Security_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-TLS-004",
            "TLS certificate expires soon",
            "transport-security",
            Kind.PROBE,
            S.LOW,
            C.CONFIRMED,
            (298,),
            "A04",
            "The certificate is valid today but expires within 30 days.",
            "Renew the certificate and automate renewal.",
            (),
        ),
        Rule(
            "WEB-TLS-005",
            "Legacy TLS/SSL protocol versions offered",
            "transport-security",
            Kind.TOOL,
            S.MEDIUM,
            C.CONFIRMED,
            (327,),
            "A04",
            "The external TLS tool reported SSLv2/SSLv3/TLS 1.0/TLS 1.1 as accepted.",
            "Disable protocol versions older than TLS 1.2.",
            (_CS + "Transport_Layer_Security_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-TLS-006",
            "TLS protocol and cipher analysis",
            "transport-security",
            Kind.TOOL,
            S.INFORMATIONAL,
            C.CONFIRMED,
            (),
            "A04",
            "Protocol/cipher coverage from an installed sslyze or testssl.sh. Without a tool "
            "this check is skipped; no cipher coverage is claimed.",
            "",
            (),
        ),
        Rule(
            "WEB-HDR-001",
            "Strict-Transport-Security header missing",
            "security-headers",
            Kind.PASSIVE,
            S.LOW,
            C.CONFIRMED,
            (319,),
            "A02",
            "HTTPS responses do not send HSTS, so a first visit or a typed http:// URL can be "
            "downgraded by a network attacker.",
            "Send Strict-Transport-Security with max-age of at least 15552000 on HTTPS.",
            (_MDN + "Strict-Transport-Security",),
        ),
        Rule(
            "WEB-HDR-002",
            "Content-Security-Policy missing or weak",
            "security-headers",
            Kind.PASSIVE,
            S.LOW,
            C.CONFIRMED,
            (693,),
            "A02",
            "HTML responses have no CSP, or the CSP allows 'unsafe-inline'/'unsafe-eval'/"
            "wildcard script sources. This is a basic check, not complete CSP validation.",
            "Deploy a restrictive CSP (script-src without unsafe-inline, object-src 'none', "
            "base-uri 'none').",
            (_CS + "Content_Security_Policy_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-HDR-003",
            "X-Content-Type-Options header missing",
            "security-headers",
            Kind.PASSIVE,
            S.LOW,
            C.CONFIRMED,
            (693,),
            "A02",
            "Responses do not send 'X-Content-Type-Options: nosniff'.",
            "Send X-Content-Type-Options: nosniff on all responses.",
            (_MDN + "X-Content-Type-Options",),
        ),
        Rule(
            "WEB-HDR-004",
            "No clickjacking protection",
            "security-headers",
            Kind.PASSIVE,
            S.LOW,
            C.CONFIRMED,
            (1021,),
            "A02",
            "HTML responses send neither CSP frame-ancestors nor X-Frame-Options.",
            "Send CSP frame-ancestors 'self' (or 'none'); X-Frame-Options for old browsers.",
            (_CS + "Clickjacking_Defense_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-HDR-005",
            "Referrer-Policy header missing",
            "security-headers",
            Kind.PASSIVE,
            S.INFORMATIONAL,
            C.CONFIRMED,
            (200,),
            "A02",
            "No Referrer-Policy; browsers fall back to their default policy.",
            "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
            (_MDN + "Referrer-Policy",),
        ),
        Rule(
            "WEB-HDR-006",
            "Permissions-Policy header missing",
            "security-headers",
            Kind.PASSIVE,
            S.INFORMATIONAL,
            C.CONFIRMED,
            (),
            "A02",
            "No Permissions-Policy restricting powerful browser features.",
            "Send a Permissions-Policy disabling features the site does not use.",
            (_MDN + "Permissions-Policy",),
        ),
        Rule(
            "WEB-HDR-007",
            "Obsolete security header in use",
            "security-headers",
            Kind.PASSIVE,
            S.INFORMATIONAL,
            C.CONFIRMED,
            (),
            "",
            "Obsolete headers (X-XSS-Protection enabled, Expect-CT, Public-Key-Pins) are "
            "ignored or harmful in current browsers. Informational only.",
            "Remove obsolete headers; rely on CSP and HSTS.",
            (),
        ),
        Rule(
            "WEB-HDR-008",
            "Duplicate or conflicting security headers",
            "security-headers",
            Kind.PASSIVE,
            S.LOW,
            C.CONFIRMED,
            (693,),
            "A02",
            "A security header appears more than once with different values; browsers may "
            "combine or ignore them unpredictably.",
            "Emit each security header once with a single intended value.",
            (),
        ),
        Rule(
            "WEB-COOKIE-001",
            "Cookie set without Secure flag over HTTPS",
            "cookies",
            Kind.PASSIVE,
            S.LOW,
            C.CONFIRMED,
            (614,),
            "A02",
            "A cookie set on an HTTPS response lacks Secure and can be sent over plain HTTP.",
            "Set the Secure attribute on all cookies of HTTPS sites.",
            (_CS + "Session_Management_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-COOKIE-002",
            "Session-like cookie without HttpOnly",
            "cookies",
            Kind.PASSIVE,
            S.LOW,
            C.PROBABLE,
            (1004,),
            "A02",
            "A cookie whose name looks like a session identifier lacks HttpOnly, so scripts "
            "can read it.",
            "Set HttpOnly on session cookies.",
            (_CS + "Session_Management_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-COOKIE-003",
            "Cookie SameSite attribute missing or unsafe",
            "cookies",
            Kind.PASSIVE,
            S.LOW,
            C.CONFIRMED,
            (1275,),
            "A01",
            "A cookie has no SameSite attribute, or SameSite=None without Secure.",
            "Set SameSite=Lax or Strict (None only with Secure when cross-site use is needed).",
            (_MDN + "Set-Cookie",),
        ),
        Rule(
            "WEB-INFO-001",
            "Server or framework version disclosed",
            "information-disclosure",
            Kind.PASSIVE,
            S.LOW,
            C.CONFIRMED,
            (200,),
            "A02",
            "Response headers reveal product version numbers, which helps attackers match "
            "known vulnerabilities. The version itself is an observation, not a vulnerability.",
            "Remove version details from Server, X-Powered-By and similar headers.",
            (),
        ),
        Rule(
            "WEB-INFO-002",
            "Debug output or stack trace exposed",
            "information-disclosure",
            Kind.PASSIVE,
            S.MEDIUM,
            C.PROBABLE,
            (209,),
            "A10",
            "A response contains a framework debug page or stack trace signature.",
            "Disable debug mode in production and return generic error pages.",
            (_CS + "Error_Handling_Cheat_Sheet.html",),
            aggregate=False,
        ),
        Rule(
            "WEB-INFO-003",
            "Default installation page",
            "misconfiguration",
            Kind.PASSIVE,
            S.LOW,
            C.PROBABLE,
            (1188,),
            "A02",
            "A web server or framework default landing page is served.",
            "Remove default content and serve only the intended application.",
            (),
            aggregate=False,
        ),
        Rule(
            "WEB-INFO-004",
            "Directory listing enabled",
            "misconfiguration",
            Kind.PASSIVE,
            S.MEDIUM,
            C.CONFIRMED,
            (548,),
            "A02",
            "The server generates an index of directory contents.",
            "Disable automatic directory indexes.",
            (),
            aggregate=False,
        ),
        Rule(
            "WEB-FILE-001",
            "Sensitive file exposure probing (not built in)",
            "misconfiguration",
            Kind.TOOL,
            S.INFORMATIONAL,
            C.NEEDS_REVIEW,
            (538,),
            "A02",
            "This build does not probe for sensitive files. Directory listings, debug and "
            "default pages are still detected passively on crawled pages. Use imported tool "
            "results for file-exposure coverage. Always reported as skipped, never as a pass.",
            "",
            (),
            aggregate=False,
        ),
        Rule(
            "WEB-REDIR-001",
            "Possible open redirect indicator",
            "redirects",
            Kind.PASSIVE,
            S.LOW,
            C.POTENTIAL,
            (601,),
            "A01",
            "A URL-valued parameter was observed in a redirect to another host. Detected "
            "passively; the off-scope destination was NOT requested.",
            "Allow only relative or allow-listed redirect destinations.",
            (_CS + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",),
            aggregate=False,
        ),
        Rule(
            "WEB-CORS-001",
            "Permissive CORS policy",
            "cors",
            Kind.PROBE,
            S.MEDIUM,
            C.CONFIRMED,
            (942,),
            "A02",
            "The server reflects an arbitrary Origin (or 'null') in Access-Control-Allow-Origin"
            " together with Allow-Credentials, letting other sites read authenticated responses.",
            "Allow only explicit trusted origins; never reflect Origin with credentials.",
            (_CS + "HTML5_Security_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-CACHE-001",
            "Sensitive-looking response may be cached",
            "caching",
            Kind.PASSIVE,
            S.LOW,
            C.POTENTIAL,
            (525,),
            "A02",
            "A response that sets cookies or contains a password field has no Cache-Control "
            "no-store/private. Heuristic: not every cacheable response is a problem.",
            "Send Cache-Control: no-store on authenticated or sensitive responses.",
            (),
        ),
        Rule(
            "WEB-COMP-001",
            "Technology component detected",
            "components",
            Kind.PASSIVE,
            S.INFORMATIONAL,
            C.PROBABLE,
            (),
            "A03",
            "A product or library was identified from headers, metadata, asset paths or "
            "cookies. Observation only, never proof of a vulnerability.",
            "",
            (),
            aggregate=False,
        ),
        Rule(
            "WEB-COMP-002",
            "Known-vulnerability (CVE) matching",
            "components",
            Kind.TOOL,
            S.INFORMATIONAL,
            C.NEEDS_REVIEW,
            (1104,),
            "A03",
            "Matches detected component versions against a locally imported CVE catalog. "
            "Skipped when no catalog is imported; no CVE is ever inferred without one.",
            "",
            (),
        ),
        Rule(
            "WEB-REFL-001",
            "Parameter value reflected without HTML encoding (passive)",
            "injection-indicators",
            Kind.PASSIVE,
            S.LOW,
            C.POTENTIAL,
            (79,),
            "A05",
            "A query parameter value that was already present in a crawled link appears in "
            "the HTML response with its HTML metacharacters unencoded. Passive indicator only: "
            "no test input was sent, so this is neither confirmed nor exhaustive.",
            "Encode output for its HTML context; add a restrictive CSP. Verify with a "
            "dedicated tool and import its results.",
            (_CS + "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",),
            aggregate=False,
        ),
        Rule(
            "WEB-DBERR-001",
            "Database error message in response (passive)",
            "injection-indicators",
            Kind.PASSIVE,
            S.MEDIUM,
            C.PROBABLE,
            (209,),
            "A10",
            "A normally crawled response contains a database error signature. This leaks "
            "internals and can indicate unsafe query construction. Passive indicator only.",
            "Return generic errors, log details server-side, use parameterized queries.",
            (_CS + "Error_Handling_Cheat_Sheet.html",),
            aggregate=False,
        ),
        Rule(
            "WEB-MIXED-001",
            "Mixed content on an HTTPS page",
            "transport-security",
            Kind.PASSIVE,
            S.LOW,
            C.CONFIRMED,
            (319,),
            "A04",
            "An HTTPS page loads a script, stylesheet or image over plain HTTP, which a "
            "network attacker can tamper with (actively-loaded resources such as scripts are "
            "typically blocked by the browser; passive content such as images is usually "
            "only a warning).",
            "Serve every page resource (scripts, stylesheets, images, fonts) over HTTPS.",
            (_MDN + "../Mixed_content",),
        ),
        Rule(
            "WEB-SRI-001",
            "Third-party script/stylesheet without Subresource Integrity",
            "components",
            Kind.PASSIVE,
            S.LOW,
            C.PROBABLE,
            (353,),
            "A03",
            "A <script> or stylesheet <link> is loaded from a different host with no "
            "integrity attribute, so a compromise of that third party can silently change "
            "what runs in this page.",
            'Add a Subresource Integrity (integrity="sha384-...") attribute to third-party '
            "scripts and stylesheets, or self-host them.",
            (_MDN + "../Subresource_Integrity",),
        ),
        Rule(
            "WEB-FORM-001",
            "Password field does not disable autocomplete",
            "misconfiguration",
            Kind.PASSIVE,
            S.LOW,
            C.PROBABLE,
            (522,),
            "A02",
            'A form with a password field does not set autocomplete="off"/"new-password", '
            "so a browser or shared/public machine may store or offer to fill the credential.",
            'Set autocomplete="new-password" (registration/change) or "current-password" '
            '(login) as appropriate; use "off" only where credential storage must be refused.',
            (_CS + "Authentication_Cheat_Sheet.html",),
        ),
        Rule(
            "WEB-INFO-005",
            "Sensitive content in an HTML comment",
            "information-disclosure",
            Kind.PASSIVE,
            S.LOW,
            C.PROBABLE,
            (615,),
            "A02",
            "An HTML comment in the response contains what looks like private key material, "
            "an internal/private IP address, or a developer note referencing a credential or "
            "secret. Passive signature match only; a flagged comment may be harmless.",
            "Remove comments containing secrets, internal network details or TODO/FIXME notes "
            "about credentials before shipping to production.",
            (),
            aggregate=False,
        ),
        Rule(
            "WEB-METHOD-001",
            "Potentially unsafe HTTP methods advertised",
            "misconfiguration",
            Kind.PROBE,
            S.MEDIUM,
            C.CONFIRMED,
            (650,),
            "A02",
            "An OPTIONS request reveals TRACE/TRACK is enabled (cross-site tracing, a known "
            "XST vector), or that state-changing methods (PUT/DELETE/CONNECT) are advertised, "
            "which is worth reviewing even though it may be an intentional REST API.",
            "Disable TRACE/TRACK at the web server. Confirm PUT/DELETE/CONNECT are actually "
            "intended and properly authenticated and authorized if advertised.",
            (_CS + "HTTP_Headers_Cheat_Sheet.html",),
            aggregate=False,
        ),
        Rule(
            "WEB-INJ-000",
            "Active injection testing (not built in)",
            "injection-indicators",
            Kind.TOOL,
            S.INFORMATIONAL,
            C.NEEDS_REVIEW,
            (),
            "A05",
            "This build does not send injection test input. SQL injection and XSS coverage "
            "comes from importing results of a dedicated tool (e.g. OWASP ZAP, Burp Suite) "
            "run against an authorized target. Always reported as skipped, never as a pass.",
            "",
            (),
        ),
    ]
}


def register_rules(rules: list[Rule]) -> None:
    """Add another module's rules to the shared registry (ids must be unique)."""
    for rule in rules:
        existing = RULES.get(rule.rule_id)
        if existing is not None and existing != rule:
            raise ValueError(f"duplicate rule id {rule.rule_id}")
        RULES[rule.rule_id] = rule


@dataclass
class EvidenceDraft:
    evidence_type: str = "http_exchange"
    request_excerpt: str = ""
    response_excerpt: str = ""
    bytes_observed: int | None = None
    sha256: str | None = None
    truncated: bool = False


@dataclass
class CheckResult:
    rule_id: str
    outcome: Outcome
    subject: str  # URL, origin or component the result is about
    rationale: str
    parameter: str = ""
    method: str = "GET"
    status: int | None = None
    severity: Severity | None = None  # overrides the rule default when set
    confidence: Confidence | None = None
    detail: str = ""
    evidence: EvidenceDraft | None = None
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]


def catalog_summary(prefix: str = "WEB-") -> list[dict[str, Any]]:
    return [
        {
            "rule_id": r.rule_id,
            "title": r.title,
            "category": r.category,
            "kind": r.kind.value,
            "severity": r.severity.value,
            "cwe": list(r.cwe),
            "owasp": f"A{r.owasp[1:]}:{OWASP_VERSION}" if r.owasp else "",
        }
        for r in RULES.values()
        if r.rule_id.startswith(prefix)
    ]
