# Web Scanner Rule Catalog — `vapt-web-rules` 1.1.0

> Source of truth: `backend/app/scanners/webapp/rules.py` (`CATALOG_VERSION = "1.1.0"`). This document describes it; a change to rule semantics must bump the catalog version and this file.
>
> **1.1.0** added 5 rules (`WEB-MIXED-001`, `WEB-SRI-001`, `WEB-FORM-001`, `WEB-INFO-005`, `WEB-METHOD-001`) to widen passive/probe detection depth toward OWASP ZAP's passive-scan rule set, at the user's request — still no active injection/exploitation input (TBD-049/050 unchanged).

## Outcomes

Every check returns exactly one outcome per evaluated subject, always with a rationale:

| Outcome | Meaning |
|---|---|
| `pass` | The control was observed and is in place (e.g. "control present in 12 response(s) examined"). |
| `observation` | Noteworthy, not a weakness on its own (detected component, wildcard CORS on a public resource, escaped reflection, TLS tool protocol list). |
| `finding` | A weakness with evidence. Becomes a canonical `Finding` with sanitized evidence. |
| `skipped` | The check could not run: disabled, not in scope, tool missing, no applicable subject, or **not built in**. |
| `error` | The check tried and failed (timeout, unparseable tool output). **An error is never a pass.** |

Every rule appears in the scan's `coverage.json`; a rule with no applicable subject is listed as `skipped` with that reason.

## Safe mode by default (TBD-049, TBD-050) — active injection confirmation is opt-in (TBD-115)

- **No injection test input is sent unless explicitly opted in.** By default, SQL injection / XSS coverage comes from *passive* indicators (`WEB-REFL-001`, `WEB-DBERR-001`) and from importing a dedicated tool's results (Phase 08). A project can opt in per probe type via `ScanPolicy.active_probes.sqli_error_differential`/`xss_reflection` (both `false` by default); when on, `WEB-SQLI-001`/`WEB-XSS-001` send exactly one bounded confirmation request per already-crawled parameter — never a payload-fuzzing loop, never blind/time-based injection, and gated by a separate, tighter `max_active_probe_requests_per_target` budget on top of the usual scope gate. See TBD_DECISIONS.md.
- **No sensitive-file probing.** `WEB-FILE-001` is always `skipped`; directory listings, debug pages and default pages are still detected on pages the crawler reaches.

## Rules

OWASP column: OWASP Top 10:2025 category the rule *relates to* (mapping confidence "probable"; not a 1:1 claim). Kind: `passive` = uses crawl responses only; `probe` = a few bounded benign extra requests; `tool` = external tool / catalog.

| Rule | Title | Kind | Default severity / confidence | CWE | OWASP |
|---|---|---|---|---|---|
| WEB-TLS-001 | HTTPS is not available | probe | medium / confirmed | 319 | A04 |
| WEB-TLS-002 | HTTP does not redirect to HTTPS | probe | low / confirmed | 319 | A04 |
| WEB-TLS-003 | TLS certificate is not valid for this host (expired, not yet valid, untrusted, hostname mismatch) | probe | medium / confirmed | 295 | A04 |
| WEB-TLS-004 | TLS certificate expires within 30 days | probe | low / confirmed | 298 | A04 |
| WEB-TLS-005 | Legacy TLS/SSL protocol versions offered (from sslyze/testssl.sh only) | tool | medium / confirmed | 327 | A04 |
| WEB-TLS-006 | TLS protocol and cipher analysis (tool provenance; skipped without a tool) | tool | informational | — | A04 |
| WEB-HDR-001 | Strict-Transport-Security missing or max-age < 180 days (HTTPS only) | passive | low / confirmed | 319 | A02 |
| WEB-HDR-002 | Content-Security-Policy missing or weak (`unsafe-inline` without nonce/hash, `unsafe-eval`, wildcard/scheme-only script sources, unrestricted `object-src`) — basic check, not full CSP validation | passive | low / confirmed | 693 | A02 |
| WEB-HDR-003 | X-Content-Type-Options: nosniff missing | passive | low / confirmed | 693 | A02 |
| WEB-HDR-004 | No clickjacking protection (no CSP `frame-ancestors`, no XFO DENY/SAMEORIGIN) | passive | low / confirmed | 1021 | A02 |
| WEB-HDR-005 | Referrer-Policy missing | passive | informational | 200 | A02 |
| WEB-HDR-006 | Permissions-Policy missing | passive | informational | — | A02 |
| WEB-HDR-007 | Obsolete header in use (X-XSS-Protection enabled, Expect-CT, Public-Key-Pins) | passive | informational | — | — |
| WEB-HDR-008 | Duplicate/conflicting security headers | passive | low / confirmed | 693 | A02 |
| WEB-COOKIE-001 | Cookie set over HTTPS without Secure | passive | low / confirmed | 614 | A02 |
| WEB-COOKIE-002 | Session-like cookie without HttpOnly | passive | low / probable | 1004 | A02 |
| WEB-COOKIE-003 | Cookie without SameSite, or SameSite=None without Secure | passive | low / confirmed | 1275 | A01 |
| WEB-INFO-001 | Server/framework version disclosed in headers | passive | low / confirmed | 200 | A02 |
| WEB-INFO-002 | Debug output or stack trace (Python, Werkzeug, Django, Laravel, ASP.NET, Java, PHP, Rails signatures) | passive | medium / probable | 209 | A10 |
| WEB-INFO-003 | Default installation page (Apache, nginx, IIS, Tomcat) | passive | low / probable | 1188 | A02 |
| WEB-INFO-004 | Directory listing enabled | passive | medium / confirmed | 548 | A02 |
| WEB-FILE-001 | Sensitive file exposure probing — **not built in** (always skipped) | tool | — | 538 | A02 |
| WEB-REDIR-001 | Possible open redirect: a URL-valued parameter observed in a redirect to another host (destination never requested) | passive | low / potential | 601 | A01 |
| WEB-CORS-001 | Untrusted Origin reflected (with credentials: medium; without: low); `*` is an observation | probe | medium / confirmed | 942 | A02 |
| WEB-CACHE-001 | Sensitive-looking response (sets cookies / password form) without `no-store`/`private` — heuristic | passive | low / potential | 525 | A02 |
| WEB-COMP-001 | Technology component detected (headers, generator meta, asset paths, cookie names) — observation | passive | informational / per detection | — | A03 |
| WEB-COMP-002 | CVE matching against a locally imported catalog — skipped without one; never invents CVEs | tool | needs review | 1104 | A03 |
| WEB-REFL-001 | Parameter value (already present in a crawled link) reflected with unencoded `< > " '` — passive indicator, not confirmed XSS | passive | low / potential | 79 | A05 |
| WEB-DBERR-001 | Database error signature in a normally crawled response (MySQL, PostgreSQL, SQL Server, Oracle, SQLite, PDO) | passive | medium / probable | 209 | A10 |
| WEB-MIXED-001 | HTTPS page loads a script/stylesheet/image over plain HTTP | passive | low / confirmed | 319 | A04 |
| WEB-SRI-001 | Third-party `<script>`/stylesheet `<link>` has no `integrity` attribute | passive | low / probable | 353 | A03 |
| WEB-FORM-001 | A password field does not disable autocomplete (form- or field-level) | passive | low / probable | 522 | A02 |
| WEB-INFO-005 | Sensitive content in an HTML comment (private key block, internal/private IP, or a developer note referencing a credential/secret) | passive | low / probable | 615 | A02 |
| WEB-METHOD-001 | One `OPTIONS` probe per origin: TRACE/TRACK advertised is a finding (medium); PUT/DELETE/CONNECT advertised is an observation | probe | medium / confirmed | 650 | A02 |
| WEB-SQLI-001 | SQL injection confirmed by a single error-differential probe — **opt-in**, disabled by default | active | high / confirmed | 89 | A05 |
| WEB-XSS-001 | Reflected XSS confirmed by a single non-executing marker probe — **opt-in**, disabled by default | active | high / confirmed | 79 | A05 |

## Aggregation and deduplication

- Configuration-wide rules (headers, cookies, version disclosure, caching, transport) produce **one finding per origin (+ parameter, e.g. cookie or header name)** listing up to 20 affected URLs and the total count.
- Location-specific rules (debug page, default page, directory listing, reflection, DB error, redirect) produce one finding per URL (+ parameter).
- Fingerprint = SHA-256 of `project | rule | subject | parameter`. A later scan that observes the same fingerprint **re-observes** the existing finding (adds a source and a `reobserved` dedup event, keeps the analyst status) instead of creating a duplicate.

## Evidence

- HTTP evidence: request line + redacted request headers; response status + headers (cookie **values never stored**: `Set-Cookie (sanitized): name=[value omitted]; attributes`), and at most a 600-character body window around the matched signature. Redacted twice (scanner + storage), capped at 8 KiB per excerpt, with SHA-256 of the observed body and a truncation flag.
- TLS evidence: what the client observed (verified flag, protocol, cipher, subject/issuer CN, SAN, validity window, verification error).
- Tool evidence: tool name + captured version + parsed protocol list; the raw tool output is stored as a scan output file.

## Component detection and the CVE contract

`ComponentDetector` reports name, version (only from explicit strings), confidence, sources and evidence. `CveCatalog` (`app/scanners/webapp/components.py`) is the adapter contract a locally imported catalog implements (`catalog_id`, `catalog_version`, `updated_at`, `available`, `match(product, version) -> CveMatch[]` with `exact`/`range` match logic and the catalog's affected range). With no catalog (`NoCveCatalog`) the check is skipped; components without a version are skipped as "matching would not be defensible".
