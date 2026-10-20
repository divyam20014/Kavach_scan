# MASTER SPECIFICATION — Local-First VAPT Workbench (No Database)

**Audience:** Claude Code agent implementing the application in an existing repository.

**Primary outcome:** Build a fully runnable local-first application that combines a conservative web application scanner, attack surface mapper, API security tester, and scan-report ingestion/reporting workbench. It must not use a database. It must work end to end, show real scan progress and logs, persist projects and results across restarts, and generate useful HTML/PDF reports.

**Important:** Treat this file as the product source of truth. Before modifying a repository, inspect it and summarize what already exists. Extend existing code when feasible. Do not overwrite working features merely to match a preferred structure. Do not claim a feature is done unless it is implemented, tested, and visible from the application UI or documented API.

---

## 1. Product vision and boundaries

### 1.1 Product name

Use the temporary product name **VAPT Workbench** until the user chooses another name. Keep branding configurable and do not hard-code it across the application.

### 1.2 Four core product options, combined into one modular application

**A. Web Application Vulnerability Scanner**
- Accept an authorized base URL and explicitly scoped paths/hosts.
- Crawl same-origin pages under strict budgets.
- Check transport/TLS posture, security headers, cookie flags, redirects, common default/debug pages, directory listing indicators, sensitive-file exposure signals, server/framework/version indicators, and basic injection indicators.
- Support optional integration with `testssl.sh` or `sslyze` for TLS analysis.
- Produce findings with evidence, confidence, severity, standards mapping, reproduction instructions, and remediation.

**B. Attack Surface Mapper**
- Accept an authorized domain and scope definition.
- Gather candidate subdomains from manual inputs and optional passive sources.
- Resolve DNS; identify reachable hosts; enumerate only configured TCP ports using a conservative connect scan; optionally invoke Nmap as a separately configured, visible dependency.
- Discover same-scope HTTP/HTTPS services and crawl bounded endpoints.
- Fingerprint likely technology from HTTP headers, HTML/asset patterns, certificates, and service banners.
- Create a clear inventory of domains, hosts, ports, services, endpoints, and evidence, then prioritize risk.

**C. API Security Tester**
- Import OpenAPI 3.x and Swagger 2.0 documents, with explicit validation and a safe policy for `$ref` resolution.
- Inventory operations, methods, parameters, request/response schemas, auth schemes, tags, and server URLs.
- Execute conservative baseline checks for missing/incorrect authentication behavior, verbose errors, security headers, unexpected property acceptance, and simple rate-limit signals.
- Support controlled BOLA/IDOR checks only when the operator configures two authorized test identities and explicitly identifies test-owned resources/object IDs. Never infer or brute-force IDs.
- Mutating requests and tests that may alter data remain disabled by default and require explicit per-project/per-operation opt-in and cleanup strategy.

**D. Automated VAPT Report Generator**
- Import scanner outputs, normalize them to one canonical finding model, deduplicate carefully, preserve original evidence/source identifiers, and allow analyst review.
- Support prioritization, CWE mapping, versioned OWASP mappings, CVSS vectors/scores when actually calculated or supplied, remediation guidance, and confidence labels.
- Generate professional HTML/PDF reports, a management summary, technical findings, attack-surface inventory, scan methodology, tool/version information, limitations, and appendices.
- Allow JSON/CSV exports and project backup/export without any database.

### 1.3 What this application is not

- Not a stealth scanner, exploit framework, credential-harvesting tool, persistence tool, malware tool, or denial-of-service test tool.
- Not a guarantee of complete coverage or absence of vulnerabilities.
- Not permitted to test arbitrary public targets. Authorization and scope checks are product features, not merely UI disclaimers.
- Not a multi-node distributed scanning service in the first version. The filesystem persistence model is for a single host and one active application instance per data directory.
- Not allowed to follow arbitrary URLs or scan arbitrary hosts discovered from a target. Every active request must pass scope policy.

## 2. Technology stack and design constraints

Use the following unless the existing repository already has a sound equivalent; record departures in the architecture decision log.

### Backend
- Python 3.12+.
- FastAPI for HTTP API and OpenAPI generation.
- Pydantic v2 for validation and typed request/response contracts.
- `httpx` for HTTP and async network operations; set explicit timeouts and limits.
- BeautifulSoup/lxml only as appropriate for parsing HTML; disable unsafe XML external entity processing and use hardened parsers for imported XML.
- `cryptography`/OS keyring only where justified for local secret encryption; never invent a homemade cryptographic scheme.
- `reportlab` or another maintained PDF generator with acceptable license; HTML report should be the source-of-truth renderer and PDF should use consistent templates.
- `pytest`, async test support, type checks, linting, and dependency lockfiles.

### Frontend
- React + TypeScript + Vite.
- A consistent component library/design system (choose one suitable library and document it; avoid mixing several UI systems).
- Typed API client, robust loading/error/empty states, accessible forms, and responsive desktop-first layout.
- Graphs must be driven by actual normalized scan/finding data. Never render fabricated dashboard metrics.

### Filesystem persistence — mandatory
- No relational or document database of any kind; no SQLite; no Redis; no broker service.
- Store metadata and structured records as versioned JSON documents and JSONL event logs. Store uploaded source files and evidence as individual files under an application data directory.
- Keep persistent data outside the source repository by default, and support a configurable data directory (e.g. environment variable `VAPT_DATA_DIR`).
- Use a single storage abstraction. Business logic must not write random files directly throughout the application.
- Use Pydantic validation on read and write. Include `schema_version` and explicit migrations for file formats.
- Use atomic write patterns: write temporary file in same directory, flush/fsync where appropriate, then atomic replace. Ensure file permissions are restrictive where supported.
- Protect read-modify-write operations with cross-process file locks where available; lock granularity should avoid locking the entire repository unnecessarily. Document platform-specific limitations.
- Keep a manifest/index file for fast lookups, but treat canonical project/scan/finding records as the source of truth. Rebuild derived indexes after corruption or missing indexes.
- Use append-only JSONL for audit and scan event logs. Rotate logs by size/date. Redact secrets before persistence.
- Include data integrity checks, import/export, backup, recovery, deletion, and corrupted-file handling.
- Do not allow untrusted project IDs or uploaded filenames to become arbitrary filesystem paths. Resolve paths beneath the data root and reject traversal/symlink escape.
- The first release is single-host. Enforce one active application instance per data directory using a startup lock/lease file with stale-lock recovery. Never imply that this design supports multi-node write concurrency.

### Scan job execution — no Redis/Celery requirement
- Implement a local, filesystem-backed job queue. Each job is a validated JSON manifest under a job-spool directory and transitions through explicit states.
- Persist queued/running/completed/failed/cancelled/interrupted states and timestamps. Use file locking to claim a job so it cannot run twice.
- On startup, recover unclaimed queued jobs; mark stale `running` jobs as interrupted and preserve logs/evidence. Never automatically repeat a request sequence whose safety cannot be guaranteed.
- Workers must have configurable concurrency, a hard cap, per-target request budgets, timeouts, cancellation, and kill/cleanup of child processes. Default to low concurrency.
- A cancelled scan must stop scheduling new requests promptly, terminate subprocesses cleanly, and record a final state.
- A job must not report success if required steps fail; use completed-with-warnings when partial data exists and explain missing stages.

## 3. Architecture and repository layout

Adapt to repository conventions if sound, but preserve separation of concerns. A suggested layout:

```text
backend/
  app/
    main.py
    api/                 # FastAPI routers only
    core/                # settings, errors, logging, security
    models/               # Pydantic contracts
    storage/              # filesystem repository and migrations
    scope/                # authorization, canonicalization, allowlist
    jobs/                 # persisted jobs, workers, cancellation
    scanners/
      webapp/
      surface/
      api_security/
      tls/
    imports/              # parsers/adapters for external scan outputs
    findings/             # normalization, deduplication, scoring, mappings
    reports/              # HTML/PDF and exports
    integrations/         # optional external binaries/data sources
    services/             # application use cases
  tests/
frontend/
  src/
    app/
    api/
    components/
    features/
    layouts/
    pages/
    types/
docs/
data/                    # runtime data path, gitignored
scripts/
```

Do not mechanically create every directory at once if the repository has a different but clean layout. Establish and document the final architecture in `docs/ARCHITECTURE.md`.

### Required backend boundaries
- Routers: HTTP parsing, authorization gate, response serialization. Avoid placing scan logic in route functions.
- Services: orchestrate use cases.
- Scanner modules: pure and testable scan logic behind explicit interfaces.
- Integrations: subprocess/network wrappers, dependency detection, version checks, timeouts.
- Storage: all persistent file access, locking, atomic writes, schema validation, recovery.
- Models: canonical Pydantic contracts shared across API, storage, scan results, and report rendering.
- Frontend: no direct filesystem operations and no assumptions about hidden backend internals.

## 4. Safety, authorization, and network scope policy

This section is a release gate. The scanner is not acceptable if a route can bypass scope controls.

### 4.1 Authorization workflow
- Every project has an authorization record: organization/client, target owner, authorized-by, authorization date/time, start/end window, scope, exclusions, notes/reference, and an operator attestation that they have permission.
- Before an active scan, show a clear target/scope summary and require explicit confirmation. Store a timestamped audit event for the confirmation.
- Passive-only inventory may be separate, but must still be associated with a project/scope and must disclose third-party data sources.
- Do not represent a checkbox as legal verification; label it as operator attestation.
- Expired authorization must prevent starting new active scans. A running scan crossing the authorization end time must stop safely.

### 4.2 Scope representation and enforcement
- Canonical scope stores approved schemes, exact hostnames, optional wildcard domains with carefully defined boundary matching, approved IP/CIDR ranges when explicitly supplied, port allowlists, path prefixes, exclusions, and optional API server URL allowlists.
- Normalize IDNA hostnames, lowercase DNS names, strip default ports, normalize paths, and reject ambiguous URLs.
- Prevent suffix bugs: `trusted.example` must not match `trusted.example.attacker.test` or `nottrusted.example`.
- Resolve hostnames at scan time and guard against DNS rebinding. Bind each request to a scope decision; revalidate redirects and each newly discovered host/IP.
- Block loopback, link-local, private, multicast, unspecified, and cloud metadata IP ranges by default unless the operator explicitly configures an authorized internal target and confirms it. This block must be policy-backed, tested, and visible in the UI. Do not let URL redirects bypass it.
- Reject `file:`, `ftp:`, `gopher:`, `javascript:`, and any non-HTTP(S) target scheme for web scanning. No arbitrary protocol support.
- Only follow same-scope redirects. Out-of-scope redirect destinations are recorded as blocked and not requested.
- Crawling is same-scope only. Do not crawl external links by default. For subdomain discovery, discovered candidates are not active scan targets until admitted by the project scope policy.
- Every outbound request, DNS resolution, port probe, subprocess invocation, and API request must pass a documented scope/permission check before execution. Scanner code may not bypass this by calling raw HTTP helpers directly.

### 4.3 Safe request behavior
- Conservative defaults for request rate, concurrency, timeout, maximum crawl depth, number of pages/endpoints, response bytes, redirects, and total duration.
- Per-target token bucket or equivalent request budget; add per-host backoff on 429/503 and network instability.
- No denial-of-service, stress testing, endless recursion, large payloads, race-condition load tests, or high-rate fuzzing.
- No stealth/evasion features, proxy chaining for concealment, WAF bypass, IP rotation, CAPTCHA bypass, or authentication bypass code.
- No credential brute force or password guessing. A low-count rate-limit check may send a small number of benign repeated requests, within a configurable maximum.
- Active injection tests are disabled by default, require explicit opt-in, use low-impact benign canaries and differential/error/reflection evidence, and must not use destructive database commands, time-delay payloads, file writes, out-of-band callbacks, command execution, or data extraction.
- Sensitive file checks must minimize data retrieval. Use HEAD where reliable, otherwise a tightly capped GET; never store full response bodies or secret values. Evidence must redact credentials, tokens, personal data, and secret-like values.
- API write operations are disabled by default. Enable only for designated test/staging operations, test data, and a documented cleanup procedure.
- Subprocess command arguments must be passed as argument arrays (not shell interpolation). Apply executable allowlists, timeouts, output size caps, and safe flags. Never execute an uploaded file.
- Users must be able to cancel. The UI must display scan activity and targets, request counts, elapsed time, current stage, and stop control.

### 4.4 Secrets and evidence
- Never write raw credentials, authorization headers, cookies, API keys, or full sensitive response bodies into logs or findings.
- Keep secrets out of URL query strings. Use environment variable references or OS keychain references for test-account credentials; do not persist plaintext secrets in project JSON or exported backups.
- Redact evidence by default, with a configurable sanitizer for common token/secret patterns and user-configurable sensitive fields.
- Store evidence files with restrictive permissions and opaque filenames. Keep finding records pointing to evidence IDs, not arbitrary client paths.
- Provide clear delete controls and an evidence retention setting. Deleting a project must remove its files only after confirmation and must not escape the project directory.

## 5. Canonical data contracts

Use typed models and a `schema_version`. Exact fields may evolve, but equivalent information must be retained.

### 5.1 Project
- `project_id` (UUID or random stable identifier), `name`, `client_name`, `description`, timestamps, `status`.
- `authorization`: authorized-by, reference, start/end times, attestation event ID.
- `scope`: permitted hosts/domains/IPs, schemes, ports, path prefixes, excluded targets, redirect policy, internal-address override record.
- `scan_policy`: max concurrency, request rate, timeout, maximum pages/endpoints, response cap, scan duration, allowed modules, active probe toggles.
- `labels`, `notes`, `schema_version`.

### 5.2 Scan job
- `scan_id`, `project_id`, module, profile, explicit targets, parameters, state, queued/started/finished timestamps, progress, stage, counters, cancellation flag/state, actor, scope snapshot/hash, app/tool versions, warnings/errors, log references, output references, `schema_version`.
- A scan stores a snapshot of the scope/policy used at start so later project changes do not rewrite historical context.

### 5.3 Asset inventory
- Asset identifier, project, type (domain/hostname/IP/port/service/URL/API operation), canonical locator, parent relation, first-seen/last-seen, source scan, confidence, tags, observations, evidence refs, scope status.

### 5.4 Finding (canonical normalized model)
- `finding_id`, project, optional scan ID, stable fingerprint, title, summary, technical detail, category, affected asset(s), URL/endpoint, parameter/header/component when applicable, severity, confidence, verification state, business impact, evidence refs, CWE IDs, versioned OWASP mapping, API Security mapping, optional CVSS version/vector/base score, remediation, references, source tools/source finding IDs, deduplication history, analyst status (new/confirmed/false-positive/accepted-risk/fixed/retest-needed), created/updated timestamps, `schema_version`.
- Do not store a numeric CVSS score unless the vector/score is provided or calculated using a reliable implementation. Use a separate transparent heuristic risk score if needed and label it as internal prioritization, not CVSS.
- Keep technical severity, confidence, exploitability evidence, and business priority separate. A speculative issue should not automatically become Critical.

### 5.5 Evidence
- Evidence ID, project and finding references, evidence type, timestamp, source stage/tool, redacted request/response excerpts, hashes, truncation flags, data classification, relative storage path controlled by the storage layer.
- Keep response excerpts short and sanitized. Never include secrets merely to make a report look convincing.

### 5.6 Import artifact
- Import ID, project, original filename (sanitized display value), file hash, source type/tool/version when known, upload time, parse status, warnings, parser version, raw artifact relative path, number of records, mapped records, rejected records.
- Preserve original uploads for audit unless the user explicitly deletes them; limit access and enforce file size/extension/content checks.

### 5.7 Audit event
- timestamp, event ID, actor, project, action, target IDs, outcome, safe structured metadata, request correlation ID.
- Audit events include project creation/deletion, scope edits, authorization attestation, scan start/cancel, tool configuration changes, imports, finding-state changes, report generation/download, backup/restore, and safety-policy override attempts.

## 6. Module-by-module functional requirements

### Module 1 — Application shell, dashboard, projects

**Dashboard**
- Show project count, scan count, last scan status/time, total unique findings, severity breakdown, confirmed vs potential findings, reopened/retest-needed items, assets discovered, scans running/failed, and recent activity.
- Make every KPI clickable into a correctly filtered view.
- Show only real data from filesystem-backed services; provide a useful zero-data empty state.
- Clearly distinguish findings from scan events, assets from URLs, and unique findings from duplicate observations.
- Offer filters by project, time window, module, severity, confidence, state, and target.

**Project management**
- Create/edit/archive/delete projects; duplicate a project without copying secrets.
- A project setup wizard captures client/name, authorization window, target scope, exclusions, allowed modules, scan limits, and evidence policy.
- Before saving, validate all target fields and show normalized scope.
- Provide project-level overview: assets, scan history, findings, imports, reports, authorization status, and recent changes.
- Delete requires confirmation, a clear list of what will be removed, and path-safe cascading cleanup.
- Export a project as an archive with a manifest, JSON records, optional evidence, and checksums. Import must defend against archive traversal and oversized archives.

**Navigation**
- Dashboard; Projects; Assets/Attack Surface; Scans/Jobs; Findings; API Specifications; Imports; Reports; Integrations/Tools; Settings; Audit Log; Help/Methodology.
- Hide unavailable integrations only if their absence is explained; otherwise show status as unavailable/not configured.

### Module 2 — File-backed repository and settings

- One repository/service interface for CRUD on projects, scans, jobs, findings, assets, imports, evidence metadata, reports, settings, and audit events.
- Validate every file as loaded; display a repairable error for corrupt files rather than crashing the whole app.
- Create temporary files safely; atomic replacement; file locks around writes; restrict permissions; sanitize IDs and filenames.
- File schema migrations: version field, migration functions, backups before schema changes, and tests on older fixtures.
- Startup integrity checker: dangling evidence references, missing files, invalid JSON, index mismatch, orphan scan outputs, stale jobs, disk-space warnings.
- Derived indexes may accelerate queries, but can always be rebuilt from canonical files.
- Paginated/filterable queries should avoid loading huge evidence files into memory.
- Export and restore are tested end-to-end. Never execute content from imported archives.
- Settings UI displays data directory, free disk space if available, storage version, external tool availability, configured scan limits, and backup status.

### Module 3 — Scope and authorization enforcement

- Create a reusable scope engine used by the API layer and every scanner/integration.
- Provide functions such as `normalize_target`, `is_target_in_scope`, `validate_redirect`, `validate_resolved_ip`, `is_port_allowed`, `is_path_allowed`, and `require_active_authorization`.
- Apply deny-by-default when a scope cannot be parsed or safely resolved.
- Add unit and integration tests for IDN hosts, IPv4/IPv6, path prefixes, wildcard boundaries, redirects, DNS changes, private addresses, URL user-info tricks, encoded path traversal, mixed-case hosts, trailing dots, and default ports.
- Every blocked out-of-scope action is a structured event, not a request that silently proceeds.
- Scope overrides must be explicit, narrow, time-bound, auditable, and not available through a hidden config flag.

### Module 4 — Scan job manager, log stream, cancellation

- UI can create scan jobs, view queued/running/finished jobs, open live logs, cancel a job, and retry a failed job after review.
- States: queued, validating, running, completed, completed_with_warnings, failed, cancelled, interrupted, blocked_scope, and expired_authorization.
- Progress includes stage, percent only when it can be calculated meaningfully, target/endpoint counters, elapsed time, and warnings.
- Persist job state transitions and append-only structured events. Keep concise human-readable console logs alongside machine-readable events.
- Job runner enforces configured max concurrency, per-target budget, and subprocess limits. No unbounded `asyncio.gather` or unbounded queue.
- A job can write intermediate output so the UI can inspect partial results. Do not publish partial findings as fully verified.
- Handle application restart, worker crash, permission error, disk full, child-process timeout, network errors, cancellation, and corrupt job files.
- Avoid duplicate runs when two tabs submit the same request; use idempotency/request IDs where appropriate.

### Module 5 — Option A: Web Application Vulnerability Scanner

#### 5.1 Target setup and crawl
- Accept one in-scope HTTP/HTTPS base URL and optional in-scope path seeds.
- Validate scope and authorization before any request.
- Bounded crawl: maximum depth, pages, per-host requests/sec, total duration, allowed content types, maximum response size, same-scope links only, cycle detection, normalized URL deduplication.
- Respect `robots.txt` by default for crawler behavior; make the policy visible. This is not an authorization mechanism.
- Parse HTML links, forms, script/link references, and common metadata without executing JavaScript by default. Do not fetch out-of-scope assets.
- Query and form parameters are inventory only unless active tests are explicitly enabled.
- Support authenticated crawling only through explicitly configured test-session material, with secrets resolved from environment/keychain and redacted from logs. Never attempt login guessing.

#### 5.2 Security headers and browser-facing configuration
Check and explain relevant controls, including:
- Content-Security-Policy presence and basic unsafe patterns (avoid claiming complete CSP validation).
- Strict-Transport-Security only when HTTPS is used, with `includeSubDomains`/preload interpreted cautiously.
- X-Content-Type-Options, Referrer-Policy, frame protection via CSP `frame-ancestors` or X-Frame-Options, Permissions-Policy, and legacy headers only as informational when obsolete.
- Cache directives on sensitive-looking responses as a heuristic; do not flag all caching as vulnerable.
- Duplicate/conflicting headers, insecure cross-origin policy indicators, and server leakage.
- Findings must state exactly which response/path demonstrated the condition and its actual security implication.

#### 5.3 TLS/certificate analysis
- Check certificate validity window, hostname match, trust chain errors visible to the client, expiration, and HTTP-to-HTTPS behavior.
- Report protocol/cipher details only if retrieved by a reliable local TLS library or an installed `testssl.sh`/`sslyze` integration.
- External tool availability is detected, version captured, output parsed safely, timeout enforced, and unsupported modes shown clearly.
- Use conservative, documented options; no exploit checks or high-volume handshakes.
- Missing TLS integration must not be disguised as a pass. Mark it skipped/not configured.

#### 5.4 Misconfiguration/default file checks
- Configurable small list of common diagnostic/default files and directories, including directory listing indicators, known framework debug routes, default landing pages, source-control metadata, backup suffixes, and common secret/config filenames.
- Probe only in-scope paths and under request budget. Use `HEAD` when useful; otherwise cap body retrieval.
- Do not save entire sensitive body. Evidence should include status, content type, limited redacted excerpt or matching signature, bytes read, and confidence.
- A 200 status alone is not proof of exposure; inspect bounded response metadata/signature and avoid false positives from single-page applications/custom 404 pages.
- Do not automatically download backup archives or enumerate large files.

#### 5.5 Injection checks — safe mode
- Disabled by default and separately enabled for test/staging scope.
- SQL injection checks limited to benign, low-impact syntax/error/differential indicators; no time delays, database enumeration, file operations, stacked destructive statements, or data extraction.
- XSS checks use unique harmless markers to detect reflection and contextual encoding; do not execute browser scripts or attempt session theft. Report reflection separately from confirmed executable XSS.
- Do not mark a response vulnerable solely because the marker appears in escaped text.
- Keep payload catalog small, versioned, locally documented, and unit-tested against fixture apps. Cap probes per parameter and per scan.
- All active tests must have their test type and risk displayed before scan and be written to the job manifest.

#### 5.6 Component/version detection
- Identify likely server, framework, CMS, libraries, and client bundles from headers, generator metadata, common asset paths, source-map indicators, and known version patterns.
- Treat banner/version results as observations with confidence, not proof of vulnerability.
- Match to CVE records only when component identity/version mapping is defensible. Display source, version, match logic, data update timestamp, and whether the version range is exact/approximate.
- Support locally imported CVE data first; optional online lookup must be configured, rate-limited, and clearly indicated. Avoid dependence on a remote service for the scan to complete.
- Store matching catalog version and references so results can be reproduced.

#### 5.7 Web findings and evidence
- Finding title, category, severity, confidence, affected URL, method, parameter, response status, sanitized evidence, reproduction steps, impact, remediation, references, CWE/OWASP mapping, and scanner rule ID.
- Distinguish confirmed configuration problems from likely technology matches and possible injection indicators.
- Include a scan summary: pages fetched, endpoints discovered, checks run/skipped, error counts, out-of-scope blocks, rate-limit events, and limitations.

### Module 6 — Option B: Attack Surface Mapper

#### 6.1 Domain and subdomain inventory
- Inputs: explicitly authorized root domain(s), manually supplied hostnames, optional file import, optional passive-source integrations.
- Passive sources must be optional, documented, rate-limited, and disclose when third-party queries are used. Handle API keys as secrets.
- Do not perform high-volume brute-force subdomain enumeration by default. If wordlist enumeration is later supported, require explicit enablement, modest budgets, scope enforcement, and a clear warning.
- Candidate subdomains are discovery results, not automatic authorization to scan. Mark each as in-scope, pending approval, out-of-scope, unresolved, or excluded.
- Resolve A/AAAA/CNAME and relevant DNS records where safe; store source, TTL when available, timestamp, and resolution failures.
- Re-check destination IP policy to prevent DNS rebinding and inadvertent internal address scanning.

#### 6.2 Port/service inventory
- Default to a small documented TCP port allowlist and TCP connect scan (`-sT` equivalent) when Nmap integration is enabled.
- No stealth SYN scans requiring special privileges, no UDP/full-range scan, no Nmap `-A`, no intrusive NSE/vulnerability scripts, no OS detection by default.
- Show exact ports/method, timeout, rate, source tool/version, and unscanned ports. Never imply all ports were checked when only a subset was scanned.
- Use bounded service identification/banner grabs for services on discovered open ports only; redact possible secrets and do not authenticate to remote services.
- Run Nmap with explicit arguments and safe executable path; never compose commands with shell strings. Parse XML output from an isolated temporary directory and validate size/schema.
- If Nmap is absent, provide a visible “not installed” state and still support manual inventory and web checks.

#### 6.3 HTTP endpoint discovery and stack fingerprinting
- Probe only discovered hosts explicitly admitted into scope, using standard HTTP/HTTPS and configured ports.
- Discover service titles, response codes, content types, redirect chains, TLS metadata, common public endpoints, robots/sitemap links, and bounded same-origin crawl results.
- Fingerprint technologies based on multiple signals where possible; give confidence and evidence instead of absolute certainty.
- Endpoint discovery can re-use Module 5 crawl services but should avoid duplicate requests by sharing inventory/cache with expiration during a scan.
- Do not fetch authenticated/admin resources unless credentials and a test profile are explicitly configured.

#### 6.4 Attack surface dashboard and risk ranking
- Graph or nested table: root domain → host → IP → port/service → web origin → discovered endpoint.
- Filters for new/changed assets, exposed services, tech, scope status, confidence, scan date, and findings.
- Compare inventory snapshots between scans, and identify newly discovered assets or changed ports/certificates without calling change a vulnerability automatically.
- Prioritize based on confirmed exposure, asset importance configured by the user, severity/confidence of linked findings, and exposure category. Clearly disclose scoring logic.

### Module 7 — Option C: API Security Testing

#### 7.1 Specification import and validation
- Accept OpenAPI 3.0/3.1 and Swagger 2.0 YAML/JSON. Strictly limit file size, nesting, references, and number of operations.
- Parse with safe YAML and hardened JSON/XML utilities. Do not evaluate tags or execute specification content.
- Resolve local `$ref` values by default. External `$ref` fetching is disabled by default; if enabled, fetched locations must be explicitly approved and scope checked, with depth/size limits and cycle detection.
- Validate server URLs against project scope before any request. Do not trust a server URL just because it appears in a spec.
- Display import warnings for missing/invalid security schemes, deprecated fields, unresolved references, unsupported callbacks/webhooks, and ambiguous server variables.

#### 7.2 API inventory
- Show operation ID/summary, method/path, tags, auth scheme, parameters, request content types, declared response codes, schema required fields, data-type information, and whether an operation is read-only or potentially mutating.
- Support operation-level exclusion, test mode, per-operation safety flag, and tags.
- Provide a “dry inventory only” mode that parses a spec without sending traffic.
- Generate a complete route inventory report without any security probes.

#### 7.3 Authentication and access-control baseline
- Test baseline access only with explicit safe operations, starting with unauthenticated requests where policy permits.
- Store auth profiles as references to environment variables/keychain secrets, not plaintext. Redact bearer tokens, cookies, API keys, and passwords in every log/evidence layer.
- Compare authenticated and unauthenticated status/response shape cautiously. HTTP status alone is not proof of correct or incorrect access control.
- Do not test bypass payloads, steal tokens, or guess credentials.
- Function-level authorization test cases require user-defined roles/test identities and explicitly safe operations.

#### 7.4 BOLA/IDOR checks
- Enabled only when operator configures two authorized test accounts/roles and two or more test-owned object IDs or test fixture records.
- Require explicit field/path parameter mapping for object identifiers and a test plan explaining which user owns which object.
- Make at most bounded, controlled requests: owner access baseline then cross-user access comparison. Do not enumerate IDs or mutate another user's resource.
- Never infer IDs by incrementing/decrementing arbitrary production identifiers.
- Use response comparison, status, schema/field signatures, and known test fixture markers; mark ambiguous results as potential/manual review.
- Redact sensitive response fields; retain only minimal evidence demonstrating an authorization outcome.
- If preconditions are not met, show a clear skipped reason rather than a false pass.

#### 7.5 Mass assignment / object property authorization
- Inventory writable schemas and unexpected fields, but do not automatically write unrecognized fields to production.
- Default check: safe schema/response comparison or test-only requests on explicit staging/test endpoints.
- Mutating probe is allowed only when operation is marked test-safe, a disposable fixture is identified, and cleanup is configured and tested.
- Do not overwrite role, tenant, owner, balance, permission, price, or other sensitive properties in a live environment. In reports, distinguish “extra property accepted” from “unauthorized property changed and verified”.

#### 7.6 Rate-limiting and resource behavior
- No brute-force. Use a small number of benign repeated requests to one approved safe operation, within configured maximum.
- Back off immediately when 429, 503, elevated latency, or other instability is observed.
- Do not test expensive endpoints, payment/transaction operations, notification flows, or destructive workflows unless specifically reviewed and test-safe.
- State request count, time window, and evidence; a small probe that does not trigger a limit does not prove there is no rate limit.

#### 7.7 Error leakage and API configuration
- Check for verbose stack traces, framework exception pages, debug details, exposed version identifiers, sensitive error fields, missing transport/security headers, overly permissive CORS signals, and inconsistent error schemas.
- Redact PII/secret values. Show only minimal response excerpt and content-type/status.
- Avoid claiming CORS is exploitable from wildcard alone without analyzing credentials and browser context.

#### 7.8 API report and mappings
- Map findings to versioned OWASP API Security Top 10 and CWE, with mapping confidence and rationale.
- Include endpoints tested/skipped, auth profiles used by alias (never secret), count of requests, spec version/hash, operation-level coverage, safety settings, and known limitations.

### Module 8 — Option D: Import, normalization, deduplication

#### 8.1 Upload handling
- Validate file extension, size, MIME/content signatures where possible, encoding, and archive expansion limits. Do not trust user-supplied filenames.
- Store uploaded artifact in a project-specific path with hash and import metadata.
- Never execute uploaded scripts, macros, XML entities, or binaries. Parse in bounded memory/time. Harden against XML external entities, zip bombs, path traversal, and maliciously nested structures.
- Display a dry-run parse summary before merging findings into the project.

#### 8.2 Adapter interface and supported formats
Define a parser interface with `detect`, `validate`, `parse`, `normalize`, and `warnings`. Ship independent adapters with fixture files/tests for formats selected in `TBD_DECISIONS.md`.
- Nmap XML → hosts, ports, service metadata.
- Nuclei JSONL → findings, template/rule IDs, matcher evidence, references.
- OWASP ZAP supported JSON/XML/HTML exports → alerts, risk/confidence, URL, evidence, solution.
- Burp supported XML/JSON exports → issues, severity, confidence, host/path/location, request/response snippets when present.
- Nessus CSV/XML → plugin/title, severity, host/port, CVE/CWE if included, synopsis/solution.
- SARIF 2.1.0 → tool/rule/results, locations, level, fingerprints, fixes.
- Generic JSON/CSV template → user maps columns to canonical model.
- PDF/text parsing is best-effort and must show extraction confidence and require review. No fabricated detail when text is unavailable.

#### 8.3 Normalization and dedupe
- Normalize URL/host/method/path; remove secrets/query values from identifiers; preserve parameter names when useful.
- Stable fingerprint should consider category/rule/CWE, canonical asset, method, endpoint, parameter, source rule ID, and normalized title. Do not merge unrelated findings solely because their titles are similar.
- Keep source-specific IDs, original severity, original confidence, and import ID. Repeated observations should update “seen in scans/imports” history rather than lose provenance.
- Present proposed duplicates to the reviewer when confidence is medium/low. Allow manual merge/unmerge with audit history.
- Keep finding state separate from source scanner status.
- Findings imported without enough evidence should be marked `needs_review`, not silently confirmed.

#### 8.4 Analyst workflow
- Search/filter/sort findings by project, severity, status, confidence, source, CWE, OWASP mapping, asset, endpoint, first/last seen, and assignment/owner if implemented.
- Update analyst state (new, confirmed, false positive, accepted risk, fixed, retest needed), comments, business impact, and priority.
- Preserve prior values and timestamped audit log on edits.
- Support bulk updates with clear counts, preview, and undo where feasible.

### Module 9 — Unified risk scoring, standards catalog, remediation

- Maintain versioned local mapping catalogs (JSON/YAML) with source/provenance and last-updated metadata.
- Default web mapping: OWASP Top 10:2025; prior versions can be added without rewriting historical records. The catalog must not imply that every check is a one-to-one OWASP category mapping.
- Default API mapping: OWASP API Security Top 10:2023, tracked independently from the web Top 10 version.
- CWE records may contain ID, title, source, aliases, and last-updated date. Missing mapping is allowed and shown honestly.
- Use CVSS only when a valid version/vector/score is supplied or produced by a maintained correct calculator. Keep CVSS base score distinct from internal prioritization.
- Internal risk priority can consider severity, confidence, internet exposure, asset criticality, exploit evidence, and data sensitivity, but the formula and weights must be visible and configurable.
- Do not add severity points merely because a tool calls a finding “critical”. Normalize source scales carefully and preserve original values.
- Remediation content can come from curated rule definitions and source output; must be actionable, accurate, and specific to detected evidence. Avoid generic blanket language where a finding has a specific root cause.
- Include references only when known. Do not fabricate links, CVEs, affected versions, vendor advisories, or reproduction evidence.

### Module 10 — Report generation and exports

#### 10.1 HTML/PDF report structure
1. Cover page: client/project, report title, assessment dates, classification label.
2. Executive summary: concise posture, confirmed findings, priority distribution, key risks, and limits.
3. Scope and authorization statement: approved targets, exclusions, scan dates, profiles, and authorization record reference.
4. Methodology: modules/checks run, tools/versions, rates/budgets, standards/catalog versions, passive vs active actions.
5. Summary tables: severity, confidence, status, asset types, affected hosts/endpoints, trend where comparable scans exist.
6. Finding details: ID, title, severity/confidence, state, affected asset, business impact, observed evidence (sanitized), reproduction steps, remediation, mapping and references.
7. Attack surface inventory: hosts, ports/services, endpoints, technologies, discovery confidence and scope status.
8. API coverage: spec, methods/operations tested, skipped operations and reasons, auth profiles by alias.
9. Scan health/limitations: skipped checks, blocked requests, tool missing/failed, low-confidence version detections, request budget limits.
10. Appendix: glossary, score explanation, source-tool IDs, import provenance, report generation timestamp.

#### 10.2 Output and quality
- Generate readable semantic HTML, accessible tables, print styles, page breaks, headers/footers, consistent severity labels, and repeatable layout.
- PDF should match HTML content and preserve text selection where possible; avoid screenshots of pages as the report.
- Never include credentials, cookies, access tokens, full sensitive bodies, local absolute paths, or internal exception traces in client-facing reports.
- Support filtering which findings/assets appear in a report and require a preview before export.
- Include report metadata and checksum. Store generated reports in project folder and allow download.
- Provide JSON and CSV normalized findings exports with a documented schema. Export must respect secret redaction and selected scope.
- Report templates must not hide warnings or inflate confidence. “No findings” must be phrased as “No findings detected by checks executed” with limits, not “secure” or “no vulnerabilities exist.”

### Module 11 — Tool integrations and external-data management

- Integrations settings show detection status, executable/version, configuration, last successful run, and troubleshooting.
- Initial optional external tools: `sslyze` or `testssl.sh` for TLS; Nmap for bounded port/service mapping; optional passive subdomain APIs; optional local CVE data import.
- Every integration has an adapter, timeout, argument allowlist, output cap, error handling, version capture, and mocked tests.
- Missing external tooling should degrade gracefully and mark related checks skipped, never silently pass.
- No shell string execution. Validate paths and restrict configured executables. Do not execute files uploaded through the UI.
- External feeds need provenance, fetched/imported date, version, licensing notes, and stale-catalog warnings.

### Module 12 — Authentication, local security, and operator controls

- Default bind address is localhost (`127.0.0.1`), with clear UI warning if the user configures remote access.
- If remote access is supported, require explicit secure mode: authentication, secure cookie/session strategy, CSRF protection where cookies are used, strict CORS, request size limits, and secret configuration. Never ship default admin passwords.
- Local password files, if implemented, use a maintained password hashing algorithm (Argon2id preferred) and atomic write/lock handling. Passwords are never stored in plaintext.
- Apply least privilege to process/filesystem access. Validate API inputs and avoid unsafe deserialization.
- Set security headers for the Workbench UI; protect against stored/reflected XSS in imported titles/evidence by contextual escaping and content sanitization.
- Never render raw HTML from target responses or uploaded findings. Display it as escaped text unless explicitly sanitized for a safe preview.
- Add CSRF protections to state-changing routes as appropriate, restrictive CORS, strict content-type checks, request size limits, safe error messages, and structured server-side logs.
- Provide a visible kill switch to stop all active scan jobs. Disable new active scans while it is engaged.

### Module 13 — Audit, reliability, accessibility, and UX

- Audit log is append-only and records sensitive operator actions without storing secrets.
- UI must have loading, success, partial success, error, empty, disabled/not configured, cancelled, and retry states.
- Forms use inline validation and explain why a target/configuration is blocked.
- Severity must not be conveyed by color alone; use text/icon/label and accessible contrast.
- Support keyboard navigation, clear focus, semantic headings, labels, status announcements, and tables accessible to screen readers.
- Scan detail page has overview, stage timeline, live log, counters, findings, assets, warnings, and cancellation.
- Error details shown to users must be actionable without exposing stack traces or secrets.
- Use correlation IDs across HTTP action, audit event, job, subprocess, and report generation.

## 7. API endpoints and frontend pages

Choose clean REST paths and document them. Suggested endpoints:
- `/api/health`, `/api/readiness`, `/api/version`
- `/api/projects` CRUD, plus project export/import
- `/api/projects/{id}/scope` preview/validate
- `/api/projects/{id}/scans` list/create
- `/api/scans/{id}` status/detail; `/api/scans/{id}/events`; `/api/scans/{id}/cancel`
- `/api/projects/{id}/assets`; `/api/projects/{id}/findings` list/search/update; `/api/findings/{id}` details/state
- `/api/projects/{id}/api-specs` import/list/detail/validate
- `/api/projects/{id}/imports` dry-run/commit/list/detail
- `/api/projects/{id}/reports` preview/generate/list/download
- `/api/integrations` status/config validation
- `/api/settings` read/update safe settings
- `/api/audit` filtered event list

Do not implement every endpoint blindly before designing typed models. Every endpoint must have request/response schemas, validation, consistent error format, and tests.

Frontend pages:
1. Dashboard
2. Projects list and project setup wizard
3. Project overview
4. Scope/authorization setup and preview
5. Asset inventory / attack-surface map
6. Scan configuration and confirmation screen
7. Scan history and live scan details
8. Findings list/detail/edit/review
9. API specification import and operation inventory
10. Import center with dry-run and merge review
11. Report builder/preview/download
12. Integrations/tools
13. Settings/storage/backup
14. Audit log
15. Help/methodology/limitations

## 8. Testing strategy

### Unit tests
- Pydantic model validation and schema version handling.
- File repository CRUD, atomic replacement, concurrent writers, corrupt JSON, stale locks, path traversal, symlink escape, file permissions where testable, and derived-index rebuild.
- Scope normalization/matching, redirect validation, IP classification, DNS rebinding handling, IDN, IPv6, URL user-info, path prefixes and encoded traversal.
- Finding normalization/fingerprints, deduplication conflicts, severity normalization, mapping catalog versioning, evidence sanitizer.
- Scanner check logic using mocked responses and fixtures, not external targets.
- Import adapters with valid, malformed, oversized, malicious XML/JSON/YAML/CSV, duplicate records, and partial-data cases.
- Report escaping, sanitization, deterministic HTML and PDF generation, and no-secret assertions.

### Integration tests
- FastAPI test client against temporary data directory.
- Create project → configure scope → run a scan against a local test fixture server → persist findings/evidence → restart app/repository → findings remain → generate HTML/PDF → export/import project.
- Job cancellation and restart recovery.
- Optional tool integrations run only in explicitly enabled integration tests with tool mocks by default.
- Fixture-based SSRF/scope tests verify no out-of-scope request was actually made.

### Frontend tests
- Project creation validations and blocked-scope errors.
- Scan start, progress, cancellation, failed and partial results.
- Finding filters, analyst state changes and audit display.
- Import dry-run/review and report preview/export.
- Loading/empty/error states and accessible form labels.

### End-to-end acceptance
- A clean installation can start using documented commands.
- User can create a project, configure an authorized local fixture target, run safe baseline scan, view results, stop a scan, import a sample scan report, deduplicate findings, generate and download HTML/PDF, export a project, restart the app, and see persisted results.
- All test data can be generated locally; tests do not need internet access or a real third-party target.

## 9. Non-functional requirements

- Reliable on a single developer workstation with no database or broker service.
- Bounded memory, body sizes, import sizes, task queue, concurrency, request rate, crawl depth and scan duration.
- Structured logs with no secrets; rotating event log; clear disk-full behavior.
- Deterministic parsing/report generation for same input and version where practical.
- Maintainable modular code, typed interfaces, testable scanner checks, lockfiles and documented dependencies.
- Clean setup for Windows and a supported POSIX path; disclose external-tool compatibility constraints. If an optional tool is unavailable on a platform, expose a documented degraded mode.
- No hidden network requests from the Workbench itself except those explicitly configured for targets or external intelligence providers.
- All external calls must be visible in project scan summaries and settings.

## 10. Definition of done

The application is not complete until:
- All core pages and flows are wired to real backend services.
- Filesystem persistence survives restart and has locking/recovery tests.
- No database/broker is installed or required.
- Scope enforcement is invoked for every outbound scan action and is tested against bypass cases.
- Safe scan defaults, rate limits, timeouts, cancellation, and audit logging work.
- Options A, B, C, and D each have working MVP functionality, not placeholder buttons.
- Importers preserve provenance and handle malicious/malformed input safely.
- Findings have evidence, confidence, remediation, source provenance and honest standards mappings.
- HTML/PDF reports render, download and redact secrets.
- Dependency checks, backend/frontend tests, lint/type checks pass.
- README and `docs/` explain setup, configuration, scan profiles, optional integrations, data storage, backup/restore, safe use, limitations and troubleshooting.
- The final response from Claude Code lists files changed, commands run, tests passed/failed, known limitations, and remaining TBDs. Never claim tests were run if they were not run.

## 11. Implementation behavior expected from Claude Code

1. Inspect the current repository before editing. Read existing README, manifests, tests, app entry points and folder structure.
2. Create/update `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`, `docs/SCAN_SAFETY.md`, `docs/STORAGE_FORMATS.md`, and `docs/TESTING.md` as phases implement those topics.
3. Work only on the requested phase. Avoid rewriting unrelated files or jumping forward to unfinished modules.
4. Before coding, present a brief phase plan and list files likely to change. Then implement; do not stop at analysis or a proposed diff.
5. Run relevant tests, lint/type checks and build. Fix regressions created by the phase.
6. Update the requirements/traceability section in `docs/IMPLEMENTATION_STATUS.md` with `Implemented`, `Partial`, `Blocked`, or `Not started`, linking each requirement to code/tests.
7. Update `TBD_DECISIONS.md` with any material choices, trade-offs, and follow-up decisions.
8. If a dependency or feature is not feasible, implement the best safe fallback and document the limitation; do not fake results.
9. Keep each phase small enough for reliable review. Do not proceed to the next phase until asked or until using an explicitly provided phase prompt.
10. Never use a database, database-backed job queue, or an unapproved remote service to simplify implementation.

## 12. Bootstrap checklist

At the beginning of implementation:
- Inspect repo and report current framework/state.
- Confirm no database libraries/services already underpin required functionality; if they do, propose a migration path instead of silently retaining them.
- Add or adapt `.gitignore` so runtime data, uploads, scan results, secrets, reports, and evidence are not committed.
- Establish typed contracts and architecture before scanner payloads/rules.
- Set localhost-only binding as the default.
- Create harmless local fixture targets and synthetic import files for tests.
- Build the project skeleton and health check before active scanning code.
- Mark all four options in an implementation matrix and do not treat any option as out of scope.
