# PHASE-BY-PHASE CLAUDE CODE PROMPTS

Read `MASTER_SPEC.md` before starting. Use one phase at a time. At the end of each phase, run the corresponding verification prompt from `VERIFICATION_PROMPTS.md`. Do not jump ahead or claim completeness based only on compile success.

---

## Bootstrap Prompt — Repository discovery and working agreement

You are the lead engineer implementing the VAPT Workbench in this existing repository. First read `MASTER_SPEC.md`, `TBD_DECISIONS.md`, and the current repository docs/manifests/tests. Inspect the codebase before making edits.

**Do this now:**
1. Identify the framework, current run commands, existing pages/APIs, test setup, dependency managers, and any implemented features.
2. Identify every database or broker dependency already present. The required design is strictly no database: no PostgreSQL, SQLite, MySQL, MongoDB, Redis, or database-backed queue. If the repository already uses one, document a safe migration plan and do not silently rely on it.
3. Map current files to the modules in `MASTER_SPEC.md`; preserve valid work and do not rewrite unrelated code.
4. Write/update `docs/ARCHITECTURE.md`, `docs/IMPLEMENTATION_STATUS.md`, and `TBD_DECISIONS.md` with current facts, open questions, proposed safe defaults, and an implementation matrix for Options A, B, C, and D.
5. Propose phase sequencing and files likely to change, then implement only Phase 00 when prompted below.
6. Ensure runtime data and scan artifacts will be gitignored. The application defaults to localhost-only.

Do not implement scanning payloads yet. Do not fabricate existing behavior. Report findings, proposed architecture, risks, and any truly blocking repository constraints.

## Phase 00 — Architecture, threat model, and implementation baseline

**Prompt to paste:**

Implement Phase 00 only: architecture and project baseline. Follow `MASTER_SPEC.md` and preserve existing working code.

### Required work
1. Create/update `docs/ARCHITECTURE.md` showing frontend/backend/module boundaries, data flow, job flow, and filesystem persistence. Explain why this is a single-host, single-instance architecture.
2. Create `docs/SECURITY_MODEL.md` covering trust boundaries, secrets, uploaded files, external scanner processes, local API/UI, target systems, and report recipients.
3. Create `docs/SCAN_SAFETY.md` capturing authorization, scope checks, allowlist/denylist logic, conservative defaults, cancellation, rate limits, sensitive evidence redaction and prohibited behaviors.
4. Create `docs/STORAGE_FORMATS.md` documenting canonical JSON/JSONL files, IDs, schema-version strategy, atomic writes, locking, indexes, backup/restore, and corruption recovery.
5. Create `docs/TESTING.md` with unit/integration/frontend/E2E strategy and local fixture-server approach.
6. Add/update a dependency and feature inventory. Do not install a broad set of speculative packages.
7. Establish `docs/IMPLEMENTATION_STATUS.md` with every master-spec module and a status of Not started/Partial/Implemented/Blocked; include planned file paths and test references.
8. Update `TBD_DECISIONS.md`: propose safe defaults for low-risk unknowns; leave material safety/data-loss/deployment choices open if not inferable.
9. Inspect and update `.gitignore` for runtime data, secrets, uploaded sources, scan logs/evidence, generated reports and temporary tool output.
10. If missing, add a minimal health/version endpoint and a documented local dev command only if compatible with the existing repo. Do not build the scanner yet.

### Acceptance criteria
- Architecture matches the no-database constraint.
- No scan action can occur in this phase.
- Current repository and test status are accurately reported.
- All implementation statuses are honest, with evidence/test pointers where implemented.
- The application remains runnable.

### Output
Summarize files changed, architecture decisions, commands/tests run, blockers, and exact next phase recommendation. Do not proceed to Phase 01.

## Phase 01 — Backend foundation and filesystem repository

**Prompt to paste:**

Implement Phase 01 only: the typed backend foundation and filesystem persistence layer. Read `MASTER_SPEC.md` and current phase status first.

### Required work
1. Establish or adapt FastAPI configuration, settings, typed error responses, request correlation IDs, structured logging, health/readiness/version endpoints, and API versioning if appropriate.
2. Define Pydantic v2 contracts for Project, AuthorizationRecord, ScopeDefinition, ScanJob, Asset, Finding, EvidenceMetadata, ImportArtifact, AuditEvent, ReportMetadata, and AppSettings. Include `schema_version`; enforce enums and bounded strings/lists.
3. Build a `StorageRepository`/service abstraction. Routers and scanners must not perform ad hoc file writes.
4. Implement safe data-root resolution using `VAPT_DATA_DIR` with a documented default outside the repository. Reject paths outside root, traversal, untrusted absolute paths, and symlink escapes where supported.
5. Implement JSON read/write with validation; atomic write/replace; temporary-file cleanup; safe file permissions; per-record locking; cross-process startup lock for one app instance per data root.
6. Implement project/scan/finding/asset/import/evidence metadata CRUD with pagination/filter helpers as needed. If a resource has not yet been used by a UI, ensure storage APIs and tests exist without adding fake functionality.
7. Implement append-only JSONL audit/events with secret redaction, line-level corruption handling and log rotation. Prevent raw auth headers/cookies/tokens from entering the event log.
8. Implement schema versioning and migration hooks, integrity checker, derived-index rebuild, and graceful handling of corrupt or missing files.
9. Add safe startup behavior for first run and a diagnostic command/endpoint for data directory readiness, writable state and disk-space warning when available.
10. Add unit tests for CRUD, atomic replace, simultaneous updates, corrupt JSON, invalid schema, path traversal, symlink escape, stale locks, index rebuild and restart persistence.

### Constraints
- No SQLite or database-like dependency.
- No secrets stored in plaintext records.
- Do not add scanner logic in this phase.
- Keep single-instance locking explicit and documented; do not claim multi-node readiness.

### Acceptance criteria
- Test creates project/findings/assets, restarts repository, reads exact data back.
- Atomic writes protect against half-written JSON.
- Malformed records are reported safely without crashing unrelated projects.
- Tests prove path escape attempts fail.
- All backend tests/lint/type checks pass or failures are described precisely.

Do not proceed to Phase 02.

## Phase 02 — Frontend shell, dashboard, and project management

**Prompt to paste:**

Implement Phase 02 only: responsive UI shell, real dashboard, project list/create/edit/detail, and project setup wizard. Build on existing app conventions.

### Required work
1. Create the app layout, navigation, page titles/breadcrumbs, consistent spacing/typography/tables/forms, toast/alert pattern, loading states and responsive desktop-first layout.
2. Add typed API client and centralized API error handling. Do not call the filesystem from the browser.
3. Build Dashboard with real API data for project count, scan totals, active/failed scans, unique findings by severity/status/confidence, assets discovered and recent activity. If downstream resources are empty, render honest zeros and useful empty states.
4. Make KPI cards clickable into pre-filtered pages or views. Do not add fabricated graphs, static totals or pretend scan data.
5. Implement Projects list with search/sort/pagination, create/edit/archive/delete, project overview, status, authorization expiry indicators and last scan.
6. Implement setup wizard fields: project/client name, target owner, authorization window, authorized-by/reference, scope, exclusions, allowed modules, request limits, evidence retention. Normalize and preview scope before saving.
7. For deleting a project, show impact and require confirmation. Wire to backend path-safe deletion only if repository delete is implemented; otherwise provide a clearly disabled state and record the dependency rather than faking success.
8. Show app version, data directory status (without exposing absolute sensitive paths unless necessary), and tool availability placeholders only where backend API exists; unavailable integrations must be labeled not configured, not green.
9. Add accessible labels, keyboard focus, semantic headings, non-color-only statuses, and frontend tests for core forms/navigation/empty states.

### Acceptance criteria
- Create and edit a project from the UI, reload the page and confirm data persists.
- Dashboard counters derive from the API.
- Validation errors from backend show useful messages.
- No scanner controls falsely imply a scan runs.
- Frontend build, tests and available lint/type checks pass.

Do not proceed to Phase 03.

## Phase 03 — Authorization, target normalization, and scope engine

**Prompt to paste:**

Implement Phase 03 only: shared scope/authorization enforcement. This phase is a hard safety gate; later scanners must reuse these exact services.

### Required work
1. Design typed scope models for schemes, exact hosts, safe wildcard domain boundaries, permitted IP/CIDR ranges, ports, path prefixes, exclusions, API server URLs, internal-target override metadata and authorization expiry.
2. Implement canonicalization for HTTP(S) URLs, IDN hostnames, default ports, trailing dots, IPv4/IPv6 and normalized paths. Reject user-info credentials in URLs and non-HTTP(S) schemes for web/API targets.
3. Implement `normalize_target`, `is_target_in_scope`, `is_port_allowed`, `is_path_allowed`, `validate_redirect`, `validate_resolved_ip`, and `require_active_authorization` in a reusable scope package.
4. Block loopback, link-local, private, multicast, unspecified and cloud metadata IPs by default. Allow internal targets only through an explicit project-level override with scope, reason and audit event. Avoid using arbitrary internal target allowlists from request payloads.
5. Prevent suffix confusion and wildcard bypasses. Ensure `trusted.example.attacker.test` does not match `trusted.example`; handle IDN/punycode, encoded paths, unusual ports and IPv6 correctly.
6. Resolve/check every redirect, DNS-resolved IP, discovered subdomain, port, and endpoint before network activity. Add a policy hook all future HTTP/DNS/subprocess scan entrypoints must call.
7. When authorization is expired or absent, active scans are blocked. Attestation must be logged with a timestamp; scope change requires a new preview and audit event.
8. Provide a scope preview API and UI display of normalized approved targets, exclusions, blocked address ranges and policy errors.
9. Add exhaustive unit/property tests for scope matching, redirects, SSRF, DNS changes, private addresses, traversal, URL parsing tricks and expiry boundaries.

### Acceptance criteria
- Tests demonstrate that an out-of-scope host/IP/path never reaches the request adapter.
- Expired/absent authorization cannot start active work.
- Scope engine returns an auditable decision/reason for allow/block.
- All existing tests remain green.

Do not proceed to Phase 04.

## Phase 04 — Persistent job manager, scan lifecycle, logs, cancellation

**Prompt to paste:**

Implement Phase 04 only: the filesystem-backed job controller used by all scan modules. Do not introduce Redis, Celery, SQLite, or another broker/database.

### Required work
1. Define state transitions: queued, validating, running, completed, completed_with_warnings, failed, cancelled, interrupted, blocked_scope and expired_authorization. Enforce valid transitions.
2. Implement job manifests under a filesystem spool, a bounded worker loop/queue, atomic state updates, per-job locks and claim logic so duplicate workers cannot run one job twice.
3. Persist job parameters, scope/policy snapshot hash, authorized targets, module/profile, creator, timestamps, progress/stage/counters, cancellation request, versions, logs, errors and output references.
4. Implement worker concurrency cap, per-target rate budget, target request budget, maximum total duration and subprocess timeout/kill handling. Defaults must be conservative and configurable.
5. Implement structured JSONL event stream and concise human log file; apply redaction before writing. Store correlation ID across API request/job/subprocess.
6. Implement cancellation from API/UI. Stop scheduling new work, signal scanner and terminate child processes, preserve partial output and mark cancelled. Add a global kill switch preventing new active jobs and requesting cancellation of active ones.
7. On startup: queue valid unclaimed queued jobs, detect stale locks, mark orphaned running jobs interrupted, preserve partial results, and never blindly replay ambiguous in-flight active requests.
8. Ensure start endpoint checks authorization/scope and validates module availability before creating/running a job. Every scanner will later use shared job context and scoped request adapter.
9. UI: Scan History, job details, live/refreshing events, stage progress, target/counter summary, warning/error state and cancel action.
10. Add tests for state transitions, duplicate start, queue cap, cancellation, process timeout, app restart, stale job, log redaction and kill switch.

### Acceptance criteria
- A test job runs a fake worker, progress persists and UI reflects it.
- Cancellation stops new work and final state is accurate.
- Restart recovery is deterministic and documented.
- No unbounded concurrency or in-memory-only job state.

Do not proceed to Phase 05.

## Phase 05 — Shared HTTP/DNS/process adapters and Option A web scanner

**Prompt to paste:**

Implement Phase 05 only: shared safe network adapters and Option A — Web Application Vulnerability Scanner. Scope enforcement is mandatory for each outbound request. Do not add exploit-oriented behavior.

### Shared adapters
1. Build a single HTTP client/request service with explicit connect/read/write timeouts, maximum redirects, response byte limits, decompression limits, safe headers, per-host pacing, retry/backoff, and a scope validation hook before every request/redirect.
2. Avoid automatic redirect following unless each destination is validated. Avoid ambient proxy settings unless explicitly allowed/documented.
3. Add DNS resolver wrapper with result caching boundaries and IP-policy checks. Every request must account for DNS re-resolution behavior.
4. Add subprocess adapter that uses argument arrays, executable allowlists, controlled cwd/temp directory, timeout, kill/cleanup, output byte cap, version capture, and no shell interpolation.
5. Test all adapters with mocks and a local fixture server that logs requests; prove out-of-scope URLs were never requested.

### Web scanner implementation
1. Build a scan profile UI showing enabled checks, request budgets, authentication profile alias (if used), safe-mode status, and explicitly disabled checks.
2. Implement bounded same-scope crawler with URL canonicalization, loop/cycle detection, depth/page limits, allowed content types and response-size cap. Inventory links, forms, parameter names, content type, status, title, and redirect behavior.
3. Add checks: HTTPS availability and redirect behavior; TLS certificate hostname/validity; security headers; cookie Secure/HttpOnly/SameSite observations; server/version leakage; obvious debug/default pages; directory listing indicators; bounded sensitive-file exposure signatures; unsafe redirect indicators where safely detectable; common cache/CORS misconfiguration signals.
4. Add optional TLS integration adapter for `sslyze` or `testssl.sh`. Detect and report absence. Capture tool version/output provenance. Do not claim cipher coverage if the tool did not run.
5. Add component detection with evidence/confidence. Support local CVE data import later; in this phase create a clear adapter contract and do not invent CVEs or affected versions.
6. Add opt-in low-impact SQLi error/differential checks and XSS marker/reflection/context checks. They remain disabled by default and must not use time-delay, destructive, data extraction, command execution, out-of-band, or browser-executed payloads. Separate reflection from confirmed executable XSS and escaped reflection from possible vulnerability.
7. Implement a small, versioned, documented rule catalog. Every check returns pass/observation/finding/skipped/error with rationale; a failed check is not a pass.
8. Create canonical findings and sanitized evidence; cap body storage and redact secret-like values. Keep request count, check count, skipped reasons, tool versions, warnings and blocked-scope attempts in scan summary.
9. UI: scan setup/confirm; job progress; scan detail tabs for Summary, Pages/Endpoints, Findings, Logs, Warnings and Coverage. Findings filter into global findings view.
10. Add local fixture apps/responses for headers, listing marker, default page, escaped XSS reflection, unescaped marker reflection, generic error page, false-positive SPA 404, redirect off-scope, expired cert fixture if practical, and rate limiting.

### Acceptance criteria
- A safe baseline scan against a local test app discovers pages and emits evidence-backed results.
- Active injection tests require explicit enablement and are bounded.
- Scan respects scope, limits, cancellation and redaction.
- Missing TLS/CVE integrations are marked skipped/unavailable, not passed.

Do not proceed to Phase 06.

## Phase 06 — Option B attack surface mapper

**Prompt to paste:**

Implement Phase 06 only: Option B — Attack Surface Mapper, reusing the shared scope engine, adapters, job system, inventory, and finding models.

### Required work
1. Build a setup flow for authorized root domains, manually supplied hosts, imported host lists, exclusions, approved ports, passive-source configuration and scan budgets.
2. Implement subdomain candidate collection from manual inputs and any chosen passive source adapters. External data sources must be optional, rate-limited, configured and shown in the scan summary. No aggressive DNS wordlist brute force by default.
3. Store candidate status as pending approval/in-scope/excluded/out-of-scope/unresolved. Discovery alone does not grant active-scan permission.
4. Resolve A/AAAA/CNAME and supported DNS records; record source/timestamp/TTL if available; validate each resulting IP against scope policy and private-address protection.
5. Implement bounded TCP connect port checks for an explicit conservative default list. If Nmap is available, integrate through subprocess adapter with safe allowlisted flags and XML output. No stealth/SYN scan, no full-range/UDP scan, no `-A`, no intrusive NSE scripts, and no default vulnerability scripts.
6. Add manual/no-Nmap fallback and tool availability diagnostics. Report precisely which ports were tested and which were not.
7. Identify simple services/banners only on in-scope discovered open ports, without logging into services or storing secrets. Sanitize possible secret strings.
8. Identify HTTP/HTTPS origins, titles/status/TLS basics, bounded same-origin endpoints, certificate expiry, response headers and technology signals. Reuse Module 5 where possible with cache to avoid repeated requests.
9. Create asset graph/table: domain → host → IP → port/service → web origin → endpoint. Implement filters and change comparison against previous inventories.
10. Risk ranking should be transparent: confirmed findings/exposure and user-entered asset criticality may influence priority; discovery itself is not a vulnerability.
11. Add tests with mocked DNS, Nmap XML fixtures, missing executable, malformed XML, out-of-scope discovered host, private IP resolution and bounded port behavior.

### Acceptance criteria
- New subdomain candidates are not actively scanned until approved/in scope.
- Nmap commands are safe, bounded and shell-free.
- Reports disclose scan coverage and limits accurately.
- Asset relationships and last-seen changes persist across app restarts.

Do not proceed to Phase 07.

## Phase 07 — Option C API security testing module

**Prompt to paste:**

Implement Phase 07 only: API Security Testing from OpenAPI/Swagger. Start with safe inventory/dry mode, then bounded baseline checks. Follow all safety constraints in `MASTER_SPEC.md`.

### Required work
1. Implement upload handling for OpenAPI 3.0/3.1 JSON/YAML and Swagger 2.0 JSON/YAML. Use safe YAML loading, size/depth/operation limits, schema validation and path-safe storage.
2. Resolve local `$ref` values with cycle/depth limits. Keep remote `$ref` disabled by default; any optional remote fetch must pass explicit host approval, scope rules and size/time caps.
3. Validate server URLs from the spec against scope and server variables. Provide an inventory-only mode that makes zero network requests.
4. Show endpoint/method/operationID/tags/auth scheme/parameters/request schema/response schema/content type and mutability classification. Let the user exclude operations.
5. Add safe unauthenticated/authenticated baseline checks using only selected, approved operations. Credential material references env/keychain aliases; redact secrets everywhere.
6. Error leakage/config checks: stack-trace/framework error indicators, insecure transport, missing headers, overly permissive CORS signals, inconsistent errors, verbose version leakage. Avoid overclaiming CORS findings.
7. Mass assignment: inventory unexpected properties by default. Any write probe is disabled unless operation is test-safe, test fixture exists, explicit opt-in is set, and cleanup is defined. Do not attempt sensitive property modification against live systems.
8. IDOR/BOLA: UI requires two test identities plus explicit ownership/object-ID mapping and test-safe operations. Run bounded owner-vs-other-user requests only. No ID guessing/enumeration or mutation of other-user resources. If prerequisites are absent, emit skipped reasons.
9. Rate limiting: small capped benign request sequence on a designated safe operation; back off on 429/503 or latency instability. No brute force or high-rate loops.
10. Produce coverage report with tested/skipped operations, preconditions, number of requests and module settings. Normalize findings, attach evidence, map to CWE and versioned API Top 10 catalogue with confidence.
11. Add fixtures for OpenAPI v3, Swagger 2, external refs, cyclic refs, malformed schema, unauthorized endpoint, verbose stack trace, property reflection, IDOR test fixture and rate-limit responses.

### Acceptance criteria
- Spec import and inventory work offline.
- Network requests only target approved `servers` and operations.
- IDOR checks cannot run without explicit test identities/resource mapping.
- Mutating requests are disabled by default.
- Coverage includes skipped checks with reasons; no false “all passed” summary.

Do not proceed to Phase 08.

## Phase 08 — Option D import center and scanner format adapters

**Prompt to paste:**

Implement Phase 08 only: import center for external VAPT reports and scan outputs, including dry-run review, canonical normalization, provenance and deduplication. Read `TBD_DECISIONS.md` to confirm which formats are in this release.

### Required work
1. Create a parser-adapter interface: detect format, validate input, parse bounded records, normalize to canonical observation/finding/asset, emit warnings, and provide parser version.
2. Implement selected adapters with fixture-based tests. Preferred initial formats: Nmap XML, Nuclei JSONL, SARIF 2.1.0, ZAP supported export(s), Burp supported export(s), Nessus CSV/XML and generic CSV/JSON mapping. Add only formats feasible with tests; explain any unsupported format.
3. PDF/text import must be best-effort only. Show extraction confidence and ask the operator to review; never invent evidence/severity/CVE/mapping from missing text.
4. Validate file size, content type, extension, encoding, archive expansion count/size, nesting, XML safety and JSON complexity. Reject path traversal and never execute uploaded content.
5. Store original upload hash, sanitized display filename, source-tool version where possible, parser version, import timestamp, parse warnings and raw artifact path.
6. Implement dry-run import preview: parsed count, rejected count, warnings, mapping gaps and proposed duplicates. Require an explicit commit before merging normalized records into the project.
7. Normalize severity and confidence while retaining original source rating. Keep raw source identifiers and provenance. Mark weakly evidenced imports `needs_review`.
8. Implement duplicate detection with canonical host/URL/method/parameter/rule/CWE/title signals. Do not merge solely on similar title. Offer review for uncertain duplicate candidates; record merge/unmerge history.
9. Implement generic CSV mapping UI or documented mapping config and test invalid/missing columns.
10. Add tests for malformed/oversized files, XXE, zip bombs, weird encodings, duplicate IDs, malformed records, partial parser success, false-positive dedupe and provenance preservation.

### Acceptance criteria
- Import preview does not modify canonical project findings until commit.
- Source and parser provenance survive export and report generation.
- Untrusted HTML/content is escaped in UI/report.
- Every supported format has representative fixtures and failure tests.

Do not proceed to Phase 09.

## Phase 09 — Unified finding review, standards mapping and risk prioritization

**Prompt to paste:**

Implement Phase 09 only: central findings workbench, versioned standards mapping and transparent risk ranking across scanner-native and imported findings.

### Required work
1. Implement global/project findings views with search, filter, sort and pagination by severity, confidence, state, source, module, asset, endpoint, CWE, OWASP mapping, first/last seen and reviewed status.
2. Build finding detail page with sanitized evidence, source provenance, affected asset, reproduction steps, impact, remediation, references, scan history/observations and audit history.
3. Implement analyst states: new, confirmed, false_positive, accepted_risk, fixed, retest_needed, needs_review. Keep scanner confidence and severity separate from analyst state.
4. Support comments, business priority, asset criticality, owner/assignee only if user management exists; do not create fake identities. All edits create audit events.
5. Add versioned local mapping catalog for OWASP Web Top 10:2025, OWASP API Security Top 10:2023, CWE and supported CVSS versions. Store catalog provenance/version and preserve historical mappings.
6. Map rules to categories with rationale/confidence; allow no mapping and show it. Do not imply all findings map one-to-one.
7. Implement dedupe/re-observation history and manual merge/unmerge, preserving source records and rollback/audit data.
8. For CVSS, use a maintained correct calculator/library or supplied vector/score; validate vector/version. If no valid score exists, leave CVSS blank and use a clearly labelled internal prioritization score only.
9. Document internal risk formula and weights; keep severity, confidence, exploit evidence, asset criticality and exposure separate. Avoid upgrading speculative findings to Critical.
10. Update dashboard metrics to count unique findings correctly and allow click-through filters; add trend comparison only when comparable scans exist.

### Acceptance criteria
- Analysts can triage and revise a finding without losing original source data.
- Mappings show the exact catalog version.
- CVSS values are not fabricated.
- Dashboard counts reconcile to filtered canonical finding records.

Do not proceed to Phase 10.

## Phase 10 — Report builder, HTML/PDF exports, backup and restore

**Prompt to paste:**

Implement Phase 10 only: client-ready reporting, export and project backup/restore. Read the redaction and reporting requirements in `MASTER_SPEC.md` closely.

### Required work
1. Create report template components shared by HTML and PDF. Report contains cover, executive summary, scope/authorization, methodology, tools/versions, scan coverage, risk distribution, finding details, attack surface, API coverage, limitations and appendices.
2. Add report builder UI with project, scan date range, included modules, selected findings/states, severity threshold, inclusion of asset inventory and report classification. Preview before generating.
3. Include sanitized finding evidence, steps to reproduce, impact, remediation, CWE/OWASP mapping version, CVSS only when valid, references and provenance.
4. Explain checks skipped, tools unavailable, scope blocks, partial scans, low-confidence findings and limitations. A clean report must not claim the system is secure.
5. Generate semantic HTML and print stylesheet; generate searchable/text PDF using a maintained library. Add page numbering, header/footer, repeated table headers and page breaks as supported.
6. Add JSON/CSV export for findings/assets and project archive export/import with manifest/checksums/schema versions. Exclude secrets and permit the operator to include/exclude evidence.
7. Safely import archives: reject traversal, absolute paths, symlinks and oversized expanded data; validate every record; preview before restore; preserve current data unless user explicitly confirms conflict behavior.
8. Store report metadata and checksum; make downloads authorized and path-safe. Escape imported titles/notes and sanitize all content.
9. Add automated no-secret report assertions, HTML injection test, report rendering fixtures, PDF content checks, archive traversal tests and export/import round trip tests.

### Acceptance criteria
- User can build, preview, download HTML/PDF and export JSON/CSV.
- The same selected findings appear consistently in preview and files.
- Secrets and raw sensitive response bodies are not exported.
- Project backup can be restored into a clean test data directory with the same finding counts and evidence links.

Do not proceed to Phase 11.

## Phase 11 — Integrations, CVE data, tool diagnostics, settings

**Prompt to paste:**

Implement Phase 11 only: optional external-tool adapters, component-to-CVE data workflow and integration/settings diagnostics. Keep the app functional when any external tool/data provider is missing.

### Required work
1. Integrations page lists configured/available/missing tools, path/version, last use, capability, errors and troubleshooting. Do not use a green success state for an unverified tool.
2. Complete optional `sslyze` or `testssl.sh` and Nmap adapter behavior from prior phases. Detect version, validate arguments, capture safe output, time out, terminate processes and parse in a bounded/validated way.
3. Implement local CVE catalog import/update path, including source, catalog version/date, file hash, parser version and staleness display. A scan must remain functional without online lookups.
4. Map detected component/version to CVE only with defensible product/version matching; show match confidence, version range and data source. If ambiguous, create an observation or `needs_review` candidate, not confirmed vulnerability.
5. Optional online data sources must be explicitly configurable, rate-limited, and visible in scan metadata. Do not send target credentials, response contents or client-specific sensitive information to those sources.
6. Add safe configuration validation for external executable paths and API credentials. Secret values must be write-only in UI and never returned by settings-read API.
7. Add a diagnostic/self-test page and CLI command if consistent with existing project, with no active target traffic.
8. Add mocked tests for missing binary, incorrect version, timeout, oversized output, malformed CVE data and stale catalog.

### Acceptance criteria
- Missing external tools create clear skipped checks, not false passes.
- CVE evidence is source-attributed and version-aware.
- The platform can run offline against local fixtures.

Do not proceed to Phase 12.

## Phase 12 — Security hardening, performance, accessibility, and end-to-end flows

**Prompt to paste:**

Implement Phase 12 only: security/reliability pass across the complete application. Do not add new scanning capabilities until existing flows are verified.

### Required work
1. Review all FastAPI routes for request validation, authorization where applicable, scope enforcement for target actions, consistent errors, request size limits, safe download paths, CORS, CSRF needs, and secret redaction.
2. Verify app binds to localhost by default. If remote mode is supported, require secure authentication configuration and refuse insecure network binding with a useful startup message.
3. Review file-backed storage for atomic writes, locks, stale lock recovery, permissions, path traversal, symlink escape, corrupt file recovery, disk-full handling and backup/restore safety.
4. Review every external network request path for scope enforcement, redirect checks, DNS/IP policy, rate budget and cancellation.
5. Review subprocess execution for argument arrays, executable allowlist, timeout, output caps, working-directory isolation, kill/reap behavior and no shell injection.
6. Review imported content and reports for XSS/HTML injection, XXE, zip bombs, JSON/YAML complexity, secret leakage, arbitrary file paths and malicious filenames.
7. Add resource limits: pages/endpoints, parallel tasks, bytes, uploads, job queue, report size and runtime. Add a graceful disk-space/resource warning.
8. Run security-focused tests and dependency audit if appropriate for available tooling. Address high-risk issues introduced by this project before proceeding.
9. Accessibility pass: keyboard-only workflow, focus states, labels, announcements, contrast, severity not color-only, responsive tables and readable reports.
10. Performance pass with synthetic large projects: paginated queries, no unnecessary giant JSON loads, stable UI, cancellation and sensible timeouts.
11. Run full local end-to-end test flow: create project → configure test scope → safe web scan against fixture → map assets → inventory API spec → run safe API baseline → import Nmap/Nuclei/SARIF fixture → triage/dedupe → generate HTML/PDF → export/restore → restart and verify persisted data.
12. Update docs and traceability for implemented/partial/blocked requirements.

### Acceptance criteria
- All critical end-to-end workflows pass with local fixtures and without internet.
- No out-of-scope request is made in tests.
- No secret appears in logs, HTML/PDF reports, exported archives or API responses.
- Any remaining issue is documented with impact and mitigation.

Do not proceed to Phase 13.

## Phase 13 — Packaging, release checklist, user documentation

**Prompt to paste:**

Implement Phase 13 only: release packaging and operator documentation. The goal is a reproducible local installation, not a claim of production SaaS readiness.

### Required work
1. Provide clean start commands for supported OS environments, dependency installation, environment configuration, and separate frontend/backend development commands where relevant.
2. Add production-like local build instructions, startup/shutdown instructions, default localhost binding explanation, data path configuration, backup/restore and update/migration procedure.
3. Provide `README.md`, `docs/USER_GUIDE.md`, `docs/SAFE_SCAN_RUNBOOK.md`, `docs/INTEGRATIONS.md`, `docs/REPORTING.md`, `docs/TROUBLESHOOTING.md`, `docs/RELEASE_CHECKLIST.md` and `docs/LIMITATIONS.md` or update existing equivalents.
4. Document optional tool prerequisites/platform caveats for Nmap, `sslyze`/`testssl.sh`, passive data sources and CVE catalogs. Never imply unavailable tools are bundled.
5. Provide a local fixture demo project/data generator that does not contact external targets and does not include credentials.
6. Ensure runtime data/evidence/reports are excluded from Git. Add environment example without secrets.
7. Add CI commands for backend tests, frontend tests/build, lint/type checking, and optional non-network integration tests. Pin/lock dependencies using the repo's package managers.
8. Add versioning/changelog approach and support bundle export that redacts secrets and avoids including raw evidence by default.
9. Run the complete documented clean-install procedure as far as environment allows. Update docs if a command fails; do not leave hypothetical commands untested without labeling them.
10. Produce a final release assessment listing implemented modules, partial modules, unavailable integrations, test evidence, known limitations, and all remaining TBD decisions.

### Acceptance criteria
- A new developer can start the app following only documented steps.
- The demo and automated tests operate locally with no database or remote target.
- Limitations are visible and honest; no false claims of comprehensive vulnerability detection.

Do not make unsupported claims of production readiness.

---

# Short phase execution rule

After completing each phase, stop. Run its verification prompt. Fix defects created by that phase, update `docs/IMPLEMENTATION_STATUS.md` and `TBD_DECISIONS.md`, then wait for the next explicit phase prompt. If something blocks progress, implement safe unaffected work and document the blocker; do not fabricate success or jump to later modules.
