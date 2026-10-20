# VERIFICATION PROMPTS — RUN AFTER EVERY PHASE

Use the **Universal Verification Prompt** after each implementation phase, then the phase-specific supplement. Claude Code should inspect code and run tests, not merely reason from the diff.

---

## Universal Verification Prompt

You have finished one phase of the VAPT Workbench implementation. Do not implement the next phase. Perform a rigorous verification of only the work just completed plus regression checks for the existing application.

1. Re-read the phase prompt, `MASTER_SPEC.md`, `docs/IMPLEMENTATION_STATUS.md`, and `TBD_DECISIONS.md`.
2. Inspect the actual changed files. Compare each acceptance criterion with concrete code, UI behavior, or test evidence.
3. Run all relevant automated tests, backend lint/type checks, frontend tests/build, and any project-specific checks available. Do not say a check passed unless you ran it and observed the result.
4. Add missing tests for edge cases that are directly relevant to the phase. Prefer deterministic mocks and local fixtures; do not scan public or third-party targets.
5. Check for fake/stub behavior: TODO buttons, hard-coded dashboard numbers, fake scan progress, placeholder findings, mocked success in production paths, unimplemented routes returning 200, silent exceptions, or “pass” status for skipped checks. Replace these where in phase scope; otherwise mark them visibly blocked and document why.
6. Inspect error paths, cancellation/resource cleanup, secret redaction, input bounds and malicious input behavior relevant to the phase.
7. Check that no database, database driver/service, Redis, Celery, or other database-backed queue was added. Filesystem storage is the only persistence mechanism.
8. Update `docs/IMPLEMENTATION_STATUS.md` with accurate status and code/test references. Update `TBD_DECISIONS.md` for unresolved decisions and any newly made material decision.
9. Report results using this format:
   - **Verdict:** PASS / PASS WITH BLOCKERS / FAIL
   - **Acceptance criteria:** each criterion PASS/FAIL/BLOCKED, with evidence
   - **Commands run:** exact command + observed pass/fail
   - **Tests added/changed:** paths and purpose
   - **Risks/defects:** severity and remediation
   - **No-database check:** specific dependency/config inspection result
   - **Files changed:** concise list
   - **Ready for next phase:** YES/NO and why
10. If anything fails, fix defects within the current phase scope and rerun the relevant checks. Do not proceed to the next phase until the verdict is PASS or the user explicitly accepts clearly documented blockers.

## Phase-specific supplements

### After Phase 00
- Confirm architecture documentation reflects the actual repository, not a generic template.
- Confirm runtime artifacts and secrets are ignored by Git.
- Confirm no scanner request path exists yet or that any existing one is disabled/documented.
- Confirm `IMPLEMENTATION_STATUS.md` includes all four product options and every module listed in the master spec.

### After Phase 01
- Run repository tests with a temporary isolated data directory.
- Simulate truncated JSON, invalid Pydantic data, write failure, simultaneous updates and app restart.
- Attempt `../`, absolute path, encoded traversal and symlink escape for every path-taking API/service.
- Verify logs redact authorization headers, cookies, tokens, passwords, key-like values and query secrets.
- Verify a second app instance using the same data root refuses to start safely.

### After Phase 02
- Open the UI and verify project creation/edit survives reload.
- Inspect dashboard network responses and prove KPIs come from backend data rather than constants.
- Test empty state, backend offline, validation error, project deletion confirmation and keyboard navigation.
- Search frontend source for example metrics or placeholder data accidentally used in production rendering.

### After Phase 03
- Run a focused SSRF/scope test suite: redirect to loopback/private/link-local/metadata IP; suffix confusion; IDN; IPv6; user-info URL; non-HTTP scheme; encoded path; port/path exclusion; DNS rebinding simulation; expired authorization.
- Use a local HTTP fixture server to verify blocked targets receive zero requests.
- Ensure discovered subdomains do not become approved merely because DNS resolution succeeds.

### After Phase 04
- Test duplicate job submission, worker claim races, stale lock, restart during queued/running job, cancellation and child process cleanup.
- Verify log tailing does not leak secrets or load an unbounded file into memory.
- Verify global kill switch prevents new active jobs and stops currently active jobs.

### After Phase 05
- Use local fixture targets only. Test response caps, redirect validation, same-origin crawl, content-type limits, 429/503 backoff and cancellation.
- Verify injection checks are disabled by default and have no destructive/time-delay/out-of-band payloads.
- Confirm escaped XSS marker reflection is not incorrectly labeled confirmed executable XSS.
- Confirm sensitive-file checks do not persist secret contents; inspect every evidence format and report output.
- If `sslyze`/`testssl.sh` is absent, verify the UI/report says skipped/not configured rather than pass.

### After Phase 06
- Mock DNS so discovered candidates resolve to external, private and changing IPs; verify private/out-of-scope hosts are blocked.
- Inspect exact Nmap argv: no shell, no aggressive `-A`, no default intrusive scripts, no full port range or UDP scan.
- Test missing Nmap, timeout, malformed/oversized XML and partial scan.
- Verify reports identify exact ports tested and do not imply all ports were scanned.

### After Phase 07
- Test malformed OpenAPI, external/cyclic `$ref`, oversized spec, out-of-scope server URL, unsafe path variables and hidden operation methods.
- Confirm dry inventory creates zero network requests.
- Confirm IDOR/BOLA checks are unavailable unless two configured test identities and explicit test object ownership are present.
- Confirm write methods are disabled by default and no ID brute-force loop is present.
- Confirm rate-limit tests are capped and back off promptly on 429/503 or unstable latency.

### After Phase 08
- Run parser fixtures for every implemented format and malformed/oversized examples.
- Test XML external entities, zip-slip/path traversal, archive bombs, bad encodings, duplicate IDs and XSS in imported titles.
- Ensure dry-run does not modify normalized project findings until explicit commit.
- Check provenance and source ratings remain accessible after normalization and dedupe.

### After Phase 09
- Reconcile counts between stored unique findings, filtered API results and dashboard KPIs.
- Test manual merge/unmerge and ensure no source provenance disappears.
- Verify standards catalog version is stored on every mapping.
- Search for any hard-coded/fabricated CVSS score; make sure an internal risk score is not labelled CVSS.
- Verify false-positive/accepted-risk/fixed states are not counted as open confirmed issues without clear logic.

### After Phase 10
- Generate HTML and PDF from sanitized fixture findings including malicious HTML, script tags, tokens, cookies and sensitive-looking response text.
- Verify the report escapes/sanitizes content and contains no secrets or local absolute paths.
- Compare preview selection with exported file contents.
- Test archive traversal/symlink/oversized import rejection and export/import round trip in a clean temporary data root.
- Verify a no-finding report says only that executed checks did not detect findings and lists limitations.

### After Phase 11
- Test absent external tools, invalid executable, timeout, output overflow, malformed output and unsupported version.
- Verify tools execute with argument arrays and restricted arguments only.
- Confirm offline scanning works against local fixtures.
- Verify CVE matches expose catalog source/version/date and ambiguous version matches are not stated as confirmed vulnerabilities.

### After Phase 12
- Run a complete local end-to-end flow with external network disabled.
- Review every outbound network path and subprocess call for scope/safety wrapper usage.
- Search for `shell=True`, direct `subprocess` calls outside the approved adapter, raw `httpx/requests` calls outside the shared network layer, unsafe YAML load, XML parser unsafe settings, arbitrary file reads, and raw HTML rendering; explain and fix each legitimate issue.
- Test all routes for oversized requests, malformed input, CORS/CSRF expectations and safe error messages.
- Verify localhost default and remote mode refusal when security prerequisites are missing.
- Recheck secrets in logs, API payloads, scan evidence, HTML, PDF and export archives.

### After Phase 13
- Follow clean-install steps from a clean checkout or isolated environment as far as the environment allows.
- Verify required commands exist, environment example contains no secrets, runtime folders are ignored, and data dir is outside repository by default.
- Run all tests/build/lint/type checks and capture exact outcomes.
- Verify the release checklist identifies unsupported OS/tool combinations and limitations.
- Confirm the final report says what was actually tested and does not call the product production-ready without an evidence-backed basis.
