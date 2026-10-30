# Limitations — VAPT Workbench

> This is not a claim of comprehensive vulnerability detection, and it is not production SaaS.
> It is a local-first, single-operator assessment tool that is honest about what it does and
> does not check. Read this before relying on a report it generates.

## 1. What this tool is not

- **Not a comprehensive vulnerability scanner.** It runs a bounded set of safe, passive-by-default checks (Modules 5–7 of `MASTER_SPEC.md`). A clean report — zero findings — means "the checks that ran found nothing," never "this system is secure." Every generated report states this explicitly (`docs/REPORTS.md`).
- **Not an exploitation framework.** No active injection payloads, no credential brute-forcing, no exploitation chains, no persistence, no evasion. See §2.
- **Not multi-user or remote-access software.** One operator, one data directory, localhost-only (`127.0.0.1`). Remote binding is refused at startup (TBD-003); there is no authentication, session, or secure-cookie system because none is needed for a loopback-only single-user tool.
- **Not backed by a database.** Filesystem-only persistence (JSON documents, atomic writes, file locks). This is a deliberate architecture decision, not a missing feature — see `docs/ARCHITECTURE.md` and `docs/STORAGE_FORMATS.md`.

## 2. Deliberately unimplemented checks (owner-decided, not oversights)

| Capability | Status | Why | Reference |
|---|---|---|---|
| Active SQL injection / error-differential probes | Opt-in, disabled by default | Sending test input to a target is an active action; it is now available but only as an explicit, per-project opt-in (`ScanPolicy.active_probes.sqli_error_differential`), never on by default. One bounded confirmation request per already-crawled parameter, never fuzzing or blind/time-based injection. | TBD-049, TBD-115 |
| Active XSS reflection probes | Opt-in, disabled by default | Same reasoning and bounds as above (`active_probes.xss_reflection`); the probe marker never executes script. | TBD-049, TBD-115 |
| Sensitive-file signature probing (backup files, `.git/`, etc.) | Not built in | Would require guessing/requesting paths not discovered by normal crawling — an active probing behavior this build excludes. | TBD-050 |
| Mutating / destructive API writes | Never performed, even when "enabled" | The mass-assignment and write-safety checks always inventory the request schema; they never send a live mutating request. | Module 7.5 |
| CVE data fetched automatically | Never | Only a locally-imported CVE catalog is used; nothing is fetched from the internet. | TBD-028, `docs/CVE_CATALOG.md` |
| An online CVE/threat-intel lookup service | Not implemented | A settings field (`online_lookup_credential_alias`) exists for a future opt-in source but is wired to no network call today. | TBD-068 |
| ZAP / Burp Suite import formats | Not implemented | Covered instead by the generic CSV/JSON import adapters with a documented column/field map. | TBD-023 |
| Remote/multi-user secure mode | Not implemented | No authentication, CSRF, or strict-CORS layer exists; the app refuses to bind anywhere but loopback instead. | TBD-003 |

## 3. Scope of each scanning module

- **Web application scanner (Option A):** a bounded, same-origin crawl (no JavaScript execution, no authenticated/logged-in crawling), passive header/cookie/TLS/version checks, and passive injection *indicators* only (never active probes). See `docs/WEB_RULES.md`.
- **Attack surface mapper (Option B):** discovery via manual input, imports, and optional passive sources (crt.sh, off by default) plus a bounded TCP-connect port check (optional Nmap, TCP-connect scan type only — never SYN/stealth scans). Discovering a host is never treated as permission to scan it. See `docs/SURFACE_MAPPER.md`.
- **API security scanner (Option C):** offline OpenAPI/Swagger inventory plus bounded, read-mostly baseline checks (IDOR/BOLA requires two real test identities and an explicit ownership map the operator provides; it is never run on a guess). See `docs/API_SCANNER.md`.
- **Import/dedupe/report (Option D):** normalizes external scanner output (Nmap, Nessus, Nuclei, SARIF, generic CSV/JSON, best-effort PDF text) and never claims to have run a check it did not run itself.

## 4. External tool dependence

Nmap, sslyze, and testssl.sh are **optional and never bundled**. If a tool is not installed, the related checks are reported as `skipped`, with the reason — never as a false pass. The Integrations page (`docs/INTEGRATIONS.md`) shows real detection/verification status; a tool merely found on PATH is shown "detected (unverified)," never the same green state as a tool a self-test actually ran successfully.

## 5. CVE matching is a catalog match, not a confirmed vulnerability

An imported CVE catalog entry matching a passively-detected component/version is shown with its match type (`exact` version pin vs. `range`), its catalog source/version/date, and a confidence that is **never** "confirmed" — passive version detection never verifies actual exploitability. See `docs/CVE_CATALOG.md`.

## 6. Performance characteristics at scale

The findings list (`GET /api/findings`) scales linearly with the number of findings in a project, since it reads every matching finding's full record to support cross-field filtering and risk scoring (TBD-074). This is comfortably fast at the scale of a typical assessment (dozens to a few hundred findings); a project with many thousands of findings will see proportionally longer list-page load times. This is a known, accepted tradeoff of the filesystem-only architecture, not a defect — see `docs/TESTING.md`'s Phase 12 entry.

## 7. Platform notes

- Developed and tested primarily on Windows 11 with Python 3.13 and Node 22. The backend targets Python 3.12+ and is written to be POSIX-portable (see `docs/DEVELOPMENT.md`), but Linux/macOS have not been run through the full documented procedure in this environment — see `docs/RELEASE_CHECKLIST.md` for what was and was not verified.
- testssl.sh is a bash script; on Windows it only works under WSL. sslyze (pure Python) and Nmap work natively on all three platforms.
- POSIX file permission enforcement (owner-only 0600/0700 on stored files) is not meaningful on Windows and is skipped there (one test, `test_posix_permissions_are_owner_only`, is explicitly skipped — not silently ignored).

## 8. Where to find more detail

Every material "we chose X over Y, here's why" decision in this project — including everything in this document — is recorded with its rationale in `TBD_DECISIONS.md`. `docs/IMPLEMENTATION_STATUS.md` has the full module-by-module implemented/partial/not-started traceability against `MASTER_SPEC.md`.
