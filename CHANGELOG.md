# Changelog

Versioning approach: this project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`) once it reaches `1.0.0`. Before `1.0.0`, a `0.MINOR.PATCH` bump may include breaking API/data-shape changes (there are no external consumers yet — this is a pre-release, local-first tool). The backend version lives in `backend/app/__init__.py::__version__` and is reported by `GET /api/version`; the frontend's `frontend/package.json` version is kept in sync with it. `app/api/health.py::API_VERSION` is a separate, coarser compatibility marker for the HTTP API shape itself (currently `"1"`), bumped only on a breaking API change.

This file is updated at the end of each implementation phase. See `docs/IMPLEMENTATION_STATUS.md` for the full phase-by-phase traceability against `MASTER_SPEC.md`, and `TBD_DECISIONS.md` for the rationale behind every material decision referenced below.

## [Unreleased] — 0.0.1 (Phase 13)

### Added
- Packaging and release documentation: `docs/USER_GUIDE.md`, `docs/SAFE_SCAN_RUNBOOK.md`, `docs/REPORTING.md`, `docs/TROUBLESHOOTING.md`, `docs/RELEASE_CHECKLIST.md`, `docs/LIMITATIONS.md`, `.env.example`, `CHANGELOG.md` (this file), and a GitHub Actions CI workflow (`.github/workflows/ci.yml`).
- A diagnostic **support bundle** export (`GET /api/diagnostics/support-bundle`, `python -m app support-bundle`): a redacted ZIP (version/storage info, settings, recent audit events, integration status, per-project record counts) for troubleshooting — never a restorable backup, never includes evidence blobs, and full (still redacted) finding records only when explicitly requested.
- A local **demo data generator** (`backend/scripts/generate_demo_project.py`) that creates a project with synthetic findings/assets/a scan record for UI evaluation — no network access, no credentials, every target an RFC 2606 reserved domain.
- An "Application quick start" section appended to the root `README.md` (TBD-033 resolved: the existing build-pack content was never removed or reordered).

### Fixed
- The global request-size-limit guard applied one small, JSON-sized default to every route, including file-upload routes (CVE catalog, imports, API specs, backup restore) that each already declare a much larger documented cap — making every one of those larger limits unreachable in practice, and the backup archive's 200 MiB limit unreachable under *any* configuration. Fixed with per-route size overrides (TBD-075).
- Upgraded `pypdf` (5.9.0 → 6.21.2), `pytest` (8.4.2 → 9.1.1), and `python-multipart` (0.0.9 → 0.0.32) to patch disclosed vulnerabilities found by a dependency audit (TBD-073).
- Reformatted the entire backend with `ruff format` (whitespace/line-wrap only, no behavior change) so the new CI format-check gate starts green.
- Phase 13 verification: `python -m app support-bundle --output <bad path>` and `scripts/generate_demo_project.py --data-dir <relative path>` both crashed with a raw traceback instead of a clean error message; the support bundle silently truncated a large project's findings with no indication; the CLI's own documented default output (`./support-bundle.zip`) was not git-ignored. All four fixed; see `docs/IMPLEMENTATION_STATUS.md`'s "13 verification" phase-log entry.

## 0.0.1 (Phase 12) — Security hardening, performance, accessibility

Dependency vulnerability audit and upgrade; a full offline end-to-end flow test through the real HTTP API; a request-size-limit defect found and fixed (see above, folded into Phase 13's fix list since it was found during Phase 12 verification); a pagination/performance regression test and a documented (not silently accepted) linear-scaling characteristic in the findings list (TBD-074); a keyboard-accessibility spot check on the newest UI page.

## 0.0.1 (Phase 11) — Integrations, local CVE data, settings

Integrations status page with a real, no-target-traffic self-test (never a false "verified" for a merely-detected tool); a local CVE catalog import/match pipeline wired into the Phase 05 web-scanner contract (catalog source/version/date exposed on every match; an ambiguous match is never presented as confirmed); a settings API built from scratch with write-only, reference-only credential handling.

## 0.0.1 (Phase 10) — Reporting, exports, backup/restore

HTML/PDF report generation from a single shared data-resolution path (preview and the generated files always agree); JSON/CSV exports; a safe, multi-file project backup/restore archive (zip-bomb/traversal/symlink rejection, checksum verification, explicit-overwrite-gated restore, cross-project record-injection prevention added during verification).

## 0.0.1 (Phase 09) — Findings workbench, standards, risk scoring

A cross-project findings workbench with rich filtering; analyst triage fields kept strictly separate from scanner-owned fields; manual merge/unmerge with full rollback; a versioned local standards catalog (OWASP Top 10, CWE); a transparent internal risk-prioritization score (never CVSS) that can never place a low-confidence finding above the "high" tier.

## 0.0.1 (Phase 08) — Import Center

Seven import format adapters (Nmap, Nessus, Nuclei, SARIF, generic CSV/JSON, best-effort PDF) with shared input-safety bounds, two-tier deduplication, dry-run preview, and explicit commit.

## 0.0.1 (Phases 05–07) — The three scan options

Option A (web application scanner, safe/passive by default), Option B (attack surface mapper), and Option C (API security scanner from an OpenAPI/Swagger spec), each built on the shared scope-enforcement and network-adapter layer from Phases 03–04.

## 0.0.1 (Phases 00–04) — Foundation

FastAPI skeleton, filesystem-only storage repository (atomic writes, locks, schema versioning, integrity checks), the scope/authorization engine and its mandatory `ScopeGuard` enforcement point, and the job/scan lifecycle system (state machine, kill switch, crash-safe recovery).
