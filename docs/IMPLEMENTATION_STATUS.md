# Implementation Status — VAPT Workbench

> Last updated: 2026-10-20 (Phase 02 verification). Statuses use only `Not started` / `Partial` / `Implemented` / `Blocked`. `Implemented` requires a code reference **and** a passing test that was actually run. Design-only documentation does not count as implementation.

## Current baseline (observed 2026-10-20, Windows 11, Python 3.13.5)

| Check | Result |
|---|---|
| Backend tests | `poetry run pytest` → **608 passed, 1 skipped** (POSIX permission bits; N/A on Windows) |
| Frontend | `npm test` → **28 passed**; `npm run typecheck`, `npm run lint`, `npm run build` pass; `npm audit` 0 vulnerabilities |
| Real-browser E2E | `npm run e2e` → **10/10**; `npm run e2e:verify` → **12/12** (KPIs equal captured network response; tampered response changes UI; offline + retry; backend 422; edit conflict; delete confirmation; keyboard-only) |
| Lint / format / types | `ruff check .` passed · `ruff format --check .` 58 files formatted · `mypy` (strict) no issues in 37 files |
| Database / broker dependencies | **None.** 30 locked packages; static + runtime guards in `tests/test_static_guards.py`, `tests/test_startup.py::test_importing_app_loads_no_database_or_broker_modules` |
| Scanning / outbound network / subprocess code in `backend/app/` | **None.** Enforced by `tests/test_static_guards.py::test_no_network_or_subprocess_modules_yet` |
| File writes outside `app/storage/` | **None.** Enforced by `tests/test_static_guards.py::test_no_file_io_outside_storage` |

## Product option matrix (Options A–D)

| Option | Description | Status | Depends on | Phase(s) | Planned paths | Tests |
|---|---|---|---|---|---|---|
| **A** | Web Application Vulnerability Scanner | Not started | M2 ✔, M3, M4, adapters | 05 (+ TLS/CVE 11) | `backend/app/scanners/webapp/`, `scanners/tls/`, `integrations/http_client.py` | — |
| **B** | Attack Surface Mapper | Not started | M2 ✔, M3, M4, adapters, A crawl | 06 | `backend/app/scanners/surface/`, `integrations/nmap.py`, `integrations/dns.py` | — |
| **C** | API Security Testing (OpenAPI/Swagger) | Not started | M2 ✔, M3, M4, adapters | 07 | `backend/app/scanners/api_security/`, `imports/openapi/` | — |
| **D** | Import, normalize, dedupe, report | Not started (storage contracts for imports/findings/reports exist) | M2 ✔, M9, M10 | 08, 09, 10 | `backend/app/imports/`, `findings/`, `reports/` | — |

No option is out of scope.

## MASTER_SPEC module traceability

| Module / requirement | Spec | Status | Phase | Code | Tests / evidence |
|---|---|---|---|---|---|
| Architecture & threat-model docs | §3, §11 | **Implemented** (docs) | 00 | `docs/*.md` | Doc review |
| `/api/health`, `/api/version` (api_version, storage_version) | §7 | **Implemented** | 00/01 | `app/api/health.py` | `tests/test_health.py` |
| `/api/readiness` (503 when not ready) | §7, M2 | **Implemented** | 01 | `app/api/health.py` | `tests/test_api_system.py`, `tests/test_health.py` |
| Storage diagnostics endpoint + `python -m app diagnose` | Phase 01 #9 | **Implemented** | 01 | `app/storage/diagnostics.py`, `app/api/health.py`, `app/__main__.py` | `tests/test_api_system.py`, `tests/test_main_entrypoint.py::test_diagnose_command_reports_readiness` |
| Typed error envelope, no input echo, no stack traces | Phase 01 #1, M13 | **Implemented** | 01 | `app/core/errors.py` | `tests/test_api_system.py`, `tests/test_health.py` |
| Correlation IDs (header, logs, audit, errors) | M13 | **Implemented** | 01 | `app/core/correlation.py` | `tests/test_api_system.py`, `tests/test_audit_jsonl.py` |
| Structured JSON logging with redaction; uvicorn access log disabled | §9, M13 | **Implemented** | 01 | `app/core/log_config.py`, `app/core/request_guards.py` | `tests/test_api_system.py::test_request_log_redacts_query_strings`; live smoke (TESTING §2) |
| Strict runtime settings (unknown `VAPT_*` rejected) | Phase 01 #1 | **Implemented** | 01 | `app/core/settings.py` | `tests/test_startup.py`, `tests/test_main_entrypoint.py` |
| Localhost bind; loopback-peer guard; Host-header (DNS-rebinding) guard | M12 | **Implemented** | 00/01 | `app/core/config.py`, `app/core/loopback_guard.py` | `tests/test_bind_policy.py`, `tests/test_loopback_guard.py` |
| Request size limit (declared and chunked) | M12 | **Implemented** | 01 | `app/core/request_guards.py` | `tests/test_api_system.py::test_request_size_limit` |
| CSRF / strict CORS / remote secure mode | M12 | Not started | 12 | — | — |
| Canonical contracts §5.1–5.7 + AppSettings, ReportMetadata (schema_version, enums, bounds, extra=forbid) | §5 | **Implemented** | 01 | `app/models/` | `tests/test_models.py` |
| `severity_from_cvss` (FIRST bands; maps, never computes) | §5.4, M9 | **Implemented** | 01 | `app/models/finding.py` | `tests/test_models.py` |
| **M2** Data-root resolution (default outside repo, refusals) | §2 | **Implemented** | 01 | `app/storage/paths.py` | `tests/test_paths.py` |
| **M2** Path safety (ID validation, component allowlist, symlink/junction rejection) | §2, §4.4 | **Implemented** | 01 | `app/storage/paths.py`, `repository.py` | `tests/test_paths.py` (junction path exercised on Windows) |
| **M2** Atomic writes, temp cleanup, owner-only permissions (POSIX) | §2 | **Implemented** (Windows ACL limitation documented) | 01 | `app/storage/atomic.py` | `tests/test_atomic.py` (POSIX-mode test skipped on Windows) |
| **M2** Per-record + instance locking (filelock, two-level) | §2 | **Implemented** | 01 | `app/storage/locking.py` | `tests/test_locking.py` (threads, processes, crash, stale files, timeout) |
| **M2** CRUD: projects, scans, findings, assets, evidence (+blob), imports (+raw), report metadata, settings | Phase 01 #6 | **Implemented** (storage API; HTTP routes arrive with their UI phases) | 01 | `app/storage/repository.py` | `tests/test_repository.py` |
| **M2** Pagination / filters / sorting via derived indexes | §2 | **Implemented** | 01 | `repository.py` | `tests/test_repository.py`, `tests/test_indexes.py` |
| **M2** Schema versioning + migration hooks + backups | §2 | **Implemented** (no real migrations yet; v1 everywhere) | 01 | `app/storage/migrations.py`, `repository.migrate_all` | `tests/test_migrations.py` |
| **M2** Integrity checker + index rebuild | §6 M2 | **Implemented** (stale-job check is Phase 04) | 01 | `app/storage/integrity.py` | `tests/test_integrity.py`, `tests/test_indexes.py` |
| **M2** Append-only JSONL audit log: redaction, rotation, corruption tolerance | §5.7 | **Implemented** | 01 | `app/storage/jsonl.py`, `app/storage/audit.py`, `app/core/redaction.py` | `tests/test_audit_jsonl.py`, `tests/test_redaction.py` |
| Audit events for project create/update/archive/delete, scope edits, attestations | §5.7 | **Implemented** | 02 | `app/services/projects.py` | `test_api_projects.py` |
| Export/backup/restore archives | §6 M2, M10 | Not started | 10 | — | — |
| Settings UI (data dir, disk, versions; tools shown as not checked) | §6 M2 | **Implemented** (backup status: Phase 10) | 02 | `SystemPages.tsx` | `app.test.tsx` |
| **M1** App shell, navigation, breadcrumbs, toasts, loading/empty/error states | §6 M1 | **Implemented** | 02 | `frontend/src/layouts/AppLayout.tsx`, `components/` | `frontend/src/test/app.test.tsx` |
| **M1** Dashboard (API-derived KPIs, clickable pre-filtered views, recent activity) | §6 M1 | **Implemented** (trend charts deferred until comparable scans exist, Phase 09) | 02 | `app/services/dashboard.py`, `frontend/src/pages/DashboardPage.tsx` | `tests/test_api_projects.py::test_dashboard_*`, `app.test.tsx` |
| **M1** Projects list (search/sort/pagination, status, authorization expiry, last scan) | §6 M1 | **Implemented** | 02 | `app/api/projects.py`, `ProjectsPage.tsx` | `test_api_projects.py`, `app.test.tsx` |
| **M1** Project create/edit wizard with scope preview + attestation | §6 M1, §4.1 | **Implemented** (preview only; enforcement Phase 03) | 02 | `app/services/projects.py`, `app/services/scope_preview.py`, `ProjectWizardPage.tsx` | `test_api_projects.py`, `wizard.test.tsx`, E2E |
| **M1** Archive / delete with impact + typed confirmation | §6 M1 | **Implemented** | 02 | `ProjectDetailPage.tsx`, `repository.delete_project` | `test_api_projects.py::test_delete_*`, `app.test.tsx` |
| **M1** Duplicate project without secrets; project export/import | §6 M1 | Not started | 10 | — | — |
| **M3** Scope & authorization engine | §4, §6 M3 | Not started (syntax-only scope validation in models) | 03 | `backend/app/scope/` | — |
| **M4** Job manager, logs, cancellation, kill switch | §2, §6 M4 | Not started (ScanJob contract + storage exist) | 04 | `backend/app/jobs/` | — |
| Shared HTTP / DNS / subprocess adapters | §4.3 | Not started | 05 | `backend/app/integrations/` | — |
| **M5** Web scanner (Option A) | §6 M5 | Not started | 05 | — | — |
| **M6** Attack surface mapper (Option B) | §6 M6 | Not started | 06 | — | — |
| **M7** API security testing (Option C) | §6 M7 | Not started | 07 | — | — |
| **M8** Import, normalization, dedupe (Option D) | §6 M8 | Not started (ImportArtifact storage exists) | 08 | `backend/app/imports/` | — |
| **M9** Risk scoring, standards catalogs | §6 M9 | Partial (Finding mappings/CVSS contracts only) | 09 | `app/models/finding.py` | `tests/test_models.py` |
| **M10** Reports, exports, backup/restore | §6 M10 | Not started (ReportMetadata storage exists) | 10 | — | — |
| **M11** Tool integrations & CVE data | §6 M11 | Not started | 11 | — | — |
| **M12** Local security & operator controls | §6 M12 | Partial (bind, peer, host, size limit) | 01, 04, 12 | `app/core/` | see rows above |
| **M13** Audit, reliability, accessibility, UX | §6 M13 | Partial (audit log, correlation, errors) | 01, 02, 12 | `app/storage/audit.py`, `app/core/` | see rows above |
| Hardening, performance, E2E | §8, §9 | Not started | 12 | — | — |
| Packaging & operator docs | §10 | Partial (dev instructions) | 13 | `docs/DEVELOPMENT.md` | Manually run |

## Phase log

| Phase | State | Verification verdict | Notes |
|---|---|---|---|
| Bootstrap | Done | n/a | Empty repo confirmed |
| 00 | Verified | PASS (2026-10-20) | Docs, `.gitignore`, minimal FastAPI skeleton |
| 01 | Verified | **PASS** (2026-10-20) | Verification fixed 3 defects: (1) project-delete race could resurrect folders / return 500 → central lock dir + 404 mapping + lexical containment; (2) junctions named like project IDs could crash the integrity check → skipped/reported; (3) log redaction missed dict/JSON/mid-line secrets → patterns extended. Tests: `tests/test_verification_phase01.py` (+78) |
| 02 | Verified | **PASS** (2026-10-20) | Verification fixed: after delete the UI stuck on a 404 error screen instead of returning to Projects (query invalidation unmounted the dialog); added skip link; test-only build break. | UI shell, dashboard, projects, wizard, drill-down views, audit/settings pages; backend project/dashboard/scope-preview APIs; SPA served by backend with security headers |
| 03 | Not started | — | Awaiting explicit prompt |
