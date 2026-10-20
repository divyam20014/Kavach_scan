# Implementation Status — VAPT Workbench

> Last updated: 2026-10-20 (Phase 00 verification). Statuses use only `Not started` / `Partial` / `Implemented` / `Blocked`. `Implemented` requires a code reference **and** a passing test that was actually run. Design-only documentation does not count as implementation.

## Current baseline

| Check | Result (observed 2026-10-20) |
|---|---|
| Application code | Minimal backend skeleton: health/version endpoints, loopback bind policy, loopback-peer guard, dev entry point |
| Backend tests | `poetry run pytest` → **99 passed**, 1 warning (Starlette TestClient deprecation notice) |
| Lint / format / types | `ruff check` passed; `ruff format --check` 14 files formatted; `mypy` (strict) no issues in 8 files |
| Frontend | None (Phase 02) |
| Database / broker dependencies | **None** (29 locked packages inspected; see [DEPENDENCIES.md](DEPENDENCIES.md) §4) |
| Scanning / outbound request / subprocess code in `backend/app/` | **None**. Guarded by `test_only_system_routes_exist`. |
| Runtime data, evidence, logs, reports, uploads, and secrets git-ignored | Yes. 47 path assertions in `backend/tests/test_repo_hygiene.py` (ignored runtime/secret paths, plus source and fixture paths that must stay tracked). |

## Product option matrix (Options A–D)

| Option | Description | Status | Depends on | Phase(s) | Planned paths | Tests |
|---|---|---|---|---|---|---|
| **A** | Web Application Vulnerability Scanner | Not started | M2, M3, M4, adapters | 05 (+ TLS/CVE 11) | `backend/app/scanners/webapp/`, `scanners/tls/`, `integrations/http_client.py` | — |
| **B** | Attack Surface Mapper | Not started | M2, M3, M4, adapters, A crawl | 06 | `backend/app/scanners/surface/`, `integrations/nmap.py`, `integrations/dns.py` | — |
| **C** | API Security Testing (OpenAPI/Swagger) | Not started | M2, M3, M4, adapters | 07 | `backend/app/scanners/api_security/`, `imports/openapi/` | — |
| **D** | Import, normalize, dedupe, report | Not started | M2, M9, M10 | 08, 09, 10 | `backend/app/imports/`, `findings/`, `reports/` | — |

No option is out of scope.

## MASTER_SPEC module traceability

| Module / requirement | Spec | Status | Phase | Code | Tests / evidence |
|---|---|---|---|---|---|
| Architecture & threat model docs | §3, §11 | **Implemented** (docs) | 00 | [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY_MODEL.md](SECURITY_MODEL.md), [SCAN_SAFETY.md](SCAN_SAFETY.md), [STORAGE_FORMATS.md](STORAGE_FORMATS.md), [TESTING.md](TESTING.md), [DEPENDENCIES.md](DEPENDENCIES.md), [DEVELOPMENT.md](DEVELOPMENT.md) | Doc review |
| `/api/health`, `/api/version` | §7 | **Implemented** | 00 | `backend/app/api/health.py`, `backend/app/main.py` | `backend/tests/test_health.py` |
| Loopback-peer guard (non-loopback clients → 403) | M12 | **Implemented** | 00 (verification fix) | `backend/app/core/loopback_guard.py` | `backend/tests/test_loopback_guard.py` |
| `/api/readiness` (data-dir readiness) | §7, M2 | Not started | 01 | `backend/app/api/health.py` | — |
| Localhost default bind; non-loopback refused | M12 | **Implemented** (startup policy) | 00 | `backend/app/core/config.py`, `backend/app/__main__.py` | `backend/tests/test_bind_policy.py`, `backend/tests/test_main_entrypoint.py`; manual smoke (TESTING §2) |
| Remote secure mode (auth, CSRF, CORS) | M12 | Not started | 12 | — | — |
| Host-header allowlist / request size limits / error format | M12 | Not started | 01 | `backend/app/core/` | — |
| `.gitignore` for runtime/secrets | §12 | **Implemented** | 00 | `.gitignore` | `backend/tests/test_repo_hygiene.py` |
| M1 App shell, dashboard, projects | §6 M1 | Not started | 02 | `frontend/src/` | — |
| M2 File-backed repository and settings | §2, §6 M2 | Not started (design in STORAGE_FORMATS) | 01 | `backend/app/storage/`, `models/`, `core/settings.py` | — |
| Canonical data contracts §5.1–5.7 | §5 | Not started | 01 | `backend/app/models/` | — |
| Audit JSONL + redaction | §5.7, M13 | Not started | 01 | `backend/app/storage/audit.py`, `core/redaction.py` | — |
| M3 Scope & authorization engine | §4, §6 M3 | Not started (policy in SCAN_SAFETY) | 03 | `backend/app/scope/` | — |
| M4 Job manager, logs, cancellation, kill switch | §2, §6 M4 | Not started | 04 | `backend/app/jobs/` | — |
| Shared HTTP / DNS / subprocess adapters | §4.3 | Not started | 05 | `backend/app/integrations/` | — |
| M5 Web scanner (Option A) | §6 M5 | Not started | 05 | see Option A | — |
| M6 Attack surface mapper (Option B) | §6 M6 | Not started | 06 | see Option B | — |
| M7 API security testing (Option C) | §6 M7 | Not started | 07 | see Option C | — |
| M8 Import, normalization, dedupe (Option D) | §6 M8 | Not started | 08 | `backend/app/imports/` | — |
| M9 Risk scoring, standards catalogs, remediation | §6 M9 | Not started | 09 | `backend/app/findings/` | — |
| M10 Reports, exports, backup/restore | §6 M10 | Not started | 10 | `backend/app/reports/` | — |
| M11 Tool integrations & CVE data | §6 M11 | Not started | 11 | `backend/app/integrations/` | — |
| M12 Local security & operator controls (beyond bind) | §6 M12 | Partial (bind policy + loopback-peer guard only) | 01, 04, 12 | `backend/app/core/` | `test_bind_policy.py`, `test_loopback_guard.py` |
| M13 Audit, reliability, accessibility, UX | §6 M13 | Not started | 01, 02, 12 | — | — |
| Hardening, performance, E2E | §8, §9 | Not started | 12 | — | — |
| Packaging & operator docs | §10 | Partial (dev instructions only) | 13 | [DEVELOPMENT.md](DEVELOPMENT.md) | Manually run 2026-10-20 |

## Docs checklist (MASTER_SPEC §11.2)

| Doc | Status |
|---|---|
| `docs/ARCHITECTURE.md` | Implemented (Phase 00 baseline) |
| `docs/SECURITY_MODEL.md` | Implemented (design baseline) |
| `docs/SCAN_SAFETY.md` | Implemented (policy baseline) |
| `docs/STORAGE_FORMATS.md` | Implemented (design; Phase 01 must reconcile with code) |
| `docs/TESTING.md` | Implemented |
| `docs/DEPENDENCIES.md` | Implemented (inventory) |
| `docs/DEVELOPMENT.md` | Implemented (backend only) |

## Phase log

| Phase | State | Verification verdict | Notes |
|---|---|---|---|
| Bootstrap | Done | n/a | Repository discovery; empty repo confirmed |
| 00 | Verified | **PASS** (2026-10-20) | Docs, `.gitignore` + hygiene tests, minimal FastAPI skeleton. Verification fixed 3 defects: over-broad `.gitignore`, bind-policy bypass via direct uvicorn launch (added peer guard), non-canonical bind host. |
| 01 | Not started | — | Awaiting explicit prompt |
