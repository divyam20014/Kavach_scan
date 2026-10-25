# Dependency and Feature Inventory — VAPT Workbench

> Last updated: Phase 13 (2026-10-25). The sources of truth are `backend/pyproject.toml` and `backend/poetry.lock`. Licenses were read from installed package metadata (`importlib.metadata`) in the project venv. Phase 12 added no new dependency; it upgraded three existing ones to patch disclosed vulnerabilities found by `pip-audit` (TBD-073) — see §2/§3. Phase 13 (packaging/docs/support-bundle/demo-generator/CI) also added **no new runtime or dev dependency** — confirmed via `git diff --stat backend/pyproject.toml` across this phase.

## 1. Policy

- Add a dependency only in the phase that uses it, with a test that exercises it. No speculative installs.
- Python: Poetry 2.x with a committed `poetry.lock` (TBD-026, **decided**).
- Check the import-time side effects of every new dependency: a library must not pull in a database or broker client just by being imported (this is the lesson from the TBD-032 evaluation). Frontend (Phase 02): npm with `package-lock.json`.
- **Forbidden:** any database, ORM, or broker client, including `sqlalchemy`, `sqlmodel`, `psycopg*`, `asyncpg`, `pymysql`, `mysqlclient`, `pymongo`, `motor`, `redis`, `celery`, `kombu`, `rq`, `dramatiq`, `huey`, `tinydb`, `peewee`, `tortoise-orm`, `alembic`, `duckdb`, `lmdb`. The stdlib `sqlite3` and `shelve` modules must not be imported either.
- Permissive licenses preferred (MIT/BSD/Apache/PSF/ISC; weak-copyleft MPL-2.0 acceptable). Copyleft (GPL/AGPL) needs explicit owner approval (TBD-028).

## 2. Backend runtime dependencies (direct)

| Package | Locked | License | Purpose | Added in |
|---|---|---|---|---|
| fastapi | 0.150.0 | MIT | HTTP API, OpenAPI generation | 00 |
| filelock | 4.2.4 | MIT | Cross-process exclusive locks, wrapped in `storage/locking.py` (`fallback_to_soft=False`; ReadWriteLock/SoftFileLock banned) | 01 |
| uvicorn | 0.54.0 | BSD-3-Clause | ASGI server for `python -m app` | 00 |
| python-multipart | 0.0.32 (was 0.0.9; upgraded Phase 12, TBD-073) | Apache-2.0 | FastAPI `UploadFile` multipart form parsing, used by every file-upload route (API specs, imports, CVE catalog, backup restore) | 07 |
| pypdf | 6.21.2 (was 5.9.0; upgraded Phase 12, TBD-073) | BSD-3-Clause | Best-effort text extraction for the PDF import adapter (`app/imports/adapters/pdf_text.py`); never used to run or execute PDF content, only `PdfReader.extract_text()` | 08 |
| cvss | 3.6 | LGPL-3.0-or-later | CVSS v3.1/v4.0 vector parsing and base-score computation (`app/models/cvss_calc.py`); a supplied score is always cross-checked against what this library computes from the vector, never trusted verbatim | 09 |
| fpdf2 | 2.8.9 | LGPL-3.0-only | Pure-Python, searchable/text PDF report rendering (`app/reports/pdf_render.py`); no system/native dependencies (TBD-031) | 10 |

Transitive runtime packages: `starlette` 1.9.0 (BSD-3), `pydantic` 2.14.1 / `pydantic-core` 2.50.1 (MIT), `anyio` 4.15.1 (MIT), `idna` 3.20 (BSD-3), `typing-extensions` 4.16.0 (PSF-2.0), `typing-inspection` 0.4.4 (MIT), `annotated-types` 0.8.0 (MIT), `annotated-doc` 0.0.5 (MIT), `click` 8.5.0 (BSD-3), `h11` 0.16.0 (MIT), `colorama` 0.4.6 (BSD, Windows only), **`opentelemetry-api` 1.45.1 (Apache-2.0)**, and (pulled in by `fpdf2`) `pillow` 13.0.0 (MIT-CMU), `fonttools` 4.67.0 (MIT), `defusedxml` 0.7.1 (PSFL).

> **Note on `opentelemetry-api`:** this is a direct dependency of FastAPI 0.150. It is the API package only. With no SDK or exporter installed, it is a no-op and makes **no network calls**. The Workbench does not configure telemetry. Phase 12's "no hidden network requests" review must re-confirm that no OpenTelemetry SDK or exporter ever gets installed.

## 3. Backend dev dependencies

| Package | Locked | License | Purpose |
|---|---|---|---|
| pytest | 9.1.1 (was 8.4.2; upgraded Phase 12, TBD-073) | MIT | Test runner |
| httpx | 0.28.1 | BSD-3-Clause | Required by `fastapi.testclient`. **Test-only.** The scanner's outbound client is the stdlib-based pinned transport (TBD-051). |
| ruff | 0.17.1 | MIT | Lint and format |
| mypy | 2.4.0 | MIT | Strict type checking |
| hypothesis | 6.170.5 | MPL-2.0 | Property-based tests for the scope engine (Phase 03); depends only on `sortedcontainers` (Apache-2.0) |
| cryptography | 50.0.2 | Apache-2.0 / BSD-3-Clause | **Dev only** (Phase 05): generates a throwaway test CA and valid/expired/wrong-host certificates at test time for the TLS fixture servers. Pulls `cffi` (MIT) and `pycparser` (BSD-3). |

Transitive dev packages: `httpcore`, `certifi` (MPL-2.0), `iniconfig`, `pluggy`, `packaging`, `pygments`, `pathspec` (MPL-2.0), `mypy-extensions`, `ast-serialize`, `librt`.

## 4. Database/broker check (Phase 01)

`poetry.lock` contains 44 packages (Phase 10 added `fpdf2` plus its transitive `pillow`/`fonttools`/`defusedxml`, runtime). None is a database, ORM, broker or queue library. This is now enforced automatically: `tests/test_static_guards.py::test_manifest_has_no_database_or_broker_dependencies` (lockfile + manifest), `::test_no_database_imports` (source), and `tests/test_startup.py::test_importing_app_loads_no_database_or_broker_modules` (runtime: no `sqlite3`, `redis`, `celery`, … in `sys.modules`).

> **Note on `cvss` (LGPL-3.0-or-later):** this is weaker copyleft than GPL/AGPL — it only obligates sharing modifications to the *library itself* if redistributed, not to code that merely imports it. This project does not modify or redistribute `cvss`, so no obligation is triggered. It is still flagged in TBD-019 for an explicit owner sanity check, consistent with this project's general caution around any copyleft dependency.

> **Note on `fpdf2` (LGPL-3.0-only):** same reasoning as `cvss` above — this project links against `fpdf2` as an unmodified, unredistributed dependency, which triggers no LGPL obligation. Flagged in TBD-031 for the same owner sanity check.

## 4a. Dependency vulnerability audit (Phase 12, TBD-073)

`pip-audit` (run ephemerally via `poetry run pip install pip-audit`, then `poetry install --sync` to remove it afterward — it is never added to `pyproject.toml`/`poetry.lock`) was run against the full backend dependency set. It found disclosed vulnerabilities in three packages, all patched in this phase:

| Package | Before | After | Notes |
|---|---|---|---|
| `pypdf` | 5.9.0 | 6.21.2 | Runtime (PDF import adapter). `PdfReader.extract_text()` usage unchanged; full test suite re-run clean. |
| `python-multipart` | 0.0.9 | 0.0.32 | Runtime (every file-upload route, via FastAPI `UploadFile`). No direct API surface used; re-run clean. |
| `pytest` | 8.4.2 | 9.1.1 | Dev-only test runner. Full suite re-run clean across the major-version bump. |

A re-run of `pip-audit` after the upgrade reports **zero vulnerabilities** in any project dependency. `npm audit` (frontend) was re-confirmed clean (0 vulnerabilities) in the same pass — no frontend dependency changed.

## 5. Planned dependencies (not installed; added only by the owning phase)

| Phase | Candidate | Purpose | Decision |
|---|---|---|---|
| 01 | ~~`filelock`~~ | **Installed** (see §2) | TBD-032 decided |
| 01 | ~~`platformdirs`~~ | Not needed: the per-user default is resolved in `storage/paths.py` (about 10 lines, tested) | TBD-006 |
| 03 | `hypothesis` (dev) | Property tests for scope engine | — |
| 05 | ~~`httpx` (runtime)~~ | Not added: stdlib `http.client` pinned transport (TBD-051) | decided |
| 05 | ~~`beautifulsoup4` + `lxml`~~ | Not added: stdlib `html.parser` is sufficient (links, forms, metadata; no JS) | decided |
| 05 | `cryptography` (dev) | **Installed (dev only)**: TLS fixture certificates | decided |
| 06 | ~~`dnspython`~~ | Not added: A/AAAA/CNAME via stdlib `socket.getaddrinfo` suffice (TBD-055). | decided |
| 06 | ~~`python-nmap`~~ | Not added: the Nmap adapter builds argv and parses `-oX` output with stdlib ElementTree (DTD-rejecting, size-capped). | decided |
| 07 | ~~`PyYAML`~~ | **Installed** (runtime, `safe_load` only): OpenAPI/Swagger YAML. `types-PyYAML` dev. | done |
| 07 | `python-multipart` | **Installed** (runtime): spec file upload (FastAPI `UploadFile`). | done |
| 08 | ~~`defusedxml`~~ | Not added: `app/imports/safety.py::parse_xml_safely` rejects any `<!DOCTYPE`/`<!ENTITY` before handing bytes to stdlib `ElementTree`, with explicit depth/node-count bounds — the same pattern already used by the Nmap adapter (Phase 06) and the OpenAPI importer (Phase 07) | decided |
| 08 | ~~`pypdf`~~ | **Installed** (runtime): best-effort PDF text import, `extract_text()` only | TBD-024 decided |
| 09 | ~~`cvss`~~ | **Installed** (runtime): CVSS v3.1/v4.0 vector validation and the sole source of a `Finding.cvss.base_score` | TBD-019 decided |
| 10 | ~~WeasyPrint / ReportLab / Playwright~~ | Not added: `fpdf2` chosen instead (pure Python, no native/system dependencies) | TBD-031 decided |
| 11 | ~~`packaging` / `semver`~~ | Not added: `app/cve/version.py` is a small, hand-written dotted-version comparator (no pre-release/build-metadata semantics) — defensible enough for the documented catalog format and avoids a new dependency for a ~90-line module | decided |
| 11 | ~~python-nvdlib / a real NVD feed parser~~ | Not added: a documented, VAPT-Workbench-specific JSON schema is used instead of the NVD feed format (TBD-028: no bundled third-party feeds; a partial NVD parser would be a worse safety trade-off than a small, fully-defensible format) | decided |
| 02 | React, Vite, TypeScript, Mantine, TanStack Query, Vitest, Testing Library | Frontend | TBD-030 |

## 5a. Frontend dependencies (Phase 02; exact pins in `frontend/package.json` + `package-lock.json`)

| Package | Version | Kind | Purpose |
|---|---|---|---|
| react / react-dom | 18.3.1 | runtime | UI |
| @mantine/core, hooks, notifications | 7.17.8 | runtime | Component library (TBD-030) |
| @tanstack/react-query | 5.104.5 | runtime | Data fetching/caching |
| react-router-dom | 7.18.4 | runtime | Routing. 6.x carries GHSA-wrjc-x8rr-h8h6 (open redirect), so 7.18.4 is used |
| vite / @vitejs/plugin-react | 7.3.7 / 5.2.0 | dev | Build/dev server (5.x pulled vulnerable esbuild) |
| vitest / jsdom | 4.1.12 / 26.1.0 | dev | Tests (2.x pulled critical tinypool + @vitest/mocker advisories) |
| @testing-library/react, dom, user-event, jest-dom | 16.3.3, 10.4.2, 14.6.8, 6.10.0 | dev | Component tests |
| typescript / eslint / typescript-eslint / eslint-plugin-react-hooks | 5.9.3 / 9.39.5 / 8.72.0 / 5.2.0 | dev | Types and lint (ESLint 9 is past end of support; TBD-042) |
| playwright-core | 1.64.1 | dev | Drives the locally installed Edge for `npm run e2e`; downloads no browsers |

`npm audit` (runtime and dev): **0 vulnerabilities** on 2026-10-20. No icon or chart library was added: statuses use text + shapes, and no graphs exist yet.

## 6. External tools (optional, never bundled)

| Tool | Status on dev machine (2026-10-20) | Used by | Behaviour if absent |
|---|---|---|---|
| Nmap | Not installed | Option B port/service mapping | Built-in bounded TCP connect check plus a visible "not installed" state |
| sslyze | Not installed | Option A TLS details | TLS cipher/protocol checks marked **skipped: not configured** |
| testssl.sh | Not installed (bash-only; not native on Windows) | Option A TLS (POSIX/WSL) | Same as above |

## 7. Feature inventory

| Feature | State | Where |
|---|---|---|
| `GET /api/health` | Implemented | `backend/app/api/health.py`; `tests/test_health.py` |
| `GET /api/version` (name, version, Python, `scanning_available=false`) | Implemented | same |
| Loopback-only bind policy (`VAPT_HOST`, `VAPT_PORT`; canonical loopback literal; non-loopback refused) | Implemented | `backend/app/core/config.py`; `tests/test_bind_policy.py`, `tests/test_main_entrypoint.py` |
| Loopback-peer guard (403 for non-loopback clients however the app is launched) | Implemented | `backend/app/core/loopback_guard.py`; `tests/test_loopback_guard.py` |
| Dev entry point `python -m app` | Implemented | `backend/app/__main__.py` |
| `.gitignore` for runtime/secrets/build output | Implemented | `.gitignore`; `tests/test_repo_hygiene.py` |
| Filesystem storage layer (StorageRepository, locks, audit JSONL, migrations, integrity, diagnostics) | Implemented | `backend/app/storage/`; see IMPLEMENTATION_STATUS |
| Canonical Pydantic contracts | Implemented | `backend/app/models/` |
| Readiness / diagnostics endpoints, `python -m app diagnose` | Implemented | `backend/app/api/health.py`, `backend/app/__main__.py` |
| Report builder (HTML + PDF), JSON/CSV exports, project backup/restore archive | Implemented | `backend/app/reports/`, `backend/app/backup/`, `backend/app/api/reports.py`; see IMPLEMENTATION_STATUS |
| Integrations status/self-test (nmap, sslyze, testssl.sh), local CVE catalog import/match, settings API | Implemented | `backend/app/services/integrations.py`, `backend/app/cve/`, `backend/app/api/settings.py`; see IMPLEMENTATION_STATUS |
| Everything else in MASTER_SPEC | Not started | [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) |
