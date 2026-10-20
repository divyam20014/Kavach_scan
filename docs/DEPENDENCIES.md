# Dependency and Feature Inventory — VAPT Workbench

> Last updated: Phase 00 (2026-10-20). The sources of truth are `backend/pyproject.toml` and `backend/poetry.lock`. Licenses were read from installed package metadata (`importlib.metadata`) in the project venv.

## 1. Policy

- Add a dependency only in the phase that uses it, with a test that exercises it. No speculative installs.
- Python: Poetry 2.x with a committed `poetry.lock` (TBD-026). Frontend (Phase 02): npm with `package-lock.json`.
- **Forbidden:** any database, ORM, or broker client, including `sqlalchemy`, `sqlmodel`, `psycopg*`, `asyncpg`, `pymysql`, `mysqlclient`, `pymongo`, `motor`, `redis`, `celery`, `kombu`, `rq`, `dramatiq`, `huey`, `tinydb`, `peewee`, `tortoise-orm`, `alembic`, `duckdb`, `lmdb`. The stdlib `sqlite3` and `shelve` modules must not be imported either.
- Permissive licenses preferred (MIT/BSD/Apache/PSF/ISC; weak-copyleft MPL-2.0 acceptable). Copyleft (GPL/AGPL) needs explicit owner approval (TBD-028).

## 2. Backend runtime dependencies (direct)

| Package | Locked | License | Purpose | Added in |
|---|---|---|---|---|
| fastapi | 0.150.0 | MIT | HTTP API, OpenAPI generation | 00 |
| uvicorn | 0.54.0 | BSD-3-Clause | ASGI server for `python -m app` | 00 |

Transitive runtime packages: `starlette` 1.9.0 (BSD-3), `pydantic` 2.14.1 / `pydantic-core` 2.50.1 (MIT), `anyio` 4.15.1 (MIT), `idna` 3.20 (BSD-3), `typing-extensions` 4.16.0 (PSF-2.0), `typing-inspection` 0.4.4 (MIT), `annotated-types` 0.8.0 (MIT), `annotated-doc` 0.0.5 (MIT), `click` 8.5.0 (BSD-3), `h11` 0.16.0 (MIT), `colorama` 0.4.6 (BSD, Windows only), and **`opentelemetry-api` 1.45.1 (Apache-2.0)**.

> **Note on `opentelemetry-api`:** this is a direct dependency of FastAPI 0.150. It is the API package only. With no SDK or exporter installed, it is a no-op and makes **no network calls**. The Workbench does not configure telemetry. Phase 12's "no hidden network requests" review must re-confirm that no OpenTelemetry SDK or exporter ever gets installed.

## 3. Backend dev dependencies

| Package | Locked | License | Purpose |
|---|---|---|---|
| pytest | 8.4.2 | MIT | Test runner |
| httpx | 0.28.1 | BSD-3-Clause | Required by `fastapi.testclient`. **Test-only for now**; the outbound scanner client (Phase 05) will be wrapped by the shared adapter. |
| ruff | 0.17.1 | MIT | Lint and format |
| mypy | 2.4.0 | MIT | Strict type checking |

Transitive dev packages: `httpcore`, `certifi` (MPL-2.0), `iniconfig`, `pluggy`, `packaging`, `pygments`, `pathspec` (MPL-2.0), `mypy-extensions`, `ast-serialize`, `librt`.

## 4. Database/broker check (Phase 00)

`poetry show` lists 29 locked packages. A case-insensitive search for `sql|psycopg|pg8000|asyncpg|mysql|pymongo|motor|redis|celery|kombu|rq|dramatiq|huey|tortoise|peewee|alembic|sqlmodel|tinydb|shelve|lmdb|rocksdb|duckdb` found **none**. `backend/app/` imports no database modules.

## 5. Planned dependencies (not installed; added only by the owning phase)

| Phase | Candidate | Purpose | Decision |
|---|---|---|---|
| 01 | `filelock` or `portalocker` | Cross-process locks (Windows and POSIX) | TBD-032 |
| 01 | `platformdirs` | Per-user default data dir | TBD-006 |
| 03 | `hypothesis` (dev) | Property tests for scope engine | — |
| 05 | `httpx` (runtime, wrapped) | Outbound HTTP client in the shared adapter | spec §2 |
| 05 | `beautifulsoup4` + `lxml` | HTML parsing (no JS execution) | spec §2 |
| 05 | `cryptography` (dev, maybe runtime) | TLS fixture certs; certificate parsing | spec §2 |
| 05/06 | `dnspython` | DNS resolution with record types and TTL | — |
| 07 | `PyYAML` (`safe_load` only) | OpenAPI YAML | — |
| 08 | `defusedxml` | Hardened XML parsing (XXE-safe) | — |
| 08 | `pypdf` | Best-effort PDF text import | TBD-024 |
| 09 | `cvss` | CVSS vector validation and scoring | TBD-019 |
| 10 | WeasyPrint / ReportLab / Playwright | PDF rendering | TBD-031 |
| 02 | React, Vite, TypeScript, Mantine, TanStack Query, Vitest, Testing Library | Frontend | TBD-030 |

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
| Everything else in MASTER_SPEC | Not started | [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) |
