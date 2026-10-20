# Architecture — VAPT Workbench (Kavach_scan)

> **Status:** Phase 00 baseline (2026-10-20).
> **Implemented** means code and passing tests exist in this repository. **Design** means the agreed target, owned by the phase named, and not yet built. The implementation status of every module is tracked in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

Related documents: [SECURITY_MODEL.md](SECURITY_MODEL.md) · [SCAN_SAFETY.md](SCAN_SAFETY.md) · [STORAGE_FORMATS.md](STORAGE_FORMATS.md) · [TESTING.md](TESTING.md) · [DEPENDENCIES.md](DEPENDENCIES.md) · [DEVELOPMENT.md](DEVELOPMENT.md)

---

## 1. What exists today (verified)

| Area | State | Evidence |
|---|---|---|
| Git | Branch `main` has no commits. Remote `origin` (`github.com/divyam20014/Kavach_scan`) is empty. | `git log`, `git ls-remote` at bootstrap |
| Backend | **Minimal FastAPI skeleton only**: `GET /api/health`, `GET /api/version`, a loopback-only bind policy (`python -m app`), and an in-app guard that rejects non-loopback peers with 403 however the app is launched. | `backend/app/`, `backend/tests/` (99 tests pass, Phase 00 verification) |
| Frontend | **None.** Planned for Phase 02. | — |
| Persistence | **None.** No code reads or writes a data directory yet. | `backend/app/` has no file I/O |
| Scanning / outbound network / subprocess | **None.** No HTTP client, DNS, socket, or subprocess usage exists in `backend/app/`. `/api/version` reports `scanning_available: false`. | `tests/test_health.py::test_only_system_routes_exist` |
| Database / broker | **None.** The full locked dependency set (29 packages) contains no database, ORM, Redis, or queue library. | [DEPENDENCIES.md](DEPENDENCIES.md) |

Layout as it exists:

```text
.gitignore                     runtime data / secrets / build output (verified by tests)
MASTER_SPEC.md PHASE_PROMPTS.md VERIFICATION_PROMPTS.md TBD_DECISIONS.md README.md
docs/                          architecture, security, safety, storage, testing, deps, dev, status
backend/
  pyproject.toml poetry.toml poetry.lock
  app/
    __init__.py                __version__
    __main__.py                `python -m app` dev entry point (refuses non-loopback bind)
    main.py                    create_app() factory
    api/health.py              /api/health, /api/version
    core/config.py             bind config: VAPT_HOST / VAPT_PORT, canonical loopback host, refusal
    core/loopback_guard.py     ASGI middleware: 403 for any non-loopback peer (defense in depth)
  tests/
    test_health.py             endpoints, version consistency, "no other routes exist", 404/405 checks
    test_bind_policy.py        localhost default, canonicalization, non-loopback refusal, port validation
    test_loopback_guard.py     remote peers / docs / forwarded headers rejected; loopback served
    test_main_entrypoint.py    `python -m app` refuses bad config before uvicorn starts
    test_repo_hygiene.py       .gitignore covers runtime/secrets, not source/fixtures
```

## 2. Target architecture (design)

### 2.1 Process model

One local OS process runs everything:

- A **FastAPI** application (uvicorn) bound to `127.0.0.1` by default.
- An **in-process job worker pool** (asyncio tasks plus bounded thread or subprocess usage) that consumes a **filesystem job spool**. There is no separate worker service, broker, or database.
- In production-like mode, the **React + TypeScript + Vite** SPA is built to static files and served by the same FastAPI process. In development, the Vite dev server proxies `/api` to the backend.

```text
 ┌────────────────────────── Operator workstation (single host) ──────────────────────────┐
 │                                                                                         │
 │  Browser ──HTTP 127.0.0.1──►  FastAPI process                                           │
 │  (SPA)                         ├─ api/ routers ── validate, authorize, serialize       │
 │                                ├─ services/ ───── use cases                             │
 │                                │     │                                                  │
 │                                │     ├─► scope/ ── allow/deny + reason (MANDATORY gate) │
 │                                │     ├─► jobs/ ─── spool, claim locks, state machine,   │
 │                                │     │             bounded workers, cancel, kill switch │
 │                                │     │     └─► scanners/{webapp,surface,api_security,tls}│
 │                                │     │            └─► integrations/ adapters:           │
 │                                │     │                 http_client ─┐  each calls scope │
 │                                │     │                 dns ─────────┼─ policy hook      │
 │                                │     │                 subprocess ──┘  before acting    │
 │                                │     ├─► imports/ ── dry-run → commit                   │
 │                                │     ├─► findings/ ─ normalize, dedupe, map, rank       │
 │                                │     └─► reports/ ── HTML → PDF, JSON/CSV, archives     │
 │                                └─ storage/ ── the ONLY module touching VAPT_DATA_DIR    │
 │                                                  ▼                                      │
 │                                      VAPT_DATA_DIR (outside repo, per-user)             │
 │                                                                                         │
 └──────────────────────────────────────────┬──────────────────────────────────────────────┘
                                            │ only via adapters + scope gate
                                            ▼
                         Authorized targets (in scope) · optional tools (nmap, sslyze)
                         · optional external data (disabled by default, TBD-018)
```

### 2.2 Why single-host and single-instance

1. **Persistence is files only** (mandatory). OS file locks (`msvcrt` on Windows, `fcntl` on POSIX, through a maintained wrapper, TBD-032) are reliable between processes on **one host**. They are unreliable or unsupported on network filesystems (SMB/NFS) and do not coordinate across machines.
2. **The job queue is a spool directory.** Claims rely on per-job locks. A second app instance on the same data root could double-claim jobs, race on derived indexes, and interleave JSONL appends.
3. **Enforcement:** at startup the app acquires an exclusive `instance.lock` in the data root and holds it for the life of the process. A second instance fails fast with a clear message. The OS releases the lock if the process dies, so a crash never leaves a permanent stale lock (Phase 01).
4. **Product fit:** this is an operator workstation tool, bound to localhost (TBD-001/003).
5. **Not claimed:** multi-node operation, HA, shared network data dirs, or concurrent multi-user write access.

### 2.3 Module boundaries

| Package | Owns | Must never | Phase |
|---|---|---|---|
| `api/` | Request parsing, authorization gate, response models, error format | Contain scan logic; do file I/O; call adapters directly | 00 (health), 01+ |
| `core/` | Settings, bind policy, errors, logging, correlation IDs, redaction | — | 00 (bind), 01 |
| `models/` | Pydantic v2 contracts with `schema_version` | Contain I/O | 01 |
| `storage/` | Data-root resolution, atomic writes, locks, JSONL, validation, migrations, indexes, integrity | Accept untrusted strings as paths | 01 |
| `scope/` | Canonicalization, allow/deny decisions with reasons, IP policy, authorization window | Be bypassable | 03 |
| `jobs/` | Spool, claim, state machine, workers, budgets, cancellation, recovery, kill switch | Keep in-memory-only state; use Redis/Celery | 04 |
| `integrations/` | HTTP client, DNS resolver, subprocess runner, tool detection | `shell=True`; act without a scope decision | 05, 11 |
| `scanners/*` | Pure check logic behind interfaces | Import `httpx`, `socket`, or `subprocess` directly | 05–07 |
| `imports/` | Parser adapters: detect → validate → parse → normalize → warnings | Execute or resolve external entities | 08 |
| `findings/` | Fingerprints, dedupe, catalogs, risk ranking | Fabricate CVSS/CVE | 09 |
| `reports/` | HTML (source of truth), PDF, JSON/CSV, archive export/import | Include secrets or absolute paths | 10 |
| `services/` | Use-case orchestration | Bypass storage or scope | 01+ |
| `frontend/` | UI via typed API client | Touch the filesystem; show fabricated metrics | 02+ |

Rules to be enforced by tests and lint (Phase 05/12): no module outside `integrations/` imports `httpx`, `socket`, `subprocess`, or `dns`. No module outside `storage/` opens files under the data root.

### 2.4 Data flow

1. **Project setup:** the UI posts a project, authorization, and scope. `services` validates through `scope.normalize_*`, `storage` writes `project.json` atomically, and an audit event is appended (scope edit, attestation).
2. **Scan request:** `POST /api/projects/{id}/scans` runs, in order: `require_active_authorization` → scope validation of explicit targets → module availability → kill-switch check → idempotency check → write a scan record with state `queued` and a scope/policy **snapshot + hash** → enqueue a spool entry.
3. **Execution:** a worker claims the job under lock, moves it to `validating` then `running`, and executes the scanner with a `JobContext`: a scoped request adapter, budgets, cancellation token, and redacting event writer. Every outbound action → scope decision → allowed: perform; blocked: structured `scope_blocked` event, no traffic.
4. **Results:** assets, findings, and evidence metadata are written through `storage`. Evidence bodies are redacted and truncated before persistence.
5. **Completion:** the final state is `completed` / `completed_with_warnings` / `failed` / `cancelled` / `interrupted` / `blocked_scope` / `expired_authorization`, with counters and a summary.
6. **Imports:** upload → hash and store raw → dry-run parse preview (no canonical changes) → explicit commit → normalize, dedupe, and preserve provenance.
7. **Reporting:** selection → preview → HTML render → PDF from the same template data → store with checksum → path-safe download.

### 2.5 Job flow (design, Phase 04)

```text
 queued ──► validating ──► running ──► completed
    │            │            ├──────► completed_with_warnings
    │            │            ├──────► failed
    │            │            ├──────► cancelled        (cancel request / kill switch)
    │            │            └──────► expired_authorization (window ended mid-scan)
    │            ├──► blocked_scope
    │            └──► expired_authorization
    └──► cancelled
 (on startup) running/validating without a live claim ──► interrupted  (never auto-replayed)
```

Worker concurrency defaults to 1 active job (hard cap 4, TBD-011). Per-target token buckets and request budgets are carried in the job context.

### 2.6 Filesystem persistence

All persistent state lives under `VAPT_DATA_DIR`. The default is a per-user application data dir outside the repository (TBD-006). See [STORAGE_FORMATS.md](STORAGE_FORMATS.md) for the layout, IDs, schema versions, atomic writes, locking, indexes, backup/restore, and corruption recovery.

## 3. Departures from MASTER_SPEC

| Spec item | Departure | Reason | Record |
|---|---|---|---|
| §2 Python 3.12+ | Dev venv uses CPython **3.13.5**. `requires-python = ">=3.12"`. | 3.13 is the default `py` interpreter on the dev machine. `py -3.12` does not resolve there. | TBD-026 |
| §3 layout `data/` in repo | Default data dir is outside the repo. `/data/` is only a gitignored safety net. | Spec §2 requires an outside-repo default. | TBD-035 |
| §2 `reportlab` suggestion | Undecided; candidates WeasyPrint / ReportLab / Chromium. | HTML-as-source-of-truth vs Windows install friction. | TBD-031 |

## 4. Known risks

| # | Risk | Mitigation / owner |
|---|---|---|
| R1 | `python` on PATH is 3.11.9, below the minimum | Docs use the Poetry venv (3.13). `requires-python` rejects older interpreters. |
| R2 | Windows: no POSIX modes; symlink creation often needs privileges; `os.replace` can fail with `PermissionError` while antivirus or indexers hold a file | Maintained lock library; bounded retry on replace; documented ACL reliance; symlink tests skip with reason (TBD-032, Phase 01) |
| R3 | `testssl.sh` is not native on Windows; Nmap and sslyze are not installed | Explicit "not configured" states; sslyze preferred (TBD-002) |
| R4 | FastAPI 0.150 / Starlette 1.9 TestClient warns that the `httpx` backend is deprecated in favour of `httpx2` | Non-blocking today; revisit when pinning test dependencies in Phase 01 |
| R5 | Local fixture targets run on loopback, which the scope engine blocks by default | Tests must use the explicit, audited internal-target override or an injected test resolver, never a global bypass flag ([TESTING.md](TESTING.md) §4) |
| R6 | Root `README.md` is the build-pack README and must not be overwritten | Dev instructions live in [DEVELOPMENT.md](DEVELOPMENT.md) (TBD-033) |
| R7 | No commits; the remote belongs to another account | No commits or pushes without owner instruction (TBD-034) |
| R8 | The loopback guard trusts the TCP peer address. A reverse proxy on the same host (nginx, ssh tunnel, Vite dev proxy) makes remote clients appear as `127.0.0.1`. | Documented. Operators must not expose the app through a local proxy until secure mode exists (TBD-003). The Host-header allowlist arrives in Phase 01. |
