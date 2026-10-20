# Local Development — VAPT Workbench

> Phase 01 (2026-10-20). Backend foundation and filesystem storage exist; no frontend yet. These steps were run on Windows 11 with Git Bash. POSIX shells are equivalent; PowerShell differences are noted. The repository root `README.md` belongs to the build pack and is intentionally not used for app instructions (TBD-033).

## Prerequisites

- Python **3.12 or newer**. On the reference machine, the default `python` on PATH is 3.11.9 (too old), so point Poetry at a 3.12+ interpreter explicitly.
- Poetry 2.x.
- Git.

## Backend setup

```bash
cd backend
# Point Poetry at a Python 3.12+ interpreter (the path below is an example from the reference machine)
poetry env use "C:/Users/<you>/AppData/Local/Programs/Python/Python313/python.exe"   # or: poetry env use python3.12
poetry install            # creates backend/.venv (in-project, see poetry.toml); .venv is git-ignored
```

## Run the API (localhost only)

```bash
cd backend
poetry run python -m app            # first run creates the data directory
# → http://127.0.0.1:8765/api/health              liveness
# → http://127.0.0.1:8765/api/readiness           200 ready / 503 not ready
# → http://127.0.0.1:8765/api/diagnostics/storage data dir, disk space, lock, last integrity check
# → http://127.0.0.1:8765/docs                    OpenAPI UI
poetry run python -m app diagnose   # read-only JSON report; exit 0 ready, 1 not ready
poetry run python -m app --version
```

Exit codes: 0 ok · 1 not ready (diagnose) · 2 configuration error · 3 storage error (e.g. another instance is using the data directory).

| Variable | Default | Notes |
|---|---|---|
| `VAPT_HOST` | `127.0.0.1` | Only loopback IP literals (`127.0.0.0/8`, `::1`, `[::1]`) or `localhost` (mapped to `127.0.0.1`). Anything else exits with code 2 (TBD-003). |
| `VAPT_PORT` | `8765` | 1–65535 |
| `VAPT_DATA_DIR` | per-user app data | Windows `%LOCALAPPDATA%\VAPTWorkbench\data`; Linux `~/.local/share/vapt-workbench`; macOS `~/Library/Application Support/VAPTWorkbench`. Must be absolute; refused inside the repo, on a drive root, or on a non-empty non-Workbench directory. |
| `VAPT_ALLOW_REPO_DATA_DIR` | off | Escape hatch to allow a data dir inside the checkout (not recommended). |
| `VAPT_LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR`. Logs are JSON lines on stderr, redacted. |
| `VAPT_LOCK_TIMEOUT_SECONDS` | `10` | Record-lock wait before a 503 `lock_timeout`. |
| `VAPT_AUDIT_ROTATE_BYTES` | `10485760` | Audit log segment size. |
| `VAPT_MAX_RECORD_BYTES` | `5242880` | Largest JSON record. |
| `VAPT_MAX_REQUEST_BYTES` | `1048576` | Largest API request body (`python -m app` path). |
| `VAPT_DISK_WARNING_BYTES` | `2147483648` | Low-disk warning threshold. |
| `VAPT_MAX_ACTIVE_JOBS` | `1` | Concurrent jobs (hard cap 4). |
| `VAPT_MAX_QUEUED_JOBS` | `20` | Queue length before new starts are refused. |
| `VAPT_ENABLE_SELFTEST_JOBS` | off | Exposes the network-free job self-test module (development/testing only). |

Any other `VAPT_*` variable is rejected as a probable typo (exit code 2). Only one app instance may use a data directory at a time.

PowerShell: `$env:VAPT_PORT = "9000"; poetry run python -m app`.

Launching uvicorn directly (`uvicorn app.main:app ...`) skips the startup check, but the app still answers **403** to any non-loopback client. Do not put the app behind a reverse proxy or tunnel: proxied clients appear as loopback.

## Checks

```bash
cd backend
poetry run pytest
poetry run ruff check .
poetry run ruff format --check .
poetry run mypy
```

Expected results are recorded in [TESTING.md](TESTING.md) §2. Tests always use temporary data directories and never touch your real data dir.

## Frontend

React 18 + TypeScript + Vite 7 + Mantine 7 + TanStack Query + React Router 7 (TBD-030). Requires Node 20.19+ (tested on 22.16).

```bash
cd frontend
npm install              # .npmrc sets legacy-peer-deps (TBD-042)
npm run dev              # http://127.0.0.1:5173, proxies /api to the backend on 127.0.0.1:8765
npm test                 # Vitest (jsdom)
npm run typecheck && npm run lint
npm run build            # -> frontend/dist; `python -m app` then serves the UI at http://127.0.0.1:8765/
npm run e2e              # real-browser smoke test with the installed Microsoft Edge (needs a build first)
```

Run the backend (`cd backend && poetry run python -m app`) before `npm run dev`. The browser talks only to `/api`; it never touches the filesystem.

## Optional external tools and local labs (Phase 05)

The web scanner runs without any external tool. If `sslyze` (preferred) or `testssl.sh` is on `PATH`, it is detected, its version captured, and it is used for TLS protocol enumeration (protocols and certificate info only, pinned IP, 300 s timeout). Without one, the TLS protocol/cipher checks are reported as **skipped**, never as passed. Install example: `pipx install sslyze`.

To scan a local lab app on `127.0.0.1`, create the project with the app URL as target, then set an **internal-target override** for `127.0.0.1/32` on the project page (attested, audited, time-bound). Loopback and private ranges are blocked otherwise.
