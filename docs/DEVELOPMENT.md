# Local Development — VAPT Workbench

> Phase 00 (2026-10-20). Only the backend skeleton exists. These steps were run on Windows 11 with Git Bash. POSIX shells are equivalent; PowerShell differences are noted. The repository root `README.md` belongs to the build pack and is intentionally not used for app instructions (TBD-033).

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
poetry run python -m app
# → http://127.0.0.1:8765/api/health   {"status":"ok"}
# → http://127.0.0.1:8765/api/version
# → http://127.0.0.1:8765/docs         (OpenAPI UI)
```

| Variable | Default | Notes |
|---|---|---|
| `VAPT_HOST` | `127.0.0.1` | Only loopback IP literals (`127.0.0.0/8`, `::1`, `[::1]`) or `localhost` (mapped to `127.0.0.1`) are accepted. Anything else exits with code 2 until a secure remote mode exists (TBD-003). |
| `VAPT_PORT` | `8765` | 1–65535 |
| `VAPT_DATA_DIR` | — | **Not used yet.** Introduced in Phase 01 ([STORAGE_FORMATS.md](STORAGE_FORMATS.md)). |

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

Expected results at Phase 00 are recorded in [TESTING.md](TESTING.md) §2.

## Frontend

Not created yet (Phase 02).
