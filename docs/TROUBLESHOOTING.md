# Troubleshooting — VAPT Workbench

## Startup

**"Refusing to bind to non-loopback host"** — you (or your shell) set `VAPT_HOST` to something other than `127.0.0.1`/`::1`/`localhost`. This is intentional: remote access requires a secure mode that doesn't exist yet (TBD-003). Unset `VAPT_HOST` or set it to `127.0.0.1`.

**"Unknown configuration variable(s): VAPT_..."** — an environment variable starting with `VAPT_` doesn't match a known setting (usually a typo, e.g. `VAPT_DATADIR` instead of `VAPT_DATA_DIR`). See `.env.example` for the full, exact list.

**"Another VAPT Workbench instance is already using this data directory"** — only one process may hold a given data directory at a time (a safety measure against concurrent-writer corruption). Stop the other instance, or point `VAPT_DATA_DIR` at a different directory.

**"VAPT_DATA_DIR must be an absolute path"** — relative paths are rejected on purpose (an app started from a different working directory would otherwise silently use a different data root). Use a full path.

**Port already in use** — another process is using the configured port (default 8765). Set `VAPT_PORT` to a free port, or stop whatever else is using it.

## Scanning

**A check is always "skipped"** — check the scan's **Coverage** tab for the reason. Common causes: the relevant optional tool (Nmap/sslyze/testssl.sh) isn't installed (see `docs/INTEGRATIONS.md`); the check requires prerequisites you haven't configured (e.g. IDOR checks need two identities and an ownership map); or the capability is deliberately not built into this release (`docs/LIMITATIONS.md` §2) — a permanent skip, not a bug.

**Target rejected as "out of scope" or "blocked"** — check the project's scope definition and the blocked-ranges list (`GET /api/scope/blocked-ranges`, or Settings). Private/internal/cloud-metadata IP ranges are blocked by default; use the internal-target override if the target is genuinely, narrowly in scope.

**A scan won't start / stuck "queued"** — check whether the kill switch is engaged (header, or `GET /api/kill-switch`) and whether the job queue is full (`max_queued_jobs`). Check the project's authorization window hasn't expired.

**Nmap/sslyze/testssl.sh show "not configured" or "not found"** — these are optional; the app works without them (checks degrade to a built-in fallback or report `skipped`). To use one, install it and either ensure it's on `PATH` or set an explicit path in Settings → Integrations, then click **Run self-test** to verify it actually runs — being on PATH alone is shown as "detected (unverified)," not "working," until a self-test succeeds.

## Imports and reports

**Import upload rejected as too large / malformed** — each import format has a documented size/complexity limit (`docs/IMPORT_CENTER.md`); a file over that limit, or one with disallowed content (e.g. an XML external-entity declaration, an oversized/zip-bomb archive), is rejected before parsing, not partially processed.

**Report generation seems to "hang" on a large project** — report generation reads every included finding's full record; a very large project (many thousands of findings) will take longer. See `docs/LIMITATIONS.md` §6.

**Backup restore refused with a 409 conflict** — a project with that exact ID already exists in the target data directory. Pass the explicit overwrite confirmation if you intend to replace it; otherwise restore into a different, clean data directory.

## Diagnostics

Before asking for help, gather a **diagnostic support bundle**: Settings → "Download support bundle" (or `python -m app support-bundle` from `backend/`). It's redacted (no secrets, no evidence blobs by default) and safe to share — it contains version/storage info, settings, recent audit events, integration status, and per-project record counts (full finding records only if you explicitly choose "with finding records").

For a lower-level check: `python -m app diagnose` (storage readiness) and `python -m app integrations` (tool detection/self-test) both print JSON and touch nothing but the local filesystem and, for the integrations check, a single `--version` invocation of each configured tool.

## Tests and development

**`poetry install` fails on Python version** — this project requires Python 3.12+; point Poetry at a newer interpreter explicitly (see `docs/DEVELOPMENT.md`).

**A backend test fails with a network-related assertion error** — every test runs behind an autouse guard that fails the test immediately if it ever opens a non-loopback socket. If you see this, something in your change is trying to reach the network; it should not be.

**`npm run build` warns about a large chunk** — a cosmetic Vite bundle-size warning, not a build failure; the build still succeeds.
