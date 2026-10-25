# Claude Code VAPT Platform Build Pack

This pack is designed to be fed to Claude Code in small, verifiable phases. It specifies one local-first VAPT platform combining:

- **Option A — Web Application Vulnerability Scanner**
- **Option B — Attack Surface Mapper**
- **Option C — API Security Testing from OpenAPI/Swagger**
- **Option D — Scan Report Import, Deduplication, Risk Mapping, and Report Generation**

## Files in this pack

- `MASTER_SPEC.md` — product requirements, architecture, safety rules, modules, data contracts, UI requirements, and acceptance criteria.
- `PHASE_PROMPTS.md` — copy/paste implementation prompts, one phase at a time.
- `VERIFICATION_PROMPTS.md` — a repeatable verification prompt plus focused checks for each phase.
- `TBD_DECISIONS.md` — decisions Claude Code must record instead of silently inventing.

## Recommended workflow

1. Open the existing repository in Claude Code.
2. Read this pack and then paste the **Bootstrap Prompt** at the start of `PHASE_PROMPTS.md`.
3. Execute only one phase at a time, in numerical order.
4. After each phase, paste the matching verification prompt from `VERIFICATION_PROMPTS.md`.
5. Do not advance until the phase's exit criteria pass or every remaining blocker is documented in `TBD_DECISIONS.md`.
6. Commit a working checkpoint after each verified phase.

## Non-negotiable architecture decision: no database

This application must not use PostgreSQL, MySQL, SQLite, MongoDB, Redis, or any database/broker service. Persistence is via a local filesystem repository containing validated JSON/JSONL/YAML documents and evidence files. Use atomic writes, process/file locks, schema versions, backups, and recovery tests. Keep one application instance per data directory. The app should default to binding to `127.0.0.1`; remote exposure requires explicit secure configuration.

## Operational safety

Only scan systems for which the operator has explicit authorization. All active scanning must be scope-bound, rate-limited, auditable, stoppable, and conservative by default. Dangerous or potentially disruptive probes must be disabled by default. The scanner must not include stealth, evasion, persistence, credential theft, exploitation chains, destructive payloads, or denial-of-service behavior.

---

## Application quick start

Everything above this line is the original build-pack content (TBD-033) and is left exactly as it was. The sections below are the running application's own quick-start pointer, added in Phase 13.

**This is not a claim of comprehensive vulnerability detection or production SaaS readiness.** Read `docs/LIMITATIONS.md` before relying on anything this tool reports.

```bash
# Backend
cd backend
poetry install
poetry run python -m app serve   # http://127.0.0.1:8765

# Frontend (separate terminal, for UI development only — `python -m app serve` above
# already serves a production build if one exists at frontend/dist)
cd frontend
npm ci
npm run dev
```

- First-time setup, environment variables, and OS-specific notes: **`docs/DEVELOPMENT.md`**.
- Using the app day to day: **`docs/USER_GUIDE.md`**, **`docs/SAFE_SCAN_RUNBOOK.md`**.
- Try it with no real target: `poetry run python scripts/generate_demo_project.py --data-dir <path>` from `backend/` (see `docs/USER_GUIDE.md` §9).
- Optional external tools (Nmap, sslyze/testssl.sh) and CVE data: **`docs/INTEGRATIONS.md`**, **`docs/CVE_CATALOG.md`**.
- Reports and exports: **`docs/REPORTING.md`**.
- Something not working: **`docs/TROUBLESHOOTING.md`**.
- Preparing a release: **`docs/RELEASE_CHECKLIST.md`**.
- Full module-by-module implementation status: **`docs/IMPLEMENTATION_STATUS.md`**.
- Every material "why we chose X" decision: **`TBD_DECISIONS.md`**.
- Version history: **`CHANGELOG.md`**.

No database, broker, or queue service is used or required — persistence is local filesystem JSON documents (see "Non-negotiable architecture decision" above). The app binds to `127.0.0.1` only; there is no supported remote/multi-user mode.
