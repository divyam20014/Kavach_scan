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
