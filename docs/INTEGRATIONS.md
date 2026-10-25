# Integrations Status & Self-Test — Module 11/12 (Phase 11)

> Code: `backend/app/services/integrations.py`, `backend/app/api/settings.py` (`/api/integrations`, `/api/integrations/{id}/selftest`), `backend/app/models/settings.py` (`IntegrationsSettings`). Frontend: `frontend/src/pages/IntegrationsPage.tsx`.

## 1. Detection vs. verification — never a false green

Listing integrations (`GET /api/integrations`) is **detection only**: a PATH lookup (or checking an explicit configured path exists), never a subprocess execution. A tool found this way is shown `detected` (blue) — present, but unverified. The only way a tool is ever shown `verified` (green) is an explicit, operator-triggered self-test (`POST /api/integrations/{id}/selftest`) that actually ran `<tool> --version` and got a readable response in *this* process. This satisfies the Phase 11 acceptance criterion directly: "Missing external tools create clear skipped checks, not false passes" — and by extension, a tool that is merely *present* is never claimed to be *working*.

Because the self-test's result is not persisted server-side (there is no mutable "verified" flag written to storage — see §4), the frontend keeps the self-test's own response in local state for the rest of the page session rather than trusting a subsequent list refetch, which would (correctly, by design) still report `detected`.

## 2. The self-test touches no target

`run_selftest` resolves the tool's path (configured override or PATH auto-detection — the same logic `GET /api/integrations` uses) and, if found, runs exactly `<tool> --version` through the existing Phase 04 subprocess adapter (`app/integrations/process.py::run_process`): allowlisted to itself, a bounded timeout (20s), a bounded output cap (16 KiB), and the same process-tree-kill-on-timeout behavior every other subprocess invocation in this project gets. No host, port, or scan target is ever part of the self-test's argv — it is the literal "diagnostic page... no active target traffic" required by the phase prompt.

`status: verified` is only ever reported when the process both produced readable output **and** exited with status 0 (TBD-071, found during verification). A tool that doesn't understand `--version` — an unsupported/incompatible version, or an invalid executable masquerading as the real one — typically prints an error message and exits non-zero; that is reported as `status: error` with the exit code and the diagnostic text, never as a verified version. A configured path pointing at a file that isn't actually runnable (wrong binary format, no execute permission) raises an `OSError` at the OS level before any process starts, which is caught and turned into the same clean `error` status rather than an unhandled exception.

## 3. What each state means

| Status | Meaning |
|---|---|
| `not_configured` | No explicit path is configured and nothing was found on PATH. |
| `not_found` | An explicit path *is* configured, but nothing usable exists there. |
| `detected` | Found (PATH or configured path), but no self-test has verified it in this process. |
| `verified` | A self-test ran `--version` and got a readable response. |
| `error` | A self-test ran but the tool timed out, produced no readable output, or otherwise failed. |

## 4. "Last used"

Every real scan that uses sslyze/testssl.sh (Phase 05) or Nmap (Phase 06) already records a version string in `ScanJob.tool_versions` at the end of the run. Rather than add a new write path to those already-verified runners, the integrations status reads this existing data: it looks at the most recently updated scans across all projects (`StorageRepository.list_across_projects`) and reports the newest one carrying an entry for the tool in question, along with its project/scan id and the version that scan recorded (TBD-070). This is accurate for exactly what it claims — a genuine recorded scan run — and requires zero changes to Phase 05/06 code.

## 5. Settings: tool paths and a reserved credential field

`IntegrationsSettings` (part of `AppSettings`, exposed via `GET`/`PATCH /api/settings`) holds explicit path overrides for nmap/sslyze/testssl.sh (empty = auto-detect from PATH, the existing Phase 05/06 default) and `online_lookup_credential_alias`, reserved for a future opt-in online data source (TBD-068) — no such source makes any network call in this release. The credential field can only ever hold a reference (`env:NAME` or `keychain:NAME`, the same pattern as the Phase 07 API-auth aliases, TBD-058); a value that looks like a raw secret is rejected at write time with a 422, which is what makes "secret values are write-only and never returned by the settings-read API" true by construction — there is never a real secret for the API to echo back.

## 6. CLI

`python -m app integrations` runs the same self-test (PATH detection + bounded `--version` capture, no target traffic) for every known tool and prints the result as JSON — a read-only diagnostic alongside the existing `python -m app diagnose`.
