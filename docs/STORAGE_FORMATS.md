# Storage Formats — VAPT Workbench (filesystem persistence, no database)

> **Status:** **Implemented in Phase 01** (2026-10-20) in `backend/app/storage/`, except the items marked *(Phase NN)*. This document was reconciled with the code. Tests: `backend/tests/test_{paths,atomic,locking,repository,indexes,audit_jsonl,migrations,integrity,startup}.py`.
>
> **Hard constraint:** no PostgreSQL, MySQL, SQLite, MongoDB, Redis, LMDB, DuckDB, TinyDB, `shelve`, or any database or broker. Persistence is validated JSON documents, JSONL logs, and opaque binary files only.

## 1. Data root

| Item | Rule |
|---|---|
| Location | `VAPT_DATA_DIR` if set. Otherwise the per-user default: Windows `%LOCALAPPDATA%\VAPTWorkbench\data`, Linux `${XDG_DATA_HOME:-~/.local/share}/vapt-workbench`, macOS `~/Library/Application Support/VAPTWorkbench` (TBD-006). |
| Inside repository | Refused unless `VAPT_ALLOW_REPO_DATA_DIR=1` is set (tests use temp dirs instead). |
| Resolution | `Path(value).expanduser().resolve(strict=False)`. Must be absolute after resolution. Created with restrictive permissions on first run. |
| Permissions | POSIX: directories `0700`, files `0600`. Windows: inherits the per-user profile ACL (documented limitation, TBD-032). |
| Network filesystems | Unsupported (locks are not reliable). Not detected automatically yet. |
| Foreign directories | A non-empty directory without `storage.json` is **refused** (protects e.g. a mistyped `VAPT_DATA_DIR=~/Documents`). Code: `StorageRepository.initialize`. |
| Filesystem/drive root, relative path, existing file | Refused (`resolve_data_root`). |

## 2. Directory layout

```text
<VAPT_DATA_DIR>/
  instance.lock                    exclusive OS lock held for the process lifetime
  instance.json                    informational lease: pid, host, started_at, app_version
  storage.json                     { storage_version, created_at, created_by_app_version }
  settings/settings.json           AppSettings (no secret values)
  control/kill_switch.json         (Phase 04) { engaged, engaged_at, reason }
  audit/
    audit.jsonl                    current append-only audit log
    audit.000001.jsonl ...         rotated segments (higher number = newer)
  index/
    projects.json                  DERIVED: project summaries + invalid ids
  jobs/                            (Phase 04) spool/<scan_id>.json, claims/<scan_id>.lock
  projects/<project_id>/
    project.json                   Project (incl. authorization, scope, scan_policy)
    .deleting                      tombstone present only while a delete is in progress
    scans/<scan_id>/scan.json      ScanJob (events.jsonl / console.log / outputs/ in Phase 04)
    assets/<asset_id>.json
    findings/<finding_id>.json
    evidence/<evidence_id>.json    EvidenceMetadata (excerpts redacted by storage)
    evidence/<evidence_id>.bin     optional blob; SHA-256 + size recorded in metadata
    imports/<import_id>/import.json
    imports/<import_id>/raw.bin    original upload (hash verified on read; never executed)
    api-specs/<spec_id>/...        (Phase 07)
    reports/<report_id>/report.json  (+ rendered files in Phase 10)
    index/<collection>.json        DERIVED per-collection indexes
  locks/<xx>/<sha256>.lock         central lock files (hash of the locked path); see §6
  backups/migrations/<timestamp>/  originals copied before persisted schema migrations
  trash/<project_id>-<ns>/         staging for project deletion; purged at startup
```

Canonical records are the single source of truth. Everything under `index/` is derived and disposable. Dot-prefixed entries (locks, temp files, tombstones) are never treated as records.

## 3. Identifiers

| Rule | Detail |
|---|---|
| Format | `<prefix>_<32 lowercase hex>` from `uuid4().hex`. Prefixes: `prj`, `scn`, `ast`, `fnd`, `evd`, `imp`, `spc`, `rpt`, `evt`. |
| Validation | Regex `^(prj\|scn\|ast\|fnd\|evd\|imp\|spc\|rpt\|evt)_[0-9a-f]{32}$`. Every ID from an API path or body is validated **before** any path is built. The prefix must match the expected type. |
| Path construction | Only `storage/` builds paths, through `root / "projects" / project_id / ...` with validated IDs. The final path is `resolve()`d and checked with `is_relative_to(root)`. Symlinks in the chain are rejected (`lstat`). |
| User filenames | Never used as paths. Stored only as a sanitized display string (`display_filename`, ≤ 255 characters, control characters stripped). |
| Case | Lowercase-only IDs avoid case-insensitivity collisions on Windows and macOS. |

## 4. Document format and schema versions

- UTF-8 JSON, `ensure_ascii=False`, sorted keys, 2-space indent for human-inspectable records. Timestamps are ISO-8601 UTC with a `Z` suffix.
- Every document has an integer **`schema_version`** for its own type (e.g., `Project` v1). `storage.json` holds the overall `storage_version`.
- **Read path:** parse → check `schema_version` → migrate in memory if older → Pydantic validate → return. A newer version than the app supports is **refused** (no silent downgrade). The record is reported as `unsupported_version`.
- **Migrations:** a registry of pure functions `vN → vN+1` per document type. Before the first write of any migrated record, the original is copied into `backups/migrations/<timestamp>/` (same relative path). Each migration step ships with fixture tests of old documents.
- **Write path:** Pydantic validate → serialize → atomic write (§5). Invalid data is never written.

## 5. Atomic writes

```text
1. acquire record lock (§6)
2. tmp = <dir>/.<name>.<random>.tmp   (same directory → same filesystem)
3. open(tmp, "xb") with 0600 → write bytes → flush() → os.fsync(fd) → close
4. os.replace(tmp, final)             (atomic on NTFS and POSIX)
5. POSIX only: fsync the parent directory
6. release lock
on any failure: unlink tmp (best effort), re-raise a typed StorageError
```

- **Windows:** `os.replace` can raise `PermissionError` while antivirus or indexers briefly hold the target. Retry with bounded backoff (e.g., 5 tries over ~1 s), then fail cleanly.
- **Startup cleanup:** `.*.tmp` files older than 1 hour under the data root are removed and logged.
- **Disk full (`ENOSPC`):** the temp write fails, so the original file stays intact. A typed error is surfaced to the UI. Low free space triggers a warning (threshold, TBD-007).

## 6. Locking

| Lock | Scope | Implementation |
|---|---|---|
| Instance lock | Whole data root, process lifetime | Exclusive non-blocking OS lock on `instance.lock`. Failure → refuse to start ("another instance is using this data directory"). The OS releases it on crash, so no stale-lock deadlock is possible. `instance.json` is informational only. |
| Record lock | One record unit (file, or directory for nested records) | Central lock file `locks/<xx>/<sha256(path)>.lock` (changed in Phase 01 verification: filelock creates missing parent directories, so sidecar locks could resurrect a deleted project's folders during a race), via **`filelock.FileLock`** (TBD-032) in `storage/locking.py` with `fallback_to_soft=False`, timeout (default 10 s, `VAPT_LOCK_TIMEOUT_SECONDS`) → `LockTimeoutError` (503). **Two-level**: threads first queue on an in-process mutex per lock path, then take the OS lock (see TBD-032 for measurements). Not re-entrant: a nested acquire times out instead of deadlocking. `ReadWriteLock` (SQLite-backed) and `SoftFileLock` are banned, enforced by `tests/test_static_guards.py`. |
| Project lock | One project | Central lock for the project directory; never inside it, so delete can rename the directory even on Windows. Serializes project updates and deletion. |
| Index lock / append lock | One index file / one JSONL file | Same mechanism. Held only for one read-modify-write or one append. |
| Job claim lock | One job | *(Phase 04)* `jobs/claims/<scan_id>.lock`, held by the worker while running. A job whose `scan.json` says `running` but whose claim lock is acquirable is **stale** → `interrupted`. |

Lock ordering, to avoid deadlock: instance → project → record → index/append. No operation holds two record locks at once. There is no repository-wide write lock. Readers take no locks: atomic replace guarantees they see the old or the new file, never a partial one.

**Project deletion:** under the project lock, the tree is checked for symlinks/junctions (refuse if any). Then a `.deleting` tombstone is written, the directory is atomically renamed into `trash/`, and it is removed. Writers refuse projects with a tombstone and never create a project directory implicitly. A writer that loses the race gets `not_found` (404), never a 500 or a resurrected folder (`tests/test_verification_phase01.py::test_writes_racing_project_delete_never_resurrect_it`, 15/15 repeated runs). Leftover trash is purged at startup.

**Concurrency evidence (Windows 11, Phase 01):** 6 threads × 15 updates and 4 processes × 15 updates of one project, through `update_project`, lose no updates (`tests/test_locking.py`).

## 7. JSONL event and audit logs

Implemented in `storage/jsonl.py` (generic) and `storage/audit.py` (audit events).

- One JSON object per line, `\n`-terminated, UTF-8, ≤ 256 KiB. Audit lines are `AuditEvent` records: `event_id`, `ts`, `schema_version`, `actor`, `project_id`, `action` (enum), `target_ids`, `outcome`, `metadata`, `correlation_id`.
- **Redaction happens in the storage layer, before serialization**, even for pre-built events (`core/redaction.py`: sensitive keys, bearer/basic tokens, JWTs, cloud/vendor keys, URL user-info, secret query parameters, `key=value` secrets, PEM private keys). Raw headers, cookies and tokens never reach the file.
- Append: under the append lock, `O_APPEND` write of the whole line, then `fsync`. If the file does not end with `\n` (torn line from a crash), the next append starts on a new line, so the torn line costs one corrupt line, never the next event.
- **Rotation:** at `VAPT_AUDIT_ROTATE_BYTES` (default 10 MiB) the current file is renamed to the next `audit.NNNNNN.jsonl`. On Windows, if a reader holds the file, rotation is deferred to a later append.
- **Corruption tolerance:** readers skip and count unparsable or schema-invalid lines (`corrupt_lines`). One bad line never makes the log unreadable.
- **Reading:** newest-first via a reverse chunked reader (64 KiB chunks), with offset/limit and filters (project, action). Memory stays bounded regardless of log size.

## 8. Derived indexes

- `index/projects.json` and `projects/<id>/index/<collection>.json`: `{ kind, storage_version, generated_at, entries: {id: summary+revision}, invalid: {id: error_code} }`.
- Updated after canonical writes (best effort, under the index lock). Built lazily on first listing.
- **Rebuilt** when missing, unparsable, of the wrong kind/version, or when `entries ∪ invalid` differs from the IDs on disk. A **stale entry** (revision differs from the record, e.g. after a crash between record write and index write) is detected while loading a page, and the index is rebuilt once.
- Filters/sorting use index summaries; pages load canonical records. Indexes are never exported or restored (they are regenerated).

**Not yet implemented:** a full-scan detector for stale *summary fields* outside the requested page. The integrity check (`POST /api/diagnostics/integrity-check`, startup) rebuilds every index, which covers that case.

## 9. Integrity checker (startup and on demand)

Implemented in `storage/integrity.py`; runs at startup (repair mode) and via `POST /api/diagnostics/integrity-check`. It reports issues and never deletes canonical data. Issue kinds:

- `corrupt_record`, `invalid_record`, `unsupported_version`: canonical files that fail to parse, validate or migrate (other projects keep working).
- `missing_project_file`, `unexpected_entry`, `link_in_data_dir`: structure problems; links are never followed.
- `dangling_evidence_ref` (finding/asset → missing evidence), `missing_blob`, `orphan_blob`.
- `temp_file` (check mode only), `project_pending_delete` (interrupted deletion).
- Repair mode only: rebuilds all indexes and removes temp files. Locations are reported **relative to the data root**.
- *(Phase 04)* stale jobs → `interrupted`.

Free disk space below `VAPT_DISK_WARNING_BYTES` is reported by the diagnostics (`GET /api/diagnostics/storage`, `python -m app diagnose`). The Settings page shows it in Phase 02.

## 10. Corruption recovery

1. A corrupt record is **reported**, not moved or deleted automatically (avoids data loss).
2. *(Phase 02/10)* Operator actions (each audited): view the raw file (escaped), restore from a backup, or quarantine. Today the operator repairs or removes the file manually, then re-runs the integrity check.
3. A corrupt `project.json` makes only that project unavailable. Listings return it in `errors[]` (`record_corrupt`) while other projects load normally (`tests/test_repository.py`).
4. A corrupt or newer-version `storage.json` → the app **refuses to start** with a clear message and modifies nothing (`tests/test_startup.py`). It is never silently re-initialized. `python -m app diagnose` still works in this state. A corrupt `settings.json` makes settings reads fail with `record_corrupt`; the rest of the app keeps working.

## 11. Backup and restore

| Aspect | Design (Phase 10, TBD-008) |
|---|---|
| Format | `.zip` named `<project-slug>-<UTC timestamp>.vaptbak` |
| Manifest | `manifest.json`: `{ format_version, app_version, storage_version, created_at, project_id, include_evidence, files: [{ path, sha256, size, schema_type, schema_version }] }` |
| Contents | Canonical JSON records, JSONL logs, reports, optional evidence/imports. **No secrets** (there are none to include, since secrets are references only). No derived indexes. |
| Restore validation | Every entry: relative path only, no `..`, no absolute or drive paths, no symlink entries, size and count caps, SHA-256 must match the manifest, every record validated (with migration if older). |
| Preview | Shows counts and conflicts before any write. Default on ID conflict: restore as a **new project ID** (never overwrite silently). |
| Atomicity | Extract into `tmp/restore-<id>/`, validate fully, then move into `projects/` in one rename. On failure the staging dir is removed. |
| Frequency | Manual in the first release. Automatic copies only before schema migrations. |

## 12. Size limits (TBD-009 proposals)

Enforced now: JSON record ≤ 5 MiB (`VAPT_MAX_RECORD_BYTES`), evidence excerpt ≤ 8 KiB, evidence blob ≤ 10 MiB, import upload ≤ 25 MiB, JSONL line ≤ 256 KiB, API request body ≤ 1 MiB (`VAPT_MAX_REQUEST_BYTES`), page size ≤ 500. Deeply nested JSON fails safely as `record_corrupt`. Archive limits (250 MiB / 10,000 entries) arrive with Phase 10.

## 13. Jobs, events and recovery (implemented in Phase 04)

| Path | Content |
|---|---|
| `projects/<pid>/scans/<sid>/scan.json` | Canonical `ScanJob`: state, timestamps, progress/stage/counters, warnings/errors, scope snapshot + hash, policy snapshot, authorized (canonical) targets, correlation ID, output refs, `retry_of`, `final_reason` |
| `projects/<pid>/scans/<sid>/events.jsonl` | Structured, redacted `JobEvent` stream (rotated like the audit log) |
| `projects/<pid>/scans/<sid>/console.log` | Concise human log, one redacted line per event (rotated, tail-read) |
| `projects/<pid>/scans/<sid>/work/` | Tool output / partial results (written only via `write_scan_output`); subprocess working directory |
| `jobs/spool/<sid>.json` | Queue entry `{scan_id, project_id, enqueued_at}`; FIFO dispatch |
| `jobs/claims/<sid>.lock` | Claim lock held by the worker for the whole run (OS lock; dies with the process) |
| `control/kill_switch.json` | `{engaged, changed_at, reason, actor}`; an unreadable file is treated as **engaged** (fail safe) |

**State machine:** `app/jobs/states.py`. `queued → validating → running → {completed, completed_with_warnings, failed, cancelled, interrupted, expired_authorization}`; `validating → {blocked_scope, expired_authorization, cancelled, failed, interrupted}`; `queued → {cancelled, expired_authorization, blocked_scope}`. Terminal states have no outgoing transitions; every write goes through `check_transition` under the record lock.

**Exactly-once claim:** a worker runs a job only after (1) acquiring `jobs/claims/<sid>.lock` non-blockingly and (2) re-reading `scan.json` in state `queued` with no cancel request. Tested with 8 threads racing for one job (`tests/test_jobs.py::test_concurrent_claims_run_a_job_exactly_once`).

**Deterministic startup recovery** (`JobManager.recover`, run before dispatching starts; idempotent):

1. Every scan in `queued` stays queued; a missing spool entry is re-created (order: `queued_at`).
2. Every scan in `validating`/`running` whose claim lock can be acquired is marked **`interrupted`** with the reason "The application stopped while this job was active. Partial results are kept; the job was NOT replayed automatically." Ambiguous in-flight work is **never** replayed; the operator can start a new job (`retry` creates a new scan with `retry_of`).
3. Spool entries that do not belong to a `queued` scan are removed.
4. Leftover claim-lock files without an OS lock are ignored (harmless).
5. Running `recover()` a second time changes nothing (tested).

**Graceful shutdown:** dispatching stops, running jobs are signalled and end as `interrupted` (partial output kept).

## 14. Web scanner outputs (implemented in Phase 05)

Written via `JobContext.write_output` into `projects/<pid>/scans/<sid>/work/`, redacted at write (every string through the redactor) and again when served by `GET /api/projects/{pid}/scans/{sid}/results/{summary|coverage|pages}` (bounded read, 16 MiB). Written at the end of the run **and** when the run is cancelled or stopped by a limit (partial results; `stopped_early` says why).

| File | Content |
|---|---|
| `work/profile.json` | Resolved `WebScanProfile` (catalog version, safe mode, budgets, enabled/disabled check groups with reasons, limitations): the job manifest |
| `work/summary.json` | Pages, endpoints, forms, parameters, request/error/retry/rate-limit counts, scope and redirect blocks, out-of-scope hosts, crawl skips, robots status, outcome counts (`check_outcomes`: list of `{outcome, count}`; no secret-looking keys, TBD-054), findings created/re-observed, tool versions, components, warnings, limitations |
| `work/coverage.json` | Every check result: rule, outcome, subject, rationale, parameter, severity, linked finding id (at most 5000 rows) |
| `work/pages.json` | Inventory: pages (status, type, title, bytes, truncation, redirects, blocked redirect, parameters), forms (method, action, field names, login form), parameters, resources |
| `work/tls-tool-*.json` | Raw sslyze/testssl.sh output when a tool ran |
| `work/tmp/` | Subprocess TEMP/TMP/TMPDIR |

Findings, evidence and URL assets created by a web scan use the normal collections; `scan.json` additionally records `tool_versions`. Evidence records are linked to their finding (`finding_ids`).
