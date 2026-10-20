# Storage Formats — VAPT Workbench (filesystem persistence, no database)

> **Status:** Phase 00 design (2026-10-20). **No storage code exists yet.** Phase 01 implements this design in `backend/app/storage/` and must update this document wherever implementation details differ.
>
> **Hard constraint:** no PostgreSQL, MySQL, SQLite, MongoDB, Redis, LMDB, DuckDB, TinyDB, `shelve`, or any database or broker. Persistence is validated JSON documents, JSONL logs, and opaque binary files only.

## 1. Data root

| Item | Rule |
|---|---|
| Location | `VAPT_DATA_DIR` if set. Otherwise the per-user default: Windows `%LOCALAPPDATA%\VAPTWorkbench\data`, Linux `${XDG_DATA_HOME:-~/.local/share}/vapt-workbench`, macOS `~/Library/Application Support/VAPTWorkbench` (TBD-006). |
| Inside repository | Refused unless `VAPT_ALLOW_REPO_DATA_DIR=1` is set (tests use temp dirs instead). |
| Resolution | `Path(value).expanduser().resolve(strict=False)`. Must be absolute after resolution. Created with restrictive permissions on first run. |
| Permissions | POSIX: directories `0700`, files `0600`. Windows: inherits the per-user profile ACL (documented limitation, TBD-032). |
| Network filesystems | Unsupported (locks are not reliable). Warn when detectable. |

## 2. Directory layout

```text
<VAPT_DATA_DIR>/
  instance.lock                    exclusive OS lock held for the process lifetime
  instance.json                    informational lease: pid, host, started_at, app_version
  storage.json                     { storage_version, created_at, created_by_app_version }
  settings/settings.json           safe settings (no secret values)
  control/kill_switch.json         { engaged, engaged_at, reason }
  audit/
    audit.jsonl                    current append-only audit log
    audit.000001.jsonl ...         rotated segments (read-only)
  index/
    projects.json                  DERIVED: project_id → name, status, updated_at
  jobs/
    spool/<scan_id>.json           queue entry (pointer + priority + enqueued_at)
    claims/<scan_id>.lock          per-job claim lock (OS lock)
  projects/<project_id>/
    project.json                   Project (incl. authorization, scope, scan_policy)
    scans/<scan_id>/
      scan.json                    ScanJob: canonical state, counters, scope snapshot + hash
      events.jsonl                 structured, redacted events (rotated by size)
      console.log                  concise human log (redacted, rotated)
      outputs/                     intermediate/partial outputs, tool output copies
    assets/<asset_id>.json
    findings/<finding_id>.json
    evidence/<evidence_id>.json    EvidenceMetadata
    evidence/<evidence_id>.bin     redacted excerpt / artifact (opaque name)
    imports/<import_id>/import.json
    imports/<import_id>/raw.bin    original upload (hash recorded; never executed)
    api-specs/<spec_id>/spec.json  + raw.bin
    reports/<report_id>/report.json + report.html + report.pdf
    index/                         DERIVED per-project indexes (findings, assets, scans)
  backups/
    migrations/<timestamp>/        automatic copies taken before schema migrations
  tmp/                             staging for uploads/exports; cleaned at startup
```

Canonical records are the single source of truth. Everything under `index/` is derived and disposable.

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
| Record lock | One canonical document | `<file>.lock` sidecar via a maintained library (`filelock`/`portalocker`, TBD-032) with a timeout (default 10 s) → typed `LockTimeout`. |
| Append lock | One JSONL file | Same mechanism. Held only for the duration of one append. |
| Job claim lock | One job | `jobs/claims/<scan_id>.lock`, held by the worker while running. A job whose `scan.json` says `running` but whose claim lock is acquirable is **stale** → `interrupted`. |

Lock ordering, to avoid deadlock: instance → project → scan → finding/asset/evidence → append logs. No operation takes a broader lock than it needs. There is no repository-wide write lock.

## 7. JSONL event and audit logs

- One JSON object per line, `\n`-terminated, UTF-8. Each line has `event_id`, `ts`, `schema_version`, `type`, `correlation_id`, plus type-specific safe fields.
- **Redaction happens before serialization** (central redactor, see [SCAN_SAFETY.md](SCAN_SAFETY.md) §8). Raw headers, cookies, and tokens never reach the writer.
- Append: open in append mode under the append lock, write the full line in one call, flush.
- **Rotation:** at 10 MiB (configurable) the current file is renamed to the next `NNNNNN` segment. Segments are read-only.
- **Corruption tolerance:** readers skip lines that fail to parse or validate, count them, and report `{ "corrupt_lines": n }`. A truncated final line (crash mid-append) is expected and handled the same way. One bad line never makes the log unreadable.
- **Reading:** paginated tail and offset reads. Never load an entire large log into memory.

## 8. Derived indexes

- Stored under `index/` with `{ "generated_at", "source_count", "storage_version", "entries": [...] }`.
- Updated after successful canonical writes (best effort). If an index is missing, unparsable, or its `source_count` disagrees with a directory scan, it is **rebuilt** from canonical files. The rebuild is logged.
- Indexes are never exported as authoritative and never restored from backups (they are regenerated).

## 9. Integrity checker (startup and on demand)

Checks and reports, without auto-deleting anything:

- Invalid JSON or schema-invalid canonical records (listed per project; other projects keep working).
- Dangling references: finding → evidence ID missing; evidence → `.bin` missing.
- Orphans: `.bin` files without metadata; scan output directories without `scan.json`.
- Stale jobs (§6) → marked `interrupted` (state change is audited).
- Index mismatch → rebuild.
- Leftover `.tmp` files → cleaned.
- Free disk space below threshold → warning.

The result is exposed through a diagnostics endpoint (Phase 01) and the Settings page (Phase 02).

## 10. Corruption recovery

1. A corrupt record is **reported**, not moved or deleted automatically (avoids data loss).
2. Operator actions (each audited): view the raw file (escaped), restore from the latest pre-migration backup or project archive, or **quarantine**, which moves the file to `projects/<id>/quarantine/<timestamp>/` and removes it from indexes.
3. A corrupt `project.json` makes only that project unavailable. The project list shows it as `corrupt` with a repair hint.
4. A corrupt `storage.json` or `settings.json` → the app starts in a read-only diagnostic mode with instructions. It is never silently re-initialized.

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

Single JSON record ≤ 5 MiB. Evidence excerpt ≤ 8 KiB. Upload ≤ 25 MiB. Archive expanded ≤ 250 MiB / 10,000 entries. JSON nesting ≤ 64. Each limit is configurable and enforced in `storage/` or the importer, not only in the UI.
