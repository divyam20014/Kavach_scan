# Project Backup & Restore — Module 10 / Module 2 (Phase 10)

> Code: `backend/app/backup/` (`safety.py`, `archive.py`), `backend/app/api/reports.py` (`/backup/export`, `/backup/preview`, `/backup/restore`). Frontend: `BackupRestoreCard` in `frontend/src/pages/SystemPages.tsx`.

## 1. Archive safety (`safety.py::safe_extract_all`)

Generalizes the Phase 08 single-file import-safety pattern (`app/imports/safety.py`) to a multi-file ZIP archive. Before any entry's content is inflated, every declared size and count in `zipfile.ZipFile(...).infolist()` is checked: archive byte cap (200 MiB), total expanded size (1 GiB), entry count (50,000) — a cheap early rejection for an obviously-oversized archive. Every entry is then read **incrementally** (`_read_entry_bounded`) with a hard cap enforced on the actual bytes produced (30 MiB generally, 10 MiB for `.json` entries) and on the running total across the whole archive — the authoritative bound, independent of what the (forgeable) declared-size header claims. A corrupt or tampered entry (a CRC mismatch during decompression) is caught and raised as `ArchiveSafetyError`, never an unhandled `zipfile.BadZipFile`. Member names are normalized and rejected if they contain a NUL byte, an absolute path, a drive letter (`C:/...`), or a `..`/`.` path segment. Symlink entries are detected and rejected via the ZIP external-attributes Unix mode bits. A member whose *content* itself starts with a nested ZIP's magic bytes (`PK\x03\x04`) is rejected — a nested archive is never transparently unpacked.

Phase 10 verification tested a hand-crafted size-forgery attempt directly against CPython's `zipfile` (patching an entry's declared uncompressed-size header to lie about its real size): the library's own `ZipExtFile` truncates output to the declared size rather than ignoring it, so a forged small declared size cannot by itself cause unbounded decompression. The genuine gap verification found and fixed was narrower — the missing exception handling around a corrupt/tampered entry (TBD-066).

## 2. What's in an archive, and what's deliberately excluded (TBD-065)

An exported archive contains: the project record, scans, findings, assets, evidence (metadata always; raw blob bytes only if `include_evidence_blobs=true`, an operator-visible export-time choice), and import artifacts (metadata + raw upload). A `manifest.json` records `schema_version`, `exported_at`, `app_version`, `storage_version`, `project_id`, `include_evidence_blobs`, per-collection record counts, and a SHA-256 checksum for every file in the archive.

**Generated report files (`report.html`/`report.pdf`) and job event/console logs are not included.** Reports are reproducibly derivable from the findings/assets/scans already in the archive (the same `build_report_data` call that produced them originally), so shipping rendered bytes would be redundant, driftable storage; job logs are operational/debugging detail, not VAPT assessment data, and can carry stale correlation IDs from a since-cancelled run.

## 3. Preview never writes

`preview_archive(repo, raw)` is read-only end to end: it runs `safe_extract_all`, parses and validates `manifest.json`, re-verifies every checksum, and checks whether `manifest.project_id` already exists in the target repository — but makes no `repo.create_*`/`repo.save_*` call under any circumstance. `tests/test_backup_archive.py::test_preview_never_writes_anything` asserts the target repository's project count is unchanged after a preview call, including a preview of an archive that *would* restore successfully.

## 4. Restore: explicit confirmation, no silent merge, no silent overwrite

`restore_archive(repo, raw, *, confirmed, overwrite=False)`:

1. Requires `confirmed=True` or raises `ValidationFailedError` (422) — a restore is never triggered by merely uploading/previewing a file.
2. Re-verifies every checksum in the manifest against the actual archive contents; a mismatch raises `ValidationFailedError` before anything is written.
3. **Verifies every record actually belongs to this archive's project** (added during Phase 10 verification, TBD-066): the storage layer writes each scan/finding/asset/evidence/import record to whatever `project_id` field *that record itself* carries, not to "the project named in the manifest" — so without this check, a crafted or corrupted archive could write a record into a *different, already-existing* project in the destination data directory. `_check_every_record_belongs_to_this_project` compares every record's declared `project_id` against the manifest's, and `_check_project_id_consistency` additionally confirms the manifest's `project_id` agrees with what `project.json` itself declares (closing a related gap: the already-exists/overwrite decision in step 4 is made against the manifest's `project_id`, which must therefore be trustworthy). Any mismatch raises `ValidationFailedError` before anything is written.
4. If the target repository already has a project with the archive's `project_id`:
   - `overwrite=False` (default): raises `ConflictError` (409). Nothing is written; existing data is untouched.
   - `overwrite=True`: the existing project is deleted first (`repo.delete_project`), then the archive is restored fresh.
5. Every record is re-validated through its real Pydantic model (`Project`, `ScanJob`, `Finding`, `Asset`, `EvidenceMetadata`, `ImportArtifact`) before being written — the archive's JSON shape is never trusted blindly, even though its checksum already matched. A shape mismatch (valid JSON, wrong/missing fields) is caught and turned into a clean `ValidationFailedError` (`_validate_record`), never a raw, unhandled `pydantic.ValidationError`.

`preview_archive` runs the same project-id consistency checks (surfaced via `checksum_mismatches` in its response) so an inconsistent archive is flagged before the operator ever gets to a restore decision — without writing anything.

## 5. No ID remapping (TBD-065)

Restore writes back the exact same `project_id`/`finding_id`/`asset_id`/etc. captured at export time — it does not generate new IDs or rewrite cross-references. This is sufficient and simplest for the documented acceptance scenario: **restoring into a clean, separate data directory**, where the same IDs can never collide with anything already present. `tests/test_backup_archive.py::test_export_preview_restore_round_trip_preserves_counts_and_evidence_links` proves this end to end by restoring into a genuinely separate `StorageRepository` pointed at a fresh temp directory and confirming finding/asset counts and evidence-to-finding links match exactly, including the raw evidence blob bytes.

Restoring into the *same* data root under the *same* `project_id` is handled by the overwrite-confirmation path above (replace, not merge) — there is no mechanism to merge an archive's records into an existing project's data under different IDs; that scenario was not part of this phase's acceptance criteria.

## 6. Downloads and the Settings UI

`GET /projects/{id}/backup/export` streams the archive with `Content-Disposition: attachment` and records `AuditAction.BACKUP_CREATED`. The `BackupRestoreCard` on the Settings page accepts a file, calls `/backup/preview` immediately, and shows the project name, record counts, any checksum mismatch (which disables the Restore button outright), any app/storage-version mismatch warning, and — if the project already exists in this data root — an explicit "Overwrite the existing project" checkbox that must be checked before Restore is enabled. `AuditAction.BACKUP_RESTORED` is recorded on a successful restore.
