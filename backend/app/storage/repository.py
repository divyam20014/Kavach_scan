"""StorageRepository — the single component that reads and writes the data root.

Routers, services and (future) scanners call this API; they never touch files.
Canonical records are validated JSON documents; derived indexes are disposable
and rebuilt from canonical files whenever they disagree. See
docs/STORAGE_FORMATS.md for layout, IDs, locking and recovery rules.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ValidationError

from app import __version__
from app.core.redaction import redact_text
from app.core.settings import RuntimeSettings
from app.models.asset import Asset
from app.models.audit import AuditAction
from app.models.common import (
    ANY_ID_RE,
    Page,
    Record,
    RecordError,
    Severity,
    StrictModel,
    UtcDatetime,
    is_valid_id,
    utc_now,
)
from app.models.cve_catalog import CveCatalogRecord
from app.models.evidence import MAX_EXCERPT_CHARS, EvidenceMetadata
from app.models.finding import Finding
from app.models.import_artifact import ImportArtifact
from app.models.project import Project
from app.models.report import ReportMetadata
from app.models.scan import ScanJob
from app.models.settings import AppSettings
from app.models.trivy_db import TrivyDbStatusRecord
from app.storage.atomic import (
    atomic_write_bytes,
    cleanup_temp_files,
    dumps_record,
    ensure_dir,
    parse_json_object,
    read_bytes_bounded,
)
from app.storage.audit import AuditLog
from app.storage.errors import (
    AlreadyExistsError,
    CorruptRecordError,
    DataRootError,
    InvalidRecordError,
    RecordNotFoundError,
    RecordTooLargeError,
    RevisionConflictError,
    StorageError,
    StorageVersionError,
    UnsafePathError,
)
from app.storage.jsonl import JsonlLog, TextLog
from app.storage.locking import ClaimLock, InstanceLock, exclusive
from app.storage.migrations import CURRENT_VERSIONS, STORAGE_VERSION, migrate
from app.storage.paths import SafePaths, is_link_like, resolve_data_root, validate_id

M = TypeVar("M", bound=Record)

LAYOUT_DIRS = (
    "projects",
    "index",
    "audit",
    "settings",
    "backups",
    "trash",
    "locks",
    "jobs",
    "control",
    "cve_catalog",
    "diagnostics",
)
JOB_SUBDIRS = ("spool", "claims")
MAX_BLOB_BYTES = 10 * 1024 * 1024
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # TBD-009
MAX_PAGE_SIZE = 500
_SEVERITY_RANK = {s.value: i for i, s in enumerate(Severity)}  # critical=0 ... informational=4
_OWN_ROOT_ENTRIES = {InstanceLock.LOCK_NAME, InstanceLock.INFO_NAME, ".instance.lock.lock"}


class KillSwitchState(StrictModel):
    engaged: bool = False
    changed_at: UtcDatetime | None = None
    reason: str = ""
    actor: str = "local-operator"


class SpoolEntry(StrictModel):
    scan_id: str
    project_id: str
    enqueued_at: UtcDatetime


class StorageMeta(StrictModel):
    storage_version: int
    created_at: UtcDatetime
    created_by_app_version: str


@dataclass(frozen=True)
class CollectionSpec(Generic[M]):
    kind: str
    model: type[M]
    id_field: str
    dirname: str
    nested_file: str | None  # None: <dir>/<id>.json; else <dir>/<id>/<nested_file>
    summary_fields: tuple[str, ...]
    sort_fields: tuple[str, ...]


SCANS = CollectionSpec(
    "scan",
    ScanJob,
    "scan_id",
    "scans",
    "scan.json",
    ("module", "state", "profile", "idempotency_key", "queued_at"),
    ("updated_at", "created_at", "queued_at"),
)
FINDINGS = CollectionSpec(
    "finding",
    Finding,
    "finding_id",
    "findings",
    None,
    ("severity", "confidence", "analyst_status", "scan_id", "title", "merged_into"),
    ("updated_at", "created_at", "severity", "title"),
)
ASSETS = CollectionSpec(
    "asset",
    Asset,
    "asset_id",
    "assets",
    None,
    ("asset_type", "scope_status", "confidence", "locator"),
    ("updated_at", "created_at", "last_seen", "locator"),
)
EVIDENCE = CollectionSpec(
    "evidence",
    EvidenceMetadata,
    "evidence_id",
    "evidence",
    None,
    ("evidence_type", "scan_id"),
    ("updated_at", "created_at"),
)
IMPORTS = CollectionSpec(
    "import",
    ImportArtifact,
    "import_id",
    "imports",
    "import.json",
    ("status", "source_type", "display_filename"),
    ("updated_at", "created_at", "uploaded_at"),
)
REPORTS = CollectionSpec(
    "report",
    ReportMetadata,
    "report_id",
    "reports",
    "report.json",
    ("title",),
    ("updated_at", "created_at"),
)
CHILD_COLLECTIONS: tuple[CollectionSpec[Any], ...] = (
    SCANS,
    FINDINGS,
    ASSETS,
    EVIDENCE,
    IMPORTS,
    REPORTS,
)
PROJECT_SORTS = ("updated_at", "created_at", "name")

Changes = dict[str, Any] | Callable[[Any], Any]


def _summarize_validation(exc: ValidationError) -> str:
    first = exc.errors()[0]
    loc = ".".join(str(p) for p in first.get("loc", ())) or "<root>"
    return f"{exc.error_count()} validation error(s); first at {loc}: {first.get('msg', '')}"[:480]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sort_key(field: str) -> Callable[[tuple[str, dict[str, Any]]], tuple[int, Any]]:
    def key(item: tuple[str, dict[str, Any]]) -> tuple[int, Any]:
        value = item[1].get(field)
        if field == "severity":
            value = _SEVERITY_RANK.get(str(value), 99)
        elif isinstance(value, str):
            value = value.casefold()
        return (value is None, value if value is not None else "")

    return key


class StorageRepository:
    def __init__(self, root: Path, settings: RuntimeSettings, *, read_only: bool = False) -> None:
        self.settings = settings
        self.read_only = read_only
        self.paths = SafePaths(root)
        self.root = self.paths.root
        self.instance_lock = InstanceLock(self.root)
        self.temp_files_removed = 0
        self.first_run = False
        self._audit: AuditLog | None = None

    # ------------------------------------------------------------------ lifecycle

    @classmethod
    def open(cls, settings: RuntimeSettings, *, root: Path | None = None) -> StorageRepository:
        repo = cls(root if root is not None else resolve_data_root(settings), settings)
        repo.initialize()
        return repo

    def __enter__(self) -> StorageRepository:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.instance_lock.release()

    def initialize(self) -> None:
        """First-run creation or validation of the data root; holds the instance lock."""
        if self.read_only:
            raise StorageError("initialize() is not available in read-only mode")
        if self.root.exists() and is_link_like(self.root) and not self.root.is_dir():
            raise DataRootError("Data directory is a dangling link")
        has_meta = (self.root / "storage.json").exists()
        if self.root.is_dir() and not has_meta:
            foreign = [e for e in os.listdir(self.root) if e not in _OWN_ROOT_ENTRIES]
            if foreign:
                raise DataRootError(
                    "Data directory is not empty and is not a VAPT Workbench data directory "
                    "(no storage.json). Choose an empty or dedicated directory."
                )
        ensure_dir(self.root, parents=True)
        self.instance_lock.acquire()
        try:
            self.first_run = not has_meta
            if self.first_run:
                meta = StorageMeta(
                    storage_version=STORAGE_VERSION,
                    created_at=utc_now(),
                    created_by_app_version=__version__,
                )
                atomic_write_bytes(
                    self.root / "storage.json", dumps_record(meta.model_dump(mode="json"))
                )
            else:
                self.read_storage_meta()
            for name in LAYOUT_DIRS:
                ensure_dir(self.paths.path(name))
            for name in JOB_SUBDIRS:
                ensure_dir(self.paths.path("jobs", name))
            # We hold the instance lock, so every temp file belongs to a dead process.
            self.temp_files_removed = cleanup_temp_files(self.root)
            self._purge_trash()
            if self.first_run:
                self.save_settings(AppSettings())
                self.audit.record(
                    AuditAction.STORAGE_INITIALIZED, metadata={"storage_version": STORAGE_VERSION}
                )
        except BaseException:
            self.instance_lock.release()
            raise

    def read_storage_meta(self) -> StorageMeta:
        path = self.root / "storage.json"
        try:
            obj = parse_json_object(read_bytes_bounded(path, 64 * 1024))
            meta = StorageMeta.model_validate(obj)
        except FileNotFoundError as exc:
            raise StorageVersionError("storage.json is missing") from exc
        except (StorageError, ValidationError) as exc:
            raise StorageVersionError(
                "storage.json is corrupt or invalid; refusing to start. Restore it from a backup "
                "(docs/STORAGE_FORMATS.md §10). The data directory was not modified."
            ) from exc
        if meta.storage_version > STORAGE_VERSION:
            raise StorageVersionError(
                f"Data directory uses storage version {meta.storage_version}; this build supports "
                f"up to {STORAGE_VERSION}. Upgrade the application; downgrades are not supported."
            )
        return meta

    @property
    def audit(self) -> AuditLog:
        if self._audit is None:
            self._audit = AuditLog(
                self.paths.path("audit"),
                rotate_bytes=self.settings.audit_rotate_bytes,
                lock_timeout=self.settings.lock_timeout_seconds,
                lock_root=self.root / "locks",
            )
        return self._audit

    def _lock(self, unit: Path) -> Any:
        # Central lock directory: acquiring a lock never creates directories inside
        # project trees (see locking.central_lock_path).
        return exclusive(unit, self.settings.lock_timeout_seconds, lock_root=self.root / "locks")

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        try:
            atomic_write_bytes(path, data)
        except FileNotFoundError as exc:  # parent removed concurrently (e.g. project deleted)
            raise RecordNotFoundError("Parent record no longer exists") from exc

    # ------------------------------------------------------------------ low-level I/O

    def _read_raw(self, path: Path) -> dict[str, Any]:
        try:
            data = read_bytes_bounded(path, self.settings.max_record_bytes)
        except FileNotFoundError as exc:
            raise RecordNotFoundError("Record not found") from exc
        return parse_json_object(data)

    def _read_model(self, path: Path, kind: str, model: type[BaseModel]) -> Any:
        obj, _ = migrate(kind, self._read_raw(path))
        try:
            return model.model_validate(obj)
        except ValidationError as exc:
            raise InvalidRecordError(_summarize_validation(exc)) from exc

    def _write_model(self, path: Path, obj: BaseModel) -> None:
        data = dumps_record(obj.model_dump(mode="json"))
        if len(data) > self.settings.max_record_bytes:
            raise RecordTooLargeError(f"Record exceeds {self.settings.max_record_bytes} bytes")
        self._atomic_write(path, data)

    @staticmethod
    def _revalidate(model: type[M], data: dict[str, Any]) -> M:
        try:
            return model.model_validate(data)
        except ValidationError as exc:
            raise InvalidRecordError(_summarize_validation(exc)) from exc

    def _apply_changes(
        self,
        model: type[M],
        current: M,
        changes: Changes,
        expected_revision: int | None,
        immutable: tuple[str, ...],
    ) -> M:
        if expected_revision is not None and current.revision != expected_revision:
            raise RevisionConflictError(
                f"Record was modified (revision {current.revision}, expected {expected_revision})"
            )
        if callable(changes):
            candidate = changes(current.model_copy(deep=True))
            data = candidate.model_dump(mode="json")
        else:
            data = current.model_dump(mode="json")
            data.update(changes)
        original = current.model_dump(mode="json")
        for field in (*immutable, "created_at", "schema_version"):
            data[field] = original[field]
        data["revision"] = current.revision + 1
        data["updated_at"] = utc_now().isoformat()
        return self._revalidate(model, data)

    # ------------------------------------------------------------------ projects

    def _project_dir(self, project_id: str) -> Path:
        return self.paths.path("projects", validate_id("project", project_id))

    def _project_file(self, project_id: str) -> Path:
        return self.paths.path("projects", validate_id("project", project_id), "project.json")

    def _require_project_writable(self, project_id: str) -> None:
        directory = self._project_dir(project_id)
        if not (directory / "project.json").is_file() or (directory / ".deleting").exists():
            raise RecordNotFoundError("Project not found")

    def create_project(self, project: Project) -> Project:
        project = self._revalidate(Project, project.model_dump(mode="json"))
        directory = self._project_dir(project.project_id)
        with self._lock(directory):
            if directory.exists():
                raise AlreadyExistsError("Project already exists")
            ensure_dir(directory)
            try:
                self._write_model(directory / "project.json", project)
            except BaseException:
                shutil.rmtree(directory, ignore_errors=True)
                raise
        self._projects_index_upsert(project)
        return project

    def get_project(self, project_id: str) -> Project:
        path = self._project_file(project_id)
        if (path.parent / ".deleting").exists():
            raise RecordNotFoundError("Project not found")
        return self._read_model(path, "project", Project)  # type: ignore[no-any-return]

    def update_project(
        self, project_id: str, changes: Changes, *, expected_revision: int | None = None
    ) -> Project:
        directory = self._project_dir(project_id)
        with self._lock(directory):
            current = self.get_project(project_id)
            updated = self._apply_changes(
                Project, current, changes, expected_revision, ("project_id",)
            )
            self._write_model(directory / "project.json", updated)
        self._projects_index_upsert(updated)
        return updated

    def delete_project(self, project_id: str) -> None:
        """Remove a project and everything under it, without ever following links."""
        directory = self._project_dir(project_id)
        with self._lock(directory):
            if not (directory / "project.json").exists():
                raise RecordNotFoundError("Project not found")
            self._assert_no_links(directory)
            atomic_write_bytes(directory / ".deleting", b"1\n")
            target = self.paths.path("trash", f"{project_id}-{time.time_ns()}")
            self._rename_with_retry(directory, target)
        self._projects_index_remove(project_id)
        self._rmtree(target)

    def list_projects(
        self,
        *,
        status: str | None = None,
        search: str | None = None,
        sort: str = "updated_at",
        descending: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> Page[Project]:
        self._check_paging(sort, PROJECT_SORTS, offset, limit)
        needle = (search or "").casefold().strip()
        for attempt in range(2):
            index, errors = self._ensure_projects_index()
            entries = [
                (pid, e)
                for pid, e in index["entries"].items()
                if (status is None or e.get("status") == status)
                and (
                    not needle
                    or needle in e.get("name", "").casefold()
                    or needle in e.get("client_name", "").casefold()
                )
            ]
            entries.sort(key=_sort_key(sort), reverse=descending)
            items, stale = self._load_page(
                entries[offset : offset + limit], self.get_project, errors
            )
            if stale and attempt == 0:
                self._rebuild_projects_index()
                continue
            return Page[Project](
                items=items, total=len(entries), offset=offset, limit=limit, errors=errors
            )
        raise StorageError("Index could not be stabilized")  # pragma: no cover

    # ------------------------------------------------------------------ children (generic)

    def _child_unit(self, spec: CollectionSpec[Any], project_id: str, record_id: str) -> Path:
        validate_id(spec.kind, record_id)
        base = ("projects", validate_id("project", project_id), spec.dirname)
        if spec.nested_file is None:
            return self.paths.path(*base, f"{record_id}.json")
        return self.paths.path(*base, record_id)

    def _child_file(self, spec: CollectionSpec[Any], project_id: str, record_id: str) -> Path:
        unit = self._child_unit(spec, project_id, record_id)
        return (
            unit
            if spec.nested_file is None
            else self.paths.path(*self._rel(unit), spec.nested_file)
        )

    def _rel(self, path: Path) -> tuple[str, ...]:
        return path.relative_to(self.root).parts

    def _prepare_child_dirs(self, spec: CollectionSpec[Any], project_id: str) -> None:
        self._require_project_writable(project_id)
        try:
            ensure_dir(self.paths.path("projects", project_id, spec.dirname))
        except FileNotFoundError as exc:  # project removed concurrently
            raise RecordNotFoundError("Project not found") from exc

    def _create_child(
        self, spec: CollectionSpec[M], record: M, *, blobs: dict[str, bytes] | None = None
    ) -> M:
        record = self._revalidate(spec.model, record.model_dump(mode="json"))
        project_id = record.project_id  # type: ignore[attr-defined]
        record_id = getattr(record, spec.id_field)
        unit = self._child_unit(spec, project_id, record_id)
        self._prepare_child_dirs(spec, project_id)
        with self._lock(unit):
            if unit.exists():
                raise AlreadyExistsError(f"{spec.kind} already exists")
            try:
                if spec.nested_file is not None:
                    ensure_dir(unit)
                for name, data in (blobs or {}).items():
                    self._atomic_write(self._blob_path(spec, project_id, record_id, name), data)
                self._write_model(self._child_file(spec, project_id, record_id), record)
            except FileNotFoundError as exc:  # collection/project removed concurrently
                self._remove_unit(spec, project_id, record_id, blobs or {})
                raise RecordNotFoundError("Project not found") from exc
            except BaseException:
                self._remove_unit(spec, project_id, record_id, blobs or {})
                raise
        self._child_index_upsert(spec, project_id, record)
        return record

    def _get_child(self, spec: CollectionSpec[M], project_id: str, record_id: str) -> M:
        path = self._child_file(spec, project_id, record_id)
        if (self._project_dir(project_id) / ".deleting").exists():
            raise RecordNotFoundError("Project not found")
        record = self._read_model(path, spec.kind, spec.model)
        if record.project_id != project_id or getattr(record, spec.id_field) != record_id:
            raise InvalidRecordError(f"{spec.kind} file does not match its location")
        return record  # type: ignore[no-any-return]

    def _update_child(
        self,
        spec: CollectionSpec[M],
        project_id: str,
        record_id: str,
        changes: Changes,
        expected_revision: int | None,
    ) -> M:
        unit = self._child_unit(spec, project_id, record_id)
        self._require_project_writable(project_id)
        with self._lock(unit):
            current = self._get_child(spec, project_id, record_id)
            updated = self._apply_changes(
                spec.model, current, changes, expected_revision, (spec.id_field, "project_id")
            )
            self._write_model(self._child_file(spec, project_id, record_id), updated)
        self._child_index_upsert(spec, project_id, updated)
        return updated

    def _delete_child(
        self,
        spec: CollectionSpec[Any],
        project_id: str,
        record_id: str,
        blobs: tuple[str, ...] = (),
    ) -> None:
        unit = self._child_unit(spec, project_id, record_id)
        self._require_project_writable(project_id)
        with self._lock(unit):
            if not self._child_file(spec, project_id, record_id).exists():
                raise RecordNotFoundError(f"{spec.kind} not found")
            self._remove_unit(spec, project_id, record_id, dict.fromkeys(blobs, b""))
        self._child_index_remove(spec, project_id, record_id)

    def _remove_unit(
        self, spec: CollectionSpec[Any], project_id: str, record_id: str, blobs: dict[str, bytes]
    ) -> None:
        unit = self._child_unit(spec, project_id, record_id)
        if spec.nested_file is not None:
            if unit.exists():
                self._assert_no_links(unit)
                self._rmtree(unit)
            return
        for name in blobs:
            self._blob_path(spec, project_id, record_id, name).unlink(missing_ok=True)
        unit.unlink(missing_ok=True)

    def _blob_path(
        self, spec: CollectionSpec[Any], project_id: str, record_id: str, name: str
    ) -> Path:
        if spec.nested_file is None:  # flat: <dir>/<id>.<name>
            return self.paths.path("projects", project_id, spec.dirname, f"{record_id}.{name}")
        return self.paths.path("projects", project_id, spec.dirname, record_id, name)

    def _list_child(
        self,
        spec: CollectionSpec[M],
        project_id: str,
        *,
        filters: dict[str, set[str] | None],
        sort: str,
        descending: bool,
        offset: int,
        limit: int,
    ) -> Page[M]:
        self._check_paging(sort, spec.sort_fields, offset, limit)
        self.get_project(project_id)  # 404 for unknown projects
        for attempt in range(2):
            index, errors = self._ensure_child_index(spec, project_id)
            entries = [
                (rid, e)
                for rid, e in index["entries"].items()
                if all(not allowed or str(e.get(f)) in allowed for f, allowed in filters.items())
            ]
            entries.sort(key=_sort_key(sort), reverse=descending)
            items, stale = self._load_page(
                entries[offset : offset + limit],
                lambda rid: self._get_child(spec, project_id, rid),
                errors,
                project_id,
            )
            if stale and attempt == 0:
                self._rebuild_child_index(spec, project_id)
                continue
            page: Page[M] = Page[Any](
                items=items, total=len(entries), offset=offset, limit=limit, errors=errors
            )
            return page
        raise StorageError("Index could not be stabilized")  # pragma: no cover

    @staticmethod
    def _check_paging(sort: str, allowed: tuple[str, ...], offset: int, limit: int) -> None:
        if sort not in allowed:
            raise InvalidRecordError(f"sort must be one of: {', '.join(allowed)}")
        if offset < 0 or not 1 <= limit <= MAX_PAGE_SIZE:
            raise InvalidRecordError(f"offset must be >= 0 and limit between 1 and {MAX_PAGE_SIZE}")

    @staticmethod
    def _load_page(
        entries: list[tuple[str, dict[str, Any]]],
        loader: Callable[[str], Any],
        errors: list[RecordError],
        project_id: str | None = None,
    ) -> tuple[list[Any], bool]:
        items: list[Any] = []
        for record_id, entry in entries:
            try:
                record = loader(record_id)
            except RecordNotFoundError:
                return items, True
            except StorageError as exc:
                errors.append(
                    RecordError(
                        record_id=record_id,
                        project_id=project_id,
                        kind=exc.code,
                        message=exc.message,
                    )
                )
                continue
            if record.revision != entry.get("revision"):
                return items, True
            items.append(record)
        return items, False

    # ------------------------------------------------------------------ public child API

    def create_scan(self, scan: ScanJob) -> ScanJob:
        return self._create_child(SCANS, scan)

    def get_scan(self, project_id: str, scan_id: str) -> ScanJob:
        return self._get_child(SCANS, project_id, scan_id)

    def update_scan(
        self,
        project_id: str,
        scan_id: str,
        changes: Changes,
        *,
        expected_revision: int | None = None,
    ) -> ScanJob:
        return self._update_child(SCANS, project_id, scan_id, changes, expected_revision)

    def list_scans(
        self,
        project_id: str,
        *,
        state: set[str] | None = None,
        module: set[str] | None = None,
        sort: str = "updated_at",
        descending: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> Page[ScanJob]:
        return self._list_child(
            SCANS,
            project_id,
            filters={"state": state, "module": module},
            sort=sort,
            descending=descending,
            offset=offset,
            limit=limit,
        )

    def create_finding(self, finding: Finding) -> Finding:
        return self._create_child(FINDINGS, finding)

    def get_finding(self, project_id: str, finding_id: str) -> Finding:
        return self._get_child(FINDINGS, project_id, finding_id)

    def update_finding(
        self,
        project_id: str,
        finding_id: str,
        changes: Changes,
        *,
        expected_revision: int | None = None,
    ) -> Finding:
        return self._update_child(FINDINGS, project_id, finding_id, changes, expected_revision)

    def delete_finding(self, project_id: str, finding_id: str) -> None:
        self._delete_child(FINDINGS, project_id, finding_id)

    def list_findings(
        self,
        project_id: str,
        *,
        severity: set[str] | None = None,
        confidence: set[str] | None = None,
        analyst_status: set[str] | None = None,
        scan_id: set[str] | None = None,
        sort: str = "updated_at",
        descending: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> Page[Finding]:
        return self._list_child(
            FINDINGS,
            project_id,
            filters={
                "severity": severity,
                "confidence": confidence,
                "analyst_status": analyst_status,
                "scan_id": scan_id,
            },
            sort=sort,
            descending=descending,
            offset=offset,
            limit=limit,
        )

    def create_asset(self, asset: Asset) -> Asset:
        return self._create_child(ASSETS, asset)

    def get_asset(self, project_id: str, asset_id: str) -> Asset:
        return self._get_child(ASSETS, project_id, asset_id)

    def update_asset(
        self,
        project_id: str,
        asset_id: str,
        changes: Changes,
        *,
        expected_revision: int | None = None,
    ) -> Asset:
        return self._update_child(ASSETS, project_id, asset_id, changes, expected_revision)

    def delete_asset(self, project_id: str, asset_id: str) -> None:
        self._delete_child(ASSETS, project_id, asset_id)

    def list_assets(
        self,
        project_id: str,
        *,
        asset_type: set[str] | None = None,
        scope_status: set[str] | None = None,
        sort: str = "updated_at",
        descending: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> Page[Asset]:
        return self._list_child(
            ASSETS,
            project_id,
            filters={"asset_type": asset_type, "scope_status": scope_status},
            sort=sort,
            descending=descending,
            offset=offset,
            limit=limit,
        )

    def save_evidence(
        self, evidence: EvidenceMetadata, blob: bytes | None = None
    ) -> EvidenceMetadata:
        """Store evidence metadata (+ optional blob). Excerpts are always redacted here."""
        limit = MAX_EXCERPT_CHARS - 32
        req = redact_text(evidence.request_excerpt, max_chars=limit)
        resp = redact_text(evidence.response_excerpt, max_chars=limit)
        update: dict[str, Any] = {
            "request_excerpt": req,
            "response_excerpt": resp,
            "excerpt_truncated": evidence.excerpt_truncated
            or req.endswith("[TRUNCATED]")
            or resp.endswith("[TRUNCATED]"),
            "has_blob": blob is not None,
            "blob_sha256": _sha256(blob) if blob is not None else None,
            "blob_size": len(blob) if blob is not None else None,
        }
        if blob is not None and len(blob) > MAX_BLOB_BYTES:
            raise RecordTooLargeError(f"Evidence blob exceeds {MAX_BLOB_BYTES} bytes")
        record = evidence.model_copy(update=update)
        return self._create_child(
            EVIDENCE, record, blobs={"bin": blob} if blob is not None else None
        )

    def get_evidence(self, project_id: str, evidence_id: str) -> EvidenceMetadata:
        return self._get_child(EVIDENCE, project_id, evidence_id)

    def read_evidence_blob(self, project_id: str, evidence_id: str) -> bytes:
        meta = self.get_evidence(project_id, evidence_id)
        if not meta.has_blob:
            raise RecordNotFoundError("Evidence has no blob")
        try:
            data = read_bytes_bounded(
                self._blob_path(EVIDENCE, project_id, evidence_id, "bin"), MAX_BLOB_BYTES
            )
        except FileNotFoundError as exc:
            raise CorruptRecordError("Evidence blob is missing") from exc
        if _sha256(data) != meta.blob_sha256:
            raise CorruptRecordError("Evidence blob hash mismatch")
        return data

    def delete_evidence(self, project_id: str, evidence_id: str) -> None:
        self._delete_child(EVIDENCE, project_id, evidence_id, blobs=("bin",))

    def list_evidence(
        self,
        project_id: str,
        *,
        evidence_type: set[str] | None = None,
        scan_id: set[str] | None = None,
        sort: str = "updated_at",
        descending: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> Page[EvidenceMetadata]:
        return self._list_child(
            EVIDENCE,
            project_id,
            filters={"evidence_type": evidence_type, "scan_id": scan_id},
            sort=sort,
            descending=descending,
            offset=offset,
            limit=limit,
        )

    def create_import(self, artifact: ImportArtifact, raw: bytes) -> ImportArtifact:
        if len(raw) > MAX_UPLOAD_BYTES:
            raise RecordTooLargeError(f"Upload exceeds {MAX_UPLOAD_BYTES} bytes")
        if len(raw) != artifact.size_bytes or _sha256(raw) != artifact.sha256:
            raise InvalidRecordError("Upload size/hash does not match the import metadata")
        return self._create_child(IMPORTS, artifact, blobs={"raw.bin": raw})

    def get_import(self, project_id: str, import_id: str) -> ImportArtifact:
        return self._get_child(IMPORTS, project_id, import_id)

    def read_import_raw(self, project_id: str, import_id: str) -> bytes:
        meta = self.get_import(project_id, import_id)
        try:
            data = read_bytes_bounded(
                self._blob_path(IMPORTS, project_id, import_id, "raw.bin"), MAX_UPLOAD_BYTES
            )
        except FileNotFoundError as exc:
            raise CorruptRecordError("Import upload is missing") from exc
        if _sha256(data) != meta.sha256:
            raise CorruptRecordError("Import upload hash mismatch")
        return data

    def update_import(
        self,
        project_id: str,
        import_id: str,
        changes: Changes,
        *,
        expected_revision: int | None = None,
    ) -> ImportArtifact:
        return self._update_child(IMPORTS, project_id, import_id, changes, expected_revision)

    def list_imports(
        self,
        project_id: str,
        *,
        status: set[str] | None = None,
        sort: str = "updated_at",
        descending: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> Page[ImportArtifact]:
        return self._list_child(
            IMPORTS,
            project_id,
            filters={"status": status},
            sort=sort,
            descending=descending,
            offset=offset,
            limit=limit,
        )

    def save_report_metadata(self, report: ReportMetadata) -> ReportMetadata:
        return self._create_child(REPORTS, report)

    def update_report_metadata(
        self,
        project_id: str,
        report_id: str,
        changes: Changes,
        *,
        expected_revision: int | None = None,
    ) -> ReportMetadata:
        return self._update_child(REPORTS, project_id, report_id, changes, expected_revision)

    def get_report_metadata(self, project_id: str, report_id: str) -> ReportMetadata:
        return self._get_child(REPORTS, project_id, report_id)

    def list_reports(
        self,
        project_id: str,
        *,
        sort: str = "updated_at",
        descending: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> Page[ReportMetadata]:
        return self._list_child(
            REPORTS,
            project_id,
            filters={},
            sort=sort,
            descending=descending,
            offset=offset,
            limit=limit,
        )

    _REPORT_FILE_NAMES = {
        "report.html",
        "report.pdf",
        "findings.json",
        "findings.csv",
        "assets.json",
        "assets.csv",
    }

    def write_report_file(self, project_id: str, report_id: str, name: str, data: bytes) -> str:
        """Atomically store one rendered report/export file next to its `report.json`
        metadata. `name` is restricted to the fixed set this module produces — never an
        operator-controlled path."""
        if name not in self._REPORT_FILE_NAMES:
            raise InvalidRecordError(f"unsupported report file name: {name!r}")
        if len(data) > MAX_BLOB_BYTES:
            raise RecordTooLargeError(f"Report file exceeds {MAX_BLOB_BYTES} bytes")
        path = self._blob_path(REPORTS, project_id, report_id, name)
        self._atomic_write(path, data)
        return hashlib.sha256(data).hexdigest()

    def read_report_file(self, project_id: str, report_id: str, name: str) -> bytes:
        if name not in self._REPORT_FILE_NAMES:
            raise InvalidRecordError(f"unsupported report file name: {name!r}")
        path = self._blob_path(REPORTS, project_id, report_id, name)
        try:
            return read_bytes_bounded(path, MAX_BLOB_BYTES)
        except FileNotFoundError as exc:
            raise RecordNotFoundError("Report file not found") from exc

    # ------------------------------------------------------------------ job storage (Phase 04)

    def scan_dir(self, project_id: str, scan_id: str) -> Path:
        return self._child_unit(SCANS, project_id, scan_id)

    def scan_work_dir(self, project_id: str, scan_id: str) -> Path:
        """Per-scan working directory for tool output (created on demand, inside the data root)."""
        directory = self.paths.path(
            "projects", project_id, "scans", validate_id("scan", scan_id), "work"
        )
        try:
            ensure_dir(directory)
        except FileNotFoundError as exc:
            raise RecordNotFoundError("Scan not found") from exc
        return directory

    def scan_temp_dir(self, project_id: str, scan_id: str) -> Path:
        """Per-scan temp directory handed to subprocesses as TEMP/TMP/TMPDIR."""
        directory = self.scan_work_dir(project_id, scan_id) / "tmp"
        ensure_dir(directory)
        return directory

    def scan_work_subdir(self, project_id: str, scan_id: str, name: str) -> Path:
        """A named subdirectory inside the scan's work dir (created on demand), for a tool
        that needs its own directory rather than a single output file -- e.g. ZAP's `-dir`
        home directory and its report output directory. `name` is always a fixed literal
        chosen by the calling runner, never operator input."""
        directory = self.paths.path(
            "projects", project_id, "scans", validate_id("scan", scan_id), "work", name
        )
        ensure_dir(directory, parents=True)
        return directory

    def diagnostics_temp_dir(self) -> Path:
        """Scratch directory for the integrations self-test (Phase 11): running a tool's
        `--version` is not tied to any scan or project, but `run_process` still requires a
        real working/temp directory handed to the subprocess."""
        directory = self.paths.path("diagnostics", "tmp")
        ensure_dir(directory)
        return directory

    def trivy_db_dir(self) -> Path:
        """Trivy's own vulnerability database cache (roadmap Phase 2, TBD-087) -- shared
        across every project/scan, never per-project, since it is reference data about
        known vulnerabilities, not scan output. Always passed as Trivy's own `--cache-dir`
        so it is never written to Trivy's machine-wide default location outside the data
        root (confirmed directly during TBD-086's live verification)."""
        directory = self.paths.path("diagnostics", "trivy_db")
        ensure_dir(directory)
        return directory

    def _trivy_db_status_path(self) -> Path:
        return self.paths.path("diagnostics", "trivy_db_status.json")

    def get_trivy_db_status(self) -> TrivyDbStatusRecord | None:
        """`None` means the operator has never explicitly triggered the download -- the
        same "absence is the honest signal" shape `get_cve_catalog()` already uses."""
        path = self._trivy_db_status_path()
        if not path.exists():
            return None
        return self._read_model(path, "trivy_db_status", TrivyDbStatusRecord)  # type: ignore[no-any-return]

    def save_trivy_db_status(self, record: TrivyDbStatusRecord) -> TrivyDbStatusRecord:
        path = self._trivy_db_status_path()
        with self._lock(path):
            current = self.get_trivy_db_status()
            if current is not None:
                record = record.model_copy(update={"revision": current.revision + 1})
            self._write_model(path, record)
        return record

    def delete_trivy_db_status(self) -> None:
        path = self._trivy_db_status_path()
        with self._lock(path):
            path.unlink(missing_ok=True)

    def read_scan_output(
        self, project_id: str, scan_id: str, name: str, *, max_bytes: int = 8 * 1024 * 1024
    ) -> bytes:
        """Read a scan output written by `write_scan_output` (bounded; validated name)."""
        path = self.paths.path("projects", project_id, "scans", scan_id, "work", name)
        try:
            with open(path, "rb") as fh:
                data = fh.read(max_bytes + 1)
        except FileNotFoundError as exc:
            raise RecordNotFoundError("Scan output not found") from exc
        if len(data) > max_bytes:
            raise RecordTooLargeError(f"Scan output exceeds {max_bytes} bytes")
        return data

    def read_scan_work_file(
        self,
        project_id: str,
        scan_id: str,
        *relative_parts: str,
        max_bytes: int = 8 * 1024 * 1024,
    ) -> bytes:
        """Like `read_scan_output`, but for a file inside a named work subdirectory (see
        `scan_work_subdir`) rather than directly in the flat work dir -- e.g. a report a
        tool wrote into its own output directory."""
        path = self.paths.path(
            "projects", project_id, "scans", validate_id("scan", scan_id), "work", *relative_parts
        )
        try:
            with open(path, "rb") as fh:
                data = fh.read(max_bytes + 1)
        except FileNotFoundError as exc:
            raise RecordNotFoundError("Scan output not found") from exc
        if len(data) > max_bytes:
            raise RecordTooLargeError(f"Scan output exceeds {max_bytes} bytes")
        return data

    def scan_events(self, project_id: str, scan_id: str) -> JsonlLog:
        return JsonlLog(
            self.scan_dir(project_id, scan_id),
            "events",
            rotate_bytes=self.settings.audit_rotate_bytes,
            lock_timeout=self.settings.lock_timeout_seconds,
            lock_root=self.root / "locks",
        )

    def scan_console(self, project_id: str, scan_id: str) -> TextLog:
        return TextLog(
            self.scan_dir(project_id, scan_id),
            "console",
            rotate_bytes=self.settings.audit_rotate_bytes,
            lock_timeout=self.settings.lock_timeout_seconds,
            lock_root=self.root / "locks",
        )

    def write_scan_output(self, project_id: str, scan_id: str, name: str, data: bytes) -> str:
        """Atomically store a scan output file in the scan's work dir; returns 'work/<name>'."""
        if len(data) > MAX_BLOB_BYTES:
            raise RecordTooLargeError(f"Scan output exceeds {MAX_BLOB_BYTES} bytes")
        self.scan_work_dir(project_id, scan_id)
        path = self.paths.path("projects", project_id, "scans", scan_id, "work", name)
        self._atomic_write(path, data)
        return f"work/{name}"

    def _spool_path(self, scan_id: str) -> Path:
        return self.paths.path("jobs", "spool", f"{validate_id('scan', scan_id)}.json")

    def spool_add(self, project_id: str, scan_id: str) -> SpoolEntry:
        entry = SpoolEntry(
            scan_id=validate_id("scan", scan_id),
            project_id=validate_id("project", project_id),
            enqueued_at=utc_now(),
        )
        self._atomic_write(self._spool_path(scan_id), dumps_record(entry.model_dump(mode="json")))
        return entry

    def spool_remove(self, scan_id: str) -> None:
        self._spool_path(scan_id).unlink(missing_ok=True)

    def spool_entries(self) -> list[SpoolEntry]:
        """Valid spool entries, oldest first; corrupt ones are dropped (scan.json is canonical)."""
        out: list[SpoolEntry] = []
        directory = self.paths.path("jobs", "spool")
        for entry in os.scandir(directory):
            if entry.name.startswith(".") or not entry.name.endswith(".json") or entry.is_symlink():
                continue
            path = Path(entry.path)
            try:
                out.append(SpoolEntry.model_validate(self._read_raw(path)))
            except (StorageError, ValidationError):
                path.unlink(missing_ok=True)
        return sorted(out, key=lambda e: (e.enqueued_at, e.scan_id))

    def claim_lock(self, scan_id: str) -> ClaimLock:
        return ClaimLock(self.paths.path("jobs", "claims", f"{validate_id('scan', scan_id)}.lock"))

    def get_kill_switch(self) -> KillSwitchState:
        path = self.paths.path("control", "kill_switch.json")
        if not path.exists():
            return KillSwitchState()
        try:
            return KillSwitchState.model_validate(self._read_raw(path))
        except (StorageError, ValidationError):
            # Fail safe: an unreadable kill-switch file is treated as ENGAGED.
            return KillSwitchState(
                engaged=True, reason="kill_switch.json is unreadable; treated as engaged"
            )

    def set_kill_switch(
        self, engaged: bool, reason: str, actor: str = "local-operator"
    ) -> KillSwitchState:
        state = KillSwitchState(
            engaged=engaged, changed_at=utc_now(), reason=reason[:500], actor=actor
        )
        path = self.paths.path("control", "kill_switch.json")
        with self._lock(path):
            self._write_model(path, state)
        return state

    def all_scan_summaries(self) -> list[tuple[str, str, dict[str, Any]]]:
        """(project_id, scan_id, summary) for every readable scan in every project."""
        rows: list[tuple[str, str, dict[str, Any]]] = []
        for pid in sorted(self.project_summaries()[0]):
            try:
                entries, _ = self.summaries("scan", pid)
            except StorageError:
                continue
            rows.extend((pid, sid, e) for sid, e in entries.items())
        return rows

    # ------------------------------------------------------------------ cross-project reads

    def _spec(self, kind: str) -> CollectionSpec[Any]:
        for spec in CHILD_COLLECTIONS:
            if spec.kind == kind:
                return spec
        raise InvalidRecordError(f"Unknown record kind {kind!r}")

    def summaries(
        self, kind: str, project_id: str
    ) -> tuple[dict[str, dict[str, Any]], list[RecordError]]:
        """Index summaries (id -> summary fields + revision) for one project's collection.

        Cheap aggregation input for dashboards; values come from canonical records via the
        derived index (rebuilt automatically when it disagrees with the files on disk)."""
        spec = self._spec(kind)
        self.get_project(project_id)
        index, errors = self._ensure_child_index(spec, project_id)
        return dict(index["entries"]), errors

    def project_summaries(self) -> tuple[dict[str, dict[str, Any]], list[RecordError]]:
        index, errors = self._ensure_projects_index()
        return dict(index["entries"]), errors

    def list_across_projects(
        self,
        kind: str,
        *,
        project_id: str | None = None,
        filters: dict[str, set[str] | None] | None = None,
        sort: str = "updated_at",
        descending: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> Page[Any]:
        """Filtered, sorted, paginated listing of one record kind over all (or one) projects."""
        spec = self._spec(kind)
        self._check_paging(sort, spec.sort_fields, offset, limit)
        filters = filters or {}
        project_ids = (
            [validate_id("project", project_id)]
            if project_id
            else sorted(self.project_summaries()[0])
        )
        rows: list[tuple[str, str, dict[str, Any]]] = []
        errors: list[RecordError] = []
        for pid in project_ids:
            try:
                entries, errs = self.summaries(kind, pid)
            except RecordNotFoundError:
                continue
            errors.extend(errs)
            for rid, entry in entries.items():
                if all(
                    not allowed or str(entry.get(f)) in allowed for f, allowed in filters.items()
                ):
                    rows.append((pid, rid, entry))
        key = _sort_key(sort)
        rows.sort(key=lambda r: key((r[1], r[2])), reverse=descending)
        items: list[Any] = []
        for pid, rid, _ in rows[offset : offset + limit]:
            try:
                items.append(self._get_child(spec, pid, rid))
            except StorageError as exc:
                errors.append(
                    RecordError(record_id=rid, project_id=pid, kind=exc.code, message=exc.message)
                )
        page: Page[Any] = Page[Any](
            items=items, total=len(rows), offset=offset, limit=limit, errors=errors
        )
        return page

    # ------------------------------------------------------------------ settings

    def get_settings(self) -> AppSettings:
        path = self.paths.path("settings", "settings.json")
        if not path.exists():
            return AppSettings()
        return self._read_model(path, "settings", AppSettings)  # type: ignore[no-any-return]

    def save_settings(
        self, settings: AppSettings, *, expected_revision: int | None = None
    ) -> AppSettings:
        path = self.paths.path("settings", "settings.json")
        with self._lock(path):
            if path.exists():
                current = self.get_settings()
                if expected_revision is not None and current.revision != expected_revision:
                    raise RevisionConflictError("Settings were modified concurrently")
                data = settings.model_dump(mode="json") | {
                    "revision": current.revision + 1,
                    "updated_at": utc_now().isoformat(),
                }
                settings = AppSettings.model_validate(data)
            self._write_model(path, settings)
        return settings

    # ------------------------------------------------------------------ CVE catalog (Phase 11)

    def _cve_catalog_path(self) -> Path:
        return self.paths.path("cve_catalog", "catalog.json")

    def get_cve_catalog(self) -> CveCatalogRecord | None:
        path = self._cve_catalog_path()
        if not path.exists():
            return None
        return self._read_model(path, "cve_catalog", CveCatalogRecord)  # type: ignore[no-any-return]

    def save_cve_catalog(self, record: CveCatalogRecord) -> CveCatalogRecord:
        path = self._cve_catalog_path()
        with self._lock(path):
            current = self.get_cve_catalog()
            if current is not None:
                record = record.model_copy(update={"revision": current.revision + 1})
            self._write_model(path, record)
        return record

    def delete_cve_catalog(self) -> None:
        path = self._cve_catalog_path()
        with self._lock(path):
            path.unlink(missing_ok=True)

    # ------------------------------------------------------------------ indexes

    def _projects_index_path(self) -> Path:
        return self.paths.path("index", "projects.json")

    def _child_index_path(self, spec: CollectionSpec[Any], project_id: str) -> Path:
        return self.paths.path("projects", project_id, "index", f"{spec.dirname}.json")

    @staticmethod
    def _summary(record: BaseModel, fields: tuple[str, ...]) -> dict[str, Any]:
        data = record.model_dump(mode="json")
        keys = {"revision", "created_at", "updated_at", *fields}
        return {k: data.get(k) for k in keys}

    def _read_index(self, path: Path, kind: str) -> dict[str, Any] | None:
        try:
            idx = self._read_raw(path)
        except (RecordNotFoundError, CorruptRecordError, RecordTooLargeError):
            return None
        if (
            idx.get("kind") != kind
            or idx.get("storage_version") != STORAGE_VERSION
            or not isinstance(idx.get("entries"), dict)
            or not isinstance(idx.get("invalid"), dict)
        ):
            return None
        return idx

    def _write_index(
        self, path: Path, kind: str, entries: dict[str, Any], invalid: dict[str, str]
    ) -> dict[str, Any]:
        index = {
            "kind": kind,
            "storage_version": STORAGE_VERSION,
            "generated_at": utc_now().isoformat(),
            "entries": entries,
            "invalid": invalid,
        }
        atomic_write_bytes(path, dumps_record(index))
        return index

    def _scan_ids(self, directory: Path, kind: str, *, files: bool) -> set[str]:
        ids: set[str] = set()
        if not directory.is_dir():
            return ids
        for entry in os.scandir(directory):
            if entry.name.startswith(".") or entry.is_symlink() or entry.is_junction():
                continue
            name = entry.name[:-5] if files and entry.name.endswith(".json") else entry.name
            if files != entry.is_file(follow_symlinks=False):
                continue
            if is_valid_id(kind, name):
                ids.add(name)
        return ids

    def _project_ids(self) -> set[str]:
        return self._scan_ids(self.paths.path("projects"), "project", files=False)

    def _child_ids(self, spec: CollectionSpec[Any], project_id: str) -> set[str]:
        directory = self.paths.path("projects", project_id, spec.dirname)
        return self._scan_ids(directory, spec.kind, files=spec.nested_file is None)

    def _rebuild_projects_index(self) -> tuple[dict[str, Any], list[RecordError]]:
        entries: dict[str, Any] = {}
        invalid: dict[str, str] = {}
        errors: list[RecordError] = []
        for pid in sorted(self._project_ids()):
            try:
                entries[pid] = self._summary(
                    self.get_project(pid), ("name", "client_name", "status")
                )
            except StorageError as exc:
                invalid[pid] = exc.code
                errors.append(
                    RecordError(record_id=pid, project_id=pid, kind=exc.code, message=exc.message)
                )
        path = self._projects_index_path()
        with self._lock(path):
            index = self._write_index(path, "project", entries, invalid)
        return index, errors

    def _ensure_projects_index(self) -> tuple[dict[str, Any], list[RecordError]]:
        index = self._read_index(self._projects_index_path(), "project")
        if index is None or set(index["entries"]) | set(index["invalid"]) != self._project_ids():
            return self._rebuild_projects_index()
        errors = [
            RecordError(
                record_id=p, project_id=p, kind=k, message="Project record could not be loaded"
            )
            for p, k in index["invalid"].items()
        ]
        return index, errors

    def _projects_index_upsert(self, project: Project) -> None:
        self._index_mutate(
            self._projects_index_path(),
            "project",
            lambda idx: idx["entries"].__setitem__(
                project.project_id, self._summary(project, ("name", "client_name", "status"))
            ),
        )

    def _projects_index_remove(self, project_id: str) -> None:
        def drop(idx: dict[str, Any]) -> None:
            idx["entries"].pop(project_id, None)
            idx["invalid"].pop(project_id, None)

        self._index_mutate(self._projects_index_path(), "project", drop)

    def _rebuild_child_index(
        self, spec: CollectionSpec[Any], project_id: str
    ) -> tuple[dict[str, Any], list[RecordError]]:
        entries: dict[str, Any] = {}
        invalid: dict[str, str] = {}
        errors: list[RecordError] = []
        for rid in sorted(self._child_ids(spec, project_id)):
            try:
                entries[rid] = self._summary(
                    self._get_child(spec, project_id, rid), spec.summary_fields
                )
            except StorageError as exc:
                invalid[rid] = exc.code
                errors.append(
                    RecordError(
                        record_id=rid, project_id=project_id, kind=exc.code, message=exc.message
                    )
                )
        path = self._child_index_path(spec, project_id)
        ensure_dir(path.parent)
        with self._lock(path):
            index = self._write_index(path, spec.kind, entries, invalid)
        return index, errors

    def _ensure_child_index(
        self, spec: CollectionSpec[Any], project_id: str
    ) -> tuple[dict[str, Any], list[RecordError]]:
        index = self._read_index(self._child_index_path(spec, project_id), spec.kind)
        if index is None or set(index["entries"]) | set(index["invalid"]) != self._child_ids(
            spec, project_id
        ):
            return self._rebuild_child_index(spec, project_id)
        errors = [
            RecordError(
                record_id=r,
                project_id=project_id,
                kind=k,
                message=f"{spec.kind} record could not be loaded",
            )
            for r, k in index["invalid"].items()
        ]
        return index, errors

    def _child_index_upsert(
        self, spec: CollectionSpec[Any], project_id: str, record: BaseModel
    ) -> None:
        rid = getattr(record, spec.id_field)
        self._index_mutate(
            self._child_index_path(spec, project_id),
            spec.kind,
            lambda idx: (
                idx["entries"].__setitem__(rid, self._summary(record, spec.summary_fields)),
                idx["invalid"].pop(rid, None),
            ),
        )

    def _child_index_remove(
        self, spec: CollectionSpec[Any], project_id: str, record_id: str
    ) -> None:
        def drop(idx: dict[str, Any]) -> None:
            idx["entries"].pop(record_id, None)
            idx["invalid"].pop(record_id, None)

        self._index_mutate(self._child_index_path(spec, project_id), spec.kind, drop)

    def _index_mutate(self, path: Path, kind: str, mutate: Callable[[dict[str, Any]], Any]) -> None:
        """Best-effort incremental index update. A missing/corrupt index is left for the
        next read to rebuild; list() also detects stale entries by revision."""
        if not path.parent.is_dir():
            return
        try:
            with self._lock(path):
                index = self._read_index(path, kind)
                if index is None:
                    return
                mutate(index)
                self._write_index(path, kind, index["entries"], index["invalid"])
        except (StorageError, FileNotFoundError):
            path.unlink(missing_ok=True)  # force a rebuild rather than serve a wrong index

    def rebuild_all_indexes(self) -> int:
        count = 1
        self._rebuild_projects_index()
        for pid in self._project_ids():
            if not (self.paths.path("projects", pid, "project.json")).is_file():
                continue
            for spec in CHILD_COLLECTIONS:
                if self.paths.path("projects", pid, spec.dirname).is_dir():
                    self._rebuild_child_index(spec, pid)
                    count += 1
        return count

    # ------------------------------------------------------------------ migrations

    def iter_canonical_files(self) -> Iterator[tuple[str, Path]]:
        """(kind, path) for every canonical document, skipping links and dotfiles."""
        settings = self.paths.path("settings", "settings.json")
        if settings.is_file():
            yield "settings", settings
        for pid in sorted(self._project_ids()):
            project_file = self.paths.path("projects", pid, "project.json")
            if project_file.is_file() and not is_link_like(project_file):
                yield "project", project_file
            for spec in CHILD_COLLECTIONS:
                for rid in sorted(self._child_ids(spec, pid)):
                    path = self._child_file(spec, pid, rid)
                    if path.is_file() and not is_link_like(path):
                        yield spec.kind, path

    def migrate_all(self) -> int:
        """Persist pending schema migrations, backing up each original first."""
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        migrated = 0
        for kind, path in self.iter_canonical_files():
            with self._lock(path):
                original = read_bytes_bounded(path, self.settings.max_record_bytes)
                obj, changed = migrate(kind, parse_json_object(original))
                if not changed:
                    continue
                backup = self.paths.path("backups", "migrations", stamp, *self._rel(path))
                ensure_dir(backup.parent, parents=True)
                atomic_write_bytes(backup, original)
                try:
                    upgraded = _MODELS[kind].model_validate(obj)
                except ValidationError as exc:
                    raise InvalidRecordError(_summarize_validation(exc)) from exc
                self._write_model(path, upgraded)
                migrated += 1
        if migrated:
            self.audit.record(
                AuditAction.STORAGE_MIGRATED, metadata={"records": migrated, "backup": stamp}
            )
            self.rebuild_all_indexes()
        return migrated

    # ------------------------------------------------------------------ filesystem safety helpers

    def _assert_no_links(self, directory: Path) -> None:
        for dirpath, dirnames, filenames in os.walk(directory, followlinks=False):
            base = Path(dirpath)
            for name in (*dirnames, *filenames):
                if is_link_like(base / name):
                    raise UnsafePathError("Refusing to delete: a symlink or junction exists inside")

    @staticmethod
    def _rename_with_retry(src: Path, dst: Path, attempts: int = 20) -> None:
        delay = 0.01
        for i in range(attempts):
            try:
                os.replace(src, dst)
                return
            except PermissionError as exc:  # Windows: a handle inside is still open
                if i == attempts - 1:
                    raise StorageError("Project is busy; retry the deletion") from exc
                time.sleep(delay)
                delay = min(delay * 2, 0.25)

    @staticmethod
    def _rmtree(path: Path) -> None:
        def on_error(func: Callable[..., Any], target: str, _exc: BaseException) -> None:
            os.chmod(target, stat.S_IWRITE)
            func(target)

        if path.exists():
            shutil.rmtree(path, onexc=on_error)

    @staticmethod
    def _remove_link(path: Path) -> None:
        try:
            path.unlink()
        except (PermissionError, IsADirectoryError):
            os.rmdir(path)  # Windows directory symlink/junction: rmdir removes only the link

    def _purge_trash(self) -> None:
        trash = self.paths.path("trash")
        for entry in os.scandir(trash):
            target = Path(entry.path)
            if entry.is_symlink() or entry.is_junction():
                self._remove_link(target)  # removes the link only, never its target
            elif entry.is_dir(follow_symlinks=False):
                self._assert_no_links(target)
                self._rmtree(target)
            else:
                target.unlink()


_MODELS: dict[str, type[BaseModel]] = {
    "project": Project,
    "scan": ScanJob,
    "asset": Asset,
    "finding": Finding,
    "evidence": EvidenceMetadata,
    "import": ImportArtifact,
    "report": ReportMetadata,
    "settings": AppSettings,
    "cve_catalog": CveCatalogRecord,
    "trivy_db_status": TrivyDbStatusRecord,
}
assert set(_MODELS) | {"audit"} == set(CURRENT_VERSIONS)  # noqa: S101 - import-time consistency check
ID_PATTERN = ANY_ID_RE
RecordKind = Literal[
    "project", "scan", "asset", "finding", "evidence", "import", "report", "settings"
]
