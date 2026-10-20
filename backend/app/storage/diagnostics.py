"""Data-directory readiness diagnostics (API endpoint and `python -m app diagnose`)."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path
from typing import Literal

from pydantic import Field

from app.core.settings import RuntimeSettings
from app.models.common import ShortText, StrictModel, UtcDatetime, utc_now
from app.storage.errors import StorageError
from app.storage.locking import InstanceLock
from app.storage.migrations import STORAGE_VERSION
from app.storage.paths import display_path


class StorageDiagnostics(StrictModel):
    checked_at: UtcDatetime = Field(default_factory=utc_now)
    data_dir: ShortText  # home directory collapsed to "~"
    exists: bool
    initialized: bool
    writable: bool
    storage_version: int | None
    supported_storage_version: int = STORAGE_VERSION
    instance_lock: Literal["held_by_this_process", "held_by_another_process", "free", "unknown"]
    free_bytes: int | None
    total_bytes: int | None
    low_disk_space: bool
    warnings: list[ShortText] = Field(default_factory=list)
    ready: bool


def _writable_probe(root: Path) -> bool:
    probe = root / f".write-probe-{uuid.uuid4().hex[:12]}.tmp"
    try:
        fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"ok")
        os.close(fd)
        probe.unlink()
        return True
    except OSError:
        return False


def diagnose(root: Path, settings: RuntimeSettings, *, lock_held_here: bool) -> StorageDiagnostics:
    warnings: list[str] = []
    exists = root.is_dir()
    initialized = (root / "storage.json").is_file()
    version: int | None = None
    if initialized:
        # Local import: repository imports this package's siblings.
        from app.storage.repository import StorageRepository

        try:
            version = (
                StorageRepository(root, settings, read_only=True)
                .read_storage_meta()
                .storage_version
            )
        except StorageError as exc:
            warnings.append(exc.message)
    writable = exists and _writable_probe(root)
    if exists and not writable:
        warnings.append("Data directory is not writable")
    free = total = None
    if exists:
        usage = shutil.disk_usage(root)
        free, total = usage.free, usage.total
    low = free is not None and free < settings.disk_warning_bytes
    if low:
        warnings.append(
            f"Low disk space: {free} bytes free (threshold {settings.disk_warning_bytes})"
        )
    if lock_held_here:
        lock_state: Literal[
            "held_by_this_process", "held_by_another_process", "free", "unknown"
        ] = "held_by_this_process"
    elif exists:
        lock_state = "held_by_another_process" if InstanceLock.probe(root) == "held" else "free"
    else:
        lock_state = "unknown"
    if not exists:
        warnings.append("Data directory does not exist yet; it is created on first start")
    ready = exists and initialized and writable and version == STORAGE_VERSION
    return StorageDiagnostics(
        data_dir=display_path(root)[:500],
        exists=exists,
        initialized=initialized,
        writable=writable,
        storage_version=version,
        instance_lock=lock_state,
        free_bytes=free,
        total_bytes=total,
        low_disk_space=low,
        warnings=warnings,
        ready=ready,
    )
