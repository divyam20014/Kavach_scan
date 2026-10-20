"""Cross-process locks (TBD-032: `filelock`, exclusive OS locks only).

This is the ONLY module allowed to import `filelock`. Rules enforced here:
- `fallback_to_soft=False`: never degrade to a SoftFileLock, which survives crashes.
- No `ReadWriteLock` (SQLite-backed in filelock 4.x; violates the no-database rule).
- Lock files are dot-prefixed sidecars; the OS releases them when a process dies, so
  a crash cannot leave a permanently stale lock. A leftover lock *file* is harmless.
Single host only: OS file locks do not coordinate across machines or network shares.

Two-level locking: threads of this process first queue on an in-process mutex per
lock path, and only the winner contends for the OS file lock. Measured on Windows 11
(8 threads x 200 locked updates): file lock alone ~31 ms/op from threads polling the
OS lock; two-level ~14 ms/op, of which ~12 ms is the file I/O itself. See TBD-032.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from filelock import FileLock, Timeout

from app import __version__
from app.storage.atomic import atomic_write_bytes
from app.storage.errors import InstanceLockedError, LockTimeoutError

POLL_INTERVAL_SECONDS = 0.005  # TBD-032 obligation: default 0.05 s is coarse for record locks

_registry_guard = threading.Lock()
_mutexes: dict[str, tuple[threading.Lock, int]] = {}


def _checkout_mutex(key: str) -> threading.Lock:
    with _registry_guard:
        mutex, refs = _mutexes.get(key, (threading.Lock(), 0))
        _mutexes[key] = (mutex, refs + 1)
        return mutex


def _return_mutex(key: str) -> None:
    with _registry_guard:
        mutex, refs = _mutexes[key]
        if refs <= 1:
            del _mutexes[key]
        else:
            _mutexes[key] = (mutex, refs - 1)


def _new_lock(lock_path: Path, timeout: float) -> FileLock:
    return FileLock(
        str(lock_path),
        timeout=timeout,
        thread_local=False,
        fallback_to_soft=False,
        poll_interval=POLL_INTERVAL_SECONDS,
    )


def sidecar_lock_path(unit: Path) -> Path:
    """Lock file for a record file or record directory: `.<name>.lock` next to it."""
    return unit.parent / f".{unit.name}.lock"


def central_lock_path(lock_root: Path, unit: Path) -> Path:
    """Lock file in a dedicated directory, named by a hash of the unit path.

    filelock creates missing parent directories for its lock file. With sidecar locks a
    writer racing a project deletion could recreate `projects/<id>/...`; central locks
    never create anything inside record directories, and their open handles never block
    renaming a project directory on Windows.
    """
    digest = hashlib.sha256(os.path.normcase(str(unit)).encode("utf-8")).hexdigest()
    return lock_root / digest[:2] / f"{digest}.lock"


@contextmanager
def exclusive(unit: Path, timeout: float, *, lock_root: Path | None = None) -> Iterator[None]:
    """Exclusive lock on a record unit, across threads and processes. Not re-entrant:
    a nested acquire of the same unit times out with LockTimeoutError (no deadlock)."""
    lock_path = sidecar_lock_path(unit) if lock_root is None else central_lock_path(lock_root, unit)
    key = os.path.normcase(str(lock_path))
    deadline = time.monotonic() + timeout
    mutex = _checkout_mutex(key)
    try:
        if not mutex.acquire(timeout=timeout):
            raise LockTimeoutError(f"Timed out after {timeout}s waiting for a record lock")
        try:
            remaining = max(0.0, deadline - time.monotonic())
            file_lock = _new_lock(lock_path, remaining)
            try:
                file_lock.acquire()
            except Timeout as exc:
                raise LockTimeoutError(
                    f"Timed out after {timeout}s waiting for a record lock"
                ) from exc
            try:
                yield
            finally:
                file_lock.release()
        finally:
            mutex.release()
    finally:
        _return_mutex(key)


class InstanceLock:
    """Exclusive lease on a data root for the life of the process."""

    LOCK_NAME = "instance.lock"
    INFO_NAME = "instance.json"

    def __init__(self, root: Path) -> None:
        self.root = root
        self._lock = _new_lock(root / self.LOCK_NAME, timeout=0)

    @property
    def held(self) -> bool:
        return self._lock.is_locked

    def acquire(self) -> None:
        try:
            self._lock.acquire(timeout=0)
        except Timeout as exc:
            raise InstanceLockedError(
                "Another VAPT Workbench instance is already using this data directory"
                f"{self._describe_holder()}. Only one instance per data directory is supported."
            ) from exc
        info = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "started_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "app_version": __version__,
        }
        atomic_write_bytes(self.root / self.INFO_NAME, json.dumps(info, indent=2).encode())

    def release(self) -> None:
        if self._lock.is_locked:
            self._lock.release(force=True)

    def _describe_holder(self) -> str:
        try:
            info = json.loads((self.root / self.INFO_NAME).read_text("utf-8"))
            return f" (pid {int(info['pid'])}, started {str(info['started_at'])[:32]})"
        except (OSError, ValueError, KeyError, TypeError):
            return ""

    @staticmethod
    def probe(root: Path) -> str:
        """'free' | 'held' — without keeping the lock (used by diagnostics)."""
        if not (root / InstanceLock.LOCK_NAME).exists():
            return "free"
        lock = _new_lock(root / InstanceLock.LOCK_NAME, timeout=0)
        try:
            lock.acquire(timeout=0)
        except Timeout:
            return "held"
        lock.release(force=True)
        return "free"


class ClaimLock:
    """Non-blocking exclusive claim on one job, held by the worker for the whole run.

    A job whose record says it is active but whose claim lock can be acquired has no
    live worker: it is stale (the process died or the app stopped).
    """

    def __init__(self, lock_path: Path) -> None:
        self.lock_path = lock_path
        self._lock = _new_lock(lock_path, timeout=0)

    def try_acquire(self) -> bool:
        try:
            self._lock.acquire(timeout=0)
        except Timeout:
            return False
        return True

    @property
    def held(self) -> bool:
        return self._lock.is_locked

    def release(self) -> None:
        if self._lock.is_locked:
            self._lock.release(force=True)
