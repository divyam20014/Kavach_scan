"""Atomic file replacement, bounded JSON reads and temp-file cleanup."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO

from app.storage.errors import CorruptRecordError, RecordTooLargeError, StorageError

TMP_RE = re.compile(r"^\..+\.[0-9a-f]{12}\.tmp$")
_IS_WINDOWS = sys.platform.startswith("win")
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOINHERIT = getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_CLOEXEC", 0)
DIR_MODE = 0o700
FILE_MODE = 0o600


def ensure_dir(path: Path, *, parents: bool = False) -> None:
    """Create a directory with owner-only permissions (POSIX). `parents` is opt-in."""
    if path.is_dir():
        return
    if parents:
        path.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    else:
        try:
            path.mkdir(mode=DIR_MODE)
        except FileExistsError:
            pass
    if not _IS_WINDOWS:
        os.chmod(path, DIR_MODE)


REPLACE_RETRY_SECONDS = 5.0


def _replace_with_retry(
    src: Path, dst: Path, deadline_seconds: float = REPLACE_RETRY_SECONDS
) -> None:
    """os.replace with a bounded retry on Windows, where antivirus/indexers (or a reader that
    did not grant FILE_SHARE_DELETE) can briefly hold the destination open."""
    deadline = time.monotonic() + deadline_seconds
    delay = 0.01
    while True:
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if not _IS_WINDOWS or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.25)


def _fsync_dir(directory: Path) -> None:
    if _IS_WINDOWS:
        return  # directory handles cannot be fsynced on Windows; NTFS journals the rename
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write via same-directory temp file + fsync + atomic replace.

    The parent directory must already exist (callers decide which directories may be
    created). On failure the destination is untouched and the temp file is removed.
    """
    if not path.parent.is_dir():
        raise FileNotFoundError(f"parent directory missing: {path.parent.name}")
    tmp = path.parent / f".{path.name}.{uuid.uuid4().hex[:12]}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOINHERIT, FILE_MODE)
    try:
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        _replace_with_retry(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    _fsync_dir(path.parent)


def dumps_record(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def write_bytes_to_external_path(path: Path, data: bytes) -> None:
    """Write bytes to an operator-specified path outside the data directory (the CLI's
    `support-bundle --output`). Not a canonical-record write (no atomic-replace, no locking,
    no schema) — this exists only so every file write in the codebase still funnels through
    `app/storage/`, the invariant `tests/test_static_guards.py::test_no_file_io_outside_storage`
    enforces, rather than letting `app/__main__.py` write files directly."""
    path.write_bytes(data)


def _open_for_read(path: Path) -> BinaryIO:
    """Open for reading. On Windows, share read/write/DELETE so that a concurrent reader can
    never make a writer's atomic os.replace fail (Python's open() omits FILE_SHARE_DELETE)."""
    if not _IS_WINDOWS:
        return open(path, "rb")  # noqa: SIM115 - returned to the caller's context manager
    import _winapi
    import msvcrt

    share = 0x1 | 0x2 | 0x4  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    handle = _winapi.CreateFile(
        str(path), _winapi.GENERIC_READ, share, 0, _winapi.OPEN_EXISTING, 0, 0
    )
    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | _O_BINARY)
    return os.fdopen(fd, "rb")


def read_bytes_bounded(path: Path, max_bytes: int) -> bytes:
    size = os.stat(path).st_size
    if size > max_bytes:
        raise RecordTooLargeError(f"Record exceeds {max_bytes} bytes")
    with _open_for_read(path) as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise RecordTooLargeError(f"Record exceeds {max_bytes} bytes")
    return data


def parse_json_object(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise CorruptRecordError(f"Invalid JSON ({type(exc).__name__})") from exc
    if not isinstance(value, dict):
        raise CorruptRecordError("JSON document is not an object")
    return value


def cleanup_temp_files(root: Path, *, older_than_seconds: float = 0.0) -> int:
    """Remove leftover `.<name>.<hex>.tmp` files; never follows symlinks."""
    removed = 0
    cutoff = time.time() - older_than_seconds
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = [
            d for d in dirnames if not (base / d).is_symlink() and not (base / d).is_junction()
        ]
        for name in filenames:
            if not TMP_RE.fullmatch(name):
                continue
            target = base / name
            try:
                st = os.lstat(target)
                if stat.S_ISREG(st.st_mode) and st.st_mtime <= cutoff:
                    target.unlink()
                    removed += 1
            except OSError as exc:
                raise StorageError(f"Could not remove temp file: {type(exc).__name__}") from exc
    return removed
