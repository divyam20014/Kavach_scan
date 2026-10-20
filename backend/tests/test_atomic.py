import json
import os
import time
from pathlib import Path

import pytest

from app.storage import atomic
from app.storage.atomic import (
    atomic_write_bytes,
    cleanup_temp_files,
    parse_json_object,
    read_bytes_bounded,
)
from app.storage.errors import CorruptRecordError, RecordTooLargeError


def test_write_then_read(tmp_path: Path) -> None:
    target = tmp_path / "r.json"
    atomic_write_bytes(target, b'{"a": 1}')
    assert parse_json_object(read_bytes_bounded(target, 1024)) == {"a": 1}
    assert not list(tmp_path.glob(".*.tmp"))


def test_failed_replace_keeps_original_and_removes_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "r.json"
    atomic_write_bytes(target, b'{"v": "old"}')

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("simulated crash during replace")

    monkeypatch.setattr(atomic.os, "replace", boom)
    with pytest.raises(OSError, match="simulated"):
        atomic_write_bytes(target, b'{"v": "new"}')
    monkeypatch.undo()
    assert json.loads(target.read_text()) == {"v": "old"}
    assert not list(tmp_path.glob(".*.tmp"))


def test_failed_write_mid_stream_keeps_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "r.json"
    atomic_write_bytes(target, b'{"v": "old"}')
    real_write = os.write
    calls = {"n": 0}

    def half_then_fail(fd: int, data: bytes | memoryview) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            return real_write(fd, bytes(data)[:5])  # partial write ...
        raise OSError(28, "No space left on device")  # ... then disk full

    monkeypatch.setattr(atomic.os, "write", half_then_fail)
    with pytest.raises(OSError, match="No space"):
        atomic_write_bytes(target, b'{"v": "a much longer new value"}')
    monkeypatch.undo()
    assert json.loads(target.read_text()) == {"v": "old"}
    assert not list(tmp_path.glob(".*.tmp"))


def test_half_written_temp_file_never_visible_as_record(tmp_path: Path) -> None:
    """A crash leaves only a dot-temp file; the canonical file is old-or-new, never partial."""
    target = tmp_path / "r.json"
    atomic_write_bytes(target, b'{"v": 1}')
    (tmp_path / ".r.json.0123456789ab.tmp").write_bytes(
        b'{"v": 2, "trunc'
    )  # simulated crash leftover
    assert parse_json_object(read_bytes_bounded(target, 1024)) == {"v": 1}
    assert cleanup_temp_files(tmp_path) == 1
    assert not (tmp_path / ".r.json.0123456789ab.tmp").exists()


def test_cleanup_respects_age_and_ignores_other_files(tmp_path: Path) -> None:
    fresh = tmp_path / ".x.json.aaaaaaaaaaaa.tmp"
    fresh.write_text("x")
    other = tmp_path / "notes.tmp"
    other.write_text("keep")
    assert cleanup_temp_files(tmp_path, older_than_seconds=3600) == 0
    old = time.time() - 7200
    os.utime(fresh, (old, old))
    assert cleanup_temp_files(tmp_path, older_than_seconds=3600) == 1
    assert other.exists()


def test_parent_directory_never_created_implicitly(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        atomic_write_bytes(tmp_path / "missing" / "r.json", b"{}")
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize(
    "payload",
    [b'{"a": 1', b"", b"\xff\xfe\x00garbage", b"[1, 2, 3]", b"null", b'"string"', b"[" * 100_000],
    ids=["truncated", "empty", "bad-utf8", "array", "null", "string", "deep-nesting"],
)
def test_corrupt_or_non_object_json_raises_corrupt(payload: bytes) -> None:
    with pytest.raises(CorruptRecordError):
        parse_json_object(payload)


def test_oversized_record_refused(tmp_path: Path) -> None:
    target = tmp_path / "big.json"
    target.write_bytes(b" " * 2048)
    with pytest.raises(RecordTooLargeError):
        read_bytes_bounded(target, 1024)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not enforced on Windows")
def test_posix_permissions_are_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "r.json"
    atomic_write_bytes(target, b"{}")
    assert (target.stat().st_mode & 0o777) == 0o600
