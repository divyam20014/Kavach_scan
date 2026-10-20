"""Append-only JSONL logs with size rotation and line-level corruption tolerance.

Layout for a log named `audit` in directory D:
    D/audit.jsonl            current segment (appends go here)
    D/audit.000001.jsonl     rotated, read-only by convention (higher number = newer)

Reads go newest-first through a reverse chunked reader, so memory stays bounded
regardless of file size. A line that fails to parse or validate is skipped and
counted; a torn final line from a crash is repaired by starting the next append on
a fresh line.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from app.storage.atomic import FILE_MODE
from app.storage.errors import RecordTooLargeError
from app.storage.locking import exclusive

MAX_LINE_BYTES = 256 * 1024
_CHUNK = 64 * 1024
_O_BINARY = getattr(os, "O_BINARY", 0)


def _reverse_lines(path: Path) -> Iterator[bytes]:
    """Yield lines from the end of the file to the start (without trailing newlines)."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        position = fh.tell()
        remainder = b""
        while position > 0:
            step = min(_CHUNK, position)
            position -= step
            fh.seek(position)
            block = fh.read(step) + remainder
            lines = block.split(b"\n")
            remainder = lines[0]
            for line in reversed(lines[1:]):
                if line:
                    yield line
            if len(remainder) > MAX_LINE_BYTES:  # pathological line: skip it, keep bounded
                yield b"\x00oversized"
                remainder = b""
        if remainder:
            yield remainder


class JsonlLog:
    def __init__(
        self,
        directory: Path,
        name: str,
        *,
        rotate_bytes: int,
        lock_timeout: float,
        lock_root: Path | None = None,
    ) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name):
            raise ValueError("invalid log name")
        self.directory = directory
        self.name = name
        self.rotate_bytes = rotate_bytes
        self.lock_timeout = lock_timeout
        self.lock_root = lock_root
        self.current = directory / f"{name}.jsonl"
        self._segment_re = re.compile(rf"^{re.escape(name)}\.(\d{{6}})\.jsonl$")

    def segments(self) -> list[Path]:
        """Rotated segments, newest first."""
        found: list[tuple[int, Path]] = []
        if self.directory.is_dir():
            for entry in os.scandir(self.directory):
                m = self._segment_re.match(entry.name)
                if m and entry.is_file(follow_symlinks=False):
                    found.append((int(m.group(1)), Path(entry.path)))
        return [p for _, p in sorted(found, reverse=True)]

    def append(self, entry: dict[str, Any]) -> None:
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        data = line.encode("utf-8") + b"\n"
        if len(data) > MAX_LINE_BYTES:
            raise RecordTooLargeError("Log entry exceeds maximum line size")
        with exclusive(self.current, self.lock_timeout, lock_root=self.lock_root):
            size = self.current.stat().st_size if self.current.exists() else 0
            if size and size + len(data) > self.rotate_bytes:
                newest = self.segments()
                number = int(self._segment_re.match(newest[0].name).group(1)) + 1 if newest else 1  # type: ignore[union-attr]
                try:
                    os.replace(self.current, self.directory / f"{self.name}.{number:06d}.jsonl")
                    size = 0
                except PermissionError:
                    pass  # Windows: a concurrent reader holds the file; rotate on a later append
            fd = os.open(
                self.current, os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_BINARY, FILE_MODE
            )
            try:
                if size and not self._ends_with_newline():
                    data = b"\n" + data  # isolate a torn line left by a crash
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)

    def _ends_with_newline(self) -> bool:
        with open(self.current, "rb") as fh:
            fh.seek(-1, os.SEEK_END)
            return fh.read(1) == b"\n"

    def read_newest(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        parse: Callable[[dict[str, Any]], Any] = lambda d: d,
        predicate: Callable[[Any], bool] = lambda _: True,
    ) -> tuple[list[Any], int, bool]:
        """Return (items newest-first, corrupt_line_count, has_more)."""
        items: list[Any] = []
        corrupt = 0
        skipped = 0
        files = ([self.current] if self.current.exists() else []) + self.segments()
        for path in files:
            for raw in _reverse_lines(path):
                try:
                    obj = json.loads(raw.decode("utf-8"))
                    if not isinstance(obj, dict):
                        raise ValueError("not an object")
                    parsed = parse(obj)
                except Exception:  # noqa: BLE001 - any bad line is counted, never fatal
                    corrupt += 1
                    continue
                if not predicate(parsed):
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                if len(items) == limit:
                    return items, corrupt, True
                items.append(parsed)
        return items, corrupt, False
