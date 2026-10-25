"""Safety checks for untrusted project-backup archives (MASTER_SPEC §10.2 item 7).

Same defensive posture as `app/imports/safety.py` (XXE-free here since we only read JSON,
and zip-bomb/traversal protection is the main concern), generalized to a **multi-file**
archive — a project backup legitimately contains many records, unlike an import upload
which accepts exactly one file.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass

MAX_ARCHIVE_BYTES = 200 * 1024 * 1024  # the uploaded .zip itself
MAX_EXPANDED_BYTES = 1024 * 1024 * 1024  # declared uncompressed size, checked before inflation
MAX_ENTRIES = 50_000
MAX_SINGLE_ENTRY_BYTES = 30 * 1024 * 1024
MAX_JSON_BYTES = 10 * 1024 * 1024  # a single canonical record document


class ArchiveSafetyError(ValueError):
    """An untrusted archive failed a safety check; it was never extracted."""


@dataclass(frozen=True)
class SafeMember:
    name: str  # normalized, forward-slash, no leading "/", no ".."
    data: bytes


def _normalize_member_name(name: str) -> str:
    if "\x00" in name:
        raise ArchiveSafetyError(f"archive entry contains a NUL byte: {name!r}")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or ":" in normalized:
        raise ArchiveSafetyError(f"archive entry has an unsafe absolute/drive path: {name!r}")
    parts = [p for p in normalized.split("/") if p]
    if not parts or ".." in parts or any(p == "." for p in parts):
        raise ArchiveSafetyError(f"archive entry has an unsafe path: {name!r}")
    return "/".join(parts)


_READ_CHUNK = 1024 * 1024


def _per_entry_limit(name: str) -> int:
    # JSON records are bounded more tightly than the general per-entry cap, which exists
    # mainly for evidence/import raw blobs.
    return MAX_JSON_BYTES if name.endswith(".json") else MAX_SINGLE_ENTRY_BYTES


def _read_entry_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo, name: str) -> bytes:
    """Decompress one entry with a hard cap on the bytes produced, read incrementally.

    CPython's `ZipExtFile` does truncate its output to the entry's declared `file_size` (it is
    not possible to coax more bytes out of `.read()` than the header claims), so a forged small
    declared size cannot itself cause unbounded decompression. What the previous `zf.read(info)`
    call did **not** do is handle a corrupt/tampered entry gracefully: a CRC mismatch (e.g. a bit
    flipped in transit, or a declared size that disagrees with the real stream) raised
    `zipfile.BadZipFile` with nothing to catch it, which would have surfaced as an unhandled
    500 instead of a clean "invalid archive" rejection. Reading incrementally here lets that be
    turned into `ArchiveSafetyError`, and applies a JSON-specific tighter cap via
    `_per_entry_limit` as defense in depth, independent of whatever `info.file_size` claims."""
    limit = _per_entry_limit(name)
    chunks: list[bytes] = []
    total = 0
    try:
        with zf.open(info) as fh:
            while True:
                chunk = fh.read(_READ_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ArchiveSafetyError(
                        f"archive member {name!r} exceeds the {limit} byte limit "
                        "(actual decompressed size, independent of its declared header)"
                    )
                chunks.append(chunk)
    except zipfile.BadZipFile as exc:
        raise ArchiveSafetyError(f"archive member {name!r} is corrupt: {exc}") from exc
    return b"".join(chunks)


def safe_extract_all(raw: bytes) -> list[SafeMember]:
    """Validate and extract every member of a ZIP archive, defending against zip bombs
    (entry-count and declared/actual-size checks, both before and during inflation — see
    `_read_entry_bounded`), path traversal, absolute paths, symlink entries, and a corrupt or
    tampered member (translated to `ArchiveSafetyError`, never an unhandled exception). Raises
    `ArchiveSafetyError` for any violation; extracts nothing on partial failure."""
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ArchiveSafetyError(f"archive exceeds the {MAX_ARCHIVE_BYTES} byte limit")
    if len(raw) < 4 or raw[:4] != b"PK\x03\x04":
        raise ArchiveSafetyError("not a valid ZIP archive")
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ArchiveSafetyError(f"malformed ZIP archive: {exc}") from exc
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise ArchiveSafetyError(f"archive has more than {MAX_ENTRIES} entries")
    # Cheap early rejection for an obviously-oversized archive, before any entry is opened.
    # `total_actual` below (checked per-entry during the real read) is the authoritative bound.
    total_declared = sum(i.file_size for i in infos)
    if total_declared > MAX_EXPANDED_BYTES:
        raise ArchiveSafetyError(
            f"archive's declared uncompressed size ({total_declared} bytes) exceeds the "
            f"{MAX_EXPANDED_BYTES} byte limit"
        )
    members: list[SafeMember] = []
    total_actual = 0
    for info in infos:
        if info.filename.endswith("/"):
            continue  # directory entry
        name = _normalize_member_name(info.filename)
        if (info.external_attr >> 16) & 0o170000 == 0o120000:  # S_IFLNK
            raise ArchiveSafetyError(f"archive entries must not be symlinks: {name!r}")
        data = _read_entry_bounded(zf, info, name)
        total_actual += len(data)
        if total_actual > MAX_EXPANDED_BYTES:
            raise ArchiveSafetyError(
                f"archive's actual decompressed size exceeds the {MAX_EXPANDED_BYTES} byte limit"
            )
        if data[:4] == b"PK\x03\x04":
            raise ArchiveSafetyError(f"nested archives are not accepted: {name!r}")
        members.append(SafeMember(name=name, data=data))
    return members
