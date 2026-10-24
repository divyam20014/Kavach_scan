"""Shared input-safety checks for every import adapter (MASTER_SPEC §8.1, TBD-009).

Every adapter must run untrusted bytes through these helpers before (or while) parsing.
Limits are conservative defaults from TBD-009; all are plain module constants so a future
settings surface can make them configurable without changing call sites.
"""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass

MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # TBD-009: upload cap (also enforced by StorageRepository)
MAX_ARCHIVE_EXPANDED_BYTES = 250 * 1024 * 1024  # TBD-009
MAX_ARCHIVE_ENTRIES = 10_000  # TBD-009
MAX_ARCHIVE_SINGLE_ENTRY_BYTES = 50 * 1024 * 1024  # a single member may not itself be huge
MAX_JSON_DEPTH = 64  # TBD-009 (shared with the OpenAPI importer's bound)
MAX_JSON_NODES = 500_000
MAX_XML_DEPTH = 64
MAX_XML_NODES = 500_000
MAX_RECORDS = 20_000  # a single import may normalize at most this many records
MAX_ROW_BYTES = 1 * 1024 * 1024  # a single CSV/JSONL line/row this large is rejected, not parsed


class ImportSafetyError(ValueError):
    """Untrusted input failed a safety check; it was never handed to a real parser."""


def decode_text(raw: bytes, *, declared: str | None = None) -> str:
    """Decode bytes defensively. Tries the declared/sniffed encoding, then UTF-8, then
    Latin-1 (which never fails but may mangle non-ASCII text — a warning should be shown
    by the caller when that happens)."""
    if not raw:
        return ""
    candidates = [c for c in (declared, "utf-8-sig", "utf-8") if c]
    # Strip a BOM explicitly so "utf-8-sig" vs "utf-8" does not change downstream parsing.
    for enc in dict.fromkeys(candidates):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1")


def check_json_bounds(node: object, *, max_depth: int = MAX_JSON_DEPTH,
                      max_nodes: int = MAX_JSON_NODES) -> None:
    counter = [0]

    def walk(value: object, depth: int) -> None:
        if depth > max_depth:
            raise ImportSafetyError(f"JSON nesting exceeds {max_depth} levels")
        counter[0] += 1
        if counter[0] > max_nodes:
            raise ImportSafetyError(f"JSON has more than {max_nodes} nodes")
        if isinstance(value, dict):
            for v in value.values():
                walk(v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                walk(v, depth + 1)

    walk(node, 0)


def parse_xml_safely(raw: bytes, *, max_bytes: int = MAX_UPLOAD_BYTES,
                     max_depth: int = MAX_XML_DEPTH, max_nodes: int = MAX_XML_NODES) -> ET.Element:
    """Parse XML defensively: reject DTD/ENTITY declarations (XXE/billion-laughs) before
    parsing, cap size, and bound the resulting tree's depth and node count."""
    if len(raw) > max_bytes:
        raise ImportSafetyError(f"XML exceeds the {max_bytes} byte limit")
    head = raw[:8192].upper()
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in head:
        raise ImportSafetyError("DTD/entity declarations are not accepted (XXE protection)")
    try:
        root = ET.fromstring(raw)  # noqa: S314 - DTDs rejected above; size-capped
    except ET.ParseError as exc:
        raise ImportSafetyError(f"malformed XML: {exc}") from exc

    counter = [0]

    def walk(node: ET.Element, depth: int) -> None:
        if depth > max_depth:
            raise ImportSafetyError(f"XML nesting exceeds {max_depth} levels")
        counter[0] += 1
        if counter[0] > max_nodes:
            raise ImportSafetyError(f"XML has more than {max_nodes} elements")
        for child in node:
            walk(child, depth + 1)

    walk(root, 0)
    return root


@dataclass(frozen=True)
class ExtractedFile:
    name: str
    data: bytes


def maybe_extract_single_member(raw: bytes) -> ExtractedFile | None:
    """If `raw` is a ZIP archive, safely extract its single member; else return None.

    Rejects: more than one entry (a multi-file archive has no defined "the report" without
    a manifest, which we do not support), nested archives, absolute paths or `..` traversal
    in the member name, symlinks, and anything over the archive size/count/entry caps. A
    zip bomb (huge declared uncompressed size, or many entries) is rejected by the
    declared-size/count checks before any bytes are inflated.
    """
    if len(raw) < 4 or raw[:4] != b"PK\x03\x04":
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ImportSafetyError(f"malformed ZIP archive: {exc}") from exc
    infos = zf.infolist()
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise ImportSafetyError(f"archive has more than {MAX_ARCHIVE_ENTRIES} entries")
    total = sum(i.file_size for i in infos)
    if total > MAX_ARCHIVE_EXPANDED_BYTES:
        raise ImportSafetyError(
            f"archive's declared uncompressed size ({total} bytes) exceeds the "
            f"{MAX_ARCHIVE_EXPANDED_BYTES} byte limit"
        )
    real_entries = [i for i in infos if not i.filename.endswith("/")]
    if len(real_entries) != 1:
        raise ImportSafetyError(
            f"archive must contain exactly one file (found {len(real_entries)}); "
            "upload the report file directly, or a ZIP with a single member"
        )
    member = real_entries[0]
    name = member.filename.replace("\\", "/")
    if name.startswith("/") or ".." in name.split("/") or ":" in name:
        raise ImportSafetyError("archive entry has an unsafe path")
    if (member.external_attr >> 16) & 0o170000 == 0o120000:  # S_IFLNK: a symlink entry
        raise ImportSafetyError("archive entries must not be symlinks")
    if member.file_size > MAX_ARCHIVE_SINGLE_ENTRY_BYTES:
        raise ImportSafetyError(
            f"archive member exceeds the {MAX_ARCHIVE_SINGLE_ENTRY_BYTES} byte limit"
        )
    data = zf.read(member)  # declared size already checked; this will not silently balloon
    if len(data) != member.file_size:
        raise ImportSafetyError("archive member size does not match its declared size")
    if data[:4] == b"PK\x03\x04":
        raise ImportSafetyError("nested archives are not accepted")
    return ExtractedFile(name=name.rsplit("/", 1)[-1][:255], data=data)
