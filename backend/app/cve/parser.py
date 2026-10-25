"""Parse and validate an operator-uploaded CVE catalog file into a `CveCatalogRecord`.

Format: a small, documented, VAPT-Workbench-specific JSON schema (TBD-028 — no bundled
third-party feeds; the app does not attempt to parse the real NVD JSON feed format, which is
large and complex enough that a partial/best-effort parser would be a worse safety trade-off
than a documented, defensible format the operator's own export/curation step targets).

    {
      "source": "Internal curated export, 2026-10",
      "catalog_version": "2026.10",
      "stale_after_days": 180,
      "entries": [
        {"product": "jquery", "version_spec": "<1.12.4", "cve_id": "CVE-2015-9251",
         "summary": "...", "references": ["https://..."]}
      ]
    }

A structurally broken file (not JSON, not an object, no entries list) is rejected outright.
An individual malformed entry is skipped with a warning — one bad row does not sink an
otherwise-usable catalog, the same posture as every import adapter in this project.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from pydantic import ValidationError

from app.cve.version import VersionSpecError, parse_version_spec
from app.imports.safety import ImportSafetyError, check_json_bounds, decode_text
from app.models.cve_catalog import (
    MAX_ENTRIES,
    PARSER_VERSION,
    CveCatalogEntry,
    CveCatalogRecord,
)

MAX_CATALOG_BYTES = 15 * 1024 * 1024


class CveCatalogParseError(ValueError):
    """The uploaded file is not a usable CVE catalog; nothing is stored."""


@dataclass
class _Draft:
    entries: list[CveCatalogEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _parse_entries(raw_entries: object) -> _Draft:
    draft = _Draft()
    if not isinstance(raw_entries, list):
        raise CveCatalogParseError("'entries' must be a list")
    if len(raw_entries) > MAX_ENTRIES:
        raise CveCatalogParseError(f"catalog has more than {MAX_ENTRIES} entries")
    for i, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            draft.warnings.append(f"entry {i}: not an object; skipped")
            continue
        try:
            entry = CveCatalogEntry.model_validate(raw)
        except ValidationError as exc:
            draft.warnings.append(f"entry {i}: {exc.errors()[0].get('msg', 'invalid')}; skipped")
            continue
        try:
            parse_version_spec(entry.version_spec)
        except VersionSpecError as exc:
            draft.warnings.append(f"entry {i} ({entry.cve_id}): {exc}; skipped")
            continue
        draft.entries.append(entry)
    if not draft.entries:
        raise CveCatalogParseError("no usable entries after validation")
    return draft


def parse_catalog_file(raw: bytes, *, file_name: str = "") -> CveCatalogRecord:
    if not raw:
        raise CveCatalogParseError("empty file")
    if len(raw) > MAX_CATALOG_BYTES:
        raise CveCatalogParseError(f"catalog file exceeds the {MAX_CATALOG_BYTES} byte limit")
    text = decode_text(raw)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CveCatalogParseError(f"not valid JSON: {exc}") from exc
    try:
        check_json_bounds(data)
    except ImportSafetyError as exc:
        raise CveCatalogParseError(str(exc)) from exc
    if not isinstance(data, dict):
        raise CveCatalogParseError("catalog file must be a JSON object")
    source = str(data.get("source", "")).strip()[:500]
    catalog_version = str(data.get("catalog_version", "")).strip()[:500]
    if not source or not catalog_version:
        raise CveCatalogParseError("'source' and 'catalog_version' are required")
    stale_after_days = data.get("stale_after_days", 180)
    if not isinstance(stale_after_days, int) or isinstance(stale_after_days, bool):
        stale_after_days = 180
    stale_after_days = max(1, min(3650, stale_after_days))
    draft = _parse_entries(data.get("entries"))
    return CveCatalogRecord(
        source=source,
        catalog_version=catalog_version,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        file_name=file_name[:500],
        parser_version=PARSER_VERSION,
        stale_after_days=stale_after_days,
        entries=draft.entries,
        warnings=draft.warnings[:50],
    )
