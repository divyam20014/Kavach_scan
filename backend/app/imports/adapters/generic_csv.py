"""Generic CSV import with a documented, alias-based column mapping (MASTER_SPEC §8.2/#9).

No drag-and-drop mapping UI is built for this release; instead, a small set of
case-insensitive header aliases is tried automatically (documented in `ALIASES` below and
in `docs/IMPORT_CENTER.md`), and the operator may pass an explicit `column_map` override
(`{"title": "Vulnerability Name", "severity": "Risk Rating", ...}`) as the `options`
argument when the operator's own headers don't match. A row missing a usable title is
rejected (counted, with a warning), never silently dropped or invented.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from app.imports.base import (
    Adapter,
    ParsedFinding,
    ParseResult,
    extract_cwe_ids,
    normalize_confidence,
    normalize_severity,
    truncate,
)
from app.imports.safety import ImportSafetyError, decode_text

PARSER_VERSION = "vapt-import-generic-csv 1.0.0"
MAX_ROWS = 20_000
MAX_FIELD_CHARS = 20_000  # the csv module's own field-size limit, applied per value read

# Fields worth flagging to the operator as an unmapped "mapping gap" in the dry-run preview
# when no header/alias/override matched. "title" is excluded: a missing title is already a
# fatal, whole-file error (see below), not a silent gap.
_GAP_WORTHY_FIELDS = ("severity", "host", "url", "cwe", "remediation", "component")

# field -> accepted header names (lowercase, compared case-insensitively against the header row)
ALIASES: dict[str, tuple[str, ...]] = {
    "title": (
        "title",
        "name",
        "vulnerability",
        "vulnerability name",
        "finding",
        "issue",
        "summary title",
        "plugin name",
    ),
    "severity": ("severity", "risk", "risk rating", "priority"),
    "confidence": ("confidence", "certainty"),
    "summary": ("summary", "description", "synopsis", "details"),
    "remediation": ("remediation", "solution", "recommendation", "fix"),
    "host": ("host", "hostname", "target", "ip", "ip address", "asset"),
    "url": ("url", "uri", "endpoint", "location"),
    "method": ("method", "http method"),
    "parameter": ("parameter", "param", "field"),
    "component": ("component", "plugin", "module", "service"),
    "cwe": ("cwe", "cwe id", "cwe-id"),
    "cve": ("cve", "cve id", "cve-id"),
    "rule_id": ("rule id", "rule", "plugin id", "check id", "test id"),
    "source_id": ("id", "finding id", "issue id"),
    "references": ("references", "see also", "link", "links"),
}


def _build_header_map(header: list[str], overrides: dict[str, str] | None) -> dict[str, int]:
    lower = {h.strip().lower(): i for i, h in enumerate(header)}
    out: dict[str, int] = {}
    for field, names in ALIASES.items():
        for name in names:
            if name in lower:
                out[field] = lower[name]
                break
    if overrides:
        for field, column_name in overrides.items():
            if field not in ALIASES:
                continue
            key = str(column_name).strip().lower()
            if key in lower:
                out[field] = lower[key]
    return out


class GenericCsvAdapter:
    source_type = "generic_csv"
    label = "Generic CSV"
    parser_version = PARSER_VERSION

    def sniff(self, filename: str, raw: bytes) -> bool:
        if not filename.lower().endswith((".csv", ".tsv")):
            return False
        sample = decode_text(raw[:4096])
        return "," in sample or "\t" in sample or ";" in sample

    def parse(self, raw: bytes, *, options: dict[str, Any] | None = None) -> ParseResult:
        result = ParseResult()
        text = decode_text(raw)
        # decode_text's final fallback (latin-1) never raises, so it can never itself signal
        # that the bytes were not actually UTF-8 — a strict UTF-8 attempt is the only way to
        # tell whether `text` is the genuine content or a legacy-codepage guess that may have
        # mangled non-ASCII characters (e.g. a report saved as cp1252).
        if raw:
            try:
                raw.decode("utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8")
            except UnicodeDecodeError:
                result.warn(
                    "the file did not decode cleanly as UTF-8; some characters may be wrong"
                )
        column_map = None
        if options and isinstance(options.get("column_map"), dict):
            column_map = {str(k): str(v) for k, v in options["column_map"].items()}
        try:
            dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        old_limit = csv.field_size_limit()
        csv.field_size_limit(MAX_FIELD_CHARS)
        try:
            reader = csv.reader(io.StringIO(text), dialect)
            rows = list(reader)
        except csv.Error as exc:
            raise ImportSafetyError(f"malformed CSV: {exc}") from exc
        finally:
            csv.field_size_limit(old_limit)
        if not rows:
            result.warn("the file is empty")
            return result
        header, *data_rows = rows
        field_index = _build_header_map(header, column_map)
        if "title" not in field_index:
            raise ImportSafetyError(
                "could not identify a title column; pass options.column_map={'title': "
                "'<your header>'} (recognized title aliases: " + ", ".join(ALIASES["title"]) + ")"
            )
        result.mapping_gaps = [f for f in _GAP_WORTHY_FIELDS if f not in field_index]
        if result.mapping_gaps:
            result.warn(
                "no column matched for: "
                + ", ".join(result.mapping_gaps)
                + " (these fields will be empty or default on every imported row)"
            )
        if len(data_rows) > MAX_ROWS:
            result.warn(f"file has {len(data_rows)} rows; only the first {MAX_ROWS} were imported")
            data_rows = data_rows[:MAX_ROWS]
        for row_num, row in enumerate(data_rows, start=2):  # row 1 is the header
            try:
                self._parse_row(row, field_index, row_num, result)
            except Exception as exc:  # noqa: BLE001 - one bad row must not fail the import
                result.rejected_count += 1
                result.warn(f"row {row_num}: could not normalize ({type(exc).__name__})")
        return result

    def _parse_row(
        self, row: list[str], idx: dict[str, int], row_num: int, result: ParseResult
    ) -> None:
        def get(field: str) -> str:
            i = idx.get(field)
            return row[i].strip() if i is not None and i < len(row) else ""

        title = get("title")
        if not title:
            result.rejected_count += 1
            result.warn(f"row {row_num}: empty title; skipped")
            return
        severity, original = normalize_severity(get("severity") or None)
        cwe_text = f"{get('cwe')} {get('summary')}"
        result.findings.append(
            ParsedFinding(
                title=truncate(title, 300),
                severity=severity,
                confidence=normalize_confidence(get("confidence") or None),
                original_severity=original,
                original_confidence=get("confidence"),
                summary=truncate(get("summary")),
                remediation=truncate(get("remediation")),
                url=get("url") or None,
                host=get("host") or None,
                method=(get("method") or None),
                parameter=truncate(get("parameter"), 200),
                component=truncate(get("component"), 300),
                cwe_ids=extract_cwe_ids(cwe_text),
                rule_id=truncate(get("rule_id"), 150),
                # Only a genuine tool-provided ID goes here. A synthetic "row-N" placeholder
                # would look like a real strong identity signal to dedup.fingerprint() and
                # make every row artificially unique, defeating duplicate detection entirely
                # for any report that has no explicit ID column.
                source_finding_id=truncate(get("source_id"), 300),
                references=[r.strip() for r in get("references").split() if r.strip()][:20],
                row=row_num,
            )
        )
        result.parsed_count += 1


ADAPTER: Adapter = GenericCsvAdapter()
