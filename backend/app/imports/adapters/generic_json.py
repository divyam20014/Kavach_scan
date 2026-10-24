"""Generic JSON import: a top-level array of finding-like objects, or an object holding one
under a common key (`findings`/`results`/`vulnerabilities`/`issues`/`alerts`). Uses the same
alias table as the generic CSV adapter, plus a `field_map` option for dotted-path overrides
(e.g. `{"severity": "info.severity"}`) when an operator's export uses different field names.
"""

from __future__ import annotations

from typing import Any

from app.imports.adapters.generic_csv import ALIASES
from app.imports.base import (
    Adapter,
    ParsedFinding,
    ParseResult,
    extract_cwe_ids,
    normalize_confidence,
    normalize_severity,
    truncate,
)
from app.imports.safety import ImportSafetyError, check_json_bounds

PARSER_VERSION = "vapt-import-generic-json 1.0.0"
MAX_RECORDS = 20_000
_ARRAY_KEYS = ("findings", "results", "vulnerabilities", "issues", "alerts", "items", "vulns")
_GAP_WORTHY_FIELDS = ("severity", "host", "url", "cwe", "remediation", "component")


def _dig(obj: Any, path: str) -> Any:
    current = obj
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(_as_text(v) for v in value)
    return str(value)


class GenericJsonAdapter:
    source_type = "generic_json"
    label = "Generic JSON"
    parser_version = PARSER_VERSION

    def sniff(self, filename: str, raw: bytes) -> bool:
        import json

        if not filename.lower().endswith(".json"):
            return False
        try:
            obj = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return False
        if isinstance(obj, list):
            return bool(obj) and isinstance(obj[0], dict)
        if isinstance(obj, dict):
            return any(isinstance(obj.get(k), list) for k in _ARRAY_KEYS)
        return False

    def parse(self, raw: bytes, *, options: dict[str, Any] | None = None) -> ParseResult:
        import json

        result = ParseResult()
        try:
            doc = json.loads(raw)
        except Exception as exc:  # noqa: BLE001 - surfaced as a clean import error
            raise ImportSafetyError(f"invalid JSON: {exc}") from exc
        check_json_bounds(doc)
        records = self._records(doc)
        if records is None:
            raise ImportSafetyError(
                "could not find a findings array (expected a top-level list, or an object "
                "with one of: " + ", ".join(_ARRAY_KEYS) + ")"
            )
        field_map: dict[str, str] = {}
        if options and isinstance(options.get("field_map"), dict):
            field_map = {str(k): str(v) for k, v in options["field_map"].items()}
        if len(records) > MAX_RECORDS:
            result.warn(f"found {len(records)} records; only the first {MAX_RECORDS} were imported")
            records = records[:MAX_RECORDS]
        result.mapping_gaps = [
            name for name in _GAP_WORTHY_FIELDS
            if not any(isinstance(r, dict) and self._field(r, name, field_map) not in (None, "")
                      for r in records)
        ]
        if result.mapping_gaps:
            result.warn("no field matched for: " + ", ".join(result.mapping_gaps) +
                       " (these fields will be empty or default on every imported record)")
        for row, rec in enumerate(records, start=1):
            try:
                self._parse_record(rec, field_map, row, result)
            except Exception as exc:  # noqa: BLE001 - one bad record must not fail the import
                result.rejected_count += 1
                result.warn(f"record {row}: could not normalize ({type(exc).__name__})")
        return result

    @staticmethod
    def _records(doc: Any) -> list[Any] | None:
        if isinstance(doc, list):
            return doc
        if isinstance(doc, dict):
            for key in _ARRAY_KEYS:
                value = doc.get(key)
                if isinstance(value, list):
                    return value
        return None

    def _field(self, rec: dict[str, Any], name: str, field_map: dict[str, str]) -> Any:
        if name in field_map:
            return _dig(rec, field_map[name])
        for alias in ALIASES.get(name, ()):
            flat_key = alias.replace(" ", "_")
            for key in (alias, flat_key, name):
                if key in rec:
                    return rec[key]
        return None

    def _parse_record(self, rec: Any, field_map: dict[str, str], row: int,
                      result: ParseResult) -> None:
        if not isinstance(rec, dict):
            result.rejected_count += 1
            result.warn(f"record {row}: not a JSON object; skipped")
            return
        title = _as_text(self._field(rec, "title", field_map)).strip()
        if not title:
            result.rejected_count += 1
            result.warn(f"record {row}: no usable title field; skipped")
            return
        severity, original = normalize_severity(self._field(rec, "severity", field_map))
        cwe_text = _as_text(self._field(rec, "cwe", field_map))
        refs = self._field(rec, "references", field_map)
        ref_list = [str(r)[:500] for r in refs][:20] if isinstance(refs, list) else (
            [str(refs)[:500]] if refs else [])
        result.findings.append(ParsedFinding(
            title=truncate(title, 300), severity=severity,
            confidence=normalize_confidence(
                _as_text(self._field(rec, "confidence", field_map)) or None),
            original_severity=original,
            original_confidence=_as_text(self._field(rec, "confidence", field_map)),
            summary=truncate(_as_text(self._field(rec, "summary", field_map))),
            remediation=truncate(_as_text(self._field(rec, "remediation", field_map))),
            url=(_as_text(self._field(rec, "url", field_map)) or None),
            host=(_as_text(self._field(rec, "host", field_map)) or None),
            method=(_as_text(self._field(rec, "method", field_map)) or None),
            parameter=truncate(_as_text(self._field(rec, "parameter", field_map)), 200),
            component=truncate(_as_text(self._field(rec, "component", field_map)), 300),
            cwe_ids=extract_cwe_ids(cwe_text), rule_id=truncate(_as_text(
                self._field(rec, "rule_id", field_map)), 150),
            # Only a genuine tool-provided ID goes here (see generic_csv.py for why a
            # synthetic "record-N" placeholder would defeat dedup.fingerprint()).
            source_finding_id=truncate(_as_text(self._field(rec, "source_id", field_map)), 300),
            references=ref_list, row=row,
        ))
        result.parsed_count += 1


ADAPTER: Adapter = GenericJsonAdapter()
