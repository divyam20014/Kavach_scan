"""Nuclei JSONL output import: one JSON object per line (`nuclei -jsonl`)."""

from __future__ import annotations

import json
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
from app.imports.safety import MAX_ROW_BYTES, check_json_bounds

PARSER_VERSION = "vapt-import-nuclei-jsonl 1.0.0"


def _urlsplit_host(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        return urlsplit(url).netloc or url
    except ValueError:
        return url


class NucleiJsonlAdapter:
    source_type = "nuclei_jsonl"
    label = "Nuclei JSONL"
    parser_version = PARSER_VERSION

    def sniff(self, filename: str, raw: bytes) -> bool:
        if not (filename.lower().endswith((".jsonl", ".ndjson")) or b"template-id" in raw[:65536]):
            return False
        first = raw.lstrip().splitlines()[:1]
        if not first:
            return False
        try:
            obj = json.loads(first[0])
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        return isinstance(obj, dict) and "template-id" in obj and "info" in obj

    def parse(self, raw: bytes, *, options: dict[str, Any] | None = None) -> ParseResult:
        result = ParseResult()
        text = raw.decode("utf-8", "replace")
        lines = text.splitlines()
        for row, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            if len(line.encode("utf-8")) > MAX_ROW_BYTES:
                result.rejected_count += 1
                result.warn(f"line {row}: exceeds the per-row size limit; skipped")
                continue
            try:
                obj = json.loads(line)
                check_json_bounds(obj, max_depth=32, max_nodes=5000)
            except (json.JSONDecodeError, ValueError) as exc:
                result.rejected_count += 1
                result.warn(f"line {row}: invalid JSON ({exc})")
                continue
            try:
                self._parse_record(obj, row, result)
            except Exception as exc:  # noqa: BLE001 - one bad record must not fail the import
                result.rejected_count += 1
                result.warn(f"line {row}: could not normalize record ({type(exc).__name__})")
        if not result.parsed_count and not result.rejected_count:
            result.warn("file contained no Nuclei finding records")
        return result

    def _parse_record(self, obj: dict[str, Any], row: int, result: ParseResult) -> None:
        if not isinstance(obj, dict):
            result.rejected_count += 1
            result.warn(f"line {row}: not a JSON object; skipped")
            return
        info_raw = obj.get("info")
        info: dict[str, Any] = info_raw if isinstance(info_raw, dict) else {}
        template_id = str(obj.get("template-id", ""))[:150]
        name = str(info.get("name") or template_id or "Nuclei finding")[:300]
        severity, original = normalize_severity(info.get("severity"))
        matched = str(obj.get("matched-at") or obj.get("host") or "")[:2048]
        classification_raw = info.get("classification")
        classification: dict[str, Any] = (
            classification_raw if isinstance(classification_raw, dict) else {}
        )
        cwe_field = classification.get("cwe-id")
        cwe_text = " ".join(cwe_field) if isinstance(cwe_field, list) else str(cwe_field or "")
        cve_field = classification.get("cve-id")
        cves = cve_field if isinstance(cve_field, list) else ([cve_field] if cve_field else [])
        references = info.get("reference")
        refs = (
            [str(r)[:500] for r in references][:50]
            if isinstance(references, list)
            else ([str(references)[:500]] if references else [])
        )
        description = truncate(info.get("description"))
        if cves:
            description = (description + "\n\nCVE: " + ", ".join(str(c) for c in cves[:20])).strip()
        matcher_status = obj.get("matcher-status")
        confidence = normalize_confidence(None, weak_evidence=matcher_status is False)
        result.findings.append(
            ParsedFinding(
                title=name,
                severity=severity,
                confidence=confidence,
                original_severity=original,
                original_confidence="",
                summary=description or f"Nuclei template {template_id} matched.",
                technical_detail=truncate(json_excerpt(obj)),
                category=truncate(",".join(str(t) for t in (info.get("tags") or [])[:10]), 200),
                url=matched or None,
                host=_urlsplit_host(matched) if matched else None,
                cwe_ids=extract_cwe_ids(cwe_text),
                rule_id=template_id,
                source_finding_id=truncate(f"{template_id}:{matched}", 300),
                remediation=truncate(info.get("remediation")),
                references=refs,
                row=row,
            )
        )
        result.parsed_count += 1


def json_excerpt(obj: dict[str, Any]) -> str:
    safe = {k: v for k, v in obj.items() if k not in ("curl-command",)}
    return json.dumps(safe, default=str)[:3000]


ADAPTER: Adapter = NucleiJsonlAdapter()
