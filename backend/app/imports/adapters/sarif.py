"""SARIF 2.1.0 import (static analysis / code-scanning tool output)."""

from __future__ import annotations

import json
from typing import Any

from app.imports.base import (
    Adapter,
    ParsedFinding,
    ParseResult,
    extract_cwe_ids,
    normalize_confidence,
    truncate,
)
from app.imports.safety import ImportSafetyError, check_json_bounds
from app.models.common import Severity

PARSER_VERSION = "vapt-import-sarif 1.0.0"

_LEVEL_TO_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFORMATIONAL,
}


class SarifAdapter:
    source_type = "sarif"
    label = "SARIF 2.1.0"
    parser_version = PARSER_VERSION

    def sniff(self, filename: str, raw: bytes) -> bool:
        if not (filename.lower().endswith((".sarif", ".json")) or b'"runs"' in raw[:65536]):
            return False
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        return (
            isinstance(obj, dict)
            and "runs" in obj
            and (
                "sarif" in str(obj.get("$schema", "")).lower()
                or str(obj.get("version", "")).startswith("2.")
            )
        )

    def parse(self, raw: bytes, *, options: dict[str, Any] | None = None) -> ParseResult:
        result = ParseResult()
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ImportSafetyError(f"SARIF: invalid JSON ({exc})") from exc
        check_json_bounds(doc)
        if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
            raise ImportSafetyError("SARIF: missing or malformed 'runs' array")
        version = str(doc.get("version", "unknown"))
        tools: list[str] = []
        row = 0
        for run in doc["runs"]:
            if not isinstance(run, dict):
                continue
            raw_driver = (
                (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else {}
            )
            driver: dict[str, Any] = raw_driver if isinstance(raw_driver, dict) else {}
            tool_name = str(driver.get("name", "unknown-tool"))
            tool_version = str(driver.get("version", ""))
            tools.append(f"{tool_name} {tool_version}".strip())
            rules = {
                str(r.get("id")): r
                for r in driver.get("rules", [])
                if isinstance(r, dict) and r.get("id")
            }
            for res in run.get("results", []) or []:
                row += 1
                try:
                    self._parse_result(res, rules, tool_name, result)
                except Exception as exc:  # noqa: BLE001 - one bad result must not fail the import
                    result.rejected_count += 1
                    result.warn(f"result {row}: could not normalize ({type(exc).__name__})")
        result.source_tool_version = (
            (f"SARIF {version}; " + ", ".join(tools)) if tools else f"SARIF {version}"
        )
        if row == 0:
            result.warn("SARIF document contained no results")
        return result

    def _parse_result(
        self, res: Any, rules: dict[str, Any], tool_name: str, result: ParseResult
    ) -> None:
        if not isinstance(res, dict):
            result.rejected_count += 1
            result.warn("a result entry was not an object; skipped")
            return
        rule_id = str(res.get("ruleId", ""))[:150]
        rule: dict[str, Any] = rules.get(rule_id, {})
        default_config: dict[str, Any] = rule.get("defaultConfiguration") or {}
        level = str(res.get("level") or default_config.get("level") or "warning").lower()
        severity = _LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM)
        message = (
            self._text(res.get("message")) or self._text(rule.get("shortDescription")) or rule_id
        )
        description = self._text(rule.get("fullDescription")) or self._text(rule.get("help"))
        tags: list[str] = []
        props: dict[str, Any] = rule.get("properties") or {}
        if isinstance(props.get("tags"), list):
            tags = [str(t) for t in props["tags"]][:20]
        uri, line = self._location(res)
        result.findings.append(
            ParsedFinding(
                title=truncate(message, 300) or rule_id or "SARIF finding",
                severity=severity,
                confidence=normalize_confidence(None),
                original_severity=level,
                original_confidence="",
                summary=truncate(description or message),
                technical_detail=truncate(f"rule={rule_id} tool={tool_name} location={uri}:{line}"),
                category=truncate(",".join(tags), 200),
                component=truncate(uri, 500),
                parameter=str(line) if line else "",
                cwe_ids=extract_cwe_ids(*tags, rule_id),
                rule_id=rule_id,
                source_finding_id=truncate(f"{rule_id}@{uri}:{line}", 300),
                references=[str(h) for h in (rule.get("helpUri"),) if h][:5],
            )
        )
        result.parsed_count += 1

    @staticmethod
    def _text(node: Any) -> str:
        if isinstance(node, dict):
            return str(node.get("text", ""))
        return ""

    @staticmethod
    def _location(res: dict[str, Any]) -> tuple[str, int]:
        locs = res.get("locations")
        if not isinstance(locs, list) or not locs or not isinstance(locs[0], dict):
            return "", 0
        phys = locs[0].get("physicalLocation")
        if not isinstance(phys, dict):
            return "", 0
        artifact: dict[str, Any] = phys.get("artifactLocation") or {}
        region: dict[str, Any] = phys.get("region") or {}
        uri = str(artifact.get("uri", ""))[:500]
        try:
            line = int(region.get("startLine", 0))
        except (TypeError, ValueError):
            line = 0
        return uri, line


ADAPTER: Adapter = SarifAdapter()
