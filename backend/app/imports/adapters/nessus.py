"""Nessus `.nessus` XML report import (TBD-023).

Nessus CSV exports are not given a dedicated adapter: their columns (Risk, Name, Synopsis,
Description, Solution, Plugin ID, Host...) already match the generic CSV adapter's alias
table, so a Nessus CSV export is imported correctly by `generic_csv` without bespoke code
(verified by `tests/test_import_generic_csv.py::test_nessus_style_csv_export`). This
adapter covers the richer, authoritative `.nessus` XML format.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from app.imports.base import (
    Adapter,
    ParsedAsset,
    ParsedFinding,
    ParseResult,
    extract_cwe_ids,
    normalize_confidence,
    normalize_severity,
    truncate,
)
from app.imports.safety import ImportSafetyError, parse_xml_safely

PARSER_VERSION = "vapt-import-nessus-xml 1.0.0"


class NessusAdapter:
    source_type = "nessus"
    label = "Nessus (.nessus XML)"
    parser_version = PARSER_VERSION

    def sniff(self, filename: str, raw: bytes) -> bool:
        return (filename.lower().endswith(".nessus") or
                (filename.lower().endswith(".xml") and b"NessusClientData" in raw[:65536]))

    def parse(self, raw: bytes, *, options: dict[str, Any] | None = None) -> ParseResult:
        result = ParseResult()
        try:
            root = parse_xml_safely(raw)
        except ImportSafetyError as exc:
            raise ImportSafetyError(f"Nessus: {exc}") from exc
        if "NessusClientData" not in root.tag:
            raise ImportSafetyError("not a Nessus .nessus XML report")
        hosts = root.findall(".//ReportHost")
        row = 0
        for host in hosts:
            host_name = host.get("name", "")
            props = {t.get("name", ""): (t.text or "") for t in host.findall("HostProperties/tag")}
            ip = props.get("host-ip", "") or host_name
            fqdn = props.get("host-fqdn", "")
            if ip:
                result.assets.append(ParsedAsset(asset_type="ip", locator=ip,
                                                 parent_locator=fqdn or None,
                                                 observation="imported from Nessus"))
            if fqdn:
                result.assets.append(ParsedAsset(asset_type="hostname", locator=fqdn,
                                                 observation="imported from Nessus"))
            for item in host.findall("ReportItem"):
                row += 1
                try:
                    self._parse_item(item, ip or host_name, result)
                except Exception as exc:  # noqa: BLE001 - one bad item must not fail the import
                    result.rejected_count += 1
                    result.warn(f"item {row}: could not normalize ({type(exc).__name__})")
        if row == 0:
            result.warn("no <ReportItem> entries found in this report")
        return result

    def _parse_item(self, item: ET.Element, host: str, result: ParseResult) -> None:
        plugin_id = item.get("pluginID", "")
        plugin_name = item.get("pluginName", "") or f"Nessus plugin {plugin_id}"
        port = item.get("port", "0")
        protocol = item.get("protocol", "tcp")
        severity, original = normalize_severity(item.get("severity"))
        risk_factor = (item.findtext("risk_factor") or "").strip()
        if risk_factor and risk_factor.lower() != "none":
            severity, original = normalize_severity(risk_factor)
        synopsis = truncate(item.findtext("synopsis"))
        description = truncate(item.findtext("description"))
        solution = truncate(item.findtext("solution"))
        cves = [c.text.strip() for c in item.findall("cve") if c.text and c.text.strip()]
        xrefs = " ".join((x.text or "") for x in item.findall("xref"))
        cvss = item.findtext("cvss_base_score") or item.findtext("cvss3_base_score")
        summary = synopsis or description
        if cves:
            summary = (summary + "\n\nCVE: " + ", ".join(cves[:20])).strip()
        result.findings.append(ParsedFinding(
            title=truncate(plugin_name, 300), severity=severity,
            confidence=normalize_confidence(None, weak_evidence=False),
            original_severity=original or (cvss or ""), original_confidence="",
            summary=summary, technical_detail=description,
            remediation=solution, host=host, parameter=f"{port}/{protocol}",
            component=truncate(plugin_name, 300),
            cwe_ids=extract_cwe_ids(xrefs),
            rule_id=f"nessus-{plugin_id}",
            source_finding_id=f"{host}:{port}/{protocol}#{plugin_id}",
        ))
        result.parsed_count += 1


ADAPTER: Adapter = NessusAdapter()
