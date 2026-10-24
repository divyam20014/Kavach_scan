"""Nmap XML report import (`nmap -oX`). Open ports become asset inventory; only the same
exposure classes the live Attack Surface Mapper flags (database/admin/cleartext services,
and a disclosed service version) become findings — "a port is open" is not a vulnerability.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from app.imports.base import Adapter, ParsedAsset, ParsedFinding, ParseResult, truncate
from app.imports.safety import ImportSafetyError, parse_xml_safely
from app.models.common import Confidence, Severity
from app.scanners.surface.rules import ADMIN_PORTS, CLEARTEXT_PORTS, DATABASE_PORTS

PARSER_VERSION = "vapt-import-nmap-xml 1.0.0"


class NmapXmlAdapter:
    source_type = "nmap_xml"
    label = "Nmap XML"
    parser_version = PARSER_VERSION

    def sniff(self, filename: str, raw: bytes) -> bool:
        head = raw.lstrip()[:4096]
        return ((filename.lower().endswith(".xml") or b"<nmaprun" in head) and
                b"<nmaprun" in raw[:65536])

    def parse(self, raw: bytes, *, options: dict[str, Any] | None = None) -> ParseResult:
        result = ParseResult()
        try:
            root = parse_xml_safely(raw)
        except ImportSafetyError as exc:
            raise ImportSafetyError(f"Nmap XML: {exc}") from exc
        if root.tag != "nmaprun":
            raise ImportSafetyError("not an Nmap XML report (missing <nmaprun> root)")
        version = root.get("version", "")
        result.source_tool_version = f"Nmap {version}" if version else "Nmap (version unknown)"
        hosts = root.findall("host")
        for row, host in enumerate(hosts, start=1):
            try:
                self._parse_host(host, result)
            except Exception as exc:  # noqa: BLE001 - one bad host must not fail the import
                result.rejected_count += 1
                result.warn(f"row {row}: could not parse host entry ({type(exc).__name__})")
        if not hosts:
            result.warn("no <host> entries found in this report")
        return result

    def _parse_host(self, host: ET.Element, result: ParseResult) -> None:
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            return
        address_el = next((a for a in host.findall("address") if a.get("addrtype") in
                           ("ipv4", "ipv6")), None)
        ip = address_el.get("addr", "") if address_el is not None else ""
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""
        if not ip and not hostname:
            result.warn("host entry has no usable address or hostname; skipped")
            return
        primary = hostname or ip
        if ip:
            result.assets.append(ParsedAsset(asset_type="ip", locator=ip,
                                             parent_locator=hostname or None,
                                             observation="imported from Nmap XML"))
        if hostname:
            result.assets.append(ParsedAsset(asset_type="hostname", locator=hostname,
                                             observation="imported from Nmap XML"))
        for port_el in host.findall("ports/port"):
            if port_el.get("protocol") != "tcp":
                continue  # UDP results are inventoried nowhere in this build; TCP only for now
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            try:
                port = int(port_el.get("portid", ""))
            except (TypeError, ValueError):
                result.rejected_count += 1
                result.warn(f"{primary}: port entry has a non-numeric portid; skipped")
                continue
            svc = port_el.find("service")
            service = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            svc_version = svc.get("version", "") if svc is not None else ""
            extra = svc.get("extrainfo", "") if svc is not None else ""
            host_ref = ip or hostname
            bracketed = f"[{host_ref}]" if ":" in host_ref else host_ref
            port_locator = f"tcp://{bracketed}:{port}"
            result.assets.append(ParsedAsset(
                asset_type="port", locator=port_locator, parent_locator=ip or hostname,
                observation=truncate(f"service={service} product={product} version={svc_version} "
                                     f"{extra}".strip(), 480)))
            label = DATABASE_PORTS.get(port) or ADMIN_PORTS.get(port) or CLEARTEXT_PORTS.get(port)
            if label:
                result.findings.append(ParsedFinding(
                    title=f"{label} service reachable", severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED, original_severity="", original_confidence="",
                    summary=f"Nmap reported TCP port {port} ({label}) open on {primary}.",
                    technical_detail=truncate(
                        f"service={service} product={product} version={svc_version} {extra}"),
                    category="exposure", host=host_ref, parameter=str(port),
                    component=truncate(f"{product} {svc_version}".strip()),
                    rule_id=f"nmap-open-{label}", source_finding_id=f"{host_ref}:{port}/tcp"))
            if product and svc_version:
                result.findings.append(ParsedFinding(
                    title="Service banner discloses product version",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.CONFIRMED, original_severity="", original_confidence="",
                    summary=f"{product} {svc_version} identified on {primary}:{port} by Nmap "
                    "service/version detection.",
                    technical_detail=truncate(f"service={service} product={product} "
                                              f"version={svc_version} {extra}"),
                    category="information-disclosure", host=host_ref, parameter=str(port),
                    component=truncate(f"{product} {svc_version}"),
                    rule_id="nmap-version-disclosure", source_finding_id=f"{host_ref}:{port}/tcp"))
            result.parsed_count += 1


ADAPTER: Adapter = NmapXmlAdapter()
