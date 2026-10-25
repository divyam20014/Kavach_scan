"""Normalized JSON/CSV exports for findings and assets (MASTER_SPEC §10.2 item 6).

Driven by the same `ReportData` snapshot the HTML/PDF renderers use, so an operator
comparing a CSV export against the report sees the identical finding set — never a
separately-resolved query that could silently drift.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from app.reports.builder import ReportData

FINDINGS_JSON_SCHEMA_VERSION = 1
ASSETS_JSON_SCHEMA_VERSION = 1

_FINDING_CSV_COLUMNS = [
    "finding_id",
    "title",
    "severity",
    "confidence",
    "analyst_status",
    "business_priority",
    "module",
    "url",
    "parameter",
    "component",
    "cwe_ids",
    "owasp_mappings",
    "cvss_vector",
    "cvss_base_score",
    "remediation",
    "rule_id",
    "first_seen",
    "last_seen",
]
_ASSET_CSV_COLUMNS = [
    "asset_id",
    "asset_type",
    "locator",
    "scope_status",
    "criticality",
    "confidence",
    "first_seen",
    "last_seen",
]


def _owasp_mapping_text(finding: Any) -> str:
    return "; ".join(f"{m.catalog}:{m.catalog_version}:{m.entry_id}" for m in finding.mappings)


_FORMULA_LEAD_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: object) -> str:
    """Prevent CSV/formula injection (OWASP): a free-text field (finding title, remediation,
    an imported asset locator…) that starts with a spreadsheet-formula trigger character would
    otherwise execute as a formula when a client opens the export in Excel/Sheets. Prefixing
    with a single quote neutralizes it while leaving the value human-readable."""
    text = str(value)
    if text.startswith(_FORMULA_LEAD_CHARS):
        return "'" + text
    return text


def findings_to_json(data: ReportData) -> bytes:
    payload = {
        "schema_version": FINDINGS_JSON_SCHEMA_VERSION,
        "project_id": data.project.project_id,
        "generated_at": data.generated_at.isoformat(),
        "filters": data.filters.as_dict(),
        "count": len(data.findings),
        "findings": [
            json.loads(f.model_dump_json())  # reuse the model's own JSON-safe serialization
            for f in data.findings
        ],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def findings_to_csv(data: ReportData) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_FINDING_CSV_COLUMNS)
    from app.services.findings import module_for

    for f in data.findings:
        writer.writerow(
            [
                _csv_safe(v)
                for v in (
                    f.finding_id,
                    f.title,
                    f.severity.value,
                    f.confidence.value,
                    f.analyst_status.value,
                    f.business_priority or "",
                    module_for(f),
                    f.url or "",
                    f.parameter,
                    f.component,
                    ",".join(str(c) for c in f.cwe_ids),
                    _owasp_mapping_text(f),
                    f.cvss.vector if f.cvss else "",
                    f.cvss.base_score if f.cvss else "",
                    f.remediation,
                    f.rule_id,
                    f.created_at.isoformat(),
                    f.updated_at.isoformat(),
                )
            ]
        )
    return buf.getvalue().encode("utf-8")


def assets_to_json(data: ReportData) -> bytes:
    payload = {
        "schema_version": ASSETS_JSON_SCHEMA_VERSION,
        "project_id": data.project.project_id,
        "generated_at": data.generated_at.isoformat(),
        "count": len(data.assets),
        "assets": [json.loads(a.model_dump_json()) for a in data.assets],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def assets_to_csv(data: ReportData) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_ASSET_CSV_COLUMNS)
    for a in data.assets:
        writer.writerow(
            [
                _csv_safe(v)
                for v in (
                    a.asset_id,
                    a.asset_type.value,
                    a.locator,
                    a.scope_status.value,
                    a.criticality or "",
                    a.confidence.value,
                    a.first_seen.isoformat(),
                    a.last_seen.isoformat(),
                )
            ]
        )
    return buf.getvalue().encode("utf-8")
