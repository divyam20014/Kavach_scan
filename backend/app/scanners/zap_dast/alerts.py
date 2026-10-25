"""Parsing OWASP ZAP's `traditional-json` Automation Framework report into normalized
alert records. Confirmed directly against real output captured from a local ZAP 2.17.0
run (`report['site'][].alerts[].{pluginid,alert,riskcode,confidence,desc,instances,...}`),
not assumed from documentation alone.

This module never writes a file or runs anything -- it only parses bytes a caller already
read (through the storage layer).
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.models.common import Confidence, Severity

_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://[^\s<>\"]+")
MAX_TEXT_CHARS = 4000
MAX_REFERENCES = 20
MAX_INSTANCES = 200

#: ZAP's own `riskcode`: 0 Informational, 1 Low, 2 Medium, 3 High.
RISK_TO_SEVERITY: dict[str, Severity] = {
    "0": Severity.INFORMATIONAL,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}
#: ZAP's own `confidence`: 0 False Positive, 1 Low, 2 Medium, 3 High, 4 Confirmed. A
#: passive/baseline scan never confirms exploitation by sending test input, so even ZAP's
#: own "Confirmed" rating is capped at PROBABLE here -- the same posture this project's
#: native passive rules (WEB-REFL-001, WEB-DBERR-001) already take, never CONFIRMED from
#: observation alone.
CONFIDENCE_TO_OURS: dict[str, Confidence] = {
    "0": Confidence.NEEDS_REVIEW,
    "1": Confidence.POTENTIAL,
    "2": Confidence.POTENTIAL,
    "3": Confidence.PROBABLE,
    "4": Confidence.PROBABLE,
}


class ZapReportError(ValueError):
    """The report could not be interpreted; no alert may be claimed from it."""


def _strip_html(value: object) -> str:
    text = html.unescape(_TAG_RE.sub(" ", str(value or "")))
    return " ".join(text.split())[:MAX_TEXT_CHARS]


def _references(value: object) -> list[str]:
    return _URL_RE.findall(str(value or ""))[:MAX_REFERENCES]


def _cwe_id(value: object) -> int | None:
    if value in (None, "", "-1"):
        return None
    try:
        parsed = int(str(value))
    except ValueError:
        return None
    return parsed if 0 < parsed < 100_000 else None


@dataclass(frozen=True)
class ZapInstance:
    uri: str
    method: str
    param: str
    evidence: str


@dataclass(frozen=True)
class ZapAlert:
    plugin_id: str
    alert: str
    risk_code: str
    confidence_code: str
    description: str
    solution: str
    references: list[str]
    cwe_id: int | None
    site: str
    instances: list[ZapInstance] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return RISK_TO_SEVERITY.get(self.risk_code, Severity.INFORMATIONAL)

    @property
    def confidence(self) -> Confidence:
        return CONFIDENCE_TO_OURS.get(self.confidence_code, Confidence.NEEDS_REVIEW)


def _instance(raw: Any) -> ZapInstance | None:
    if not isinstance(raw, dict):
        return None
    return ZapInstance(
        uri=str(raw.get("uri", ""))[:2048],
        method=str(raw.get("method", "GET"))[:10],
        param=str(raw.get("param", ""))[:200],
        evidence=str(raw.get("evidence", ""))[:500],
    )


def _alert(raw: Any, site_name: str) -> ZapAlert | None:
    if not isinstance(raw, dict):
        return None
    raw_instances = raw.get("instances")
    instances = (
        [i for i in (_instance(r) for r in raw_instances) if i is not None][:MAX_INSTANCES]
        if isinstance(raw_instances, list)
        else []
    )
    return ZapAlert(
        plugin_id=str(raw.get("pluginid", ""))[:20],
        alert=str(raw.get("alert", raw.get("name", "")))[:200],
        risk_code=str(raw.get("riskcode", "")),
        confidence_code=str(raw.get("confidence", "")),
        description=_strip_html(raw.get("desc", "")),
        solution=_strip_html(raw.get("solution", "")),
        references=_references(raw.get("reference", "")),
        cwe_id=_cwe_id(raw.get("cweid")),
        site=site_name,
        instances=instances,
    )


def parse_traditional_json_report(data: bytes) -> list[ZapAlert]:
    """Raises `ZapReportError` on anything unparseable -- a malformed or unexpected report
    shape must never silently yield "no alerts" (that would look identical to a genuinely
    clean scan)."""
    try:
        parsed: Any = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ZapReportError("ZAP report is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ZapReportError("ZAP report is not a JSON object")
    sites = parsed.get("site")
    if not isinstance(sites, list):
        raise ZapReportError("ZAP report has no 'site' list")
    out: list[ZapAlert] = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        site_name = str(site.get("@name", ""))
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        out.extend(a for a in (_alert(raw, site_name) for raw in alerts) if a is not None)
    return out
