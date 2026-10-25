"""Canonical draft records and the adapter protocol every import format implements.

An adapter never touches storage. It turns validated, bounded bytes into `ParseResult`:
canonical draft findings/assets plus warnings and counts. `ImportService` (service.py) is
the only code that writes `Finding`/`Asset`/`Evidence` records, and only on an explicit
commit — never during detection or the dry-run preview.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from app.models.common import Confidence, Severity

MAX_TEXT_FIELD = 4000  # a single normalized text field this long is truncated, not rejected

_SEVERITY_ALIASES: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "severe": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "note": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "information": Severity.INFORMATIONAL,
    "unknown": Severity.INFORMATIONAL,
    "none": Severity.INFORMATIONAL,
    "error": Severity.MEDIUM,  # SARIF "error" level: a tool-reported defect, not CVSS
}


def normalize_severity(raw: str | float | int | None) -> tuple[Severity, str]:
    """Map a tool-specific severity/level/risk string to our scale. Returns
    `(normalized, original_as_string)`; the original is kept verbatim for provenance.
    Unrecognized values fall back to INFORMATIONAL rather than guessing upward, and the
    caller should emit a warning so the operator can review the mapping."""
    if raw is None:
        return Severity.INFORMATIONAL, ""
    original = str(raw).strip()
    key = original.lower()
    if key in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key], original
    # Numeric scales: CVSS-like 0-10, or a 0-4/0-5 tool-specific ordinal (Nessus: 0-4).
    try:
        score = float(key)
    except ValueError:
        return Severity.INFORMATIONAL, original
    if score <= 0:
        return Severity.INFORMATIONAL, original
    if 0 < score <= 4 and score == int(score):  # Nessus-style 0/1/2/3/4 ordinal
        return [
            Severity.INFORMATIONAL,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ][int(score)], original
    if score < 4.0:
        return Severity.LOW, original
    if score < 7.0:
        return Severity.MEDIUM, original
    if score < 9.0:
        return Severity.HIGH, original
    return Severity.CRITICAL, original


def normalize_confidence(raw: str | None, *, weak_evidence: bool = False) -> Confidence:
    """Map a tool's own confidence/certainty label. `weak_evidence` forces NEEDS_REVIEW
    regardless of the label (e.g. a record whose decisive fields could not be parsed)."""
    if weak_evidence:
        return Confidence.NEEDS_REVIEW
    key = (raw or "").strip().lower()
    if key in ("confirmed", "certain", "high", "firm"):
        return Confidence.CONFIRMED
    if key in ("firm-ish", "probable", "likely", "medium"):
        return Confidence.PROBABLE
    if key in ("tentative", "low", "possible", "potential"):
        return Confidence.POTENTIAL
    return Confidence.PROBABLE  # a tool that reports a finding at all is asserting it fired


def truncate(text: str | None, limit: int = MAX_TEXT_FIELD) -> str:
    if not text:
        return ""
    text = str(text)
    return text if len(text) <= limit else text[: limit - len("...[truncated]")] + "...[truncated]"


_CWE_RE = re.compile(r"CWE[-:]?\s*(\d{1,6})", re.IGNORECASE)


def extract_cwe_ids(*texts: str | None) -> list[int]:
    """Pull CWE numbers out of free text or an explicit identifier field (e.g. "CWE-79")."""
    out: list[int] = []
    for text in texts:
        if not text:
            continue
        for match in _CWE_RE.finditer(str(text)):
            value = int(match.group(1))
            if 0 < value <= 100_000 and value not in out:
                out.append(value)
    return out[:20]


@dataclass
class ParsedFinding:
    """A draft finding, not yet a canonical `Finding`. `row` is 1-based for error messages."""

    title: str
    severity: Severity
    confidence: Confidence
    original_severity: str = ""
    original_confidence: str = ""
    summary: str = ""
    technical_detail: str = ""
    category: str = ""
    url: str | None = None
    host: str | None = None  # used for asset linking/dedup when no URL is available
    method: str | None = None
    parameter: str = ""
    component: str = ""
    cwe_ids: list[int] = field(default_factory=list)
    rule_id: str = ""  # the tool's own rule/template/plugin id (e.g. Nuclei template-id)
    source_finding_id: str = ""  # the tool's own finding/issue id, if it has one
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    row: int = 0


@dataclass
class ParsedAsset:
    asset_type: Literal["domain", "hostname", "ip", "port", "service", "url", "api_operation"]
    locator: str
    parent_locator: str | None = None
    observation: str = ""


@dataclass
class ParseResult:
    findings: list[ParsedFinding] = field(default_factory=list)
    assets: list[ParsedAsset] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    parsed_count: int = 0  # records successfully turned into a ParsedFinding
    rejected_count: int = 0  # records that could not be normalized at all
    source_tool_version: str = ""
    # Canonical fields the generic CSV/JSON adapters could not map to any source column
    # (operator-visible in the dry-run preview, distinct from per-row warnings).
    mapping_gaps: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        if len(self.warnings) < 1000:
            self.warnings.append(truncate(message, 500))


class Adapter(Protocol):
    source_type: str  # one of ImportSourceType
    label: str
    parser_version: str

    def sniff(self, filename: str, raw: bytes) -> bool:
        """Cheap, best-effort format detection (extension + magic bytes/shape). Never
        raises; returns False when unsure."""
        ...

    def parse(self, raw: bytes, *, options: dict[str, Any] | None = None) -> ParseResult:
        """Parse bounded, pre-safety-checked bytes. `options` is an adapter-specific,
        operator-supplied configuration dict (e.g. the generic CSV/JSON adapters' column
        mapping overrides); adapters that take no options ignore it. May raise
        `ImportSafetyError` / `ValueError` for a fatal, whole-file problem; a bad
        individual record should instead be skipped with `result.rejected_count += 1`
        and a warning (partial success), never silently dropped and never a 500."""
        ...
