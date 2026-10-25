"""Canonical normalized finding.

CVSS is stored only as a supplied/calculated vector with its score; a bare
number is rejected (MASTER_SPEC §5.4). Technical severity, confidence and
analyst status are separate fields and never derived from one another
implicitly.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from app.models.common import (
    AnalystStatus,
    AssetId,
    CommentId,
    Confidence,
    EvidenceId,
    FindingId,
    ImportId,
    LongText,
    Name,
    ProjectId,
    Record,
    ScanId,
    Severity,
    Sha256Hex,
    ShortText,
    StrictModel,
    UtcDatetime,
    utc_now,
)
from app.models.cvss_calc import CALCULATOR_LABEL, compute_base_score
from app.models.project import HttpUrlStr

FINDING_SCHEMA_VERSION: Literal[1] = 1

_CVSS31 = re.compile(
    r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
    r"(/[A-Za-z]{1,3}:[A-Za-z]{1,2})*$"
)
_CVSS40 = re.compile(
    r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]"
    r"/SC:[HLN]/SI:[HLN]/SA:[HLN](/[A-Za-z]{1,3}:[A-Za-z]{1,2})*$"
)


def severity_from_cvss(score: float) -> Severity:
    """Qualitative rating for a CVSS v3.x/v4.0 base score (FIRST bands).

    0.0 → None (mapped to informational), 0.1–3.9 low, 4.0–6.9 medium,
    7.0–8.9 high, 9.0–10.0 critical. This maps a score; it never computes one.
    """
    if not 0.0 <= score <= 10.0:
        raise ValueError("CVSS base score must be between 0.0 and 10.0")
    score = round(score, 1)
    if score == 0.0:
        return Severity.INFORMATIONAL
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


class CvssRecord(StrictModel):
    version: Literal["3.1", "4.0"]
    vector: Annotated[str, StringConstraints(max_length=300)]
    base_score: float = Field(ge=0.0, le=10.0)
    source: Literal["supplied", "calculated"]
    calculator: ShortText = ""  # library name/version when source == "calculated"

    @model_validator(mode="after")
    def _vector_matches_version(self) -> CvssRecord:
        pattern = _CVSS31 if self.version == "3.1" else _CVSS40
        if not pattern.fullmatch(self.vector):
            raise ValueError(f"vector is not a valid CVSS {self.version} base vector")
        if self.source == "calculated" and not self.calculator:
            raise ValueError("calculated CVSS scores must name the calculator used")
        # TBD-019: a CVSS score is never trusted verbatim from an untrusted source (a
        # scanner, an import, or operator input) — it must match what the maintained
        # `cvss` library itself computes from the vector, or it is rejected outright.
        computed = compute_base_score(self.version, self.vector)
        if abs(computed - self.base_score) > 0.05:
            raise ValueError(
                f"base_score {self.base_score} does not match the score computed from "
                f"the vector ({computed}) by {CALCULATOR_LABEL}; a CVSS score is always "
                "verified against its vector, never accepted verbatim"
            )
        return self


class StandardMapping(StrictModel):
    """A mapping to a versioned catalog entry, e.g. OWASP Top 10:2025 A05."""

    catalog: Literal["owasp_top10", "owasp_api_top10", "cwe"]
    catalog_version: Annotated[str, StringConstraints(min_length=1, max_length=32)]
    entry_id: Annotated[str, StringConstraints(min_length=1, max_length=32)]
    title: ShortText = ""
    rationale: ShortText = ""
    confidence: Confidence = Confidence.PROBABLE


class FindingSource(StrictModel):
    tool: Name
    tool_version: ShortText = ""
    rule_id: ShortText = ""
    source_finding_id: ShortText = ""
    original_severity: ShortText = ""
    original_confidence: ShortText = ""
    import_id: ImportId | None = None
    scan_id: ScanId | None = None
    observed_at: UtcDatetime = Field(default_factory=utc_now)


class DedupEvent(StrictModel):
    action: Literal["merged", "unmerged", "reobserved"]
    other_finding_id: FindingId | None = None
    at: UtcDatetime = Field(default_factory=utc_now)
    note: ShortText = ""


def _cwe(value: int) -> int:
    if value <= 0 or value > 100_000:
        raise ValueError("CWE ids are positive integers")
    return value


# Phase 09: analyst-visible business priority, distinct from scanner-reported Severity and
# never derived from it automatically — an analyst sets this deliberately (MASTER_SPEC §9:
# "keep severity, confidence... separate").
BusinessPriority = Literal["p1", "p2", "p3", "p4"]


class FindingComment(StrictModel):
    """A free-text analyst note. There is no multi-user identity system in this release
    (TBD-003); `author` is always the fixed local-operator actor, never a fabricated name."""

    comment_id: CommentId
    author: Name = "local-operator"
    text: LongText
    created_at: UtcDatetime = Field(default_factory=utc_now)


class Finding(Record):
    schema_version: Literal[1] = FINDING_SCHEMA_VERSION
    finding_id: FindingId
    project_id: ProjectId
    scan_id: ScanId | None = None
    fingerprint: Sha256Hex | None = None
    title: Name
    summary: LongText = ""
    technical_detail: LongText = ""
    category: ShortText = ""
    affected_asset_ids: list[AssetId] = Field(default_factory=list, max_length=500)
    url: HttpUrlStr | None = None
    method: Annotated[str, StringConstraints(pattern=r"^[A-Z]{3,10}$")] | None = None
    parameter: ShortText = ""
    component: ShortText = ""
    severity: Severity
    confidence: Confidence
    verification_state: Literal["unverified", "automated_evidence", "manually_verified"] = (
        "unverified"
    )
    analyst_status: AnalystStatus = AnalystStatus.NEW
    business_impact: LongText = ""
    evidence_ids: list[EvidenceId] = Field(default_factory=list, max_length=500)
    cwe_ids: list[Annotated[int, AfterValidator(_cwe)]] = Field(default_factory=list, max_length=20)
    mappings: list[StandardMapping] = Field(default_factory=list, max_length=20)
    cvss: CvssRecord | None = None
    remediation: LongText = ""
    references: list[HttpUrlStr] = Field(default_factory=list, max_length=50)
    rule_id: ShortText = ""
    sources: list[FindingSource] = Field(default_factory=list, max_length=200)
    dedup_history: list[DedupEvent] = Field(default_factory=list, max_length=500)
    # Phase 09 (optional, backward compatible additions):
    business_priority: BusinessPriority | None = None
    comments: list[FindingComment] = Field(default_factory=list, max_length=500)
    # Set when this Finding was manually merged into another as a confirmed duplicate. The
    # record is never deleted (preserves source data/provenance/rollback per MASTER_SPEC
    # §8.3); it is just excluded from the default workbench view and flagged on its detail
    # page. Cleared by an explicit unmerge, which also restores it to normal visibility.
    merged_into: FindingId | None = None
