"""Internal risk prioritization score (MASTER_SPEC Module 9).

This is deliberately NOT CVSS and is never presented as CVSS. It is a transparent,
documented, code-level formula combining signals the project already has honest data
for — technical severity, scanner confidence, exploit evidence (verification state),
asset criticality, and a simple network-exposure proxy — so an analyst can triage without
any single tool's severity label being taken as the final word. See docs/RISK_SCORING.md
for the full worked rationale and weight table; this module is the single source of truth
both documents describe.

Hard rule (explicitly required): a finding with `Confidence.NEEDS_REVIEW` — i.e. one the
normalization pipeline could not evidence well — can never reach the "critical" risk tier,
regardless of its other inputs. This stops a speculative, unverified finding from being
visually indistinguishable from a confirmed critical one.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.asset import Asset, Criticality
from app.models.common import Confidence, Severity
from app.models.finding import Finding

# --------------------------------------------------------------------------- weights
# All weights are plain module constants: visible by reading this file, and by the
# GET /api/risk-formula endpoint that serializes them for the UI. Changing them is a
# deliberate code change (not a hidden runtime toggle), so every change is reviewable.

SEVERITY_POINTS: dict[Severity, float] = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 75.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 25.0,
    Severity.INFORMATIONAL: 5.0,
}

CONFIDENCE_MULTIPLIER: dict[Confidence, float] = {
    Confidence.CONFIRMED: 1.0,
    Confidence.PROBABLE: 0.8,
    Confidence.POTENTIAL: 0.55,
    Confidence.NEEDS_REVIEW: 0.35,
}

ASSET_CRITICALITY_BONUS: dict[str, float] = {
    "critical": 15.0,
    "high": 8.0,
    "medium": 0.0,
    "low": -5.0,
}
ASSET_CRITICALITY_BONUS_UNSET = 0.0  # no operator-assigned criticality on any linked asset

EXPOSURE_BONUS = 10.0  # the finding has a URL: it was observed over the network, not inferred
EXPOSURE_BONUS_NONE = 0.0

VERIFICATION_BONUS: dict[str, float] = {
    "manually_verified": 15.0,
    "automated_evidence": 5.0,
    "unverified": 0.0,
}

# Tier bands over the 0-100 raw score, independent of (and never fed back into) Severity.
_TIER_BANDS: tuple[tuple[float, str], ...] = (
    (85.0, "critical"),
    (65.0, "high"),
    (40.0, "medium"),
    (15.0, "low"),
)
_INFORMATIONAL_TIER = "informational"

# Hard ceiling: a NEEDS_REVIEW-confidence finding can never be scored into a tier above this,
# no matter how high its other inputs push the raw score.
_NEEDS_REVIEW_TIER_CEILING = "high"
_TIER_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


@dataclass(frozen=True)
class RiskBreakdown:
    severity_points: float
    confidence_multiplier: float
    severity_after_confidence: float
    asset_criticality_bonus: float
    exposure_bonus: float
    verification_bonus: float
    raw_score: float
    score: float  # raw_score clamped to [0, 100]
    tier: str
    capped_for_needs_review: bool

    def as_dict(self) -> dict[str, float | str | bool]:
        return {
            "severity_points": self.severity_points,
            "confidence_multiplier": self.confidence_multiplier,
            "severity_after_confidence": self.severity_after_confidence,
            "asset_criticality_bonus": self.asset_criticality_bonus,
            "exposure_bonus": self.exposure_bonus,
            "verification_bonus": self.verification_bonus,
            "raw_score": self.raw_score,
            "score": self.score,
            "tier": self.tier,
            "capped_for_needs_review": self.capped_for_needs_review,
        }


def max_asset_criticality(assets: list[Asset]) -> Criticality | None:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    best: Criticality | None = None
    for asset in assets:
        if asset.criticality is None:
            continue
        if best is None or rank[asset.criticality] > rank[best]:
            best = asset.criticality
    return best


def score_finding(finding: Finding, linked_assets: list[Asset] | None = None) -> RiskBreakdown:
    """Compute the documented internal risk score for one finding. `linked_assets` should
    be the already-loaded `Asset` records for `finding.affected_asset_ids` (callers batch
    this lookup; passing none scores the finding as having no criticality signal)."""
    severity_points = SEVERITY_POINTS[finding.severity]
    confidence_mult = CONFIDENCE_MULTIPLIER[finding.confidence]
    severity_after_confidence = severity_points * confidence_mult

    criticality = max_asset_criticality(linked_assets or [])
    asset_bonus = (
        ASSET_CRITICALITY_BONUS[criticality] if criticality else ASSET_CRITICALITY_BONUS_UNSET
    )
    exposure_bonus = EXPOSURE_BONUS if finding.url else EXPOSURE_BONUS_NONE
    verification_bonus = VERIFICATION_BONUS[finding.verification_state]

    raw = severity_after_confidence + asset_bonus + exposure_bonus + verification_bonus
    score = max(0.0, min(100.0, raw))

    tier = _INFORMATIONAL_TIER
    for threshold, name in _TIER_BANDS:
        if score >= threshold:
            tier = name
            break

    capped = False
    if finding.confidence == Confidence.NEEDS_REVIEW and (
        _TIER_RANK[tier] > _TIER_RANK[_NEEDS_REVIEW_TIER_CEILING]
    ):
        tier = _NEEDS_REVIEW_TIER_CEILING
        capped = True

    return RiskBreakdown(
        severity_points=severity_points,
        confidence_multiplier=confidence_mult,
        severity_after_confidence=round(severity_after_confidence, 2),
        asset_criticality_bonus=asset_bonus,
        exposure_bonus=exposure_bonus,
        verification_bonus=verification_bonus,
        raw_score=round(raw, 2),
        score=round(score, 2),
        tier=tier,
        capped_for_needs_review=capped,
    )


def formula_description() -> dict[str, object]:
    """Serializable description of the formula and its weights, for `GET /api/risk-formula`
    — the "formula and weights must be visible" requirement (MASTER_SPEC §9)."""
    return {
        "formula": (
            "score = clamp(severity_points[severity] * confidence_multiplier[confidence] "
            "+ asset_criticality_bonus + exposure_bonus + verification_bonus, 0, 100); "
            "tier is banded from score, then capped at 'high' when confidence is "
            "needs_review, regardless of score."
        ),
        "severity_points": {k.value: v for k, v in SEVERITY_POINTS.items()},
        "confidence_multiplier": {k.value: v for k, v in CONFIDENCE_MULTIPLIER.items()},
        "asset_criticality_bonus": {
            **ASSET_CRITICALITY_BONUS,
            "none": ASSET_CRITICALITY_BONUS_UNSET,
        },
        "exposure_bonus": {"has_url": EXPOSURE_BONUS, "no_url": EXPOSURE_BONUS_NONE},
        "verification_bonus": VERIFICATION_BONUS,
        "tier_bands": {name: threshold for threshold, name in _TIER_BANDS}
        | {_INFORMATIONAL_TIER: 0.0},
        "needs_review_tier_ceiling": _NEEDS_REVIEW_TIER_CEILING,
        "notes": (
            "This is an internal prioritization aid, not CVSS and not a claim of exploit "
            "likelihood. It never upgrades a finding's stored Severity/Confidence; those "
            "remain exactly what the scanner or import reported. Exposure is a simple "
            "proxy (whether the finding has a URL) — not a verified internet-reachability "
            "assessment."
        ),
    }
