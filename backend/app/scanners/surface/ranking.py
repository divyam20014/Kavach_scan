"""Transparent asset prioritization (internal triage aid, NOT a CVSS score).

score = criticality points + worst-finding points + exposure points, every term listed.
- criticality (operator-entered): low 5, medium 10, high 20, critical 30; unset 0;
- worst open finding attached to the asset or any descendant, counting only `confirmed`
  or `probable` findings that are not marked false-positive/fixed/accepted:
  critical 40, high 30, medium 20, low 10, informational 0;
- exposure: +10 if a database/admin/cleartext service on the asset (or below it) is reachable;
- discovery alone adds nothing: an asset with no findings and no criticality scores 0
  and says so.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.models.asset import Asset
from app.models.common import AnalystStatus, Confidence, Severity
from app.models.finding import Finding
from app.scanners.surface.rules import ADMIN_PORTS, CLEARTEXT_PORTS, DATABASE_PORTS

CRITICALITY_POINTS = {"low": 5, "medium": 10, "high": 20, "critical": 30}
SEVERITY_POINTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 30,
    Severity.MEDIUM: 20,
    Severity.LOW: 10,
    Severity.INFORMATIONAL: 0,
}
COUNTED_CONFIDENCE = {Confidence.CONFIRMED, Confidence.PROBABLE}
CLOSED_STATUS = {AnalystStatus.FALSE_POSITIVE, AnalystStatus.FIXED, AnalystStatus.ACCEPTED_RISK}
SENSITIVE_PORTS = set(DATABASE_PORTS) | set(ADMIN_PORTS) | set(CLEARTEXT_PORTS)


def rank(assets: list[Asset], findings: list[Finding]) -> dict[str, dict[str, Any]]:
    children: dict[str, list[str]] = defaultdict(list)
    for a in assets:
        for parent in {a.parent_asset_id, *a.related_asset_ids} - {None}:
            children[parent].append(a.asset_id)  # type: ignore[index]
    by_id = {a.asset_id: a for a in assets}
    direct: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.confidence in COUNTED_CONFIDENCE and f.analyst_status not in CLOSED_STATUS:
            for aid in f.affected_asset_ids:
                direct[aid].append(f)

    memo: dict[str, tuple[list[Finding], bool]] = {}

    def subtree(aid: str, seen: frozenset[str] = frozenset()) -> tuple[list[Finding], bool]:
        if aid in memo:
            return memo[aid]
        asset = by_id.get(aid)
        found = list(direct.get(aid, []))
        exposed = bool(asset and asset.attributes.get("port") in SENSITIVE_PORTS)
        for child in children.get(aid, []):
            if child in seen:
                continue
            sub_f, sub_e = subtree(child, seen | {aid})
            found += sub_f
            exposed = exposed or sub_e
        memo[aid] = (found, exposed)
        return memo[aid]

    out: dict[str, dict[str, Any]] = {}
    for asset in assets:
        found, exposed = subtree(asset.asset_id)
        factors: list[str] = []
        score = 0
        if asset.criticality:
            points = CRITICALITY_POINTS[asset.criticality]
            score += points
            factors.append(f"+{points} operator criticality: {asset.criticality}")
        if found:
            worst = max(found, key=lambda f: SEVERITY_POINTS[f.severity])
            points = SEVERITY_POINTS[worst.severity]
            score += points
            factors.append(
                f"+{points} worst open finding: {worst.severity.value} "
                f"({worst.title[:80]}; {len({f.finding_id for f in found})} finding(s))"
            )
        if exposed:
            score += 10
            factors.append("+10 database/admin/cleartext service reachable")
        if not factors:
            factors.append("0: discovered only (discovery is not a vulnerability)")
        out[asset.asset_id] = {
            "score": score,
            "factors": factors,
            "findings": len({f.finding_id for f in found}),
        }
    return out
