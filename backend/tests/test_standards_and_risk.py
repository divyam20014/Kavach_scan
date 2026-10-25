"""Phase 09: standards catalog provenance, CVSS validation, and the internal risk formula."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.models.asset import Asset
from app.models.common import AssetType, Confidence, ScopeStatus, Severity, new_id
from app.models.cvss_calc import CvssValidationError, compute_base_score
from app.models.finding import CvssRecord, Finding, StandardMapping
from app.services.risk import formula_description, score_finding
from app.standards import CATALOGS, cwe_title


def test_catalogs_carry_independent_versions_and_provenance() -> None:
    assert CATALOGS["owasp_top10"].version == "2025"
    assert CATALOGS["owasp_api_top10"].version == "2023"
    assert CATALOGS["owasp_top10"].version != CATALOGS["owasp_api_top10"].version
    for info in CATALOGS.values():
        assert info.source
        assert info.imported_at
        assert info.entry_count > 0
        assert info.coverage_note  # every catalog admits what it does and does not cover


def test_standard_mapping_requires_a_non_empty_catalog_version() -> None:
    """Required-work item 5: "Store catalog provenance/version" on every mapping — enforced
    structurally, not just by convention: a StandardMapping cannot be constructed at all
    without a non-empty catalog_version."""
    with pytest.raises(ValidationError):
        StandardMapping(catalog="owasp_top10", catalog_version="", entry_id="A01")
    with pytest.raises(ValidationError):
        StandardMapping(catalog="cwe", entry_id="CWE-79")  # type: ignore[call-arg]
    ok = StandardMapping(catalog="owasp_top10", catalog_version="2025", entry_id="A01")
    assert ok.catalog_version == "2025"


def test_every_standard_mapping_emitted_by_the_web_rule_catalog_carries_its_catalog_version() -> (
    None
):
    """End-to-end: run the actual rule-to-mapping code path (not just the model in
    isolation) and confirm every emitted mapping names a real, non-empty catalog version
    matching the live catalog registry — not a stale or placeholder string."""
    from app.standards import CATALOGS

    for finding in make_web_scan_findings_with_mappings():
        for mapping in finding.mappings:
            assert mapping.catalog_version
            assert mapping.catalog_version == CATALOGS[mapping.catalog].version


def make_web_scan_findings_with_mappings() -> list[Finding]:
    """Minimal real exercise of `app.scanners.webapp.findings.FindingWriter` to produce
    Findings the way a live scan actually does, rather than hand-building `Finding` objects
    (which would not prove the production code path attaches mappings correctly)."""
    import tempfile
    from pathlib import Path

    from app.core.settings import RuntimeSettings
    from app.models.common import new_id
    from app.scanners.webapp.findings import FindingWriter
    from app.scanners.webapp.rules import RULES, CheckResult, Outcome
    from app.storage.repository import StorageRepository
    from tests.surfacefixtures import surface_project

    tmp = Path(tempfile.mkdtemp())
    settings = RuntimeSettings(data_dir=str(tmp / "data"))
    repo = StorageRepository.open(settings)
    try:
        pid = repo.create_project(surface_project([443], hosts=["x.test"])).project_id
        scan_id = new_id("scan")
        writer = FindingWriter(repo, pid, scan_id)
        candidates = [r for r in RULES.values() if r.owasp or r.cwe][:3]
        created_ids = []
        for rule in candidates:
            result = CheckResult(
                rule_id=rule.rule_id,
                outcome=Outcome.FINDING,
                subject="https://x.test/",
                rationale="test",
                detail="test",
            )
            finding_id = writer.write(result)
            if finding_id:
                created_ids.append(finding_id)
        return [repo.get_finding(pid, fid) for fid in created_ids]
    finally:
        repo.close()


def test_cwe_title_is_honest_about_what_it_does_not_know() -> None:
    assert cwe_title(79) == "Cross-Site Scripting (XSS)"
    assert cwe_title(999_999) == ""  # outside the curated subset: no invented title


def test_compute_base_score_matches_the_library_and_rejects_garbage() -> None:
    assert compute_base_score("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    with pytest.raises(CvssValidationError):
        compute_base_score("3.1", "not a vector")
    with pytest.raises(CvssValidationError):
        compute_base_score("9.9", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_cvss_record_rejects_a_score_that_does_not_match_its_vector() -> None:
    """The acceptance criterion "CVSS values are not fabricated": supplying a vector with
    an unrelated/made-up score must fail validation, not be stored verbatim."""
    with pytest.raises(ValidationError, match="does not match"):
        CvssRecord(
            version="3.1",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=1.0,  # the real score for this vector is 9.8
            source="supplied",
        )


def test_cvss_record_accepts_a_correct_vector_and_score() -> None:
    rec = CvssRecord(
        version="3.1",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
        source="supplied",
    )
    assert rec.base_score == 9.8


def _finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "finding_id": new_id("finding"),
        "project_id": new_id("project"),
        "title": "t",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.NEEDS_REVIEW,
    }
    data.update(overrides)
    return Finding(**data)  # type: ignore[arg-type]


def test_needs_review_confidence_can_never_reach_the_critical_tier() -> None:
    """Hard requirement: 'avoid upgrading speculative findings to Critical.'"""
    worst_case = _finding(
        severity=Severity.CRITICAL,
        confidence=Confidence.NEEDS_REVIEW,
        verification_state="manually_verified",
        url="https://x.test/",
    )
    asset = Asset(
        asset_id=new_id("asset"),
        project_id=worst_case.project_id,
        asset_type=AssetType.URL,
        locator="https://x.test/",
        confidence=Confidence.CONFIRMED,
        scope_status=ScopeStatus.IN_SCOPE,
        criticality="critical",
    )
    breakdown = score_finding(worst_case, [asset])
    assert breakdown.tier != "critical"
    assert breakdown.tier == "high"


def test_confirmed_critical_with_full_corroboration_reaches_critical_tier() -> None:
    f = _finding(
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        verification_state="manually_verified",
        url="https://x.test/",
    )
    asset = Asset(
        asset_id=new_id("asset"),
        project_id=f.project_id,
        asset_type=AssetType.URL,
        locator="https://x.test/",
        confidence=Confidence.CONFIRMED,
        scope_status=ScopeStatus.IN_SCOPE,
        criticality="critical",
    )
    breakdown = score_finding(f, [asset])
    assert breakdown.tier == "critical"
    assert breakdown.score == 100.0


def test_severity_alone_does_not_determine_the_tier() -> None:
    """Two CRITICAL findings with different confidence/evidence must score differently —
    severity is an input, never the whole story."""
    confirmed = _finding(severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED)
    needs_review = _finding(severity=Severity.CRITICAL, confidence=Confidence.NEEDS_REVIEW)
    assert score_finding(confirmed, []).score > score_finding(needs_review, []).score


def test_risk_score_never_mutates_the_stored_severity_or_confidence() -> None:
    f = _finding(severity=Severity.LOW, confidence=Confidence.POTENTIAL)
    score_finding(f, [])
    assert f.severity == Severity.LOW  # scoring is read-only; never writes back
    assert f.confidence == Confidence.POTENTIAL


def test_score_is_bounded_zero_to_one_hundred() -> None:
    low = _finding(severity=Severity.INFORMATIONAL, confidence=Confidence.POTENTIAL)
    assert 0.0 <= score_finding(low, []).score <= 100.0
    high = _finding(
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        verification_state="manually_verified",
        url="https://x.test/",
    )
    assert 0.0 <= score_finding(high, []).score <= 100.0


def test_formula_description_is_visible_and_matches_the_module_constants() -> None:
    desc: dict[str, Any] = formula_description()
    assert desc["severity_points"]["critical"] == 100.0
    assert desc["confidence_multiplier"]["needs_review"] == 0.35
    assert desc["needs_review_tier_ceiling"] == "high"
    assert "not cvss" in str(desc["notes"]).lower()  # explicit, not just silent omission
    assert "vector" not in desc and "base_score" not in desc  # no CVSS-shaped fields here
