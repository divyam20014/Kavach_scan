"""Phase 09: findings workbench service — list/filter/search, module derivation, triage
edits, comments, merge/unmerge, and that none of this ever discards original source data."""

from __future__ import annotations

import pytest

from app.core.errors import ConflictError, ValidationFailedError
from app.models.common import AnalystStatus, Severity, new_id
from app.models.finding import FindingSource
from app.services import findings as svc
from app.storage.repository import StorageRepository
from tests.conftest import make_finding
from tests.surfacefixtures import surface_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(surface_project([80], hosts=["x.test"])).project_id


def test_module_for_uses_the_documented_rule_id_prefixes() -> None:
    pid = new_id("project")
    assert svc.module_for(make_finding(pid, rule_id="WEB-TLS-001")) == "web_app"
    assert svc.module_for(make_finding(pid, rule_id="SURF-SVC-001")) == "attack_surface"
    assert svc.module_for(make_finding(pid, rule_id="API-AUTH-001")) == "api_security"
    imported = make_finding(pid, rule_id="nmap-open-mysql",
                            sources=[FindingSource(tool="Nmap XML", import_id=new_id("import"))])
    assert svc.module_for(imported) == "import"
    assert svc.module_for(make_finding(pid, rule_id="")) == "unknown"


def test_list_findings_filters_by_severity_and_free_text_search(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="Reflected XSS in search", severity="high"))
    repo.create_finding(make_finding(pid, title="Outdated jQuery", severity="low"))
    page = svc.list_findings(repo, filters=svc.FindingListFilters(project_id=pid, severity={Severity.HIGH}))
    assert page.total == 1 and page.items[0].finding.title == "Reflected XSS in search"
    page2 = svc.list_findings(repo, filters=svc.FindingListFilters(project_id=pid, q="jquery"))
    assert page2.total == 1 and page2.items[0].finding.title == "Outdated jQuery"
    page3 = svc.list_findings(repo, filters=svc.FindingListFilters(project_id=pid, q="nonexistent"))
    assert page3.total == 0


def test_list_findings_filters_by_cwe_and_mapping(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="A", cwe_ids=[79]))
    repo.create_finding(make_finding(pid, title="B", cwe_ids=[89]))
    page = svc.list_findings(repo, filters=svc.FindingListFilters(project_id=pid, cwe=79))
    assert page.total == 1 and page.items[0].finding.title == "A"


def test_list_findings_reviewed_filter_tracks_analyst_status(repo: StorageRepository) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid, title="New one"))
    svc.update_finding(repo, pid, f.finding_id,
                       changes={"analyst_status": "confirmed"}, expected_revision=1)
    repo.create_finding(make_finding(pid, title="Still new"))
    reviewed = svc.list_findings(repo, filters=svc.FindingListFilters(project_id=pid, reviewed=True))
    assert reviewed.total == 1 and reviewed.items[0].finding.title == "New one"
    unreviewed = svc.list_findings(repo, filters=svc.FindingListFilters(project_id=pid, reviewed=False))
    assert unreviewed.total == 1 and unreviewed.items[0].finding.title == "Still new"


def test_list_findings_sorts_by_risk_score(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="low risk", severity="low",
                                     confidence="potential"))
    repo.create_finding(make_finding(pid, title="high risk", severity="critical",
                                     confidence="confirmed"))
    page = svc.list_findings(repo, filters=svc.FindingListFilters(project_id=pid),
                             sort="risk_score", descending=True)
    assert [it.finding.title for it in page.items] == ["high risk", "low risk"]


def test_merged_findings_are_excluded_by_default_but_visible_on_request(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    original = repo.create_finding(make_finding(pid, title="Original"))
    dup = repo.create_finding(make_finding(pid, title="Duplicate"))
    svc.merge_finding(repo, pid, dup.finding_id, into_finding_id=original.finding_id,
                      expected_revision=1)
    default_page = svc.list_findings(repo, filters=svc.FindingListFilters(project_id=pid))
    assert default_page.total == 1
    with_merged = svc.list_findings(
        repo, filters=svc.FindingListFilters(project_id=pid, include_merged=True)
    )
    assert with_merged.total == 2


def test_update_finding_rejects_edits_to_scanner_owned_fields(repo: StorageRepository) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    with pytest.raises(ValidationFailedError, match="cannot edit"):
        svc.update_finding(repo, pid, f.finding_id, changes={"severity": "critical"},
                           expected_revision=1)
    with pytest.raises(ValidationFailedError, match="cannot edit"):
        svc.update_finding(repo, pid, f.finding_id, changes={"cwe_ids": [1]},
                           expected_revision=1)


def test_update_finding_preserves_original_source_data(repo: StorageRepository) -> None:
    """Acceptance criterion: 'Analysts can triage and revise a finding without losing
    original source data.'"""
    source = FindingSource(tool="vapt-web-scanner", rule_id="WEB-TLS-001",
                           original_severity="Medium")
    f = repo.create_finding(make_finding(pid := (_project(repo)), sources=[source],
                                         cwe_ids=[79], rule_id="WEB-TLS-001"))
    updated = svc.update_finding(
        repo, pid, f.finding_id,
        changes={"analyst_status": "confirmed", "business_impact": "Affects checkout"},
        expected_revision=1,
    )
    assert updated.analyst_status == AnalystStatus.CONFIRMED
    assert updated.business_impact == "Affects checkout"
    # everything the scanner wrote is untouched
    assert updated.sources == f.sources
    assert updated.cwe_ids == [79]
    assert updated.rule_id == "WEB-TLS-001"
    assert updated.severity == f.severity
    assert updated.confidence == f.confidence


def test_add_comment_appends_without_losing_prior_comments(repo: StorageRepository) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    r1 = svc.add_comment(repo, pid, f.finding_id, text="first note", expected_revision=1)
    r2 = svc.add_comment(repo, pid, f.finding_id, text="second note", expected_revision=r1.revision)
    assert [c.text for c in r2.comments] == ["first note", "second note"]
    assert all(c.author == "local-operator" for c in r2.comments)  # no fabricated identities


def test_merge_and_unmerge_round_trip_preserves_both_records(repo: StorageRepository) -> None:
    pid = _project(repo)
    original = repo.create_finding(make_finding(pid, title="Original"))
    dup = repo.create_finding(make_finding(pid, title="Duplicate"))
    merged_dup, merged_target = svc.merge_finding(
        repo, pid, dup.finding_id, into_finding_id=original.finding_id,
        expected_revision=1, note="same root cause",
    )
    assert merged_dup.merged_into == original.finding_id
    assert merged_dup.dedup_history[-1].action == "merged"
    assert merged_target.dedup_history[-1].action == "merged"
    # the duplicate's own record (title, sources) still exists — nothing was deleted
    still_there = repo.get_finding(pid, dup.finding_id)
    assert still_there.title == "Duplicate"

    unmerged = svc.unmerge_finding(repo, pid, dup.finding_id, expected_revision=merged_dup.revision)
    assert unmerged.merged_into is None
    assert unmerged.dedup_history[-1].action == "unmerged"


def test_merge_never_drops_source_provenance_from_either_record(repo: StorageRepository) -> None:
    """Explicit check that merging is a cross-reference, not a data-destructive operation:
    each record's own `sources`/`evidence_ids`/`cwe_ids`/`rule_id` survive untouched, and the
    duplicate stays fully retrievable (both directly and via the canonical record's detail
    view) for rollback."""
    original_source = FindingSource(tool="vapt-web-scanner", rule_id="WEB-TLS-001")
    dup_source = FindingSource(tool="Nessus (.nessus XML)", rule_id="nessus-12345",
                               import_id=new_id("import"))
    pid = _project(repo)
    original = repo.create_finding(make_finding(
        pid, title="Original", sources=[original_source], cwe_ids=[79], evidence_ids=[],
    ))
    dup = repo.create_finding(make_finding(
        pid, title="Duplicate", sources=[dup_source], cwe_ids=[89],
    ))

    merged_dup, merged_target = svc.merge_finding(
        repo, pid, dup.finding_id, into_finding_id=original.finding_id, expected_revision=1,
    )

    # neither record's own provenance/evidence is touched by the merge
    assert merged_dup.sources == [dup_source]
    assert merged_dup.cwe_ids == [89]
    assert merged_target.sources == [original_source]
    assert merged_target.cwe_ids == [79]

    # both are still independently fetchable with everything intact
    refetched_dup = repo.get_finding(pid, dup.finding_id)
    refetched_original = repo.get_finding(pid, original.finding_id)
    assert refetched_dup.sources == [dup_source]
    assert refetched_original.sources == [original_source]

    # the canonical record's detail view surfaces the duplicate (and its data) for review
    detail = svc.get_finding_detail(repo, pid, original.finding_id)
    assert len(detail.merged_duplicates) == 1
    assert detail.merged_duplicates[0].sources == [dup_source]


def test_merge_rejects_merging_into_self_and_double_merge(repo: StorageRepository) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    with pytest.raises(ValidationFailedError, match="itself"):
        svc.merge_finding(repo, pid, f.finding_id, into_finding_id=f.finding_id,
                          expected_revision=1)
    other = repo.create_finding(make_finding(pid, title="other"))
    merged, _ = svc.merge_finding(repo, pid, f.finding_id, into_finding_id=other.finding_id,
                                  expected_revision=1)
    with pytest.raises(ConflictError):
        svc.merge_finding(repo, pid, f.finding_id, into_finding_id=other.finding_id,
                          expected_revision=merged.revision)


def test_unmerge_rejects_a_finding_that_is_not_merged(repo: StorageRepository) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    with pytest.raises(ConflictError):
        svc.unmerge_finding(repo, pid, f.finding_id, expected_revision=1)


def test_get_finding_detail_reports_module_risk_and_merge_lineage(repo: StorageRepository) -> None:
    pid = _project(repo)
    original = repo.create_finding(make_finding(pid, title="Original", rule_id="WEB-TLS-001"))
    dup = repo.create_finding(make_finding(pid, title="Duplicate"))
    svc.merge_finding(repo, pid, dup.finding_id, into_finding_id=original.finding_id,
                      expected_revision=1)
    detail = svc.get_finding_detail(repo, pid, original.finding_id)
    assert detail.module == "web_app"
    assert "tier" in detail.risk and "score" in detail.risk
    assert [d.finding_id for d in detail.merged_duplicates] == [dup.finding_id]

    dup_detail = svc.get_finding_detail(repo, pid, dup.finding_id)
    assert dup_detail.duplicate_of is not None
    assert dup_detail.duplicate_of.finding_id == original.finding_id
