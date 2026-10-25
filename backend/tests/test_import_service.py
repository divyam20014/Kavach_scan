"""Service-level tests: preview is read-only, commit creates/reobserves, redaction runs on
every tool-derived field, and provenance (sources/dedup_history) survives commit."""

from __future__ import annotations

from app.core.redaction import redact_text
from app.imports.adapters.generic_json import ADAPTER as GENERIC_JSON
from app.imports.service import commit, parse_upload, preview
from app.models.common import new_id
from app.storage.repository import StorageRepository
from tests import importfixtures as fx
from tests.surfacefixtures import surface_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(surface_project([80], hosts=["x.test"])).project_id


def test_preview_does_not_write_any_canonical_record(repo: StorageRepository) -> None:
    pid = _project(repo)
    adapter, result = parse_upload("findings.json", fx.GENERIC_JSON)
    prev = preview(repo, pid, adapter, result)
    assert prev.parsed_count == 1
    assert repo.list_findings(pid).total == 0
    assert repo.list_assets(pid).total == 0


def test_commit_then_reobserve_on_second_identical_import(repo: StorageRepository) -> None:
    pid = _project(repo)
    adapter, result = parse_upload("findings.json", fx.GENERIC_JSON)
    imp_1 = new_id("import")
    summary1 = commit(repo, pid, imp_1, adapter, result)
    assert summary1.findings_created == 1
    assert summary1.findings_reobserved == 0
    findings = repo.list_findings(pid).items
    assert len(findings) == 1
    assert len(findings[0].sources) == 1
    assert findings[0].sources[0].import_id == imp_1

    # Re-import the exact same report under a different import_id: same fingerprint ->
    # reobserved, not duplicated.
    adapter2, result2 = parse_upload("findings.json", fx.GENERIC_JSON)
    imp_2 = new_id("import")
    summary2 = commit(repo, pid, imp_2, adapter2, result2)
    assert summary2.findings_created == 0
    assert summary2.findings_reobserved == 1
    findings_after = repo.list_findings(pid).items
    assert len(findings_after) == 1  # still one Finding, not two
    assert len(findings_after[0].sources) == 2
    assert {s.import_id for s in findings_after[0].sources} == {imp_1, imp_2}
    assert findings_after[0].dedup_history[-1].action == "reobserved"


def test_commit_redacts_tool_derived_text_fields(repo: StorageRepository) -> None:
    pid = _project(repo)
    secret_summary = "Login succeeded with Authorization: Bearer sk-ABCDEFGHIJKLMNOPQRSTUVWX"  # noqa: S105
    raw = (
        f'[{{"title": "Leaked token in logs", "severity": "high", "summary": "{secret_summary}"}}]'
    ).encode()
    adapter, result = parse_upload("leak.json", raw)
    commit(repo, pid, new_id("import"), adapter, result)
    stored = repo.list_findings(pid).items[0]
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in stored.summary
    assert stored.summary == redact_text(secret_summary, max_chars=20_000)


def test_commit_creates_assets_from_nmap_import(repo: StorageRepository) -> None:
    pid = _project(repo)
    adapter, result = parse_upload("scan.xml", fx.NMAP_XML)
    summary = commit(repo, pid, new_id("import"), adapter, result)
    assert summary.assets_created > 0
    assets = repo.list_assets(pid).items
    assert any(a.locator == "10.0.0.5" for a in assets)


def test_commit_marks_needs_review_confidence_as_needs_review_status(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    adapter, result = parse_upload("report.pdf", fx.PDF_MINIMAL)
    commit(repo, pid, new_id("import"), adapter, result)
    stored = repo.list_findings(pid).items[0]
    assert stored.analyst_status == "needs_review"


def test_preview_flags_update_existing_when_fingerprint_matches(repo: StorageRepository) -> None:
    pid = _project(repo)
    adapter, result = parse_upload("findings.json", fx.GENERIC_JSON)
    commit(repo, pid, new_id("import"), adapter, result)
    adapter2, result2 = parse_upload("findings.json", fx.GENERIC_JSON)
    prev = preview(repo, pid, adapter2, result2)
    assert prev.records[0].action == "update_existing"
    assert prev.records[0].existing_finding_id is not None


def test_generic_json_sniff_still_works_without_options() -> None:
    assert GENERIC_JSON.sniff("x.json", fx.GENERIC_JSON)


def test_preview_and_commit_collapse_duplicate_ids_within_a_single_import(
    repo: StorageRepository,
) -> None:
    """A single report that lists the same vulnerability twice (e.g. a scanner quirk, or
    the same plugin firing on two separate crawl passes merged into one export) must become
    exactly one Finding, both in the dry-run preview AND on commit — never two."""
    pid = _project(repo)
    raw = b"""[
        {"title": "Outdated jQuery (dup A)", "severity": "medium", "host": "10.0.0.3",
         "rule_id": "CVE-2020-11023", "parameter": ""},
        {"title": "Outdated jQuery (dup B, different wording)", "severity": "medium",
         "host": "10.0.0.3", "rule_id": "CVE-2020-11023", "parameter": ""}
    ]"""
    adapter, result = parse_upload("dupe.json", raw)
    assert result.parsed_count == 2

    prev = preview(repo, pid, adapter, result)
    assert prev.records[0].action == "new"
    assert prev.records[1].action == "duplicate_in_import"
    assert prev.records[1].duplicate_of_index == 0
    assert prev.records[1].existing_finding_id is None

    summary = commit(repo, pid, new_id("import"), adapter, result)
    assert summary.findings_created == 1
    assert summary.findings_reobserved == 1
    findings = repo.list_findings(pid).items
    assert len(findings) == 1
    assert len(findings[0].sources) == 2
    assert findings[0].dedup_history[-1].action == "reobserved"


def test_original_severity_and_confidence_and_rule_id_survive_commit_and_reobserve(
    repo: StorageRepository,
) -> None:
    """Normalization must not destroy the source's own rating or identifiers: the mapped
    Severity/Confidence is what the project uses for triage, but the original scanner-reported
    values and rule id must still be readable from FindingSource after commit, and again
    after a second import causes a re-observe (not a fresh, provenance-free record)."""
    pid = _project(repo)
    raw = b'[{"title": "SQLi in login", "severity": "Critical", "confidence": "firm", "rule_id": "nessus-99999", "host": "10.0.0.2"}]'
    adapter, result = parse_upload("rated.json", raw)
    assert result.findings[0].original_severity == "Critical"
    imp_1 = new_id("import")
    commit(repo, pid, imp_1, adapter, result)
    stored = repo.list_findings(pid).items[0]
    source = stored.sources[0]
    assert source.original_severity == "Critical"
    assert source.original_confidence == "firm"
    assert source.rule_id == "nessus-99999"
    assert source.tool == "Generic JSON"
    assert source.import_id == imp_1

    # Re-import under a different import_id: the new source entry is appended, not
    # replaced, so every import's original rating remains individually inspectable.
    adapter2, result2 = parse_upload("rated.json", raw)
    imp_2 = new_id("import")
    commit(repo, pid, imp_2, adapter2, result2)
    stored_after = repo.list_findings(pid).items[0]
    assert len(stored_after.sources) == 2
    assert all(s.original_severity == "Critical" for s in stored_after.sources)
    assert {s.import_id for s in stored_after.sources} == {imp_1, imp_2}
    # the canonical, normalized rating used for triage is separate from, and unaffected by,
    # the per-source original rating
    assert stored_after.severity == "critical"


def test_xss_payload_in_imported_title_is_stored_verbatim_not_executed(
    repo: StorageRepository,
) -> None:
    """Untrusted content must never be interpreted as markup at storage time; it is escaped
    only at render time (React's default text escaping — see frontend/src/test/imports.test.tsx).
    Storage must preserve it exactly so the operator can see what the scanner actually found."""
    import json

    pid = _project(repo)
    payload = "<script>alert(1)</script>"
    raw = json.dumps([{"title": payload, "severity": "low"}]).encode()
    adapter, result = parse_upload("xss.json", raw)
    assert result.findings[0].title == payload
    commit(repo, pid, new_id("import"), adapter, result)
    stored = repo.list_findings(pid).items[0]
    assert stored.title == payload  # never stripped, never HTML-encoded in storage
    assert "&lt;" not in stored.title
