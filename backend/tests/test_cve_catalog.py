"""Phase 11: local CVE catalog import, version matching, and the CveCatalog adapter."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from app.core.settings import RuntimeSettings
from app.cve.matcher import StoredCveCatalog
from app.cve.parser import CveCatalogParseError, parse_catalog_file
from app.cve.version import VersionSpecError, parse_version_spec, version_satisfies_spec
from app.models.common import Confidence, utc_now
from app.models.cve_catalog import CveCatalogRecord
from app.scanners.webapp.components import Component, cve_results
from app.storage.repository import StorageRepository


def _good_catalog_bytes(**overrides: object) -> bytes:
    payload: dict[str, object] = {
        "source": "Internal curated export",
        "catalog_version": "2026.10",
        "entries": [
            {"product": "jquery", "version_spec": "<1.12.4", "cve_id": "CVE-2015-9251"},
            {"product": "openssl", "version_spec": "==1.0.1", "cve_id": "CVE-2014-0160"},
        ],
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


# ---------------------------------------------------------------- version comparator


def test_version_spec_range_matching() -> None:
    assert version_satisfies_spec("1.12.3", "<1.12.4") is True
    assert version_satisfies_spec("1.12.4", "<1.12.4") is False
    assert version_satisfies_spec("2.0.0", ">=2.0,<2.3.1") is True
    assert version_satisfies_spec("2.3.1", ">=2.0,<2.3.1") is False
    assert version_satisfies_spec("1.0.1", "==1.0.1") is True
    assert version_satisfies_spec("1.0.2", "==1.0.1") is False


def test_version_spec_unparseable_is_none_not_a_guess() -> None:
    assert version_satisfies_spec("not-a-version", "<1.0") is None
    assert version_satisfies_spec("1.0.0", "not-a-spec") is None
    assert version_satisfies_spec("1.0.0", "") is None


def test_version_spec_rejects_malformed_conditions() -> None:
    with pytest.raises(VersionSpecError):
        parse_version_spec("~>1.0")  # not a supported operator
    with pytest.raises(VersionSpecError):
        parse_version_spec("")
    with pytest.raises(VersionSpecError):
        parse_version_spec("<1.0,")  # trailing empty condition


# ---------------------------------------------------------------- parser (malformed input)


def test_parse_catalog_file_accepts_a_well_formed_catalog() -> None:
    record = parse_catalog_file(_good_catalog_bytes(), file_name="catalog.json")
    assert record.source == "Internal curated export"
    assert record.catalog_version == "2026.10"
    assert len(record.entries) == 2
    assert record.file_name == "catalog.json"
    assert len(record.file_sha256) == 64


def test_parse_catalog_file_rejects_non_json() -> None:
    with pytest.raises(CveCatalogParseError, match="not valid JSON"):
        parse_catalog_file(b"not json at all")


def test_parse_catalog_file_rejects_empty_file() -> None:
    with pytest.raises(CveCatalogParseError, match="empty"):
        parse_catalog_file(b"")


def test_parse_catalog_file_rejects_oversized_file() -> None:
    import app.cve.parser as parser_mod

    old = parser_mod.MAX_CATALOG_BYTES
    parser_mod.MAX_CATALOG_BYTES = 100
    try:
        with pytest.raises(CveCatalogParseError, match="byte limit"):
            parse_catalog_file(_good_catalog_bytes())
    finally:
        parser_mod.MAX_CATALOG_BYTES = old


def test_parse_catalog_file_requires_source_and_version() -> None:
    with pytest.raises(CveCatalogParseError, match="required"):
        parse_catalog_file(json.dumps({"entries": []}).encode())


def test_parse_catalog_file_rejects_entries_not_a_list() -> None:
    with pytest.raises(CveCatalogParseError, match="'entries' must be a list"):
        parse_catalog_file(_good_catalog_bytes(entries={"not": "a list"}))


def test_parse_catalog_file_skips_malformed_individual_entries_with_a_warning() -> None:
    record = parse_catalog_file(
        _good_catalog_bytes(
            entries=[
                {"product": "jquery", "version_spec": "<1.12.4", "cve_id": "CVE-2015-9251"},
                {"product": "bad", "version_spec": "<1.0", "cve_id": "not-a-cve-id"},  # bad cve_id
                {"product": "bad2", "cve_id": "CVE-2020-0001"},  # missing version_spec
                {
                    "product": "bad3",
                    "version_spec": "~garbage~",
                    "cve_id": "CVE-2020-0002",
                },  # bad spec
                "not even an object",
            ]
        )
    )
    assert len(record.entries) == 1
    assert record.entries[0].cve_id == "CVE-2015-9251"
    assert len(record.warnings) == 4


def test_parse_catalog_file_rejects_a_catalog_with_zero_usable_entries() -> None:
    with pytest.raises(CveCatalogParseError, match="no usable entries"):
        parse_catalog_file(_good_catalog_bytes(entries=[{"product": "x", "cve_id": "bad"}]))


def test_parse_catalog_file_rejects_oversized_entry_count() -> None:
    import app.cve.parser as parser_mod

    old = parser_mod.MAX_ENTRIES
    parser_mod.MAX_ENTRIES = 2
    try:
        with pytest.raises(CveCatalogParseError, match="more than"):
            parse_catalog_file(
                _good_catalog_bytes(
                    entries=[
                        {"product": "a", "version_spec": "<1.0", "cve_id": "CVE-2020-0001"},
                        {"product": "b", "version_spec": "<1.0", "cve_id": "CVE-2020-0002"},
                        {"product": "c", "version_spec": "<1.0", "cve_id": "CVE-2020-0003"},
                    ]
                )
            )
    finally:
        parser_mod.MAX_ENTRIES = old


def test_parse_catalog_file_caps_stale_after_days_to_a_sane_range() -> None:
    record = parse_catalog_file(_good_catalog_bytes(stale_after_days=999999))
    assert record.stale_after_days == 3650


# ---------------------------------------------------------------- staleness


def test_catalog_staleness_is_derived_from_imported_at(repo: StorageRepository) -> None:
    record = parse_catalog_file(_good_catalog_bytes(stale_after_days=10))
    stale_record = record.model_copy(update={"imported_at": utc_now() - timedelta(days=11)})
    saved = repo.save_cve_catalog(stale_record)
    age_days = (utc_now() - saved.imported_at).days
    assert age_days > saved.stale_after_days


# ---------------------------------------------------------------- matcher / adapter contract


def test_stored_cve_catalog_is_unavailable_with_no_import(repo: StorageRepository) -> None:
    catalog = StoredCveCatalog(repo)
    assert catalog.available is False
    assert catalog.match("jquery", "1.11.0") == []


def test_stored_cve_catalog_matches_a_range_and_an_exact_entry(repo: StorageRepository) -> None:
    repo.save_cve_catalog(parse_catalog_file(_good_catalog_bytes()))
    catalog = StoredCveCatalog(repo)
    assert catalog.available is True

    range_matches = catalog.match("jquery", "1.11.0")
    assert len(range_matches) == 1
    assert range_matches[0].match == "range"
    assert range_matches[0].cve_id == "CVE-2015-9251"
    assert range_matches[0].catalog_id == "Internal curated export"

    exact_matches = catalog.match("openssl", "1.0.1")
    assert len(exact_matches) == 1
    assert exact_matches[0].match == "exact"

    assert catalog.match("jquery", "1.12.4") == []  # outside the affected range
    assert catalog.match("unknown-product", "1.0.0") == []  # no product-name match


def test_cve_match_exposes_source_version_and_date(repo: StorageRepository) -> None:
    """Acceptance criterion: "Confirm CVE matches expose catalog source/version/date."""
    repo.save_cve_catalog(parse_catalog_file(_good_catalog_bytes()))
    catalog = StoredCveCatalog(repo)
    matches = catalog.match("jquery", "1.11.0")
    assert len(matches) == 1
    m = matches[0]
    assert m.catalog_id == "Internal curated export"  # source
    assert m.catalog_version == "2026.10"
    assert m.catalog_date  # imported_at, ISO-8601, non-empty
    from datetime import datetime

    datetime.fromisoformat(m.catalog_date)  # must actually parse as a real timestamp


def test_cve_finding_rationale_includes_catalog_date(repo: StorageRepository) -> None:
    repo.save_cve_catalog(parse_catalog_file(_good_catalog_bytes()))
    catalog = StoredCveCatalog(repo)
    comp = Component(name="jquery", version="1.11.0", confidence=Confidence.CONFIRMED)
    results = [r for r in cve_results([comp], catalog) if r.rationale.startswith("CVE-")]
    assert len(results) == 1
    assert "imported" in results[0].rationale


def test_stored_cve_catalog_match_is_case_insensitive_on_product_but_exact_on_name(
    repo: StorageRepository,
) -> None:
    repo.save_cve_catalog(parse_catalog_file(_good_catalog_bytes()))
    catalog = StoredCveCatalog(repo)
    assert catalog.match("JQuery", "1.11.0")  # case-insensitive match
    assert catalog.match("jquery-ui", "1.11.0") == []  # no substring/fuzzy matching


def test_cve_results_never_marks_a_match_as_confirmed(repo: StorageRepository) -> None:
    """Acceptance criterion: "If ambiguous, create an observation or needs_review candidate,
    not confirmed vulnerability" — checked for both a range match (ambiguous) and an exact
    version-pin match (still only passive detection, never verified exploitation)."""
    repo.save_cve_catalog(parse_catalog_file(_good_catalog_bytes()))
    catalog = StoredCveCatalog(repo)

    range_comp = Component(name="jquery", version="1.11.0", confidence=Confidence.CONFIRMED)
    range_results = [
        r for r in cve_results([range_comp], catalog) if r.rationale.startswith("CVE-")
    ]
    assert len(range_results) == 1
    assert range_results[0].confidence != Confidence.CONFIRMED  # None -> rule default needs_review

    exact_comp = Component(name="openssl", version="1.0.1", confidence=Confidence.CONFIRMED)
    exact_results = [
        r for r in cve_results([exact_comp], catalog) if r.rationale.startswith("CVE-")
    ]
    assert len(exact_results) == 1
    assert exact_results[0].confidence == Confidence.PROBABLE  # elevated, but never confirmed


def test_cve_results_skipped_with_no_catalog() -> None:
    from app.scanners.webapp.components import NoCveCatalog

    comp = Component(name="jquery", version="1.11.0", confidence=Confidence.CONFIRMED)
    results = cve_results([comp], NoCveCatalog())
    assert len(results) == 1
    assert results[0].outcome.value == "skipped"


def test_cve_results_passes_when_no_catalog_entry_matches(repo: StorageRepository) -> None:
    repo.save_cve_catalog(parse_catalog_file(_good_catalog_bytes()))
    catalog = StoredCveCatalog(repo)
    comp = Component(name="jquery", version="2.0.0")  # not in the affected range
    results = cve_results([comp], catalog)
    assert len(results) == 1
    assert results[0].outcome.value == "pass"


def test_cve_results_notes_staleness_when_the_catalog_has_aged_past_its_own_limit(
    repo: StorageRepository,
) -> None:
    record = parse_catalog_file(_good_catalog_bytes(stale_after_days=10))
    stale_record = record.model_copy(update={"imported_at": utc_now() - timedelta(days=11)})
    repo.save_cve_catalog(stale_record)
    catalog = StoredCveCatalog(repo)
    assert catalog.available is True and catalog.stale is True

    comp = Component(name="jquery", version="2.0.0")  # not in the affected range -> PASS
    results = cve_results([comp], catalog)
    assert len(results) == 1
    assert results[0].outcome.value == "pass"
    assert "stale" in results[0].rationale


def test_cve_results_does_not_mention_staleness_for_a_fresh_catalog(
    repo: StorageRepository,
) -> None:
    repo.save_cve_catalog(parse_catalog_file(_good_catalog_bytes()))
    catalog = StoredCveCatalog(repo)
    assert catalog.stale is False
    comp = Component(name="jquery", version="2.0.0")
    results = cve_results([comp], catalog)
    assert "stale" not in results[0].rationale


def test_importing_a_new_catalog_replaces_the_old_one(repo: StorageRepository) -> None:
    repo.save_cve_catalog(parse_catalog_file(_good_catalog_bytes()))
    repo.save_cve_catalog(
        parse_catalog_file(
            _good_catalog_bytes(
                source="Second export",
                catalog_version="2026.11",
                entries=[
                    {"product": "lodash", "version_spec": "<4.17.21", "cve_id": "CVE-2021-23337"}
                ],
            )
        )
    )
    current = repo.get_cve_catalog()
    assert current is not None
    assert current.source == "Second export"
    assert len(current.entries) == 1
    assert current.revision == 2


def test_delete_cve_catalog_reverts_to_unavailable(repo: StorageRepository) -> None:
    repo.save_cve_catalog(parse_catalog_file(_good_catalog_bytes()))
    repo.delete_cve_catalog()
    assert repo.get_cve_catalog() is None
    assert StoredCveCatalog(repo).available is False


def test_cve_catalog_matches_a_real_component_in_a_full_offline_scan(
    repo: StorageRepository,
    settings: RuntimeSettings,
) -> None:
    """Acceptance criterion: "Confirm offline scanning works against local fixtures" and
    "the component/version to CVE matching" actually functions end to end — not just the
    isolated matcher unit tests above — through the real `JobManager` -> `WebAppRunner` ->
    `ComponentDetector` -> `StoredCveCatalog` pipeline against a local fixture server, with
    no network access beyond loopback."""
    from app.jobs.manager import JobManager, StartScanRequest
    from app.models.common import ScanModule, ScanState
    from app.scanners.webapp.runner import WebAppRunner
    from tests.jobhelpers import terminal, wait_for
    from tests.webfixtures import MapResolver, lab_project, lab_servers

    repo.save_cve_catalog(
        parse_catalog_file(
            _good_catalog_bytes(
                source="Offline scan test catalog",
                catalog_version="2026.10",
                entries=[
                    # the lab fixture server reports "Apache/2.4.41" via its Server header
                    {"product": "Apache", "version_spec": "<2.4.42", "cve_id": "CVE-2021-41773"},
                ],
            )
        )
    )
    catalog = StoredCveCatalog(repo)

    with lab_servers() as (lab, _victim):
        pid = repo.create_project(lab_project([lab])).project_id
        jm = JobManager(
            repo,
            settings,
            runners={ScanModule.WEB_APP: WebAppRunner(tls_tools=lambda: [], cve_catalog=catalog)},
            resolver_factory=MapResolver,
        )
        scan, _ = jm.submit(
            pid,
            StartScanRequest(
                module=ScanModule.WEB_APP,
                targets=[f"http://lab.test:{lab}/"],
                parameters={},
                confirmed=True,
            ),
        )
        jm.start()
        try:
            # 150s, not 90s: TBD-107 traced a real stuck-near-completion failure here to
            # Windows antivirus/indexer retry delays (`atomic.py::_replace_with_retry`,
            # bounded at 5s each) compounding across several sequential output writes on an
            # already-busy, long-running full-suite run -- not an application hang.
            done = wait_for(repo, pid, scan.scan_id, terminal, timeout=150)
        finally:
            jm.stop()

    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS), done.final_reason
    findings = repo.list_findings(pid, limit=200).items
    cve_findings = [
        f for f in findings if f.rule_id == "WEB-COMP-002" and "CVE-" in f.technical_detail
    ]
    assert len(cve_findings) >= 1, [
        f.technical_detail for f in findings if f.rule_id == "WEB-COMP-002"
    ]
    f = cve_findings[0]
    assert "CVE-2021-41773" in f.technical_detail
    assert "Offline scan test catalog" in f.technical_detail  # source
    assert "2026.10" in f.technical_detail  # version
    assert "imported" in f.technical_detail  # date
    assert f.confidence.value != "confirmed"  # never a confirmed vulnerability


def test_cve_catalog_record_rejects_a_malformed_cve_id_at_the_model_level() -> None:
    with pytest.raises(Exception, match="cve_id|CVE"):
        CveCatalogRecord(
            source="x",
            catalog_version="x",
            file_sha256="a" * 64,
            entries=[
                {
                    "product": "x",
                    "version_spec": "<1.0",
                    "cve_id": "not-a-real-id",
                }
            ],
        )
