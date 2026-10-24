"""Fixture-based tests for every Phase 08 import adapter (acceptance criterion: every
supported format has representative fixtures and failure tests)."""

from __future__ import annotations

import pytest

from app.imports.adapters import ADAPTERS, UNSUPPORTED, detect
from app.imports.adapters.generic_csv import ADAPTER as GENERIC_CSV
from app.imports.adapters.generic_json import ADAPTER as GENERIC_JSON
from app.imports.adapters.nessus import ADAPTER as NESSUS
from app.imports.adapters.nmap_xml import ADAPTER as NMAP_XML
from app.imports.adapters.nuclei_jsonl import ADAPTER as NUCLEI_JSONL
from app.imports.adapters.pdf_text import ADAPTER as PDF_TEXT
from app.imports.adapters.sarif import ADAPTER as SARIF
from app.imports.safety import ImportSafetyError
from app.models.common import Confidence, Severity
from tests import importfixtures as fx


def test_registry_is_ordered_per_tbd_023() -> None:
    assert [a.source_type for a in ADAPTERS] == [
        "nmap_xml", "nessus", "nuclei_jsonl", "sarif", "generic_csv", "generic_json", "pdf_text",
    ]
    assert set(UNSUPPORTED) == {"zap", "burp"}
    for reason in UNSUPPORTED.values():
        assert reason  # every unsupported format must explain why


def test_nmap_xml_adapter() -> None:
    assert NMAP_XML.sniff("scan.xml", fx.NMAP_XML)
    result = NMAP_XML.parse(fx.NMAP_XML)
    assert result.rejected_count == 0
    # mysql -> database exposure finding; ssh is not in DATABASE/ADMIN/CLEARTEXT... wait ssh IS admin
    titles = {f.title for f in result.findings}
    assert "mysql service reachable" in titles
    assert "ssh service reachable" in titles
    assert any(f.title == "Service banner discloses product version" for f in result.findings)
    assert result.source_tool_version == "Nmap 7.94"
    # UDP port is never turned into a finding or asset locator with protocol udp
    assert not any(a.locator.startswith("udp://") for a in result.assets)
    ip_assets = [a for a in result.assets if a.asset_type == "ip"]
    assert ip_assets and ip_assets[0].locator == "10.0.0.5"


def test_nmap_xml_rejects_xxe() -> None:
    with pytest.raises(ImportSafetyError, match="DTD|entity"):
        NMAP_XML.parse(fx.NMAP_XML_XXE)


def test_nmap_xml_rejects_wrong_root() -> None:
    with pytest.raises(ImportSafetyError):
        NMAP_XML.parse(b"<?xml version='1.0'?><notnmap/>")


def test_nessus_adapter() -> None:
    assert NESSUS.sniff("report.nessus", fx.NESSUS_XML)
    result = NESSUS.parse(fx.NESSUS_XML)
    assert result.rejected_count == 0
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.title == "SSL Certificate Expiry"
    assert f.severity == Severity.HIGH  # risk_factor "High" overrides numeric severity=3
    assert 295 in f.cwe_ids
    assert "CVE-2020-0001" in f.summary
    assert any(a.asset_type == "ip" and a.locator == "10.0.0.9" for a in result.assets)
    assert any(a.asset_type == "hostname" and a.locator == "app.internal.test"
              for a in result.assets)


def test_nessus_style_csv_is_handled_by_generic_csv() -> None:
    """Confirms the documented decision not to write a separate Nessus-CSV adapter."""
    assert GENERIC_CSV.sniff("nessus_export.csv", fx.GENERIC_CSV_NESSUS_STYLE)
    result = GENERIC_CSV.parse(fx.GENERIC_CSV_NESSUS_STYLE)
    assert result.rejected_count == 0
    f = result.findings[0]
    assert f.title == "Outdated OpenSSL"
    assert f.severity == Severity.HIGH
    assert f.host == "10.0.0.9"


def test_nuclei_jsonl_adapter_partial_success() -> None:
    assert NUCLEI_JSONL.sniff("results.jsonl", fx.NUCLEI_JSONL)
    result = NUCLEI_JSONL.parse(fx.NUCLEI_JSONL)
    # line 2 is invalid JSON -> rejected; line 3 has an empty template-id but still parses
    assert result.rejected_count == 1
    assert result.parsed_count == 2
    good = next(f for f in result.findings if f.rule_id == "exposed-panel-jenkins")
    assert good.severity == Severity.MEDIUM
    assert 200 in good.cwe_ids
    assert good.host == "10.0.0.7:8080"
    assert any("line 2" in w for w in result.warnings)


def test_sarif_adapter() -> None:
    assert SARIF.sniff("results.sarif", fx.SARIF_JSON)
    result = SARIF.parse(fx.SARIF_JSON)
    assert result.rejected_count == 0
    f = result.findings[0]
    assert f.title == "eval() used with untrusted input"
    assert f.severity == Severity.HIGH  # SARIF level "error"
    assert 95 in f.cwe_ids
    assert f.component == "src/app.js"
    assert f.parameter == "42"
    assert "ExampleScanner 1.2.3" in result.source_tool_version


def test_sarif_rejects_malformed_json() -> None:
    with pytest.raises(ImportSafetyError):
        SARIF.parse(b'{"runs": not json')


def test_sarif_requires_runs_array() -> None:
    with pytest.raises(ImportSafetyError):
        SARIF.parse(b'{"version": "2.1.0"}')


def test_generic_csv_adapter_rejects_empty_title_row() -> None:
    assert GENERIC_CSV.sniff("export.csv", fx.GENERIC_CSV)
    result = GENERIC_CSV.parse(fx.GENERIC_CSV)
    assert result.parsed_count == 1
    assert result.rejected_count == 1
    assert any("empty title" in w for w in result.warnings)
    assert result.findings[0].title == "Outdated jQuery"
    assert result.findings[0].severity == Severity.MEDIUM


def test_generic_csv_missing_title_column_is_fatal_without_mapping() -> None:
    raw = b"Col A,Col B\r\nfoo,bar\r\n"
    with pytest.raises(ImportSafetyError, match="title column"):
        GENERIC_CSV.parse(raw)


def test_generic_csv_column_map_override_recovers_missing_title() -> None:
    raw = b"Col A,Col B\r\nfoo,bar\r\n"
    result = GENERIC_CSV.parse(raw, options={"column_map": {"title": "Col A"}})
    assert result.parsed_count == 1
    assert result.findings[0].title == "foo"


def test_generic_csv_reports_mapping_gaps_for_unmatched_columns() -> None:
    raw = b"Title,Extra\r\nSomething odd,x\r\n"
    result = GENERIC_CSV.parse(raw)
    assert result.parsed_count == 1
    assert set(result.mapping_gaps) >= {"severity", "host", "url", "cwe", "remediation", "component"}
    assert any("no column matched for" in w for w in result.warnings)


def test_generic_csv_no_mapping_gap_when_every_gap_worthy_field_is_present() -> None:
    result = GENERIC_CSV.parse(fx.GENERIC_CSV_NESSUS_STYLE)
    assert "severity" not in result.mapping_gaps
    assert "host" not in result.mapping_gaps


def test_generic_json_adapter() -> None:
    assert GENERIC_JSON.sniff("export.json", fx.GENERIC_JSON)
    result = GENERIC_JSON.parse(fx.GENERIC_JSON)
    assert result.parsed_count == 1
    assert result.rejected_count == 1  # second record has no title
    f = result.findings[0]
    assert f.title == "Reflected XSS"
    assert f.severity == Severity.HIGH
    assert 79 in f.cwe_ids


def test_generic_json_reports_mapping_gaps_for_absent_fields() -> None:
    result = GENERIC_JSON.parse(fx.GENERIC_JSON)
    assert "remediation" in result.mapping_gaps
    assert "component" in result.mapping_gaps
    assert "severity" not in result.mapping_gaps  # present in the fixture
    assert "host" not in result.mapping_gaps


def test_generic_json_field_map_override() -> None:
    raw = b'[{"name": "Custom Title", "lvl": "critical"}]'
    result = GENERIC_JSON.parse(raw, options={"field_map": {"title": "name", "severity": "lvl"}})
    assert result.parsed_count == 1
    assert result.findings[0].title == "Custom Title"
    assert result.findings[0].severity == Severity.CRITICAL


def test_generic_json_requires_a_findings_array() -> None:
    with pytest.raises(ImportSafetyError):
        GENERIC_JSON.parse(b'{"not_a_findings_key": 1}')


def test_pdf_text_adapter_best_effort() -> None:
    assert PDF_TEXT.sniff("report.pdf", fx.PDF_MINIMAL)
    result = PDF_TEXT.parse(fx.PDF_MINIMAL)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.INFORMATIONAL  # never guessed
    assert f.confidence == Confidence.NEEDS_REVIEW
    assert "Sample VAPT finding text extraction test" in f.summary
    assert not f.cwe_ids  # never invented
    assert any("review the text" in w for w in result.warnings)


def test_pdf_text_adapter_rejects_corrupt_pdf() -> None:
    with pytest.raises(ImportSafetyError):
        PDF_TEXT.parse(b"%PDF-1.4\nnot a real pdf body at all")


def test_pdf_text_adapter_no_extractable_text_yields_no_finding() -> None:
    import io

    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    buf = io.BytesIO()
    writer.write(buf)
    result = PDF_TEXT.parse(buf.getvalue())
    assert result.findings == []
    assert any("no extractable text" in w for w in result.warnings)


def test_detect_picks_the_right_adapter_for_every_fixture() -> None:
    assert detect("scan.xml", fx.NMAP_XML).source_type == "nmap_xml"
    assert detect("report.nessus", fx.NESSUS_XML).source_type == "nessus"
    assert detect("results.jsonl", fx.NUCLEI_JSONL).source_type == "nuclei_jsonl"
    assert detect("results.sarif", fx.SARIF_JSON).source_type == "sarif"
    assert detect("export.csv", fx.GENERIC_CSV).source_type == "generic_csv"
    assert detect("export.json", fx.GENERIC_JSON).source_type == "generic_json"
    assert detect("report.pdf", fx.PDF_MINIMAL).source_type == "pdf_text"
