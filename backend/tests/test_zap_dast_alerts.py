"""ZAP `traditional-json` report parsing (roadmap Phase 1 increment 2, TBD-080).

`REAL_REPORT_SAMPLE` below is a trimmed, genuine excerpt of a `traditional-json` report
actually produced by a local ZAP 2.17.0 run against a local fixture server in this
session (see TBD-080) -- not a hand-invented shape. Only field values were trimmed (the
`desc`/`reference` HTML shortened); every field name and the overall structure (`site[] ->
alerts[] -> instances[]`) is exactly what ZAP wrote.
"""

from __future__ import annotations

import json

import pytest

from app.models.common import Confidence, Severity
from app.scanners.zap_dast.alerts import ZapReportError, parse_traditional_json_report

REAL_REPORT_SAMPLE = {
    "@programName": "ZAP",
    "@version": "2.17.0",
    "site": [
        {
            "@name": "http://127.0.0.1:18080",
            "@host": "127.0.0.1",
            "@port": "18080",
            "@ssl": "false",
            "alerts": [
                {
                    "pluginid": "10038",
                    "alertRef": "10038-1",
                    "alert": "Content Security Policy (CSP) Header Not Set",
                    "name": "Content Security Policy (CSP) Header Not Set",
                    "riskcode": "2",
                    "confidence": "3",
                    "riskdesc": "Medium (High)",
                    "desc": "<p>Content Security Policy (CSP) is an added layer of "
                    "security &amp; mitigation.</p>",
                    "instances": [
                        {
                            "id": "6",
                            "uri": "http://127.0.0.1:18080",
                            "nodeName": "http:\\/\\/127.0.0.1:18080",
                            "method": "GET",
                            "param": "",
                            "attack": "",
                            "evidence": "",
                            "otherinfo": "",
                        },
                        {
                            "id": "7",
                            "uri": "http://127.0.0.1:18080/about",
                            "nodeName": "http:\\/\\/127.0.0.1:18080\\/about",
                            "method": "GET",
                            "param": "",
                            "attack": "",
                            "evidence": "",
                            "otherinfo": "",
                        },
                    ],
                    "count": "2",
                    "systemic": True,
                    "solution": "<p>Ensure that your web server is configured to set "
                    "the Content-Security-Policy header.</p>",
                    "otherinfo": "",
                    "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/"
                    "Guides/CSP</p><p>https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Content_Security_Policy_Cheat_Sheet.html</p>",
                    "cweid": "693",
                    "wascid": "15",
                    "sourceid": "10",
                },
                {
                    "pluginid": "10020",
                    "alert": "Missing Anti-clickjacking Header",
                    "riskcode": "1",
                    "confidence": "2",
                    "desc": "<p>The response does not include an anti-clickjacking header.</p>",
                    "instances": [{"id": "9", "uri": "http://127.0.0.1:18080/", "method": "GET"}],
                    "count": "1",
                    "solution": "<p>Use the X-Frame-Options header.</p>",
                    "reference": "",
                    "cweid": "-1",
                    "wascid": "15",
                    "sourceid": "10",
                },
            ],
        }
    ],
}


def test_parses_the_real_captured_report_shape_correctly() -> None:
    alerts = parse_traditional_json_report(json.dumps(REAL_REPORT_SAMPLE).encode())
    assert len(alerts) == 2
    csp, clickjacking = alerts

    assert csp.plugin_id == "10038"
    assert csp.alert == "Content Security Policy (CSP) Header Not Set"
    assert csp.site == "http://127.0.0.1:18080"
    assert csp.severity == Severity.MEDIUM  # riskcode 2
    assert csp.confidence == Confidence.PROBABLE  # ZAP confidence 3 -> capped at probable
    assert csp.cwe_id == 693
    assert len(csp.instances) == 2
    assert csp.instances[0].uri == "http://127.0.0.1:18080"
    assert "https://developer.mozilla.org" in csp.references[0]
    # HTML tags are stripped and entities decoded, never rendered as markup
    assert "<p>" not in csp.description and "&amp;" not in csp.description
    assert "security & mitigation" in csp.description

    assert clickjacking.severity == Severity.LOW  # riskcode 1
    assert clickjacking.confidence == Confidence.POTENTIAL  # ZAP confidence 2
    assert clickjacking.cwe_id is None  # "-1" means "no CWE", never mistaken for CWE 1
    assert clickjacking.references == []  # empty reference string -> no fabricated links


def test_unknown_risk_or_confidence_codes_degrade_safely_not_crash() -> None:
    report = {
        "site": [
            {
                "@name": "http://a.example",
                "alerts": [
                    {
                        "pluginid": "1",
                        "alert": "x",
                        "riskcode": "99",
                        "confidence": "99",
                        "desc": "",
                        "solution": "",
                        "reference": "",
                        "instances": [],
                    }
                ],
            }
        ]
    }
    alerts = parse_traditional_json_report(json.dumps(report).encode())
    assert alerts[0].severity == Severity.INFORMATIONAL  # safe default, never a guess up
    assert alerts[0].confidence == Confidence.NEEDS_REVIEW  # safe default, never CONFIRMED


@pytest.mark.parametrize(
    "raw",
    [
        b"not json at all",
        b"[]",  # valid JSON but not an object
        b'{"no_site_key": true}',
        b'{"site": "not a list"}',
    ],
)
def test_malformed_report_is_rejected_never_silently_empty(raw: bytes) -> None:
    with pytest.raises(ZapReportError):
        parse_traditional_json_report(raw)


def test_a_site_with_no_alerts_list_is_skipped_not_fatal() -> None:
    report = {"site": [{"@name": "http://a.example"}, {"@name": "http://b.example", "alerts": []}]}
    assert parse_traditional_json_report(json.dumps(report).encode()) == []


def test_non_dict_entries_in_site_or_alerts_or_instances_are_skipped() -> None:
    report = {
        "site": [
            "not a dict",
            {
                "@name": "http://a.example",
                "alerts": ["not a dict", {"pluginid": "1", "alert": "x", "instances": ["x", {}]}],
            },
        ]
    }
    alerts = parse_traditional_json_report(json.dumps(report).encode())
    assert len(alerts) == 1
    assert len(alerts[0].instances) == 1  # the non-dict instance "x" was skipped
