"""Phase 05 unit tests: rule catalog, profile, passive checks, components/CVE contract, API."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.integrations.http_service import Hop, HttpExchange
from app.models.common import ScanModule
from app.models.project import ScanPolicy
from app.scanners.webapp.checks import PassiveChecks, csp_weaknesses
from app.scanners.webapp.components import (
    Component,
    ComponentDetector,
    CveMatch,
    NoCveCatalog,
    cve_results,
)
from app.scanners.webapp.crawler import PageRecord, canonical_url
from app.scanners.webapp.html import parse_html
from app.scanners.webapp.profile import build_profile, validate_parameters
from app.scanners.webapp.rules import CATALOG_VERSION, RULES, Outcome, catalog_summary
from app.scope.guard import TransportResponse
from app.storage.repository import StorageRepository
from tests.webfixtures import lab_project

# ---------------------------------------------------------------------- catalog / profile


def test_catalog_is_versioned_and_complete() -> None:
    assert CATALOG_VERSION == "1.0.0"
    for rule in RULES.values():
        assert rule.rule_id.startswith("WEB-") and rule.title and rule.summary
        assert rule.owasp in ("", "A01", "A02", "A03", "A04", "A05", "A10")
    rows = catalog_summary()
    assert len(rows) == len(RULES) and all(
        r["owasp"].endswith(":2025") or not r["owasp"] for r in rows
    )


def test_profile_defaults_are_safe_and_explicit() -> None:
    profile = build_profile({}, ScanPolicy())
    assert profile.safe_mode is True and profile.auth_profile is None
    disabled = {c.group: c.reason for c in profile.checks if not c.enabled}
    assert set(disabled) == {"cve", "active_injection", "sensitive_files"}
    assert all(
        "not built in" in disabled[g].lower() for g in ("active_injection", "sensitive_files")
    )
    assert profile.budgets.max_pages == 200 and profile.respect_robots and profile.tls_verify
    assert any("injection" in limit.lower() for limit in profile.limitations)


def test_profile_toggles_and_lowered_budgets() -> None:
    policy = ScanPolicy(max_pages=100, max_crawl_depth=3)
    profile = build_profile(
        {
            "check_cors": False,
            "run_tls_tool": False,
            "max_pages": 10,
            "max_depth": 1,
            "seed_paths": "/a, /b",
        },
        policy,
    )
    assert not profile.enabled("cors") and not profile.enabled("tls_tool")
    assert profile.budgets.max_pages == 10 and profile.budgets.max_depth == 1
    assert profile.seed_paths == ["/a", "/b"]


@pytest.mark.parametrize(
    ("params", "fragment"),
    [
        ({"active_sqli": True}, "unknown parameter"),
        ({"max_pages": 0}, "max_pages"),
        ({"max_pages": 10_000}, "max_pages"),
        ({"max_depth": 50}, "max_depth"),
        ({"seed_paths": "relative"}, "seed paths"),
        ({"seed_paths": "/ok,https://evil/"}, "seed paths"),
        ({"tls_verify": "no"}, "true or false"),
        ({"max_pages": True}, "integer"),
    ],
)
def test_parameter_validation(params: dict[str, Any], fragment: str) -> None:
    problems = validate_parameters(params, ScanPolicy())
    assert problems and any(fragment in p for p in problems), problems


# ---------------------------------------------------------------------- crawler helpers


def test_canonical_url_dedup_and_rejects() -> None:
    a = canonical_url("HTTP://Lab.Test:80/a/./b/../c?z=1&a=2#frag")
    b = canonical_url("http://lab.test/a/c?a=2&z=1")
    assert a == b == "http://lab.test/a/c?a=2&z=1"
    assert canonical_url("http://user:pw@lab.test/") is None
    assert canonical_url("http://lab.test/%2e%2e/%252e") is None
    assert canonical_url("javascript:alert(1)") is None


def test_html_extraction() -> None:
    info = parse_html(
        '<html><head><title> T  1 </title><meta name="generator" content="Drupal 10">'
        '<base href="/sub/"></head><body><a href="x">x</a><iframe src="f"></iframe>'
        '<script src="/s.js"></script><form method=post action=/l><input name=u>'
        '<input type=password name=p></form><a href="y"'
    )
    assert info.title == "T 1" and info.generator == "Drupal 10" and info.base_href == "/sub/"
    assert info.links[:2] == ["x", "f"] and info.resources == ["/s.js"]
    assert info.forms[0].method == "POST" and info.forms[0].has_password
    assert info.forms[0].fields == ["u", "p"]


# ---------------------------------------------------------------------- passive checks


def _exchange(
    url: str,
    headers: list[tuple[str, str]],
    body: bytes = b"<html></html>",
    status: int = 200,
    hops: list[Hop] | None = None,
) -> HttpExchange:
    response = TransportResponse(status=status, headers=tuple(headers), body=body, url=url)
    return HttpExchange(method="GET", url=url, hops=hops or [Hop(url, status)], response=response)


def _run(
    url: str,
    headers: list[tuple[str, str]],
    body: bytes = b"<html></html>",
    ctype: str = "text/html",
    **kw: Any,
) -> dict[str, list[Any]]:
    checks = PassiveChecks()
    page = PageRecord(url=url, depth=0, status=kw.get("status", 200), content_type=ctype)
    exchange = _exchange(url, [("Content-Type", ctype), *headers], body, **kw)
    checks.observe(page, exchange, parse_html(body.decode()) if ctype == "text/html" else None)
    out: dict[str, list[Any]] = {}
    for r in checks.results():
        out.setdefault(r.rule_id, []).append(r)
    return out


SECURE_HEADERS = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
]


def test_well_configured_response_passes_every_header_rule() -> None:
    out = _run("https://app.example.com/", SECURE_HEADERS)
    for rule in (
        "WEB-HDR-001",
        "WEB-HDR-002",
        "WEB-HDR-003",
        "WEB-HDR-004",
        "WEB-HDR-005",
        "WEB-HDR-006",
        "WEB-HDR-007",
        "WEB-HDR-008",
        "WEB-INFO-001",
    ):
        assert [r.outcome for r in out[rule]] == [Outcome.PASS], rule


def test_header_weaknesses_are_findings() -> None:
    headers = [
        ("Strict-Transport-Security", "max-age=60"),
        ("Content-Security-Policy", "script-src * 'unsafe-eval'"),
        ("X-XSS-Protection", "1; mode=block"),
        ("X-Frame-Options", "DENY"),
        ("X-Frame-Options", "SAMEORIGIN"),
        ("Server", "nginx/1.18.0"),
    ]
    out = _run("https://app.example.com/", headers)
    for rule in ("WEB-HDR-001", "WEB-HDR-002", "WEB-HDR-007", "WEB-HDR-008", "WEB-INFO-001"):
        assert any(r.outcome == Outcome.FINDING for r in out[rule]), rule
    assert "unsafe-eval" in out["WEB-HDR-002"][0].rationale


def test_hsts_not_evaluated_over_http() -> None:
    out = _run("http://app.example.com/", [])
    assert "WEB-HDR-001" not in out


def test_csp_weakness_parser() -> None:
    assert csp_weaknesses("default-src 'self'; object-src 'none'") == []
    assert csp_weaknesses("script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'") == []
    assert "script sources allow 'unsafe-inline'" in csp_weaknesses("script-src 'unsafe-inline'")
    assert "no script-src or default-src directive" in csp_weaknesses("img-src *")


def test_cookie_checks() -> None:
    out = _run(
        "https://app.example.com/",
        [
            ("Set-Cookie", "sessionid=abc; Path=/"),
            ("Set-Cookie", "pref=1; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "track=1; Secure; SameSite=None"),
        ],
    )
    findings = {
        (r.rule_id, r.parameter) for rs in out.values() for r in rs if r.outcome == Outcome.FINDING
    }
    assert ("WEB-COOKIE-001", "sessionid") in findings
    assert ("WEB-COOKIE-002", "sessionid") in findings
    assert ("WEB-COOKIE-003", "sessionid") in findings
    assert not any(p == "pref" for _, p in findings)
    assert ("WEB-COOKIE-003", "track") not in findings  # SameSite=None with Secure is fine
    for rs in out.values():
        for r in rs:
            if r.evidence:
                assert "abc" not in r.evidence.response_excerpt.split("sessionid=")[-1][:3]


def test_signatures_require_real_content() -> None:
    assert "WEB-INFO-004" not in {
        k
        for k, v in _run("http://a.example/", [], b"<p>Index of products</p>").items()
        if any(r.outcome == Outcome.FINDING for r in v)
    }
    out = _run("http://a.example/x", [], b"<title>Index of /backup</title>")
    assert out["WEB-INFO-004"][0].outcome == Outcome.FINDING
    out = _run("http://a.example/", [], b"ORA-00933: SQL command not properly ended")
    assert out["WEB-DBERR-001"][0].outcome == Outcome.FINDING


def test_passive_reflection_requires_unencoded_metacharacters() -> None:
    raw = _run("http://a.example/s?q=%3Cb%3Ex%3C%2Fb%3E", [], b"<p><b>x</b></p>")
    escaped = _run("http://a.example/s?q=%3Cb%3Ex%3C%2Fb%3E", [], b"<p>&lt;b&gt;x&lt;/b&gt;</p>")
    plain = _run("http://a.example/s?q=hello", [], b"<p>hello</p>")
    assert raw["WEB-REFL-001"][0].outcome == Outcome.FINDING
    assert escaped["WEB-REFL-001"][0].outcome == Outcome.PASS
    assert "WEB-REFL-001" not in plain  # value without metacharacters says nothing


def test_open_redirect_indicator_is_passive() -> None:
    hops = [
        Hop("http://a.example/go?next=https%3A%2F%2Fevil.example%2F", 302, "https://evil.example/"),
    ]
    out = _run(
        "http://a.example/go?next=https%3A%2F%2Fevil.example%2F", [], b"", status=302, hops=hops
    )
    assert out["WEB-REDIR-001"][0].outcome == Outcome.FINDING
    assert "not requested" in out["WEB-REDIR-001"][0].detail


def test_aggregation_lists_urls_once_per_origin() -> None:
    checks = PassiveChecks()
    for i in range(30):
        url = f"http://a.example/p{i}"
        checks.observe(
            PageRecord(url=url, depth=1, status=200, content_type="text/html"),
            _exchange(url, [("Content-Type", "text/html")]),
            parse_html("<html></html>"),
        )
    nosniff = [r for r in checks.results() if r.rule_id == "WEB-HDR-003"]
    assert len(nosniff) == 1 and nosniff[0].data["affected_count"] == 30
    assert len(nosniff[0].data["affected_urls"]) == 20 and "and 10 more" in nosniff[0].detail


# ---------------------------------------------------------------------- components / CVE contract


def test_component_detection_with_confidence() -> None:
    d = ComponentDetector()
    d.observe_headers(
        "http://a/",
        (
            ("Server", "Apache/2.4.41 (Ubuntu)"),
            ("X-Powered-By", "Express"),
            ("Set-Cookie", "JSESSIONID=x"),
        ),
    )
    d.observe_generator("http://a/", "WordPress 6.4.2")
    d.observe_resource("http://a/static/jquery-3.5.1.min.js")
    d.observe_resource("http://a/js/bootstrap@5.3.0/dist/b.js")
    d.observe_resource("http://a/app.js.map")
    found = {(c.name.lower(), c.version): c for c in d.components()}
    assert ("apache", "2.4.41") in found and ("ubuntu", "") not in found
    assert found[("jquery", "3.5.1")].confidence.value == "probable"
    assert ("wordpress", "6.4.2") in found and ("bootstrap", "5.3.0") in found
    assert ("express", "") in found and ("java servlet container", "") in found
    assert ("source map", "") in found
    results = d.results()
    assert all(r.outcome == Outcome.OBSERVATION for r in results)


class FakeCatalog:
    catalog_id = "local-test"
    catalog_version = "2026.10"
    updated_at = "2026-10-01"

    @property
    def available(self) -> bool:
        return True

    def match(self, product: str, version: str) -> list[CveMatch]:
        if product.lower() == "jquery" and version == "3.5.1":
            return [
                CveMatch(
                    "CVE-0000-0001",
                    "jquery",
                    version,
                    "range",
                    "<3.6.0",
                    self.catalog_id,
                    self.catalog_version,
                )
            ]
        return []


def test_cve_contract_never_invents_matches() -> None:
    comps = [Component("jquery", "3.5.1"), Component("nginx", "1.2.3"), Component("PHP")]
    skipped = cve_results(comps, NoCveCatalog())
    assert [r.outcome for r in skipped] == [Outcome.SKIPPED]
    assert "No local CVE catalog" in skipped[0].rationale
    out = cve_results(comps, FakeCatalog())
    outcomes = {(r.subject, r.outcome) for r in out}
    assert ("jquery 3.5.1", Outcome.FINDING) in outcomes
    assert ("nginx 1.2.3", Outcome.PASS) in outcomes
    assert ("PHP", Outcome.SKIPPED) in outcomes  # no version: matching not defensible


# ---------------------------------------------------------------------- API


def test_web_scan_profile_endpoint(client: TestClient, repo: StorageRepository) -> None:
    pid = repo.create_project(lab_project([8080], max_pages=50)).project_id
    resp = client.get(f"/api/projects/{pid}/web-scan-profile", params={"check_cors": "false"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["problems"] == [] and body["profile"]["safe_mode"] is True
    groups = {c["group"]: c for c in body["profile"]["checks"]}
    assert groups["cors"]["enabled"] is False and groups["headers"]["enabled"] is True
    assert body["profile"]["budgets"]["max_pages"] == 50
    bad = client.get(f"/api/projects/{pid}/web-scan-profile", params={"max_pages": 500}).json()
    assert bad["problems"] and "max_pages" in bad["problems"][0]


def test_results_endpoint_and_findings_scan_filter(
    client: TestClient, repo: StorageRepository
) -> None:
    from tests.conftest import make_finding

    pid = repo.create_project(lab_project([8080])).project_id
    from app.models import new_id
    from app.models.scan import ScanJob

    scan = repo.create_scan(
        ScanJob(scan_id=new_id("scan"), project_id=pid, module=ScanModule.WEB_APP)
    )
    repo.write_scan_output(
        pid, scan.scan_id, "summary.json", b'{"pages_fetched": 3, "note": "token=abcdef123456"}'
    )
    ok = client.get(f"/api/projects/{pid}/scans/{scan.scan_id}/results/summary")
    assert ok.status_code == 200 and ok.json()["pages_fetched"] == 3
    assert "abcdef123456" not in ok.text  # re-redacted on read
    assert (
        client.get(f"/api/projects/{pid}/scans/{scan.scan_id}/results/coverage").status_code == 404
    )
    assert client.get(f"/api/projects/{pid}/scans/{scan.scan_id}/results/../x").status_code == 404
    assert (
        client.get(f"/api/projects/{pid}/scans/{scan.scan_id}/results/secrets").status_code == 404
    )

    repo.create_finding(make_finding(pid, scan_id=scan.scan_id))
    repo.create_finding(make_finding(pid))
    page = client.get("/api/findings", params={"scan_id": scan.scan_id}).json()
    assert page["total"] == 1 and page["items"][0]["scan_id"] == scan.scan_id
    assert client.get("/api/findings", params={"scan_id": "../etc"}).status_code == 422


def test_web_module_is_available(client: TestClient) -> None:
    modules = {m["module"]: m for m in client.get("/api/jobs/modules").json()}
    assert modules["web_app"]["available"] is True
    assert modules["attack_surface"]["available"] is False
