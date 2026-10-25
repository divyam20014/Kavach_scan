"""Phase 05 verification: edge cases for the web scanner against local fixtures only.

- the scanner sends no crafted input (only GET, only URLs that appeared as links);
- response caps, content-type limits, redirect validation into excluded paths;
- 503 backoff, and cancellation interrupting a long Retry-After wait;
- every evidence format and every scan output is free of secrets;
- raw TLS-tool output is redacted; absent tools are reported skipped.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient

from app.core.settings import RuntimeSettings
from app.integrations.http_client import HttpClientConfig, PinnedHttpTransport
from app.integrations.http_service import HttpService
from app.integrations.tls_tools import TlsToolSpec
from app.jobs.manager import JobManager, StartScanRequest
from app.models.common import Confidence, ScanModule, ScanState
from app.models.evidence import MAX_EXCERPT_CHARS
from app.scanners.webapp.evidence import MAX_BODY_WINDOW
from app.scanners.webapp.rules import RULES, Kind
from app.scanners.webapp.runner import WebAppRunner
from app.scope import MemorySink, ScopeGuard
from app.storage.repository import StorageRepository
from tests.jobhelpers import terminal, wait_for
from tests.test_http_adapters import FakeCtx
from tests.webfixtures import (
    SESSION_SECRET,
    LabHandler,
    MapResolver,
    VictimHandler,
    lab_project,
    lab_servers,
    make_pki,
    server_context,
    start_server,
)


@pytest.fixture
def ports() -> Iterator[tuple[int, int]]:
    with lab_servers() as p:
        yield p


def _jm(
    repo: StorageRepository, settings: RuntimeSettings, runner: WebAppRunner | None = None
) -> JobManager:
    return JobManager(
        repo,
        settings,
        runners={ScanModule.WEB_APP: runner or WebAppRunner(tls_tools=lambda: [])},
        resolver_factory=MapResolver,
    )


def _run(
    repo: StorageRepository,
    settings: RuntimeSettings,
    pid: str,
    target: str,
    runner: WebAppRunner | None = None,
    **params: Any,
) -> Any:
    jm = _jm(repo, settings, runner)
    scan, _ = jm.submit(
        pid,
        StartScanRequest(
            module=ScanModule.WEB_APP, targets=[target], parameters=params, confirmed=True
        ),
    )
    jm.start()
    try:
        return wait_for(repo, pid, scan.scan_id, terminal, timeout=90)
    finally:
        jm.stop()


def _out(repo: StorageRepository, pid: str, sid: str, name: str) -> Any:
    return json.loads(repo.read_scan_output(pid, sid, name))


# ---------------------------------------------------------------------- no crafted input


LINKED_QUERIES = {
    "/dberror?id=1",
    "/echo?msg=%3Cb%3Ehello%3C%2Fb%3E",
    "/echo-safe?msg=%3Ci%3Esafe%3C%2Fi%3E",
}


def test_scanner_sends_no_crafted_input(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    """Safe mode: only GET and the read-only, non-mutating OPTIONS method-enumeration probe
    (WEB-METHOD-001, one per origin) are ever sent; every query string sent is one that
    appeared in a crawled link."""
    lab, victim = ports
    pid = repo.create_project(lab_project([lab])).project_id
    _run(repo, settings, pid, f"http://lab.test:{lab}/")
    assert {h.method for h in LabHandler.hits} == {"GET", "OPTIONS"}
    assert sum(h.method == "OPTIONS" for h in LabHandler.hits) == 1  # one per origin, not per page
    sent_queries = {h.path for h in LabHandler.hits if "?" in h.path}
    allowed = {unquote(q) for q in LINKED_QUERIES} | {
        unquote(f"/go?next=http%3A%2F%2Fvictim.test%3A{victim}%2Fsteal")
    }
    assert {unquote(q) for q in sent_queries} <= allowed, sent_queries
    # The only non-default header the scanner ever adds is the fixed CORS test Origin.
    origins = {h.headers.get("origin") for h in LabHandler.hits} - {None}
    assert origins == {"https://vapt-cors-check.invalid"}
    assert not any(
        h.headers.get("cookie") or h.headers.get("authorization") for h in LabHandler.hits
    )


def test_catalog_has_no_active_rules_and_no_confirmed_xss_claim() -> None:
    web = [r for r in RULES.values() if r.rule_id.startswith("WEB-")]
    assert not [r for r in web if r.kind == Kind.ACTIVE]  # the web scanner has no active rules
    refl = RULES["WEB-REFL-001"]
    assert refl.confidence == Confidence.POTENTIAL and "passive" in refl.title.lower()
    assert "neither confirmed" in refl.summary
    for rule in web:
        assert "confirmed executable" not in rule.title.lower()


def test_active_parameters_are_rejected(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    from app.core.errors import ValidationFailedError

    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    for name in ("active_sqli", "active_xss", "active_ack", "payloads"):
        with pytest.raises(ValidationFailedError):
            _jm(repo, settings).submit(
                pid,
                StartScanRequest(
                    module=ScanModule.WEB_APP,
                    targets=[f"http://lab.test:{lab}/"],
                    parameters={name: True},
                    confirmed=True,
                ),
            )
    assert LabHandler.hits == []


# ---------------------------------------------------------------------- caps / content types / redirects


def test_response_cap_and_content_type_limits(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab], max_response_bytes=64 * 1024)).project_id
    done = _run(
        repo, settings, pid, f"http://lab.test:{lab}/about", seed_paths="/big,/text", max_depth=1
    )
    pages = {
        p["url"].split(f":{lab}", 1)[1]: p
        for p in _out(repo, pid, done.scan_id, "pages.json")["pages"]
    }
    assert pages["/big"]["truncated"] is True and pages["/big"]["bytes"] <= 64 * 1024
    assert pages["/text"]["content_type"] == "text/plain" and pages["/text"]["links_found"] == 0
    assert "/from-plain-text" not in [h.path for h in LabHandler.hits]  # non-HTML is never parsed


def test_redirect_into_excluded_path_is_recorded_not_followed(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    done = _run(
        repo, settings, pid, f"http://lab.test:{lab}/to-private", max_depth=0, respect_robots=False
    )
    page = _out(repo, pid, done.scan_id, "pages.json")["pages"][0]
    assert page["status"] == 302 and "/private/keys" in page["redirect_blocked_to"]
    assert not any(h.path.startswith("/private") for h in LabHandler.hits)
    assert _out(repo, pid, done.scan_id, "summary.json")["redirects_blocked"] == 1


# ---------------------------------------------------------------------- backoff and cancellation


def test_503_retry_after_is_honoured(ports: tuple[int, int]) -> None:
    lab, _ = ports
    guard = ScopeGuard(lab_project([lab]), resolver=MapResolver(), sink=MemorySink())
    ctx = FakeCtx(guard)
    service = HttpService(ctx, PinnedHttpTransport(HttpClientConfig()))
    exchange = service.fetch("GET", f"http://lab.test:{lab}/flaky")
    assert exchange.status == 200 and ctx.sleeps[0] >= 0.9
    assert ctx.counters["rate_limited_responses"] == 1


def test_cancel_interrupts_a_long_retry_after_wait(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    jm = _jm(repo, settings)
    scan, _ = jm.submit(
        pid,
        StartScanRequest(
            module=ScanModule.WEB_APP,
            confirmed=True,
            targets=[f"http://lab.test:{lab}/unavailable"],
            parameters={"respect_robots": False},
        ),
    )
    jm.start()
    try:
        deadline = time.monotonic() + 30
        while (
            not any(h.path == "/unavailable" for h in LabHandler.hits)
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        time.sleep(0.5)  # now inside the 25 s Retry-After backoff
        started = time.monotonic()
        jm.cancel(pid, scan.scan_id)
        done = wait_for(repo, pid, scan.scan_id, terminal, timeout=20)
        elapsed = time.monotonic() - started
    finally:
        jm.stop()
    assert done.state == ScanState.CANCELLED and elapsed < 8, elapsed
    assert sum(h.path == "/unavailable" for h in LabHandler.hits) == 1  # no retry after cancel


# ---------------------------------------------------------------------- evidence and outputs


def test_every_evidence_record_and_output_is_bounded_and_secret_free(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int], client: TestClient
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    done = _run(repo, settings, pid, f"http://lab.test:{lab}/")
    evidence = repo.list_evidence(pid, limit=200).items
    assert evidence, "findings must carry evidence"
    for ev in evidence:
        assert ev.evidence_type in (
            "http_exchange",
            "tls_certificate",
            "text_excerpt",
            "tool_output",
        )
        for text in (ev.request_excerpt, ev.response_excerpt):
            assert len(text) <= MAX_EXCERPT_CHARS and SESSION_SECRET not in text
        if "[body excerpt" in ev.response_excerpt:  # body window is bounded
            body_part = ev.response_excerpt.split("[body excerpt", 1)[1]
            assert len(body_part) <= MAX_BODY_WINDOW + 200
        assert not ev.has_blob  # no response bodies are stored as blobs
    for finding in repo.list_findings(pid, limit=200).items:
        dumped = finding.model_dump_json()
        assert SESSION_SECRET not in dumped
    for kind in ("summary", "coverage", "pages", "profile"):
        body = client.get(f"/api/projects/{pid}/scans/{done.scan_id}/results/{kind}").text
        assert SESSION_SECRET not in body
        # Nothing secret is in these outputs, so redaction must not have wiped any structural
        # field (regression: a "pass" outcome-count key was once redacted as secret-like).
        assert "[REDACTED]" not in body, (kind, body[body.find("[REDACTED]") - 80 :][:200])
    events = client.get(
        f"/api/projects/{pid}/scans/{done.scan_id}/events", params={"limit": 500}
    ).text
    console = client.get(f"/api/projects/{pid}/scans/{done.scan_id}/console").text
    assert SESSION_SECRET not in events and SESSION_SECRET not in console


LEAKY_TOOL = r"""
import json, sys
if "--version" in sys.argv:
    print("sslyze 6.0.0 (fixture)")
    sys.exit(0)
no = {"status": "COMPLETED", "result": {"accepted_cipher_suites": []}}
ok = {"status": "COMPLETED", "result": {"accepted_cipher_suites": [{"cipher_suite": {"name": "X"}}]}}
print(json.dumps({"note": "password=hunter2-tool-secret", "server_scan_results": [{
    "scan_status": "COMPLETED", "scan_result": {"ssl_2_0_cipher_suites": no, "ssl_3_0_cipher_suites": no,
    "tls_1_0_cipher_suites": no, "tls_1_1_cipher_suites": no, "tls_1_2_cipher_suites": ok,
    "tls_1_3_cipher_suites": ok}}]}))
"""


def test_raw_tls_tool_output_is_redacted_and_absent_tool_is_skipped(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Path
) -> None:
    pki = make_pki(tmp_path)
    script = tmp_path / "leaky_sslyze.py"
    script.write_text(LEAKY_TOOL)
    spec = TlsToolSpec("sslyze", sys.executable, prefix=(str(script),))

    def factory(config: HttpClientConfig) -> PinnedHttpTransport:
        from dataclasses import replace

        return PinnedHttpTransport(replace(config, ssl_context_factory=pki.client_context))

    LabHandler.hits = []
    server = start_server(LabHandler, server_context(pki, "valid"))
    port = server.server_address[1]
    try:
        pid = repo.create_project(lab_project([port], schemes=["https"])).project_id
        with_tool = _run(
            repo,
            settings,
            pid,
            f"https://lab.test:{port}/",
            WebAppRunner(transport_factory=factory, tls_tools=lambda: [spec]),
            max_depth=0,
        )
        pid2 = repo.create_project(lab_project([port], schemes=["https"])).project_id
        without = _run(
            repo,
            settings,
            pid2,
            f"https://lab.test:{port}/",
            WebAppRunner(transport_factory=factory, tls_tools=lambda: []),
            max_depth=0,
        )
    finally:
        server.shutdown()
        server.server_close()
    work = repo.scan_work_dir(pid, with_tool.scan_id)
    raw_files = list(work.glob("tls-tool-*.json"))
    assert raw_files
    for f in raw_files:
        assert b"hunter2-tool-secret" not in f.read_bytes(), f.read_bytes()[:300]
    assert with_tool.tool_versions["sslyze"].startswith("sslyze 6.0.0")

    cov = _out(repo, pid2, without.scan_id, "coverage.json")["results"]
    tls_rows = [r for r in cov if r["rule_id"] in ("WEB-TLS-005", "WEB-TLS-006")]
    assert tls_rows and {r["outcome"] for r in tls_rows} == {"skipped"}
    assert all("neither sslyze nor testssl.sh is installed" in r["rationale"] for r in tls_rows)
    summary = _out(repo, pid2, without.scan_id, "summary.json")
    assert (
        summary["tool_versions"] == {}
        and {c["outcome"]: c["count"] for c in summary["check_outcomes"]}["pass"] >= 1
    )
    assert VictimHandler.hits == []
