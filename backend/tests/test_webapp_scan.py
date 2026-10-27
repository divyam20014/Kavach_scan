"""Phase 05 web scanner, end to end through the real JobManager against local fixture apps.

Acceptance criteria covered here:
- a safe baseline scan against a local test app discovers pages and emits evidence-backed
  results (findings + evidence + coverage + summary);
- the scan respects scope (off-scope redirect/links/excluded/robots never requested),
  limits (pages, request budget), cancellation and redaction;
- missing TLS tool / CVE catalog / non-built-in checks are reported skipped, never passed.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from app.core.errors import ValidationFailedError
from app.core.settings import RuntimeSettings
from app.integrations.http_client import HttpClientConfig, PinnedHttpTransport
from app.integrations.tls_tools import TlsToolSpec
from app.jobs.manager import JobManager, StartScanRequest
from app.models.common import ScanModule, ScanState
from app.models.finding import Finding
from app.scanners.webapp.runner import WebAppRunner
from app.storage.repository import StorageRepository
from tests.jobhelpers import terminal, wait_for
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


def _manager(
    repo: StorageRepository, settings: RuntimeSettings, runner: WebAppRunner | None = None
) -> JobManager:
    return JobManager(
        repo,
        settings,
        runners={ScanModule.WEB_APP: runner or WebAppRunner(tls_tools=lambda: [])},
        resolver_factory=MapResolver,
    )


def _scan(
    repo: StorageRepository,
    jm: JobManager,
    pid: str,
    targets: list[str],
    # 150s, not 90s: TBD-107 traced a real stuck-near-completion failure here directly
    # (`test_failing_tls_tool_is_an_error_not_a_pass`) to bounded Windows antivirus/indexer
    # retry delays compounding across several sequential output writes on an already-busy,
    # long-running suite run.
    timeout: float = 150,
    **params: Any,
) -> Any:
    scan, _ = jm.submit(
        pid,
        StartScanRequest(
            module=ScanModule.WEB_APP, targets=targets, parameters=params, confirmed=True
        ),
    )
    jm.start()
    try:
        return wait_for(repo, pid, scan.scan_id, terminal, timeout=timeout)
    finally:
        jm.stop()


def _output(repo: StorageRepository, pid: str, sid: str, name: str) -> Any:
    return json.loads(repo.read_scan_output(pid, sid, name))


def _findings(repo: StorageRepository, pid: str) -> list[Finding]:
    return repo.list_findings(pid, limit=200).items


# ---------------------------------------------------------------------- baseline scan


def test_baseline_scan_discovers_pages_and_emits_evidence_backed_results(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _victim = ports
    pid = repo.create_project(lab_project([lab])).project_id
    done = _scan(repo, _manager(repo, settings), pid, [f"http://lab.test:{lab}/"])
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS), done.final_reason

    pages = _output(repo, pid, done.scan_id, "pages.json")
    urls = {p["url"] for p in pages["pages"]}
    for path in ("/", "/about", "/listing/", "/default", "/error", "/echo-safe?msg="):
        assert any(u.split(f":{lab}", 1)[1].startswith(path) for u in urls), path
    assert any(f["login_form"] for f in pages["forms"])
    home = next(p for p in pages["pages"] if p["url"].endswith(f":{lab}/"))
    assert home["title"] == "Lab home" and home["status"] == 200

    rules = {f.rule_id for f in _findings(repo, pid)}
    expected = {
        "WEB-HDR-002",
        "WEB-HDR-003",
        "WEB-HDR-004",
        "WEB-HDR-005",
        "WEB-HDR-006",
        "WEB-COOKIE-002",
        "WEB-COOKIE-003",
        "WEB-INFO-001",
        "WEB-INFO-002",
        "WEB-INFO-003",
        "WEB-INFO-004",
        "WEB-DBERR-001",
        "WEB-REFL-001",
        "WEB-REDIR-001",
        "WEB-CORS-001",
        "WEB-CACHE-001",
        "WEB-FORM-001",
        "WEB-METHOD-001",
    }
    assert expected <= rules, expected - rules
    for finding in _findings(repo, pid):
        assert finding.scan_id == done.scan_id and finding.fingerprint
        assert finding.evidence_ids, finding.rule_id
        assert finding.sources[0].rule_id == finding.rule_id
        evidence = repo.get_evidence(pid, finding.evidence_ids[0])
        assert finding.finding_id in evidence.finding_ids
    # Escaped reflection is NOT a finding; the unescaped one is (passive, from crawled link).
    reflections = [f for f in _findings(repo, pid) if f.rule_id == "WEB-REFL-001"]
    assert len(reflections) == 1 and "/echo?" in (reflections[0].url or "")

    summary = _output(repo, pid, done.scan_id, "summary.json")
    assert summary["pages_fetched"] == len(pages["pages"]) >= 8
    assert summary["requests_sent"] >= summary["pages_fetched"]
    assert summary["redirects_blocked"] >= 1 and summary["out_of_scope_links"] >= 1
    assert summary["crawl_skipped"]["robots_disallowed"] >= 1
    assert summary["safe_mode"] is True and summary["limitations"]
    assert any(
        c["name"].lower() == "wordpress" and c["version"] == "6.4.2" for c in summary["components"]
    )
    assert any(
        c["name"].lower() == "jquery" and c["version"] == "3.5.1" for c in summary["components"]
    )

    coverage = {
        (r["rule_id"], r["outcome"])
        for r in _output(repo, pid, done.scan_id, "coverage.json")["results"]
    }
    for rule in ("WEB-INJ-000", "WEB-FILE-001", "WEB-COMP-002", "WEB-TLS-005", "WEB-TLS-006"):
        assert (rule, "skipped") in coverage and (rule, "pass") not in coverage, rule
    assert ("WEB-HDR-002", "finding") in coverage
    assert ("WEB-CORS-001", "finding") in coverage
    assert ("WEB-METHOD-001", "finding") in coverage  # fixture advertises TRACE via OPTIONS
    assert ("WEB-FORM-001", "finding") in coverage  # home page's password field has no autocomplete


def test_scan_never_requests_out_of_scope_or_disallowed_urls(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    _scan(repo, _manager(repo, settings), pid, [f"http://lab.test:{lab}/"])
    assert VictimHandler.hits == []  # off-scope redirect destination never contacted
    paths = [h.path for h in LabHandler.hits]
    assert not any(p.startswith("/private") for p in paths)  # excluded by scope
    assert not any(p.startswith("/admin") for p in paths)  # robots.txt disallow
    assert not any(p.endswith(".pdf") or p.endswith(".js") for p in paths)  # assets not fetched
    assert paths.count("/") <= 3  # home + CORS probe (+ one at most for redirects)
    assert max(p.count("/a") for p in paths) <= 4  # crawler trap bounded


def test_secrets_never_reach_findings_evidence_or_outputs(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    done = _scan(repo, _manager(repo, settings), pid, [f"http://lab.test:{lab}/"])
    blob = b""
    for path in repo.root.rglob("*"):
        if path.is_file() and pid in str(path):
            blob += path.read_bytes()
    assert blob and SESSION_SECRET.encode() not in blob
    cookie = next(f for f in _findings(repo, pid) if f.rule_id == "WEB-COOKIE-003")
    evidence = repo.get_evidence(pid, cookie.evidence_ids[0])
    assert "PHPSESSID=[value omitted]" in evidence.response_excerpt
    assert done.scan_id


def test_rescan_reobserves_instead_of_duplicating(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    first = _scan(repo, _manager(repo, settings), pid, [f"http://lab.test:{lab}/"])
    count = len(_findings(repo, pid))
    LabHandler.rate_limited_once = set()
    second = _scan(repo, _manager(repo, settings), pid, [f"http://lab.test:{lab}/"])
    assert len(_findings(repo, pid)) == count
    summary = _output(repo, pid, second.scan_id, "summary.json")
    assert summary["findings_created"] == 0 and summary["findings_reobserved"] == count
    sample = _findings(repo, pid)[0]
    assert {s.scan_id for s in sample.sources} == {first.scan_id, second.scan_id}


# ---------------------------------------------------------------------- limits / cancellation


def test_page_limit_and_request_budget_are_enforced(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab], max_requests_per_target=6)).project_id
    done = _scan(repo, _manager(repo, settings), pid, [f"http://lab.test:{lab}/"])
    assert done.state == ScanState.COMPLETED_WITH_WARNINGS
    assert "budget" in done.final_reason
    assert len(LabHandler.hits) <= 6
    summary = _output(repo, pid, done.scan_id, "summary.json")  # partial results still written
    assert summary["stopped_early"]

    LabHandler.hits = []
    pid2 = repo.create_project(lab_project([lab])).project_id
    limited = _scan(repo, _manager(repo, settings), pid2, [f"http://lab.test:{lab}/"], max_pages=3)
    pages = _output(repo, pid2, limited.scan_id, "pages.json")["pages"]
    assert len(pages) == 3
    assert "page limit" in _output(repo, pid2, limited.scan_id, "summary.json")["crawl_limit"]


def test_cancellation_stops_scan_and_keeps_partial_results(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    LabHandler.delay = 0.4
    pid = repo.create_project(lab_project([lab])).project_id
    jm = _manager(repo, settings)
    scan, _ = jm.submit(
        pid,
        StartScanRequest(
            module=ScanModule.WEB_APP, targets=[f"http://lab.test:{lab}/"], confirmed=True
        ),
    )
    jm.start()
    try:
        wait_for(
            repo, pid, scan.scan_id, lambda s: s.progress.counters.get("pages_fetched", 0) >= 2
        )
        jm.cancel(pid, scan.scan_id)
        done = wait_for(repo, pid, scan.scan_id, terminal, timeout=30)
    finally:
        jm.stop()
    assert done.state == ScanState.CANCELLED
    hits_at_cancel = len(LabHandler.hits)
    time.sleep(1.0)
    assert len(LabHandler.hits) == hits_at_cancel  # no traffic after cancellation
    summary = _output(repo, pid, done.scan_id, "summary.json")
    assert summary["stopped_early"] and summary["pages_fetched"] >= 2


def test_invalid_parameters_are_rejected_before_anything_is_created(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab], max_pages=50)).project_id
    jm = _manager(repo, settings)
    for params in (
        {"unknown_flag": True},
        {"max_pages": 500},
        {"seed_paths": "http://x/"},
        {"respect_robots": "yes"},
    ):
        with pytest.raises(ValidationFailedError):
            jm.submit(
                pid,
                StartScanRequest(
                    module=ScanModule.WEB_APP,
                    parameters=params,
                    targets=[f"http://lab.test:{lab}/"],
                    confirmed=True,
                ),
            )
    assert repo.list_scans(pid).total == 0 and LabHandler.hits == []


def test_seed_paths_and_robots_toggle(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    _scan(
        repo,
        _manager(repo, settings),
        pid,
        [f"http://lab.test:{lab}/about"],
        seed_paths="/listing/",
        respect_robots=False,
        max_depth=0,
    )
    paths = [h.path for h in LabHandler.hits]
    assert "/listing/" in paths and "/robots.txt" not in paths


# ---------------------------------------------------------------------- authenticated crawling


def test_authenticated_crawling_sends_the_configured_session_header(
    repo: StorageRepository,
    settings: RuntimeSettings,
    ports: tuple[int, int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VAPT_TEST_SESSION_TOKEN", "s3cr3t-s3ss10n-v4lue")
    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    done = _scan(
        repo,
        _manager(repo, settings),
        pid,
        [f"http://lab.test:{lab}/about"],
        max_depth=0,
        auth_scheme="bearer",
        auth_secret_ref="env:VAPT_TEST_SESSION_TOKEN",  # noqa: S106 - alias, not a secret value
    )
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS), done.final_reason
    hits = [h for h in LabHandler.hits if h.path == "/about"]
    assert hits and all(
        h.headers.get("authorization") == "Bearer s3cr3t-s3ss10n-v4lue" for h in hits
    )
    # Never persisted anywhere, including profile.json (only the non-secret scheme/header
    # name are) -- mirrors test_secrets_never_reach_findings_evidence_or_outputs above.
    blob = b""
    for path in repo.root.rglob("*"):
        if path.is_file() and pid in str(path):
            blob += path.read_bytes()
    assert b"s3cr3t-s3ss10n-v4lue" not in blob
    profile = _output(repo, pid, done.scan_id, "profile.json")
    assert profile["auth_scheme"] == "bearer" and profile["auth_header_name"] == "Authorization"


def test_authenticated_crawling_fails_fast_when_the_secret_is_not_set(
    repo: StorageRepository, settings: RuntimeSettings, ports: tuple[int, int]
) -> None:
    lab, _ = ports
    pid = repo.create_project(lab_project([lab])).project_id
    done = _scan(
        repo,
        _manager(repo, settings),
        pid,
        [f"http://lab.test:{lab}/"],
        auth_scheme="bearer",
        auth_secret_ref="env:VAPT_TEST_TOKEN_NOT_SET",  # noqa: S106 - alias, not a secret value
    )
    assert done.state == ScanState.FAILED
    assert done.errors and "VAPT_TEST_TOKEN_NOT_SET" in " ".join(done.errors)
    assert LabHandler.hits == []  # never crawled unauthenticated by mistake


# ---------------------------------------------------------------------- TLS


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Any:
    return make_pki(tmp_path_factory.mktemp("pki"))


def _tls_runner(pki: Any, **kw: Any) -> WebAppRunner:
    def factory(config: HttpClientConfig) -> PinnedHttpTransport:
        from dataclasses import replace

        return PinnedHttpTransport(replace(config, ssl_context_factory=pki.client_context))

    return WebAppRunner(transport_factory=factory, **kw)


@pytest.mark.parametrize("kind", ["valid", "expired", "wronghost", "expiring"])
def test_certificate_checks(
    repo: StorageRepository, settings: RuntimeSettings, pki: Any, kind: str
) -> None:
    LabHandler.hits = []
    server = start_server(LabHandler, server_context(pki, kind))
    port = server.server_address[1]
    try:
        pid = repo.create_project(lab_project([port], schemes=["https"])).project_id
        done = _scan(
            repo,
            _manager(repo, settings, _tls_runner(pki, tls_tools=lambda: [])),
            pid,
            [f"https://lab.test:{port}/"],
            tls_verify=kind == "valid",
        )
    finally:
        server.shutdown()
        server.server_close()
    coverage = _output(repo, pid, done.scan_id, "coverage.json")["results"]
    outcome = {r["rule_id"]: r for r in coverage if r["rule_id"] in ("WEB-TLS-003", "WEB-TLS-004")}
    if kind == "valid":
        assert outcome["WEB-TLS-003"]["outcome"] == "pass"
        assert outcome["WEB-TLS-004"]["outcome"] == "pass"
        assert "WEB-HDR-001" in {f.rule_id for f in _findings(repo, pid)}  # HTTPS, no HSTS
    elif kind == "expiring":
        assert outcome["WEB-TLS-004"]["outcome"] == "finding"
    else:
        assert outcome["WEB-TLS-003"]["outcome"] == "finding"
        reason = outcome["WEB-TLS-003"]["rationale"].lower()
        assert (
            ("expired" in reason)
            if kind == "expired"
            else ("hostname" in reason or "match" in reason)
        )
        # tls_verify was off for the crawl: pages were still inventoried
        assert _output(repo, pid, done.scan_id, "summary.json")["pages_fetched"] >= 1


FAKE_SSLYZE = r"""
import json, sys
if "--version" in sys.argv:
    print("sslyze 6.0.0 (fixture)")
    sys.exit(0)
target = sys.argv[-1]
assert "{127.0.0.1}" in target, target  # pinned IP was passed
ok = {"status": "COMPLETED", "result": {"accepted_cipher_suites": [{"cipher_suite": {"name": "X"}}]}}
no = {"status": "COMPLETED", "result": {"accepted_cipher_suites": []}}
print(json.dumps({"server_scan_results": [{"scan_status": "COMPLETED", "scan_result": {
    "ssl_2_0_cipher_suites": no, "ssl_3_0_cipher_suites": no, "tls_1_0_cipher_suites": ok,
    "tls_1_1_cipher_suites": no, "tls_1_2_cipher_suites": ok, "tls_1_3_cipher_suites": ok}}]}))
"""


def test_tls_tool_adapter_runs_with_pinned_ip_and_records_version(
    repo: StorageRepository, settings: RuntimeSettings, pki: Any, tmp_path: Path
) -> None:
    script = tmp_path / "fake_sslyze.py"
    script.write_text(FAKE_SSLYZE)
    spec = TlsToolSpec("sslyze", sys.executable, prefix=(str(script),))
    server = start_server(LabHandler, server_context(pki, "valid"))
    port = server.server_address[1]
    try:
        pid = repo.create_project(lab_project([port], schemes=["https"])).project_id
        done = _scan(
            repo,
            _manager(repo, settings, _tls_runner(pki, tls_tools=lambda: [spec])),
            pid,
            [f"https://lab.test:{port}/"],
        )
    finally:
        server.shutdown()
        server.server_close()
    assert done.tool_versions["sslyze"].startswith("sslyze 6.0.0")
    legacy = [f for f in _findings(repo, pid) if f.rule_id == "WEB-TLS-005"]
    assert len(legacy) == 1 and "TLS 1.0" in legacy[0].technical_detail
    coverage = {
        (r["rule_id"], r["outcome"])
        for r in _output(repo, pid, done.scan_id, "coverage.json")["results"]
    }
    assert ("WEB-TLS-006", "observation") in coverage


def test_failing_tls_tool_is_an_error_not_a_pass(
    repo: StorageRepository, settings: RuntimeSettings, pki: Any, tmp_path: Path
) -> None:
    script = tmp_path / "broken.py"
    script.write_text("import sys\nprint('garbage output')\n")
    spec = TlsToolSpec("sslyze", sys.executable, prefix=(str(script),))
    server = start_server(LabHandler, server_context(pki, "valid"))
    port = server.server_address[1]
    try:
        pid = repo.create_project(lab_project([port], schemes=["https"])).project_id
        done = _scan(
            repo,
            _manager(repo, settings, _tls_runner(pki, tls_tools=lambda: [spec])),
            pid,
            [f"https://lab.test:{port}/"],
        )
    finally:
        server.shutdown()
        server.server_close()
    coverage = {
        (r["rule_id"], r["outcome"])
        for r in _output(repo, pid, done.scan_id, "coverage.json")["results"]
    }
    assert ("WEB-TLS-005", "error") in coverage and ("WEB-TLS-005", "pass") not in coverage
