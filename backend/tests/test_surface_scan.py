"""Phase 06 end-to-end: the attack surface mapper through the real JobManager.

Local fixtures only: banner TCP services on 127.0.0.1 and the Phase 05 HTTP fixture app.
Fake DNS maps the lab hostnames to loopback; an internal-target override authorizes
127.0.0.1 for the lab. Every service counts its connections so tests can prove that
out-of-scope and pending-approval hosts are never touched.
"""

from __future__ import annotations

import json
from typing import Any

from app.core.settings import RuntimeSettings
from app.jobs.manager import JobManager, StartScanRequest
from app.models.common import ScanModule, ScanState
from app.scanners.surface.runner import SurfaceRunner
from app.storage.repository import StorageRepository
from tests.jobhelpers import terminal, wait_for
from tests.surfacefixtures import BannerServer, surface_dns, surface_project


def _manager(
    repo: StorageRepository, settings: RuntimeSettings, runner: SurfaceRunner
) -> JobManager:
    return JobManager(
        repo,
        settings,
        runners={ScanModule.ATTACK_SURFACE: runner},
        resolver_factory=surface_dns,
    )


def _runner(**kw: Any) -> SurfaceRunner:
    # No Nmap, fast timeouts: deterministic TCP-connect behaviour.
    kw.setdefault("nmap", lambda: None)
    kw.setdefault("connect_timeout", 1.0)
    kw.setdefault("banner_timeout", 0.5)
    return SurfaceRunner(**kw)


def _scan(
    repo: StorageRepository,
    jm: JobManager,
    pid: str,
    targets: list[str],
    # 150s, not 90s: TBD-107 traced a real stuck-near-completion failure (in a sibling test
    # using the same shape) to bounded Windows antivirus/indexer retry delays compounding
    # across several sequential output writes on an already-busy, long-running suite run.
    timeout: float = 150,
    **params: Any,
) -> Any:
    scan, _ = jm.submit(
        pid,
        StartScanRequest(
            module=ScanModule.ATTACK_SURFACE, targets=targets, parameters=params, confirmed=True
        ),
    )
    jm.start()
    try:
        return wait_for(repo, pid, scan.scan_id, terminal, timeout=timeout)
    finally:
        jm.stop()


def _out(repo: StorageRepository, pid: str, sid: str, name: str) -> Any:
    return json.loads(repo.read_scan_output(pid, sid, name))


def test_discovery_classifies_and_only_scans_in_scope_hosts(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    ssh = BannerServer(b"SSH-2.0-OpenSSH_8.9p1\r\n")
    try:
        # scope in-range ports include the ssh fixture port; www is a CNAME to lab
        pid = repo.create_project(surface_project([ssh.port, 80])).project_id
        done = _scan(
            repo,
            _manager(repo, settings, _runner()),
            pid,
            ["lab.test"],
            hosts="www.lab.test, new.lab.test, elsewhere.example",
            ports=f"{ssh.port},80",
        )
    finally:
        ssh.close()
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS), done.final_reason
    summary = _out(repo, pid, done.scan_id, "summary.json")
    by_status = summary["candidates_by_status"]
    # lab.test + www.lab.test are in scope; new.lab.test is a pending-approval subdomain;
    # elsewhere.example is out of scope.
    assert by_status.get("in_scope", 0) >= 2
    assert by_status.get("pending_approval", 0) == 1
    assert by_status.get("out_of_scope", 0) == 1
    not_checked = summary["hosts_not_checked"]
    assert "new.lab.test" in not_checked and "not in scope" in not_checked["new.lab.test"]
    assert "elsewhere.example" in not_checked
    # the ssh port shows as reachable on the in-scope hosts
    assert any(s["port"] == ssh.port and s["service"] == "ssh" for s in summary["open_services"])


def test_private_and_metadata_resolutions_are_blocked_and_never_connected(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    # internal.lab.test -> 10.0.0.5 (private), meta.lab.test -> 169.254.169.254 (metadata).
    # Both are in-scope *hosts*, but their addresses are blocked, so no connection is made.
    pid = repo.create_project(
        surface_project([80], hosts=["lab.test", "internal.lab.test", "meta.lab.test"])
    ).project_id
    done = _scan(
        repo,
        _manager(repo, settings, _runner()),
        pid,
        ["lab.test"],
        hosts="internal.lab.test, meta.lab.test",
        ports="80",
    )
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["dns"]["blocked_addresses"] >= 2
    nc = summary["hosts_not_checked"]
    assert "internal.lab.test" in nc and "meta.lab.test" in nc
    assert all(
        "IP policy" in nc[h] or "no address" in nc[h]
        for h in ("internal.lab.test", "meta.lab.test")
    )
    # the private/metadata IPs are inventoried as excluded, never as open ports
    hosts_detail = _out(repo, pid, done.scan_id, "hosts.json")
    assert hosts_detail["dns"]["internal.lab.test"]["blocked"]
    assert not summary["open_services"]


def test_coverage_lists_tested_and_untested_ports_with_reasons(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    # scope allows only 80 and 443; request 80,443,9999 -> 9999 is reported not-tested.
    pid = repo.create_project(surface_project([80, 443])).project_id
    done = _scan(repo, _manager(repo, settings, _runner()), pid, ["lab.test"], ports="80,443,9999")
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["ports_requested"] == [80, 443, 9999]
    assert summary["ports_tested"] == [80, 443]
    assert "9999" in summary["ports_not_tested"]
    coverage = _out(repo, pid, done.scan_id, "coverage.json")["results"]
    cov = [r for r in coverage if r["rule_id"] == "SURF-COV-001"]
    assert cov and any("2 port(s) tested" in r["rationale"] for r in cov)


def test_banner_and_exposure_findings_are_created_with_sanitized_evidence(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    # A "database" service on an in-scope host: reachability is a finding; the banner that
    # leaks a version is a finding; a secret in the banner is never stored.
    db = BannerServer(b"5.7.40-log mysql_native_password token=supersecret-abcdef\n\x00")
    try:
        pid = repo.create_project(surface_project([db.port])).project_id
        _scan(repo, _manager(repo, settings, _runner()), pid, ["lab.test"], ports=str(db.port))
    finally:
        db.close()
    findings = repo.list_findings(pid, limit=100).items
    rules = {f.rule_id for f in findings}
    assert "SURF-SVC-001" in rules  # reachable service (mapped by banner to mysql)
    assert "SURF-BANNER-001" in rules  # version disclosed
    for f in findings:
        assert "supersecret-abcdef" not in f.model_dump_json()
        for eid in f.evidence_ids:
            ev = repo.get_evidence(pid, eid)
            assert "supersecret-abcdef" not in ev.response_excerpt


def test_web_origin_probe_reuses_module5_checks(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    from tests.webfixtures import LabHandler, start_server

    LabHandler.hits = []
    web = start_server(LabHandler)
    port = web.server_address[1]
    try:
        pid = repo.create_project(surface_project([port])).project_id
        done = _scan(
            repo,
            _manager(repo, settings, _runner()),
            pid,
            ["lab.test"],
            ports=str(port),
            web_max_pages=3,
        )
    finally:
        web.shutdown()
        web.server_close()
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["web_origins"], "an HTTP origin should be discovered on the open port"
    origin = summary["web_origins"][0]
    assert origin["status"] == 200 and origin["title"] == "Lab home"
    # the web scanner's passive header/cookie checks run on the discovered origin
    rules = {f.rule_id for f in repo.list_findings(pid, limit=200).items}
    assert any(r.startswith("WEB-HDR") for r in rules)
    # endpoints discovered under the origin are inventoried as URL assets
    assets = repo.list_assets(pid, limit=500).items
    assert any(
        a.asset_type.value == "url" and a.attributes.get("kind") == "endpoint" for a in assets
    )


def test_inventory_and_changes_persist_across_restart(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    extra = BannerServer(b"SSH-2.0-OpenSSH_9.0\r\n")
    try:
        pid = repo.create_project(surface_project([80, extra.port])).project_id
        # First scan: only port 80 tested (closed on 127.0.0.1 for the plain-http default).
        first = _scan(repo, _manager(repo, settings, _runner()), pid, ["lab.test"], ports="80")
        first_assets = {a.locator for a in repo.list_assets(pid, limit=500).items}
        assert "lab.test" in {
            a.locator
            for a in repo.list_assets(pid, limit=500).items
            if a.asset_type.value == "hostname"
        }
        # Second scan (fresh manager = restart): the ssh port is now tested and opens.
        second = _scan(
            repo, _manager(repo, settings, _runner()), pid, ["lab.test"], ports=f"80,{extra.port}"
        )
    finally:
        extra.close()
    assert first.scan_id != second.scan_id
    # the hostname asset persisted and was re-observed (last_seen advanced), not duplicated
    hostnames = [
        a
        for a in repo.list_assets(pid, limit=500).items
        if a.asset_type.value == "hostname" and a.locator == "lab.test"
    ]
    assert len(hostnames) == 1 and hostnames[0].last_seen >= hostnames[0].first_seen
    changes = _out(repo, pid, second.scan_id, "changes.json")
    assert changes["baseline"] is False and changes["previous_scan_id"] == first.scan_id
    assert any(c["port"] == extra.port for c in changes["opened_ports"])
    assert "lab.test" in first_assets


FAKE_NMAP = r"""
import sys
if "--version" in sys.argv:
    print("Nmap version 7.95 ( https://nmap.org )")
    sys.exit(0)
# argv must contain -sT, -oX -, and pinned IP literals only
assert "-sT" in sys.argv and sys.argv[sys.argv.index("-oX") + 1] == "-", sys.argv
ports = sys.argv[sys.argv.index("-p") + 1].split(",")
ip = sys.argv[-1]
assert ip == "127.0.0.1", ip  # pinned IP, never a hostname
rows = "".join(
    f'<port protocol="tcp" portid="{p}"><state state="{"open" if p==ports[0] else "closed"}" '
    f'reason="syn-ack"/><service name="ssh"/></port>' for p in ports)
print(f'<?xml version="1.0"?><nmaprun version="7.95" args="nmap">'
      f'<host><address addr="{ip}" addrtype="ipv4"/><ports>{rows}</ports></host></nmaprun>')
"""


def test_nmap_integration_uses_pinned_ip_and_safe_argv(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Any
) -> None:
    import sys

    from app.integrations.nmap import NmapSpec

    script = tmp_path / "fake_nmap.py"
    script.write_text(FAKE_NMAP)
    spec = NmapSpec(sys.executable, prefix=(str(script),))
    pid = repo.create_project(surface_project([22, 80, 443])).project_id
    done = _scan(
        repo,
        _manager(repo, settings, _runner(nmap=lambda: spec)),
        pid,
        ["lab.test"],
        ports="22,80,443",
        read_banners=False,
    )
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["tool_versions"]["nmap"].startswith("Nmap 7.95")
    assert summary["port_method"] == "auto"
    hosts = _out(repo, pid, done.scan_id, "hosts.json")
    states = hosts["port_states"]["lab.test"]
    assert states.get("127.0.0.1:22") == "open"  # first port reported open by fake nmap
    assert states.get("127.0.0.1:80") == "closed"


def test_malformed_nmap_output_falls_back_without_failing(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Any
) -> None:
    import sys

    from app.integrations.nmap import NmapSpec

    script = tmp_path / "bad_nmap.py"
    script.write_text(
        "import sys\nsys.exit(0) if '--version' in sys.argv else print('<<<not xml>>>')\n"
    )
    spec = NmapSpec(sys.executable, prefix=(str(script),))
    pid = repo.create_project(surface_project([80])).project_id
    done = _scan(
        repo, _manager(repo, settings, _runner(nmap=lambda: spec)), pid, ["lab.test"], ports="80"
    )
    # malformed XML -> warning + TCP-connect fallback, scan still completes
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert any(
        "connect (nmap unusable" in r.get("method", "") for r in summary["hosts_checked"].values()
    )


def test_cancellation_stops_scan_and_keeps_partial_results(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:

    svc = BannerServer(b"SSH-2.0-OpenSSH_8.9\r\n")
    try:
        # many hosts so the run is long enough to cancel mid-way
        pid = repo.create_project(surface_project([svc.port, 80])).project_id
        jm = _manager(repo, settings, _runner())
        scan, _ = jm.submit(
            pid,
            StartScanRequest(
                module=ScanModule.ATTACK_SURFACE,
                targets=["lab.test"],
                parameters={"ports": f"{svc.port},80", "web_max_pages": 2},
                confirmed=True,
            ),
        )
        jm.start()
        try:
            wait_for(repo, pid, scan.scan_id, lambda s: s.state == ScanState.RUNNING, timeout=20)
            jm.cancel(pid, scan.scan_id)
            done = wait_for(repo, pid, scan.scan_id, terminal, timeout=30)
        finally:
            jm.stop()
    finally:
        svc.close()
    assert done.state == ScanState.CANCELLED
    assert "work/profile.json" in done.output_refs  # partial output written before the stop
