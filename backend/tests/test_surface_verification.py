"""Phase 06 verification: changing/private IPs, exact Nmap argv, timeout/partial/oversized XML,
coverage honesty, and secret-free evidence. Local fixtures only."""

from __future__ import annotations

import json
import sys
from typing import Any

from app.core.settings import RuntimeSettings
from app.integrations.nmap import NmapSpec
from app.jobs.manager import JobManager, StartScanRequest
from app.models.common import ScanModule, ScanState
from app.scanners.surface.runner import SurfaceRunner
from app.storage.repository import StorageRepository
from tests.jobhelpers import terminal, wait_for
from tests.surfacefixtures import surface_dns, surface_project


def _mgr(repo: StorageRepository, settings: RuntimeSettings, runner: SurfaceRunner) -> JobManager:
    return JobManager(
        repo, settings, runners={ScanModule.ATTACK_SURFACE: runner}, resolver_factory=surface_dns
    )


def _runner(**kw: Any) -> SurfaceRunner:
    kw.setdefault("nmap", lambda: None)
    kw.setdefault("connect_timeout", 1.0)
    kw.setdefault("banner_timeout", 0.4)
    return SurfaceRunner(**kw)


def _scan(
    repo: StorageRepository, jm: JobManager, pid: str, targets: list[str], **params: Any
) -> Any:
    scan, _ = jm.submit(
        pid,
        StartScanRequest(
            module=ScanModule.ATTACK_SURFACE, targets=targets, parameters=params, confirmed=True
        ),
    )
    jm.start()
    try:
        return wait_for(repo, pid, scan.scan_id, terminal, timeout=90)
    finally:
        jm.stop()


def _out(repo: StorageRepository, pid: str, sid: str, name: str) -> Any:
    return json.loads(repo.read_scan_output(pid, sid, name))


# ---------------------------------------------------------------------- changing / private IPs


def test_changing_dns_answer_is_revalidated_each_scan(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    """Re-resolution happens every scan; an in-scope host that 'rebinds' from an allowed
    loopback address to a private one is blocked and never connected the second time."""
    from tests.surfacefixtures import RecordsResolver

    resolver = RecordsResolver(table={"lab.test": ["127.0.0.1"], "a.lab.test": ["127.0.0.1"]})
    pid = repo.create_project(surface_project([80], hosts=["lab.test", "a.lab.test"])).project_id

    def run() -> Any:
        jm = JobManager(
            repo,
            settings,
            runners={ScanModule.ATTACK_SURFACE: _runner()},
            resolver_factory=lambda: resolver,
        )
        return _scan(repo, jm, pid, ["lab.test"], hosts="a.lab.test", ports="80")

    first = run()
    # first scan: a.lab.test -> 127.0.0.1, allowed via the override, so it is eligible/checked
    assert resolver.calls.count("a.lab.test") >= 1
    s1 = _out(repo, pid, first.scan_id, "summary.json")
    assert "a.lab.test" in s1["hosts_checked"]

    # it 'rebinds' to a private address: re-resolved, now blocked, never connected
    resolver.table["a.lab.test"] = ["10.1.2.3"]
    second = run()
    assert resolver.calls.count("a.lab.test") >= 2  # re-resolved, not cached from the first scan
    s2 = _out(repo, pid, second.scan_id, "summary.json")
    assert s2["dns"]["blocked_addresses"] >= 1
    assert "a.lab.test" in s2["hosts_not_checked"]
    hosts = _out(repo, pid, second.scan_id, "hosts.json")
    assert hosts["dns"]["a.lab.test"]["blocked"]


def test_out_of_scope_host_is_never_resolved(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    from tests.surfacefixtures import RecordsResolver

    resolver = RecordsResolver(table=surface_dns().table, cnames=surface_dns().cnames)
    pid = repo.create_project(surface_project([80])).project_id
    jm = JobManager(
        repo,
        settings,
        runners={ScanModule.ATTACK_SURFACE: _runner()},
        resolver_factory=lambda: resolver,
    )
    done = _scan(repo, jm, pid, ["lab.test"], hosts="elsewhere.example", ports="80")
    # elsewhere.example is out of scope: it is classified but never resolved.
    assert "elsewhere.example" not in resolver.calls
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["candidates_by_status"].get("out_of_scope", 0) == 1


# ---------------------------------------------------------------------- exact Nmap argv

CAPTURE_NMAP = r"""
import sys, json
if "--version" in sys.argv:
    print("Nmap version 7.95 ( https://nmap.org )"); sys.exit(0)
with open(sys.argv[1], "w") as fh:
    json.dump(sys.argv[2:], fh)  # record the exact argv the runner passed
ip = sys.argv[-1]
print(f'<?xml version="1.0"?><nmaprun version="7.95" args="x"><host>'
      f'<address addr="{ip}" addrtype="ipv4"/><ports>'
      f'<port protocol="tcp" portid="80"><state state="closed"/></port>'
      f'</ports></host></nmaprun>')
"""


def test_exact_nmap_argv_has_no_shell_or_aggressive_flags(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Any
) -> None:
    capture = tmp_path / "argv.json"
    script = tmp_path / "capture_nmap.py"
    script.write_text(CAPTURE_NMAP)
    spec = NmapSpec(sys.executable, prefix=(str(script), str(capture)))
    pid = repo.create_project(surface_project([22, 80, 443])).project_id
    _scan(
        repo,
        _mgr(repo, settings, _runner(nmap=lambda: spec)),
        pid,
        ["lab.test"],
        ports="22,80,443",
        read_banners=False,
    )
    argv = json.loads(capture.read_text())
    assert argv[:4] == ["-sT", "-Pn", "-n", "--unprivileged"]
    assert "127.0.0.1" in argv and argv[argv.index("-p") + 1] == "22,80,443"
    assert argv[argv.index("-oX") + 1] == "-"
    joined = " ".join(argv)
    for banned in (
        "-sS",
        "-sU",
        "-sN",
        "-sF",
        "-sX",
        "-sA",
        "-A",
        "-O",
        "-sV",
        "-sC",
        "--script",
        "-p-",
        "-T4",
        "-T5",
        "-D",
        "--spoof",
        "-f",
        ";",
        "|",
        "&",
        "`",
    ):
        assert banned not in joined, banned
    # no port range, no UDP
    assert "-" not in argv[argv.index("-p") + 1]


# ---------------------------------------------------------------------- timeout / oversized / partial

TIMEOUT_NMAP = (
    "import sys, time\n"
    "sys.exit(0) if '--version' in sys.argv else None\n"
    'print(\'<?xml version="1.0"?><nmaprun version="7.95" args="x">\', flush=True)\n'
    "time.sleep(30)\n"  # emits a partial, well-formed-looking prefix then hangs
)
OVERSIZED_NMAP = (
    "import sys\n"
    "sys.exit(0) if '--version' in sys.argv else None\n"
    "sys.stdout.write('<nmaprun>' + ' ' * (9 * 1024 * 1024) + '</nmaprun>')\n"
)
PARTIAL_NMAP = (  # valid XML but reports only one host; the runner must mark the rest honestly
    "import sys\n"
    "sys.exit(0) if '--version' in sys.argv else None\n"
    "ip = sys.argv[-1]\n"
    'print(f\'<nmaprun version="7.95" args="x"><host><address addr="{ip}" addrtype="ipv4"/>\'\n'
    '      f\'<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>\'\n'
    "      f'</host></nmaprun>')\n"
)


def _nmap_scan(
    repo: StorageRepository,
    settings: RuntimeSettings,
    tmp_path: Any,
    body: str,
    *,
    ports: str = "22,80",
    timeout: float = 3.0,
) -> Any:
    script = tmp_path / "nmap.py"
    script.write_text(body)
    spec = NmapSpec(sys.executable, prefix=(str(script),))
    import app.scanners.surface.runner as r

    original = r.NMAP_TIMEOUT
    r.NMAP_TIMEOUT = timeout
    try:
        pid = repo.create_project(surface_project([22, 80])).project_id
        done = _scan(
            repo,
            _mgr(repo, settings, _runner(nmap=lambda: spec)),
            pid,
            ["lab.test"],
            ports=ports,
            read_banners=False,
        )
        return pid, done
    finally:
        r.NMAP_TIMEOUT = original


def test_nmap_timeout_falls_back_and_does_not_trust_partial_xml(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Any
) -> None:
    pid, done = _nmap_scan(repo, settings, tmp_path, TIMEOUT_NMAP, timeout=2.0)
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert any(
        "connect (nmap unusable" in r.get("method", "") for r in summary["hosts_checked"].values()
    )


def test_nmap_oversized_xml_is_rejected(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Any
) -> None:
    pid, done = _nmap_scan(repo, settings, tmp_path, OVERSIZED_NMAP)
    assert done.state in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert any("nmap unusable" in r.get("method", "") for r in summary["hosts_checked"].values())


def test_partial_nmap_scan_marks_unreported_ports_honestly(
    repo: StorageRepository, settings: RuntimeSettings, tmp_path: Any
) -> None:
    # nmap reports port 22 open but says nothing about 80; the report must not imply 80 was
    # confirmed closed by nmap, and must not claim coverage it does not have.
    pid, done = _nmap_scan(repo, settings, tmp_path, PARTIAL_NMAP, ports="22,80")
    hosts = _out(repo, pid, done.scan_id, "hosts.json")
    states = hosts["port_states"]["lab.test"]
    assert states.get("127.0.0.1:22") == "open"
    # 80 was not reported open by nmap -> either "not reported by nmap" or a connect result,
    # but never silently dropped from coverage.
    assert "127.0.0.1:80" in states


def test_coverage_does_not_imply_all_ports_scanned(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = repo.create_project(surface_project([80, 443])).project_id
    done = _scan(repo, _mgr(repo, settings, _runner()), pid, ["lab.test"], ports="80,443,9999")
    summary = _out(repo, pid, done.scan_id, "summary.json")
    # explicit list only; 9999 not in scope is reported, total tested is exactly 2
    assert summary["ports_tested"] == [80, 443]
    assert set(summary["ports_not_tested"]) == {"9999"}
    coverage = _out(repo, pid, done.scan_id, "coverage.json")["results"]
    cov = next(r for r in coverage if r["rule_id"] == "SURF-COV-001")
    assert "2 port(s) tested" in cov["rationale"]
    # the summary never claims a full/complete port scan
    assert "all ports" not in json.dumps(summary).lower()


# ---------------------------------------------------------------------- redaction / passivity


def test_tcp_probe_sends_nothing_to_the_service(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    from tests.surfacefixtures import BannerServer

    svc = BannerServer(b"SSH-2.0-OpenSSH_9.0\r\n")
    try:
        pid = repo.create_project(surface_project([svc.port])).project_id
        _scan(repo, _mgr(repo, settings, _runner()), pid, ["lab.test"], ports=str(svc.port))
    finally:
        received = svc.received
        svc.close()
    # the banner was read, but the scanner must never have written anything to the socket
    assert received == b"", received


def test_banner_secret_never_reaches_outputs_or_evidence(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    from tests.surfacefixtures import BannerServer

    secret = "api_key=sk_live_ZZZ987654321abc"  # noqa: S105 - fixture value that must be redacted
    svc = BannerServer(f"220 FTP ready {secret} token=qwerty12345\r\n".encode())
    try:
        pid = repo.create_project(surface_project([svc.port])).project_id
        done = _scan(repo, _mgr(repo, settings, _runner()), pid, ["lab.test"], ports=str(svc.port))
    finally:
        svc.close()
    blob = b""
    for path in repo.root.rglob("*"):
        if path.is_file() and pid in str(path):
            blob += path.read_bytes()
    assert blob and b"sk_live_ZZZ987654321abc" not in blob and b"qwerty12345" not in blob
    assert done.scan_id


def test_reports_disclose_passive_source_and_nmap_absence(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    pid = repo.create_project(surface_project([80])).project_id
    done = _scan(
        repo, _mgr(repo, settings, _runner(nmap=lambda: None)), pid, ["lab.test"], ports="80"
    )
    summary = _out(repo, pid, done.scan_id, "summary.json")
    assert summary["port_method"] == "auto"  # requested auto
    assert summary["tool_versions"] == {}  # no nmap ran
    assert any("Nmap is not installed" in lim for lim in summary["limitations"])
    profile = _out(repo, pid, done.scan_id, "profile.json")
    assert any(src["name"] == "crtsh" for src in profile["sources"])
