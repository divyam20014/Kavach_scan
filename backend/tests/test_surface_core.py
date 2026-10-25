"""Phase 06: target checks, service id, TCP guard, passive parsing, inventory diff, ranking."""

from __future__ import annotations

from typing import Any

import pytest

from app.integrations.passive_sources import parse_crtsh
from app.integrations.tcp import probe_port
from app.models.asset import Asset
from app.models.common import AssetType, Confidence, ScopeStatus, Severity, new_id
from app.models.finding import Finding
from app.scanners.surface.profile import DEFAULT_PORTS, parse_hosts, port_plan, validate_parameters
from app.scanners.surface.ranking import rank
from app.scanners.surface.runner import check_targets
from app.scanners.surface.services import identify, sanitize_banner
from app.scope import AuthorizedTarget, TransportResponse, normalize_target
from app.scope.engine import ScopePolicy
from tests.surfacefixtures import surface_project

PID = "prj_" + "a" * 32


def _policy() -> ScopePolicy:
    project = surface_project(list(DEFAULT_PORTS))
    return ScopePolicy(project)


# ---------------------------------------------------------------------- targets


def test_check_targets_accepts_hosts_roots_ips_and_rejects_others() -> None:
    project = surface_project([80, 443], hosts=["lab.test"]).model_copy()
    policy = ScopePolicy(project)
    ok, problems = check_targets(["lab.test", "https://LAB.TEST/x"], policy)
    assert ok == ["lab.test"] and not problems
    # a sibling host not in scope and not a root is rejected
    _, bad = check_targets(["nope.example"], policy)
    assert bad and "neither" in bad[0][1]


def test_check_targets_rejects_excluded_and_bad_input() -> None:
    policy = _policy()
    _, problems = check_targets(["not a host!!", "http://["], policy)
    assert len(problems) == 2


# ---------------------------------------------------------------------- hosts parsing


def test_parse_hosts_normalizes_and_rejects() -> None:
    hosts, rejected = parse_hosts("lab.test, https://www.lab.test:8443/x\n*.wild.test  BAD_HOST!!")
    assert "lab.test" in hosts and "www.lab.test" in hosts and "wild.test" in hosts
    assert rejected == ["BAD_HOST!!"]


# ---------------------------------------------------------------------- services / banners


def test_sanitize_banner_strips_control_and_secrets() -> None:
    out = sanitize_banner(b"220 FTP ready\r\n\x00\x01 password=hunter2 token=abcdef123456")
    assert "\x00" not in out and "\r" not in out
    assert "hunter2" not in out and "abcdef123456" not in out


@pytest.mark.parametrize(
    ("port", "banner", "service", "product"),
    [
        (22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu", "ssh", "OpenSSH"),
        (21, "220 (vsFTPd 3.0.3)", "ftp", "vsftpd"),
        (25, "220 mail.test ESMTP Postfix", "smtp", "Postfix"),
        (9999, "", "unknown", ""),
        (3306, "", "mysql", ""),
    ],
)
def test_identify(port: int, banner: str, service: str, product: str) -> None:
    info = identify(port, banner)
    assert info.service == service and info.product == product


# ---------------------------------------------------------------------- TCP adapter guard


def test_probe_port_refuses_unpinned_address() -> None:
    target = normalize_target("http://lab.test:80/")
    authorized = AuthorizedTarget(target=target, pinned_ips=("127.0.0.1",), decisions=())
    with pytest.raises(ValueError, match="did not pin"):
        probe_port(authorized, "10.0.0.5", 80)  # not pinned
    with pytest.raises(ValueError, match="does not match"):
        probe_port(authorized, "127.0.0.1", 81)  # wrong port


# ---------------------------------------------------------------------- passive parsing


def test_parse_crtsh_only_keeps_in_scope_canonical_names() -> None:
    data = [
        {"name_value": "a.lab.test\n*.b.lab.test"},
        {"name_value": "LAB.TEST"},
        {"name_value": "evil.example"},  # different root: dropped
        {"name_value": "1.2.3.4"},  # not a hostname: dropped
        {"common_name": "ignored"},
        "not-a-dict",
    ]
    names = parse_crtsh(data, "lab.test")
    assert set(names) == {"a.lab.test", "b.lab.test", "lab.test"}


def test_parse_crtsh_rejects_non_list() -> None:
    assert parse_crtsh({"x": 1}, "lab.test") == []


# ---------------------------------------------------------------------- inventory diff


def test_diff_snapshots_reports_changes_without_false_removals() -> None:
    prev = {
        "scan_id": "scn_old",
        "hosts": {
            "a.lab.test": {
                "status": "in_scope",
                "ips": ["127.0.0.1"],
                "open_ports": [80],
                "tested_ports": [80, 443],
            },
            "b.lab.test": {
                "status": "pending_approval",
                "ips": [],
                "open_ports": [],
                "tested_ports": [],
            },
        },
        "origins": ["http://a.lab.test"],
    }
    cur = {
        "scan_id": "scn_new",
        "hosts": {
            "a.lab.test": {
                "status": "in_scope",
                "ips": ["127.0.0.2"],
                "open_ports": [80, 443],
                "tested_ports": [80, 443],
            },
            "c.lab.test": {
                "status": "in_scope",
                "ips": ["127.0.0.1"],
                "open_ports": [],
                "tested_ports": [80],
            },
        },
        "origins": ["http://a.lab.test", "https://a.lab.test"],
    }
    changes = __import__(
        "app.scanners.surface.inventory", fromlist=["diff_snapshots"]
    ).diff_snapshots(prev, cur)
    assert changes["previous_scan_id"] == "scn_old"
    assert changes["new_hosts"] == ["c.lab.test"]
    assert changes["not_observed_hosts"] == ["b.lab.test"]
    assert {"host": "a.lab.test", "port": 443} in changes["opened_ports"]
    assert changes["ip_changes"][0]["host"] == "a.lab.test"
    assert "https://a.lab.test" in changes["new_origins"]


def test_diff_snapshots_baseline() -> None:
    from app.scanners.surface.inventory import diff_snapshots

    changes = diff_snapshots(None, {"hosts": {}, "origins": []})
    assert changes["baseline"] is True


# ---------------------------------------------------------------------- ranking


def _asset(atype: AssetType, locator: str, *, parent: str | None = None, **kw: object) -> Asset:
    return Asset(
        asset_id=new_id("asset"),
        project_id=PID,
        asset_type=atype,
        locator=locator,
        parent_asset_id=parent,
        scope_status=ScopeStatus.IN_SCOPE,
        **kw,
    )  # type: ignore[arg-type]


def _finding(
    asset_id: str,
    severity: Severity,
    *,
    confidence: Confidence = Confidence.CONFIRMED,
    **kw: object,
) -> Finding:
    return Finding(
        finding_id=new_id("finding"),
        project_id=PID,
        title="t",
        severity=severity,
        confidence=confidence,
        affected_asset_ids=[asset_id],
        **kw,
    )  # type: ignore[arg-type]


def test_ranking_is_transparent_and_discovery_is_not_a_vulnerability() -> None:
    host = _asset(AssetType.HOSTNAME, "a.lab.test")
    port = _asset(
        AssetType.PORT, "tcp://127.0.0.1:3306", parent=host.asset_id, attributes={"port": 3306}
    )
    bare = _asset(AssetType.HOSTNAME, "b.lab.test")
    crit = _asset(AssetType.HOSTNAME, "c.lab.test", criticality="high")
    findings = [_finding(port.asset_id, Severity.MEDIUM)]
    ranks = rank([host, port, bare, crit], findings)
    # discovery only -> 0, explicitly stated
    assert ranks[bare.asset_id]["score"] == 0
    assert "discovery is not a vulnerability" in ranks[bare.asset_id]["factors"][0]
    # host inherits the medium finding from its port (+20) and the sensitive-port exposure (+10)
    assert ranks[host.asset_id]["score"] == 30
    assert any("worst open finding" in f for f in ranks[host.asset_id]["factors"])
    assert any("database/admin/cleartext" in f for f in ranks[host.asset_id]["factors"])
    # criticality alone contributes, transparently
    assert ranks[crit.asset_id]["score"] == 20


def test_ranking_ignores_closed_and_low_confidence_findings() -> None:
    from app.models.common import AnalystStatus

    host = _asset(AssetType.HOSTNAME, "a.lab.test")
    fp = _finding(host.asset_id, Severity.CRITICAL, analyst_status=AnalystStatus.FALSE_POSITIVE)
    weak = _finding(host.asset_id, Severity.HIGH, confidence=Confidence.POTENTIAL)  # low confidence
    ranks = rank([host], [fp, weak])
    assert ranks[host.asset_id]["score"] == 0


# ---------------------------------------------------------------------- profile validation


def test_validate_parameters_and_port_plan() -> None:
    policy = _policy()
    assert validate_parameters({"ports": "80,443"}, policy.project.scan_policy) == []
    assert validate_parameters({"ports": "1-100"}, policy.project.scan_policy)  # ranges rejected
    assert validate_parameters({"unknown": 1}, policy.project.scan_policy)
    assert validate_parameters({"port_method": "syn"}, policy.project.scan_policy)
    assert validate_parameters({"max_hosts": 0}, policy.project.scan_policy)
    plan = port_plan({}, policy)
    assert plan.requested == list(DEFAULT_PORTS)
    assert set(plan.tested) <= set(DEFAULT_PORTS)


def test_up_to_1000_explicit_ports_are_accepted_above_1000_rejected() -> None:
    """Widened from 100 to 1000 ports (TBD-077) for Nmap-'top ports'-scale coverage; the list
    is still explicit ports only, never a range."""
    policy = _policy()
    ports_1000 = ",".join(str(p) for p in range(1, 1001))
    ports_1001 = ",".join(str(p) for p in range(1, 1002))
    assert validate_parameters({"ports": ports_1000}, policy.project.scan_policy) == []
    assert validate_parameters({"ports": ports_1001}, policy.project.scan_policy)


def test_port_plan_excludes_out_of_scope_ports() -> None:
    project = surface_project([80, 443])  # only 80,443 in scope
    plan = port_plan({"ports": "80,443,8080"}, ScopePolicy(project))
    assert plan.tested == [80, 443] and "8080" in plan.not_tested


# ---------------------------------------------------------------------- passive source adapter


class _FakeTransport:
    def __init__(self, response: TransportResponse) -> None:
        self.response = response
        self.sent: list[Any] = []

    def send(
        self, method: str, authorized: AuthorizedTarget, options: Any = None
    ) -> TransportResponse:
        self.sent.append((method, authorized.target.url, authorized.pinned_ips, options))
        return self.response


def test_crtsh_source_pins_public_ip_rate_limits_and_parses() -> None:
    from app.integrations.passive_sources import CrtShSource

    body = b'[{"name_value": "a.lab.test"}, {"name_value": "b.lab.test"}]'
    transport = _FakeTransport(TransportResponse(status=200, body=body))

    class Resolver:
        def resolve(self, host: str) -> list[str]:
            assert host == "crt.sh"
            return ["93.184.216.34"]  # public

    sleeps: list[float] = []
    source = CrtShSource(
        Resolver(), transport=transport, min_interval=5.0, sleep=sleeps.append, clock=lambda: 100.0
    )
    result = source.query("lab.test")
    assert set(result.names) == {"a.lab.test", "b.lab.test"}
    assert transport.sent[0][2] == ("93.184.216.34",)  # pinned to the public IP
    assert "q=%25.lab.test" in transport.sent[0][3].query  # %.lab.test query
    source.query("lab.test")  # second query must wait for the rate-limit interval
    assert sleeps and sleeps[-1] > 0


def test_crtsh_source_refuses_private_resolution() -> None:
    from app.integrations.passive_sources import CrtShSource

    class Resolver:
        def resolve(self, host: str) -> list[str]:
            return ["127.0.0.1"]  # not public

    source = CrtShSource(
        Resolver(),
        transport=_FakeTransport(TransportResponse(status=200)),
        sleep=lambda _s: None,
        clock=lambda: 0.0,
    )
    result = source.query("lab.test")
    assert "non-public" in result.error and result.names == []
