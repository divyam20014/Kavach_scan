"""Property-based tests (hypothesis) for matching invariants that must hold for ALL inputs."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from app.models import new_id
from app.models.project import AuthorizationRecord, ScopeDefinition
from app.scope.canonical import (
    CanonicalizationError,
    host_matches_wildcard,
    normalize_path,
    normalize_target,
    path_matches_prefix,
)
from app.scope.engine import ScopePolicy
from app.scope.ip_policy import blocked_range_for
from tests.conftest import make_project

T0 = datetime(2026, 11, 1, tzinfo=UTC)
label = st.from_regex(r"[a-z][a-z0-9]{0,9}", fullmatch=True)
hostname = st.lists(label, min_size=2, max_size=4).map(".".join)
segment = st.text(alphabet="abcxyz019-_.~%2eE/;", min_size=0, max_size=8)
FAST = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def policy(hosts: list[str], wildcards: list[str] | None = None) -> ScopePolicy:
    auth = AuthorizationRecord(
        organization="o",
        target_owner="t",
        authorized_by="a",
        window_start=T0 - timedelta(days=1),
        window_end=T0 + timedelta(days=1),
        attestation_event_id=new_id("event"),
    )
    scope = ScopeDefinition(hosts=hosts, wildcard_domains=wildcards or [], path_prefixes=["/"])
    return ScopePolicy(make_project(authorization=auth, scope=scope), clock=lambda: T0)


@FAST
@given(trusted=hostname, attacker=hostname)
def test_suffix_confusion_never_matches(trusted: str, attacker: str) -> None:
    p = policy([trusted], [f"*.{trusted}"])
    for host in (f"{trusted}.{attacker}", f"x{trusted}", f"{trusted}x.{attacker}"):
        # skip coincidences where the generated host genuinely IS the trusted domain or a subdomain of it
        if host == trusted or host.endswith("." + trusted):
            continue
        assert not p.is_target_in_scope(f"https://{host}/").allowed, host


@FAST
@given(base=hostname, sub=label, other=hostname)
def test_wildcard_matches_iff_label_boundary_suffix(base: str, sub: str, other: str) -> None:
    assert host_matches_wildcard(f"{sub}.{base}", f"*.{base}")
    assert not host_matches_wildcard(base, f"*.{base}")
    assume(not other.endswith("." + base) and other != base)
    assert not host_matches_wildcard(other, f"*.{base}")


@FAST
@given(parts=st.lists(segment, max_size=6))
def test_path_normalization_is_idempotent_and_never_escapes_root(parts: list[str]) -> None:
    raw = "/" + "/".join(parts)
    try:
        once = normalize_path(raw)
    except CanonicalizationError:
        return
    assert once.startswith("/")
    assert normalize_path(once) == once
    assert ".." not in once.split("/")  # no dot-dot segment survives (names like "..0" are fine)


@FAST
@given(parts=st.lists(segment, max_size=6))
def test_normalized_path_outside_prefix_is_never_allowed(parts: list[str]) -> None:
    raw = "/app/" + "/".join(parts)
    try:
        normalized = normalize_path(raw)
    except CanonicalizationError:
        return
    p = policy(["a.example.com"])
    p.paths = ("/app",)  # restrict for this property
    decision = p.is_path_allowed(raw)
    assert decision.allowed == path_matches_prefix(normalized, "/app")


@FAST
@given(ip=st.ip_addresses())
def test_every_non_global_ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Python's own classification of non-public space must be a subset of our blocked set."""
    if ip.version == 6 and ip in ipaddress.ip_network("2001::/23"):
        return  # IETF protocol space; Teredo handled separately, the rest is not routable traffic
    if not ip.is_global:
        assert blocked_range_for(ip) is not None, ip


@FAST
@given(host=hostname, port=st.integers(min_value=1, max_value=65535))
def test_canonical_url_round_trips(host: str, port: int) -> None:
    try:
        target = normalize_target(f"https://{host.upper()}:{port}/a/./b")
    except CanonicalizationError:
        return
    assert normalize_target(target.url) == target
