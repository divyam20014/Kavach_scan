"""Scope engine: matching, exclusions, suffix confusion, redirects, authorization expiry."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.models import new_id
from app.models.project import AuthorizationRecord, InternalTargetOverride, Project, ScopeDefinition
from app.scope.engine import AuthorizationError, Reason, ScopePolicy, require_active_authorization
from tests.conftest import make_project

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def project(
    scope: dict[str, Any] | None = None,
    *,
    start: datetime = T0 - timedelta(days=1),
    end: datetime = T0 + timedelta(days=10),
    attested: bool = True,
    **kw: Any,
) -> Project:
    auth = AuthorizationRecord(
        organization="o",
        target_owner="t",
        authorized_by="a",
        window_start=start,
        window_end=end,
        attestation_event_id=new_id("event") if attested else None,
    )
    return make_project(authorization=auth, scope=ScopeDefinition(**(scope or {})), **kw)


def policy(scope: dict[str, Any] | None = None, now: datetime = T0, **kw: Any) -> ScopePolicy:
    return ScopePolicy(project(scope, **kw), clock=lambda: now)


BASE = {
    "schemes": ["https"],
    "hosts": ["trusted.example", "app.example.com"],
    "wildcard_domains": ["*.api.example.com"],
    "ip_ranges": ["203.0.114.0/24"],
    "ports": [443, 8443],
    "path_prefixes": ["/app", "/api/"],
    "exclusions": {
        "hosts": ["admin.api.example.com"],
        "wildcard_domains": ["*.internal.api.example.com"],
        "ip_ranges": ["203.0.114.128/25"],
        "ports": [8443],
        "path_prefixes": ["/app/logout"],
    },
}


@pytest.mark.parametrize(
    "url",
    [
        "https://trusted.example/app",
        "https://TRUSTED.example./app/x",
        "https://app.example.com/api/v1/users",
        "https://v1.api.example.com/app",
        "https://a.b.api.example.com/api/",
        "https://203.0.114.5/app",
        "https://trusted.example/app/./x/../y",
    ],
)
def test_allowed_targets(url: str) -> None:
    d = policy(BASE).is_target_in_scope(url)
    assert d.allowed, (url, d.reason, d.message)
    assert d.reason == Reason.ALLOWED and d.rule


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://trusted.example.attacker.test/app", Reason.HOST_OUT_OF_SCOPE),
        ("https://nottrusted.example/app", Reason.HOST_OUT_OF_SCOPE),
        ("https://trusted.examplex/app", Reason.HOST_OUT_OF_SCOPE),
        ("https://sub.trusted.example/app", Reason.HOST_OUT_OF_SCOPE),  # exact host != subdomain
        ("https://api.example.com/app", Reason.HOST_OUT_OF_SCOPE),  # wildcard excludes apex
        ("https://xapi.example.com/app", Reason.HOST_OUT_OF_SCOPE),
        ("https://v1.api.example.com.evil.test/app", Reason.HOST_OUT_OF_SCOPE),
        ("https://admin.api.example.com/app", Reason.HOST_EXCLUDED),
        ("https://db.internal.api.example.com/app", Reason.HOST_EXCLUDED),
        ("http://trusted.example/app", Reason.SCHEME_NOT_ALLOWED),
        ("https://trusted.example:8443/app", Reason.PORT_EXCLUDED),
        ("https://trusted.example:9443/app", Reason.PORT_NOT_ALLOWED),
        ("https://trusted.example/apiary", Reason.PATH_OUT_OF_SCOPE),
        ("https://trusted.example/admin", Reason.PATH_OUT_OF_SCOPE),
        ("https://trusted.example/app/../admin", Reason.PATH_OUT_OF_SCOPE),
        ("https://trusted.example/app/%2e%2e/admin", Reason.PATH_OUT_OF_SCOPE),
        ("https://trusted.example/app/logout", Reason.PATH_EXCLUDED),
        ("https://trusted.example/app/%6Cogout", Reason.PATH_EXCLUDED),  # %6C = 'l'
        ("https://trusted.example/app/%252e%252e/admin", Reason.AMBIGUOUS_PATH),
        ("https://trusted.example/app/..;/admin", Reason.AMBIGUOUS_PATH),
        ("https://203.0.114.200/app", Reason.IP_EXCLUDED),
        ("https://203.0.115.1/app", Reason.IP_OUT_OF_SCOPE),
        ("https://user:pw@trusted.example/app", Reason.USERINFO_IN_URL),
        ("https://127.1/app", Reason.AMBIGUOUS_HOST),
        ("ftp://trusted.example/app", Reason.SCHEME_NOT_ALLOWED),
        ("not a url", Reason.UNPARSEABLE),
    ],
)
def test_blocked_targets_with_reason(url: str, reason: Reason) -> None:
    d = policy(BASE).is_target_in_scope(url)
    assert not d.allowed and d.reason == reason, (url, d.reason, d.message)
    assert d.project_id and d.scope_hash and d.decision_id and d.message


def test_idn_scope_matches_unicode_and_punycode_targets() -> None:
    p = policy({"hosts": ["bücher.example".encode("idna").decode()], "path_prefixes": ["/"]})
    assert p.is_target_in_scope("https://bücher.example/").allowed
    assert p.is_target_in_scope("https://xn--bcher-kva.example/").allowed
    assert not p.is_target_in_scope("https://bucher.example/").allowed  # homograph without umlaut


def test_ipv6_ranges() -> None:
    p = policy({"hosts": [], "ip_ranges": ["2001:db9::/32"], "path_prefixes": ["/"]})
    assert p.is_target_in_scope("https://[2001:db9::10]/").allowed
    assert not p.is_target_in_scope("https://[2001:dba::10]/").allowed


def test_private_ip_literal_in_scope_still_blocked_without_override() -> None:
    p = policy({"hosts": [], "ip_ranges": ["10.0.0.0/24"], "path_prefixes": ["/"]})
    d = p.is_target_in_scope("https://10.0.0.5/")
    assert not d.allowed and d.reason == Reason.IP_BLOCKED_RANGE


def test_override_allows_only_listed_ranges_until_expiry() -> None:
    override = InternalTargetOverride(
        ip_ranges=["10.0.0.0/24"],
        reason="internal staging environment",
        expires_at=T0 + timedelta(hours=1),
        audit_event_id=new_id("event"),
    )
    scope = {
        "hosts": ["staging.corp.example"],
        "ip_ranges": ["10.0.0.0/16"],
        "path_prefixes": ["/"],
        "internal_override": override,
    }
    p = policy(scope)
    assert p.is_target_in_scope("https://10.0.0.5/").allowed
    assert not p.is_target_in_scope("https://10.0.1.5/").allowed  # in scope but not in override
    assert p.validate_resolved_ip("staging.corp.example", "10.0.0.9").allowed
    assert not p.validate_resolved_ip("staging.corp.example", "127.0.0.1").allowed
    expired = policy(scope, now=T0 + timedelta(hours=1))
    assert not expired.validate_resolved_ip("staging.corp.example", "10.0.0.9").allowed
    assert any("expired" in w for w in expired.warnings())


def test_metadata_never_allowed_even_with_override_in_scope() -> None:
    override = InternalTargetOverride(
        ip_ranges=["169.254.0.0/16"],
        reason="link-local lab network",
        expires_at=T0 + timedelta(days=1),
        audit_event_id=new_id("event"),
    )
    p = policy({"hosts": ["x.example"], "path_prefixes": ["/"], "internal_override": override})
    assert p.validate_resolved_ip("x.example", "169.254.1.1").allowed
    d = p.validate_resolved_ip("x.example", "169.254.169.254")
    assert not d.allowed and d.reason == Reason.IP_CLOUD_METADATA


@pytest.mark.parametrize(
    ("location", "allowed", "reason"),
    [
        ("/app/next", True, Reason.ALLOWED),
        ("https://app.example.com/api/v2", True, Reason.ALLOWED),
        ("https://evil.test/app", False, Reason.HOST_OUT_OF_SCOPE),
        ("//evil.test/app", False, Reason.HOST_OUT_OF_SCOPE),  # protocol-relative
        ("http://trusted.example/app", False, Reason.SCHEME_NOT_ALLOWED),  # downgrade
        ("https://127.0.0.1/app", False, Reason.IP_OUT_OF_SCOPE),
        ("https://169.254.169.254/latest/meta-data/", False, Reason.IP_OUT_OF_SCOPE),
        ("/admin", False, Reason.PATH_OUT_OF_SCOPE),
        ("../admin", False, Reason.PATH_OUT_OF_SCOPE),
        ("https://trusted.example@evil.test/", False, Reason.USERINFO_IN_URL),
        ("javascript:alert(1)", False, Reason.SCHEME_NOT_ALLOWED),
    ],
)
def test_redirect_validation(location: str, allowed: bool, reason: Reason) -> None:
    d = policy(BASE).validate_redirect("https://trusted.example/app/start", location)
    assert d.allowed is allowed and d.reason == reason and d.check == "redirect", (
        location,
        d.message,
    )


def test_discovered_hosts_are_not_approved_by_resolution() -> None:
    p = policy(BASE)
    assert p.host_status("new.api.example.com")[0] == "in_scope"  # admitted by wildcard
    assert p.host_status("dev.trusted.example")[0] == "pending_approval"  # related, not approved
    assert p.host_status("evil.test")[0] == "out_of_scope"
    assert p.host_status("admin.api.example.com")[0] == "excluded"


# ------------------------------------------------------------------ authorization


@pytest.mark.parametrize(
    ("now", "reason"),
    [
        (T0 - timedelta(days=1) - timedelta(seconds=1), Reason.AUTHORIZATION_NOT_STARTED),
        (T0 - timedelta(days=1), None),  # start boundary is inclusive
        (T0 + timedelta(days=10) - timedelta(microseconds=1), None),
        (T0 + timedelta(days=10), Reason.AUTHORIZATION_EXPIRED),  # end boundary is exclusive
        (T0 + timedelta(days=30), Reason.AUTHORIZATION_EXPIRED),
    ],
)
def test_authorization_window_boundaries(now: datetime, reason: Reason | None) -> None:
    p = project(BASE)
    if reason is None:
        assert require_active_authorization(p, now).allowed
    else:
        with pytest.raises(AuthorizationError) as info:
            require_active_authorization(p, now)
        assert info.value.decision.reason == reason


def test_missing_authorization_attestation_and_archived() -> None:
    no_auth = make_project(authorization=None)
    with pytest.raises(AuthorizationError) as info:
        require_active_authorization(no_auth, T0)
    assert info.value.decision.reason == Reason.AUTHORIZATION_MISSING
    with pytest.raises(AuthorizationError) as info:
        require_active_authorization(project(BASE, attested=False), T0)
    assert info.value.decision.reason == Reason.ATTESTATION_MISSING
    with pytest.raises(AuthorizationError) as info:
        require_active_authorization(project(BASE, status="archived"), T0)
    assert info.value.decision.reason == Reason.PROJECT_ARCHIVED


def test_invalid_stored_scope_denies_everything() -> None:
    p = project({"hosts": ["ok.example"], "path_prefixes": ["/"]})
    # bypass model validation to simulate a legacy/corrupt scope entry
    broken = p.model_copy(update={"scope": p.scope.model_copy(update={"hosts": ["127.1"]})})
    pol = ScopePolicy(broken, clock=lambda: T0)
    assert not pol.valid
    d = pol.is_target_in_scope("https://ok.example/")
    assert not d.allowed and d.reason == Reason.SCOPE_INVALID


def test_scope_warnings_flag_blocked_overlaps() -> None:
    p = policy(
        {"hosts": [], "ip_ranges": ["10.0.0.0/8", "169.254.169.254/32"], "path_prefixes": ["/"]}
    )
    text = " ".join(p.warnings())
    assert "blocked unless an internal-target override" in text and "can never be reached" in text
