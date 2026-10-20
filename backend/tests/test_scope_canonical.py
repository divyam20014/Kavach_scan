"""Canonicalization: URL parsing tricks, IDN, ports, IPv4/IPv6, paths."""

from __future__ import annotations

import pytest

from app.scope.canonical import (
    CanonicalizationError,
    host_matches_wildcard,
    normalize_host,
    normalize_path,
    normalize_target,
    path_matches_prefix,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://Example.COM", "https://example.com/"),
        ("HTTPS://example.com:443/", "https://example.com/"),
        ("http://example.com:80", "http://example.com/"),
        ("http://example.com:8080/a", "http://example.com:8080/a"),
        ("https://example.com./x", "https://example.com/x"),
        ("https://bücher.example/", "https://xn--bcher-kva.example/"),
        ("https://BÜCHER.example/", "https://xn--bcher-kva.example/"),
        ("https://example。com/", "https://example.com/"),  # ideographic full stop
        ("https://[2001:DB8::0001]/", "https://[2001:db8::1]/"),
        ("https://[2001:db8::1]:8443/x", "https://[2001:db8::1]:8443/x"),
        ("https://93.184.216.34/", "https://93.184.216.34/"),
        ("https://example.com/a/./b/../c", "https://example.com/a/c"),
        ("https://example.com/%7Euser/%41", "https://example.com/~user/A"),
        ("https://example.com/a%2Fb".replace("%2F", "%20"), None),  # space-encoded is fine
        ("https://example.com/search?q=1#frag", "https://example.com/search"),
        ("https://example.com", "https://example.com/"),
    ],
)
def test_canonical_forms(url: str, expected: str | None) -> None:
    target = normalize_target(url)
    if expected is not None:
        assert target.url == expected


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("ftp://example.com/", "scheme_not_allowed"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("javascript:alert(1)", "scheme_not_allowed"),
        ("gopher://example.com/", "scheme_not_allowed"),
        ("//example.com/", "scheme_not_allowed"),
        ("https://user:pass@example.com/", "userinfo_in_url"),
        ("https://trusted.example@evil.test/", "userinfo_in_url"),
        ("https://trusted.example:443@evil.test/", "userinfo_in_url"),
        ("https://evil.test\\@trusted.example/", "unparseable"),
        ("https://exa mple.com/", "unparseable"),
        ("https://example.com/\x00", "unparseable"),
        ("https://example.com\t/", "unparseable"),
        ("https://127.1/", "ambiguous_host"),
        ("https://0x7f.0.0.1/", "ambiguous_host"),
        ("https://0x7f000001/", "ambiguous_host"),
        ("https://2130706433/", "ambiguous_host"),
        ("https://017700000001/", "ambiguous_host"),
        ("https://0177.0.0.1/", "ambiguous_host"),
        ("https://127.000.000.001/", "ambiguous_host"),
        ("https://example.123/", "ambiguous_host"),
        ("https://[fe80::1%25eth0]/", "ambiguous_host"),
        ("https://exam%70le.com/", "ambiguous_host"),
        ("https://example.com:0/", "invalid_port"),
        ("https://example.com:65536/", "invalid_port"),
        ("https://example.com:+80/", "invalid_port"),
        ("https://example.com:80:80/", "unparseable"),
        ("https://2001:db8::1/", "unparseable"),
        ("https://[127.0.0.1]/", "unparseable"),  # IPv4 in brackets
        ("https://-bad.example/", "invalid_host"),
        ("https://" + "a" * 64 + ".example/", "invalid_host"),
        ("https://example.com/%2e%2e%2fadmin".replace("%2e%2e", ".."), "ambiguous_path"),
        ("https://example.com/api/%252e%252e/admin", "ambiguous_path"),
        ("https://example.com/api/..;/admin", "ambiguous_path"),
        ("https://example.com/api/%00/x", "ambiguous_path"),
        ("https://example.com/a%5Cb", "ambiguous_path"),
        ("", "unparseable"),
        ("https://" + "a" * 5000, "unparseable"),
    ],
)
def test_rejected_inputs(url: str, code: str) -> None:
    with pytest.raises(CanonicalizationError) as info:
        normalize_target(url)
    assert info.value.code == code, (url, info.value.code, info.value.message)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/", "/"),
        ("", "/"),
        ("/a/b/../../../../etc", "/etc"),  # cannot climb above root
        ("/api/%2e%2e/admin", "/admin"),  # encoded dot segments are decoded then removed
        ("/api/%2E/x", "/api/x"),
        ("/a//b", "/a//b"),
        ("/a/b/.", "/a/b/"),
        ("/a/b/..", "/a/"),
        ("/%7e", "/~"),
        ("/%e2%82%ac", "/%E2%82%AC"),  # non-unreserved stays encoded (uppercased)
    ],
)
def test_path_normalization(raw: str, expected: str) -> None:
    assert normalize_path(raw) == expected


@pytest.mark.parametrize(
    ("path", "prefix", "matches"),
    [
        ("/api", "/api", True),
        ("/api/v1", "/api", True),
        ("/apiary", "/api", False),
        ("/api-docs", "/api", False),
        ("/x", "/", True),
        ("/api/", "/api/", True),
        ("/api", "/api/", True),
        ("/api2/", "/api/", False),
    ],
)
def test_path_prefix_segment_boundary(path: str, prefix: str, matches: bool) -> None:
    assert path_matches_prefix(path, prefix) is matches


@pytest.mark.parametrize(
    ("host", "matches"),
    [
        ("a.example.com", True),
        ("a.b.example.com", True),
        ("example.com", False),  # wildcard does not include the apex
        ("badexample.com", False),
        ("example.com.attacker.test", False),
        ("a.example.com.attacker.test", False),
        ("xexample.com", False),
        ("a-example.com", False),
    ],
)
def test_wildcard_label_boundaries(host: str, matches: bool) -> None:
    assert host_matches_wildcard(host, "*.example.com") is matches


def test_host_normalization_returns_ip_for_literals() -> None:
    assert normalize_host("[::1]")[1] is not None
    assert normalize_host("10.0.0.1") == ("10.0.0.1", normalize_host("10.0.0.1")[1])
    assert normalize_host("Example.COM.")[0] == "example.com"
