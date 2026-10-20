"""IP policy: every default-blocked range, embedded IPv4 in IPv6, metadata never overridable."""

from __future__ import annotations

import ipaddress

import pytest

from app.scope.ip_policy import BLOCKED_RANGES, blocked_range_for, embedded_ipv4


@pytest.mark.parametrize("rng", BLOCKED_RANGES, ids=lambda r: str(r.network))
def test_every_blocked_range_blocks_first_and_last_address(rng) -> None:  # type: ignore[no-untyped-def]
    net = rng.network
    for ip in (net.network_address, net.broadcast_address):
        assert blocked_range_for(ip) is not None, ip


@pytest.mark.parametrize(
    ("ip", "category"),
    [
        ("127.0.0.1", "loopback"),
        ("127.255.255.254", "loopback"),
        ("10.1.2.3", "private"),
        ("172.31.255.255", "private"),
        ("192.168.1.1", "private"),
        ("169.254.169.254", "cloud_metadata"),
        ("169.254.1.1", "link_local"),
        ("100.100.100.200", "cloud_metadata"),
        ("100.64.0.1", "shared"),
        ("168.63.129.16", "cloud_metadata"),
        ("0.0.0.0", "unspecified"),  # noqa: S104 - asserted to be blocked
        ("224.0.0.1", "multicast"),
        ("255.255.255.255", "broadcast"),
        ("::1", "loopback"),
        ("::", "unspecified"),
        ("fe80::1", "link_local"),
        ("fd00::1", "private"),
        ("fd00:ec2::254", "cloud_metadata"),
        ("ff02::1", "multicast"),
        # IPv4 hidden inside IPv6
        ("::ffff:127.0.0.1", "loopback"),
        ("::ffff:169.254.169.254", "cloud_metadata"),
        ("::ffff:10.0.0.1", "private"),
        ("64:ff9b::7f00:1", "loopback"),  # NAT64 -> 127.0.0.1
        ("64:ff9b::a9fe:a9fe", "cloud_metadata"),  # NAT64 -> 169.254.169.254
        ("2002:7f00:0001::", "tunnel"),  # 6to4 is blocked as a whole (deprecated)
        ("2002:a9fe:a9fe::1", "cloud_metadata"),  # 6to4 embedding metadata stays non-overridable
        ("::127.0.0.1", "loopback"),  # IPv4-compatible
    ],
)
def test_blocked_addresses(ip: str, category: str) -> None:
    rng = blocked_range_for(ipaddress.ip_address(ip))
    assert rng is not None and rng.category == category, (ip, rng)


@pytest.mark.parametrize(
    "ip",
    [
        "93.184.216.34",
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2a00:1450:4001:81c::200e",
        "172.32.0.1",
        "11.0.0.1",
    ],
)
def test_public_addresses_not_blocked(ip: str) -> None:
    assert blocked_range_for(ipaddress.ip_address(ip)) is None


def test_teredo_embedding_is_checked() -> None:
    # Teredo client address is the bit-inverted IPv4; 2001:0:4136:e378:8000:63bf:80ff:fffe -> client 127.0.0.1
    teredo = ipaddress.ip_address("2001:0:4136:e378:8000:63bf:80ff:fffe")
    assert ipaddress.ip_address("127.0.0.1") in embedded_ipv4(teredo)
    assert blocked_range_for(teredo) is not None


def test_metadata_ranges_are_not_overridable() -> None:
    metadata = [r for r in BLOCKED_RANGES if r.category == "cloud_metadata"]
    assert metadata and not any(r.overridable for r in metadata)
    assert all(r.overridable for r in BLOCKED_RANGES if r.category != "cloud_metadata")


@pytest.mark.parametrize(
    "ip",
    ["2002:a9fe:a9fe::1", "64:ff9b::a9fe:a9fe", "::ffff:169.254.169.254", "2002:a83f:8110::1"],
)
def test_metadata_embedded_in_overridable_prefix_is_never_overridable(ip: str) -> None:
    """A narrow override of 6to4/NAT64 space must never unlock an embedded metadata address."""
    rng = blocked_range_for(ipaddress.ip_address(ip))
    assert rng is not None and rng.category == "cloud_metadata" and not rng.overridable
