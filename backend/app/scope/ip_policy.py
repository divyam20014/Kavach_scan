"""Default-blocked address ranges (TBD-037, decided: owner-delegated, 2026-10-20).

An address is blocked when it falls in any range below. IPv6 forms that embed an
IPv4 address (IPv4-mapped, IPv4-compatible, NAT64, 6to4, Teredo) are unpacked and the
embedded IPv4 address is checked as well, so `::ffff:127.0.0.1` or `64:ff9b::a9fe:a9fe`
cannot be used to reach loopback or cloud metadata.

Ranges marked `overridable=False` (cloud metadata endpoints) can never be reached,
even with a project internal-target override.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class BlockedRange:
    network: IPNetwork
    category: str
    label: str
    overridable: bool = True


def _r(cidr: str, category: str, label: str, overridable: bool = True) -> BlockedRange:
    return BlockedRange(ipaddress.ip_network(cidr), category, label, overridable)


# Most specific first so the reported reason is the most informative one.
BLOCKED_RANGES: tuple[BlockedRange, ...] = (
    # Cloud metadata services: never reachable, not even with an override.
    _r("169.254.169.254/32", "cloud_metadata", "AWS/GCP/Azure/OpenStack instance metadata", False),
    _r("169.254.170.2/32", "cloud_metadata", "AWS ECS task metadata", False),
    _r("168.63.129.16/32", "cloud_metadata", "Azure wire server / platform DNS", False),
    _r("100.100.100.200/32", "cloud_metadata", "Alibaba Cloud metadata", False),
    _r("fd00:ec2::254/128", "cloud_metadata", "AWS IMDS over IPv6", False),
    # IPv4
    _r("0.0.0.0/8", "unspecified", "'This network' / unspecified"),
    _r("10.0.0.0/8", "private", "RFC 1918 private"),
    _r("100.64.0.0/10", "shared", "Carrier-grade NAT (RFC 6598)"),
    _r("127.0.0.0/8", "loopback", "Loopback"),
    _r("169.254.0.0/16", "link_local", "Link-local"),
    _r("172.16.0.0/12", "private", "RFC 1918 private"),
    _r("192.0.0.0/24", "reserved", "IETF protocol assignments"),
    _r("192.0.2.0/24", "documentation", "TEST-NET-1 documentation"),
    _r("192.88.99.0/24", "reserved", "Deprecated 6to4 relay anycast"),
    _r("192.168.0.0/16", "private", "RFC 1918 private"),
    _r("198.18.0.0/15", "reserved", "Benchmarking (RFC 2544)"),
    _r("198.51.100.0/24", "documentation", "TEST-NET-2 documentation"),
    _r("203.0.113.0/24", "documentation", "TEST-NET-3 documentation"),
    _r("224.0.0.0/4", "multicast", "Multicast"),
    _r("255.255.255.255/32", "broadcast", "Limited broadcast"),
    _r("240.0.0.0/4", "reserved", "Reserved for future use"),
    # IPv6
    _r("::/128", "unspecified", "Unspecified"),
    _r("::1/128", "loopback", "Loopback"),
    _r(
        "64:ff9b:1::/48",
        "nat64_local",
        "Local-use NAT64 (RFC 8215): may translate to internal IPv4",
    ),
    _r("100::/64", "reserved", "Discard-only"),
    _r("2001:db8::/32", "documentation", "Documentation"),
    _r("2001:2::/48", "reserved", "Benchmarking"),
    _r("2002::/16", "tunnel", "6to4 (deprecated, RFC 7526): routed via third-party relays"),
    _r("3fff::/20", "documentation", "Documentation (RFC 9637)"),
    _r("5f00::/16", "reserved", "SRv6 SIDs (RFC 9602)"),
    _r("fc00::/7", "private", "Unique local addresses"),
    _r("fe80::/10", "link_local", "Link-local"),
    _r("fec0::/10", "reserved", "Deprecated site-local"),
    _r("ff00::/8", "multicast", "Multicast"),
)

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_6TO4 = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")
_V4_COMPAT = ipaddress.ip_network("::/96")


def embedded_ipv4(ip: IPAddress) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses an IPv6 address may route to (mapped, compatible, NAT64, 6to4, Teredo)."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    found: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        found.append(ip.ipv4_mapped)
    packed = int(ip)
    if ip in _V4_COMPAT and packed > 1:  # ::a.b.c.d (deprecated IPv4-compatible)
        found.append(ipaddress.IPv4Address(packed & 0xFFFFFFFF))
    if ip in _NAT64 or ip in _NAT64_LOCAL:
        found.append(ipaddress.IPv4Address(packed & 0xFFFFFFFF))
    if ip in _6TO4 and ip.sixtofour is not None:
        found.append(ip.sixtofour)
    if ip in _TEREDO and ip.teredo is not None:
        found.extend(ip.teredo)  # (server, client)
    return found


def blocked_range_for(ip: IPAddress) -> BlockedRange | None:
    """The blocked range covering `ip` or any IPv4 address embedded in it, else None.

    All candidates are checked and a non-overridable match (cloud metadata) always wins,
    so a narrow override of a tunnelling prefix (e.g. 6to4) can never unlock a metadata
    address embedded inside it.
    """
    matches = [
        rng
        for candidate in (ip, *embedded_ipv4(ip))
        for rng in BLOCKED_RANGES
        if candidate.version == rng.network.version and candidate in rng.network
    ]
    if matches:
        return next((m for m in matches if not m.overridable), matches[0])
    # Teredo is a tunnelling prefix; anything unparseable inside it is treated as blocked.
    if isinstance(ip, ipaddress.IPv6Address) and ip in _TEREDO and ip.teredo is None:
        return BlockedRange(_TEREDO, "tunnel", "Teredo tunnelling")
    return None


def network_blocked_overlap(net: IPNetwork) -> list[BlockedRange]:
    """Blocked ranges that overlap a scope network (used for scope warnings)."""
    return [
        r for r in BLOCKED_RANGES if r.network.version == net.version and r.network.overlaps(net)
    ]
