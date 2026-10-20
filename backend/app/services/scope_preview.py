"""Scope *preview* normalization for the project wizard (Phase 02).

This turns free-text target lines into a validated `ScopeDefinition` so the operator
can review what will be saved. It is NOT the scope enforcement engine: allow/deny
matching, DNS/IP policy and redirect checks are implemented in Phase 03, and no scan
can run before then. Nothing here performs DNS resolution or any network access.
"""

from __future__ import annotations

import ipaddress
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, ValidationError

from app.models.common import ShortText, StrictModel
from app.models.project import Scheme, ScopeDefinition, ScopeExclusions, _default_schemes
from app.scope.canonical import CanonicalizationError, normalize_hostname
from app.scope.engine import scope_hash
from app.scope.ip_policy import BLOCKED_RANGES, network_blocked_overlap

EntryKind = Literal[
    "hostname", "wildcard", "ip_range", "url", "port", "path", "api_server_url", "invalid"
]

MAX_LINES = 1000

NOTE_ENGINE = (
    "Normalized by the scope engine. At request time every target, redirect and resolved IP "
    "is re-checked before any traffic is sent (web scanner) and again on every redirect."
)
NOTE_BLOCKED = (
    "Loopback, private, link-local and cloud-metadata ranges are blocked by default and "
    "require an explicit, audited internal-target override on the project page."
)


class ScopePreviewRequest(StrictModel):
    targets: list[str] = Field(default_factory=list, max_length=MAX_LINES)
    schemes: list[Scheme] = Field(default_factory=_default_schemes, min_length=1)
    ports: list[str] = Field(default_factory=list, max_length=200)
    path_prefixes: list[str] = Field(default_factory=list, max_length=500)
    exclude_targets: list[str] = Field(default_factory=list, max_length=MAX_LINES)
    exclude_ports: list[str] = Field(default_factory=list, max_length=200)
    exclude_paths: list[str] = Field(default_factory=list, max_length=500)
    api_server_urls: list[str] = Field(default_factory=list, max_length=100)


class PreviewEntry(StrictModel):
    field: ShortText
    input: str
    kind: EntryKind
    normalized: str | None = None
    error: ShortText | None = None
    warnings: list[ShortText] = Field(default_factory=list)


class BlockedRangeView(StrictModel):
    network: str
    category: str
    label: str
    overridable: bool


def blocked_ranges_view() -> list[BlockedRangeView]:
    return [
        BlockedRangeView(
            network=str(r.network), category=r.category, label=r.label, overridable=r.overridable
        )
        for r in BLOCKED_RANGES
    ]


class ScopePreviewResponse(StrictModel):
    valid: bool
    scope: ScopeDefinition | None
    scope_hash: str | None = None  # send back as scope_preview_hash when saving this scope
    entries: list[PreviewEntry]
    error_count: int
    notes: list[ShortText]
    blocked_ranges: list[BlockedRangeView] = Field(default_factory=blocked_ranges_view)


def _host(value: str) -> str:
    try:
        return normalize_hostname(value)
    except CanonicalizationError as exc:
        raise ValueError(exc.message) from exc


def _network_warnings(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> list[str]:
    warnings = []
    for blocked in network_blocked_overlap(net):
        if not blocked.overridable:
            warnings.append(
                f"Overlaps {blocked.network} ({blocked.label}): "
                "never reachable, even with an override"
            )
        else:
            warnings.append(
                f"Blocked by default: overlaps {blocked.network} ({blocked.label}); "
                "needs an internal-target override"
            )
    if net.num_addresses > 65536:
        warnings.append(f"Large range ({net.num_addresses} addresses): confirm this is intended")
    return warnings


def _port(value: str) -> int:
    text = value.strip()
    if not text.isascii() or not text.isdigit() or not 1 <= int(text) <= 65535:
        raise ValueError("ports must be integers between 1 and 65535")
    return int(text)


def _path(value: str) -> str:
    text = value.strip()
    if not text.startswith("/") or "\\" in text or any(c.isspace() for c in text):
        raise ValueError("path prefixes must start with '/' and contain no spaces or backslashes")
    if (
        "/../" in f"{text}/"
        or "/./" in f"{text}/"
        or "%2e" in text.lower()
        or "%2f" in text.lower()
    ):
        raise ValueError("path prefixes must not contain dot segments or encoded separators")
    return text


def _lines(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.replace(",", "\n").splitlines())
    return [v for v in out if v and not v.startswith("#")][:MAX_LINES]


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    return [x for x in items if not (x in seen or seen.add(x))]  # type: ignore[func-returns-value]


def preview_scope(req: ScopePreviewRequest) -> ScopePreviewResponse:
    entries: list[PreviewEntry] = []
    hosts: list[str] = []
    wildcards: list[str] = []
    networks: list[str] = []
    ports: list[int] = []
    paths: list[str] = []
    schemes: list[str] = list(req.schemes)

    def classify(raw: str, field: str) -> PreviewEntry:
        try:
            if "://" in raw:
                parts = urlsplit(raw)
                if parts.scheme.lower() not in ("http", "https"):
                    raise ValueError("only http and https URLs are allowed")
                if parts.username or parts.password or "@" in parts.netloc:
                    raise ValueError("URLs with embedded credentials are rejected")
                host = parts.hostname or ""
                try:
                    ip = ipaddress.ip_address(host)
                    normalized_host = str(ip)
                    networks.append(str(ipaddress.ip_network(ip)))
                    warnings = _network_warnings(ipaddress.ip_network(ip))
                except ValueError:
                    normalized_host = _host(host)
                    hosts.append(normalized_host)
                    warnings = []
                scheme = parts.scheme.lower()
                if scheme not in schemes:
                    schemes.append(scheme)
                if parts.port is not None:
                    ports.append(parts.port)
                if parts.path and parts.path != "/":
                    paths.append(_path(parts.path))
                if parts.query or parts.fragment:
                    warnings.append("Query string and fragment are ignored for scope")
                return PreviewEntry(
                    field=field,
                    input=raw,
                    kind="url",
                    normalized=f"{scheme}://{normalized_host}{parts.path or '/'}",
                    warnings=warnings,
                )
            if raw.startswith("*."):
                normalized = "*." + _host(raw[2:])
                wildcards.append(normalized)
                return PreviewEntry(
                    field=field,
                    input=raw,
                    kind="wildcard",
                    normalized=normalized,
                    warnings=["Matches subdomains only, not the bare domain"],
                )
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                normalized = _host(raw)
                hosts.append(normalized)
                return PreviewEntry(field=field, input=raw, kind="hostname", normalized=normalized)
            warnings = _network_warnings(net)
            if str(net) != raw and "/" in raw:
                warnings.append(f"Normalized to network address {net}")
            networks.append(str(net))
            return PreviewEntry(
                field=field, input=raw, kind="ip_range", normalized=str(net), warnings=warnings
            )
        except ValueError as exc:
            return PreviewEntry(field=field, input=raw[:500], kind="invalid", error=str(exc)[:480])

    for raw in _lines(req.targets):
        entries.append(classify(raw, "targets"))

    def simple(values: list[str], field: str, kind: EntryKind, fn, sink: list) -> None:  # type: ignore[no-untyped-def,type-arg]
        for raw in _lines(values):
            try:
                value = fn(raw)
                sink.append(value)
                entries.append(
                    PreviewEntry(field=field, input=raw, kind=kind, normalized=str(value))
                )
            except ValueError as exc:
                entries.append(
                    PreviewEntry(field=field, input=raw[:500], kind="invalid", error=str(exc)[:480])
                )

    simple(req.ports, "ports", "port", _port, ports)
    simple(req.path_prefixes, "path_prefixes", "path", _path, paths)

    # exclusions are classified separately so they never leak into inclusions
    ex_hosts: list[str] = []
    ex_wild: list[str] = []
    ex_nets: list[str] = []
    for raw in _lines(req.exclude_targets):
        saved = (list(hosts), list(wildcards), list(networks))
        entry = classify(raw, "exclude_targets")
        new_hosts, new_wild, new_nets = (
            hosts[len(saved[0]) :],
            wildcards[len(saved[1]) :],
            networks[len(saved[2]) :],
        )
        hosts[:], wildcards[:], networks[:] = saved
        ex_hosts += new_hosts
        ex_wild += new_wild
        ex_nets += new_nets
        if entry.kind == "url":
            entry = entry.model_copy(
                update={"warnings": [*entry.warnings, "Only the host of an excluded URL is used"]}
            )
        entries.append(entry)
    ex_ports: list[int] = []
    ex_paths: list[str] = []
    simple(req.exclude_ports, "exclude_ports", "port", _port, ex_ports)
    simple(req.exclude_paths, "exclude_paths", "path", _path, ex_paths)

    api_urls: list[str] = []
    for raw in _lines(req.api_server_urls):
        entry = classify(raw, "api_server_urls")
        if entry.kind == "url" and entry.normalized:
            api_urls.append(entry.normalized.rstrip("/") or entry.normalized)
            entry = entry.model_copy(update={"kind": "api_server_url"})
        elif entry.kind != "invalid":
            entry = PreviewEntry(
                field="api_server_urls",
                input=raw[:500],
                kind="invalid",
                error="API server URLs must be full http(s) URLs",
            )
        entries.append(entry)

    if not (hosts or wildcards or networks):
        entries.append(
            PreviewEntry(
                field="targets",
                input="",
                kind="invalid",
                error="At least one in-scope host, wildcard domain or IP range is required",
            )
        )
    error_count = sum(1 for e in entries if e.error)
    scope: ScopeDefinition | None = None
    if error_count == 0:
        try:
            scope = ScopeDefinition(
                schemes=_dedupe(schemes),  # type: ignore[arg-type]
                hosts=_dedupe(hosts),
                wildcard_domains=_dedupe(wildcards),
                ip_ranges=_dedupe(networks),  # type: ignore[arg-type]
                ports=sorted(set(ports or [80, 443])),
                path_prefixes=_dedupe(paths or ["/"]),
                api_server_urls=_dedupe(api_urls),
                exclusions=ScopeExclusions(
                    hosts=_dedupe(ex_hosts),
                    wildcard_domains=_dedupe(ex_wild),
                    ip_ranges=_dedupe(ex_nets),  # type: ignore[arg-type]
                    ports=sorted(set(ex_ports)),
                    path_prefixes=_dedupe(ex_paths),
                ),
            )
        except ValidationError as exc:
            first = exc.errors()[0]
            entries.append(
                PreviewEntry(
                    field=".".join(map(str, first["loc"])) or "scope",
                    input="",
                    kind="invalid",
                    error=str(first["msg"])[:480],
                )
            )
            error_count += 1
    notes = [NOTE_ENGINE]
    if any("Blocked by default" in w for e in entries for w in e.warnings):
        notes.append(NOTE_BLOCKED)
    return ScopePreviewResponse(
        valid=scope is not None,
        scope=scope,
        scope_hash=scope_hash(scope) if scope is not None else None,
        entries=entries,
        error_count=error_count,
        notes=notes,
    )
