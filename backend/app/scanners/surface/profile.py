"""Attack-surface scan profile: inputs, budgets, port plan and sources (shown before start,
stored as `work/profile.json`, parameters written to the audit event)."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import Field

from app.models.common import StrictModel
from app.models.project import ScanPolicy
from app.scope.canonical import CanonicalizationError, normalize_host
from app.scope.engine import ScopePolicy

PROFILE_VERSION = 1
# Explicit, conservative default list (TBD-055): common web, remote-admin, mail, DB ports.
DEFAULT_PORTS = (
    21,
    22,
    23,
    25,
    80,
    110,
    143,
    443,
    445,
    993,
    995,
    1433,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    9200,
    27017,
)
MAX_PORTS = 100
MAX_HOSTS_HARD = 1000
MAX_CANDIDATES = 5000
MAX_HOST_LIST_CHARS = 200_000
WEB_PORTS = {
    80: "http",
    8000: "http",
    8008: "http",
    8080: "http",
    8888: "http",
    443: "https",
    8443: "https",
    9443: "https",
}

PARAMETERS: dict[str, tuple[type, Any, str]] = {
    "hosts": (str, "", "Manually supplied or imported hostnames/IPs (newline or comma separated)"),
    "ports": (str, "", "Ports to test (comma separated); default: conservative list"),
    "port_method": (str, "auto", "auto (Nmap if installed, else TCP connect) | connect | nmap"),
    "max_hosts": (int, 50, "Maximum in-scope hosts to port-check and probe"),
    "passive_crtsh": (bool, False, "Query crt.sh (third party) for subdomain candidates"),
    "probe_web": (bool, True, "Probe discovered HTTP(S) origins (title, headers, TLS, endpoints)"),
    "web_max_pages": (int, 5, "Endpoint pages per web origin (same-origin, bounded)"),
    "read_banners": (bool, True, "Read service greetings passively (nothing is sent)"),
    "tls_verify": (bool, True, "Verify TLS when probing web origins"),
}


def _split(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"[\s,;]+", text) if p.strip()]


def parse_ports(text: str) -> list[int]:
    ports: list[int] = []
    for part in _split(text):
        if not part.isdigit() or not 1 <= int(part) <= 65535:
            raise ValueError(f"invalid port {part!r} (explicit numbers only, no ranges)")
        if int(part) not in ports:
            ports.append(int(part))
    return ports


class PortPlan(StrictModel):
    requested: list[int]
    tested: list[int]
    not_tested: dict[str, str] = Field(default_factory=dict)  # port -> reason


class SourcePlan(StrictModel):
    name: str
    label: str
    enabled: bool
    disclosure: str


class SurfaceScanProfile(StrictModel):
    profile_version: int = PROFILE_VERSION
    roots: list[str]
    manual_hosts: int
    port_method: Literal["auto", "connect", "nmap"]
    ports: PortPlan
    max_hosts: int
    probe_web: bool
    web_max_pages: int
    read_banners: bool
    tls_verify: bool
    sources: list[SourcePlan]
    dns: str = (
        "OS resolver: A/AAAA and CNAME (canonical name); TTL not exposed by the OS "
        "resolver (reported as unknown); no DNS brute force"
    )
    limitations: list[str] = Field(default_factory=list)


LIMITATIONS = [
    "Only explicitly listed TCP ports are tested (TCP connect; no UDP, no SYN/stealth, no "
    "full-range scans).",
    "No DNS wordlist brute force: candidates come only from your inputs and enabled passive "
    "sources.",
    "Discovered hosts that are not in scope are recorded as candidates and are NOT port-checked "
    "or probed until you approve them.",
    "Banners are read passively (nothing is sent); no login attempts, no vulnerability scripts.",
    "Web probing reuses the web scanner's passive checks on a few same-origin pages only.",
]


def validate_parameters(params: dict[str, Any], policy: ScanPolicy) -> list[str]:
    errors: list[str] = []
    for name, value in params.items():
        if name not in PARAMETERS:
            errors.append(f"unknown parameter {name!r} for the attack surface mapper")
            continue
        kind = PARAMETERS[name][0]
        if value is None:
            continue
        if kind is bool and not isinstance(value, bool):
            errors.append(f"{name} must be true or false")
        elif kind is int and (isinstance(value, bool) or not isinstance(value, int)):
            errors.append(f"{name} must be an integer")
        elif kind is str and not isinstance(value, str):
            errors.append(f"{name} must be text")
    hosts = params.get("hosts")
    if isinstance(hosts, str):
        if len(hosts) > MAX_HOST_LIST_CHARS:
            errors.append(f"host list is longer than {MAX_HOST_LIST_CHARS} characters")
        elif len(_split(hosts)) > MAX_CANDIDATES:
            errors.append(f"at most {MAX_CANDIDATES} hosts per scan")
    ports = params.get("ports")
    if isinstance(ports, str) and ports.strip():
        try:
            parsed = parse_ports(ports)
        except ValueError as exc:
            errors.append(str(exc))
        else:
            if len(parsed) > MAX_PORTS:
                errors.append(f"at most {MAX_PORTS} ports")
    method = params.get("port_method", "auto")
    if method not in ("auto", "connect", "nmap"):
        errors.append("port_method must be auto, connect or nmap")
    max_hosts = params.get("max_hosts")
    if (
        isinstance(max_hosts, int)
        and not isinstance(max_hosts, bool)
        and not 1 <= max_hosts <= MAX_HOSTS_HARD
    ):
        errors.append(f"max_hosts must be between 1 and {MAX_HOSTS_HARD}")
    pages = params.get("web_max_pages")
    if (
        isinstance(pages, int)
        and not isinstance(pages, bool)
        and not 1 <= pages <= min(50, policy.max_pages)
    ):
        errors.append("web_max_pages must be between 1 and 50 (and within the project page limit)")
    return errors


def port_plan(params: dict[str, Any], policy: ScopePolicy) -> PortPlan:
    raw = params.get("ports")
    requested = parse_ports(raw) if isinstance(raw, str) and raw.strip() else list(DEFAULT_PORTS)
    tested: list[int] = []
    not_tested: dict[str, str] = {}
    for port in requested:
        decision = policy.is_port_allowed(port)
        if decision.allowed:
            tested.append(port)
        else:
            not_tested[str(port)] = decision.message[:200]
    return PortPlan(requested=requested, tested=tested, not_tested=not_tested)


def build_profile(
    params: dict[str, Any], roots: list[str], policy: ScopePolicy, *, nmap_available: bool
) -> SurfaceScanProfile:
    from app.integrations.passive_sources import CrtShSource

    method = str(params.get("port_method", "auto"))
    hosts = params.get("hosts")
    limitations = list(LIMITATIONS)
    if method in ("auto", "nmap") and not nmap_available:
        limitations.append(
            "Nmap is not installed: TCP connect checks are used"
            + (" (explicitly requested Nmap is unavailable)" if method == "nmap" else "")
            + "."
        )
    return SurfaceScanProfile(
        roots=roots,
        manual_hosts=len(_split(hosts)) if isinstance(hosts, str) else 0,
        port_method=method,  # type: ignore[arg-type]
        ports=port_plan(params, policy),
        max_hosts=int(params.get("max_hosts") or 50),
        probe_web=bool(params.get("probe_web", True)),
        web_max_pages=int(params.get("web_max_pages") or 5),
        read_banners=bool(params.get("read_banners", True)),
        tls_verify=bool(params.get("tls_verify", True)),
        sources=[
            SourcePlan(
                name="manual",
                label="Targets and manual/imported host list",
                enabled=True,
                disclosure="Local input only.",
            ),
            SourcePlan(
                name=CrtShSource.name,
                label=CrtShSource.label,
                enabled=bool(params.get("passive_crtsh", False)),
                disclosure=CrtShSource.disclosure,
            ),
        ],
        limitations=limitations,
    )


def parse_hosts(text: str) -> tuple[list[str], list[str]]:
    """Canonical hosts and rejected inputs from a free-form list (URLs reduced to hosts)."""
    hosts: list[str] = []
    rejected: list[str] = []
    for item in _split(text)[:MAX_CANDIDATES]:
        candidate = item
        if "://" in candidate:
            candidate = candidate.split("://", 1)[1].split("/", 1)[0]
        if candidate.startswith("*."):
            candidate = candidate[2:]
        if candidate.count(":") == 1:  # host:port
            candidate = candidate.split(":", 1)[0]
        try:
            host, _ip = normalize_host(candidate)
        except CanonicalizationError:
            rejected.append(item[:100])
            continue
        if host not in hosts:
            hosts.append(host)
    return hosts, rejected
