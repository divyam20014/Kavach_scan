"""Attack surface mapper job runner (module `attack_surface`).

Stages: profile → candidates (targets, manual/imported list, optional passive sources)
→ classification → DNS (A/AAAA/CNAME) + IP policy → port checks (in-scope hosts only;
Nmap or TCP connect) → passive banners → web origins (reusing Module 5) → inventory,
findings, coverage, snapshot + change comparison → summary.

Safety properties:
- a candidate is only *classified and resolved* unless the scope policy admits it
  (`in_scope`); pending/out-of-scope/excluded candidates are never port-checked or probed;
- every connection is authorized by `ScopeGuard.authorize_connect` (host, port, every
  resolved IP, pinning); Nmap receives only pinned IP literals and allowlisted flags;
- only ports that are both requested and allowed by the project scope are tested, and the
  report lists every requested port that was not tested, with the reason;
- cancellation, kill switch, authorization lapse, budget and duration limits stop the run;
  partial results are written (no further network activity) and the stop propagates.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.core.redaction import redact
from app.integrations.http_client import HttpClientConfig, default_transport_factory
from app.integrations.http_service import HttpService
from app.integrations.nmap import (
    NmapOutputError,
    NmapPolicyError,
    NmapSpec,
    detect_nmap,
    parse_version,
    parse_xml,
)
from app.integrations.passive_sources import MAX_ROOTS_PER_SCAN, CrtShSource
from app.integrations.tcp import probe_port
from app.jobs.context import JobContext, JobStop, RunResult
from app.models.common import AssetType, Confidence, ScanModule, ScanState, ScopeStatus
from app.models.project import ScanPolicy
from app.scanners.surface.inventory import Inventory, diff_snapshots, port_locator
from app.scanners.surface.profile import (
    WEB_PORTS,
    SurfaceScanProfile,
    build_profile,
    parse_hosts,
    validate_parameters,
)
from app.scanners.surface.rules import (
    ADMIN_PORTS,
    CATALOG_ID,
    CATALOG_VERSION,
    CLEARTEXT_PORTS,
    DATABASE_PORTS,
)
from app.scanners.surface.services import identify, sanitize_banner
from app.scanners.surface.web import probe_origin
from app.scanners.webapp.checks import PassiveChecks, origin_of
from app.scanners.webapp.components import ComponentDetector, CveCatalog, NoCveCatalog, cve_results
from app.scanners.webapp.findings import FindingWriter, summarize_outcomes
from app.scanners.webapp.rules import RULES, CheckResult, EvidenceDraft, Outcome
from app.scope.canonical import normalize_host
from app.scope.engine import ScopePolicy
from app.scope.guard import ScopeBlocked, Transport

TransportFactory = Callable[[HttpClientConfig], Transport]
MAX_IPS_PER_HOST = 4
MAX_RESOLVE = 2000
NMAP_TIMEOUT = 600.0
_VERSIONISH = re.compile(r"\d+\.\d+")


def _json(data: Any) -> bytes:
    safe = redact(json.loads(json.dumps(data, default=str)), max_items=50_000)
    return json.dumps(safe, indent=2, ensure_ascii=False).encode("utf-8")


def check_targets(
    targets: list[str], policy: ScopePolicy
) -> tuple[list[str], list[tuple[int, str]]]:
    """Surface targets: in-scope hostnames, authorized root domains, or in-range IPs."""
    roots = set(policy.hosts) | {w[2:] for w in policy.wildcards}
    canonical: list[str] = []
    problems: list[tuple[int, str]] = []
    for i, raw in enumerate(targets):
        hosts, rejected = parse_hosts(raw)
        if rejected or len(hosts) != 1:
            problems.append((i, "not a valid hostname, root domain or IP address"))
            continue
        host = hosts[0]
        _, ip = normalize_host(host)
        if ip is not None:
            if not any(ip.version == n.version and ip in n for n in policy.networks):
                problems.append((i, f"{host} is not inside an approved IP range"))
                continue
        else:
            status, _rule = policy.host_status(host)
            if status == ScopeStatus.EXCLUDED:
                problems.append((i, f"{host} is excluded by the project scope"))
                continue
            if status != ScopeStatus.IN_SCOPE and host not in roots:
                problems.append(
                    (i, f"{host} is neither an in-scope host nor an authorized root domain")
                )
                continue
        if host not in canonical:
            canonical.append(host)
    return canonical, problems


class _State:
    def __init__(self) -> None:
        self.candidates: dict[str, set[str]] = {}
        self.status: dict[str, str] = {}
        self.dns: dict[str, dict[str, Any]] = {}
        self.sources: list[dict[str, Any]] = []
        self.rejected_inputs: list[str] = []
        self.hosts_checked: dict[str, dict[str, Any]] = {}
        self.hosts_not_checked: dict[str, str] = {}
        self.open: list[dict[str, Any]] = []
        self.origins: list[dict[str, Any]] = []
        self.results: list[CheckResult] = []
        self.tool_versions: dict[str, str] = {}
        self.passive = PassiveChecks()
        self.components = ComponentDetector()
        self.asset_ids: dict[tuple[str, str], str] = {}


class SurfaceRunner:
    name = "attack_surface"

    def __init__(
        self,
        *,
        transport_factory: TransportFactory = default_transport_factory,
        nmap: Callable[[], NmapSpec | None] = detect_nmap,
        crtsh_factory: Callable[[Any, Callable[[float], None]], CrtShSource] | None = None,
        cve_catalog: CveCatalog | None = None,
        connect_timeout: float = 3.0,
        banner_timeout: float = 1.5,
    ) -> None:
        self.transport_factory = transport_factory
        self.nmap = nmap
        self.crtsh_factory = crtsh_factory or (
            lambda resolver, sleep: CrtShSource(resolver, sleep=sleep)
        )
        self.cve_catalog: CveCatalog = cve_catalog or NoCveCatalog()
        self.connect_timeout = connect_timeout
        self.banner_timeout = banner_timeout

    # ------------------------------------------------------------------ manager hooks

    def validate_parameters(self, params: dict[str, Any], policy: ScanPolicy) -> list[str]:
        return validate_parameters(params, policy)

    def check_targets(
        self, targets: list[str], policy: ScopePolicy
    ) -> tuple[list[str], list[tuple[int, str]]]:
        return check_targets(targets, policy)

    # ------------------------------------------------------------------ run

    def run(self, ctx: JobContext) -> RunResult:
        params = dict(ctx.scan.parameters)
        nmap_spec = self.nmap()
        roots = list(ctx.scan.authorized_targets)
        profile = build_profile(
            params, roots, ctx.guard.policy, nmap_available=nmap_spec is not None
        )
        ctx.write_output("profile.json", _json(profile.model_dump(mode="json")))
        ctx.emit(
            "profile",
            f"surface profile: {len(roots)} target(s), ports {profile.ports.tested}, "
            f"method {profile.port_method}",
        )
        state = _State()
        inventory = Inventory(ctx.repo, ctx.project_id, ctx.scan_id)
        stop: JobStop | None = None
        try:
            self._scan(ctx, profile, state, inventory, nmap_spec)
        except JobStop as exc:
            stop = exc
            ctx.emit(
                "partial", f"scan stopped early ({exc}); writing partial results", level="warning"
            )
        self._finish(ctx, profile, state, inventory, stopped=str(stop) if stop else "")
        if stop is not None:
            raise stop
        return RunResult()

    def _scan(
        self,
        ctx: JobContext,
        profile: SurfaceScanProfile,
        state: _State,
        inventory: Inventory,
        nmap_spec: NmapSpec | None,
    ) -> None:
        params = dict(ctx.scan.parameters)
        # ---------------- candidates
        ctx.stage("candidates", 3)
        for root in profile.roots:
            state.candidates.setdefault(root, set()).add("target")
        hosts_text = params.get("hosts")
        if isinstance(hosts_text, str) and hosts_text:
            manual, rejected = parse_hosts(hosts_text)
            state.rejected_inputs = rejected[:200]
            for host in manual:
                state.candidates.setdefault(host, set()).add("manual")
        if params.get("passive_crtsh"):
            self._passive(ctx, profile, state)

        # ---------------- classification
        ctx.stage("classification", 12)
        policy = ctx.guard.policy
        for host in list(state.candidates):
            classified, _decision = ctx.guard.classify_discovered_host(host)
            state.status[host] = classified.value
        ctx.incr("candidates", len(state.candidates))

        # ---------------- DNS
        ctx.stage("dns", 15)
        domain_ids: dict[str, str] = {}
        roots = set(policy.hosts) | {w[2:] for w in policy.wildcards}
        for root in sorted(roots):
            if any(h == root or h.endswith("." + root) for h in state.candidates):
                domain_ids[root] = inventory.upsert(
                    AssetType.DOMAIN,
                    root,
                    scope_status=ScopeStatus(policy.host_status(root)[0]),
                    observation="authorized root / scope host",
                )
        resolved = 0
        for host in sorted(state.candidates):
            ctx.checkpoint()
            status = state.status[host]
            parent = next(
                (
                    domain_ids[r]
                    for r in sorted(domain_ids, key=len, reverse=True)
                    if host == r or host.endswith("." + r)
                ),
                None,
            )
            _, ip_literal = normalize_host(host)
            if ip_literal is not None:
                ip_status = ScopeStatus.IN_SCOPE if status == "in_scope" else ScopeStatus(status)
                decision = policy.validate_resolved_ip(host, host)
                aid = inventory.upsert(
                    AssetType.IP,
                    host,
                    scope_status=ip_status,
                    attributes={
                        "ip_allowed": decision.allowed,
                        "ip_policy": decision.message[:200],
                    },
                    observation=f"sources: {', '.join(sorted(state.candidates[host]))}",
                )
                state.asset_ids[("ip", host)] = aid
                state.dns[host] = {
                    "addresses": [host],
                    "allowed": [host] if decision.allowed else [],
                    "blocked": {} if decision.allowed else {host: decision.message[:200]},
                    "cname": None,
                    "ttl": None,
                    "resolved": True,
                }
                continue
            host_aid = inventory.upsert(
                AssetType.HOSTNAME,
                host,
                parent=parent,
                scope_status=ScopeStatus(status),
                confidence=Confidence.POTENTIAL if status != "in_scope" else Confidence.CONFIRMED,
                observation=f"sources: {', '.join(sorted(state.candidates[host]))}",
                attributes={"sources": ",".join(sorted(state.candidates[host]))},
            )
            state.asset_ids[("host", host)] = host_aid
            if status not in ("in_scope", "pending_approval") or resolved >= MAX_RESOLVE:
                reason = (
                    "not resolved: outside the authorized roots"
                    if status in ("out_of_scope", "excluded")
                    else "not resolved: resolution budget reached"
                )
                inventory.upsert(
                    AssetType.HOSTNAME,
                    host,
                    resolution_status="not_attempted",
                    attributes={"resolution_note": reason},
                )
                state.dns[host] = {"resolved": None, "note": reason}
                continue
            resolved += 1
            self._resolve(ctx, host, host_aid, state, inventory)
        ctx.incr("dns_lookups", resolved)

        # ---------------- port checks (in-scope only)
        ctx.stage("ports", 30)
        eligible: list[str] = []
        for host in sorted(state.candidates):
            status = state.status[host]
            dns = state.dns.get(host, {})
            if status != "in_scope":
                state.hosts_not_checked[host] = {
                    "pending_approval": "pending approval: discovered, not in scope (not scanned)",
                    "out_of_scope": "out of scope (not scanned)",
                    "excluded": "excluded by scope (not scanned)",
                }.get(status, status)
            elif dns.get("resolved") is False:
                state.hosts_not_checked[host] = "unresolved"
            elif not dns.get("allowed"):
                state.hosts_not_checked[host] = (
                    "no address allowed by the IP policy (e.g. private/blocked range)"
                )
            elif not profile.ports.tested:
                state.hosts_not_checked[host] = "no requested port is allowed by the project scope"
            else:
                eligible.append(host)
        for host in eligible[profile.max_hosts :]:
            state.hosts_not_checked[host] = f"host budget reached (max_hosts={profile.max_hosts})"
        eligible = eligible[: profile.max_hosts]
        use_nmap = nmap_spec is not None and profile.port_method in ("auto", "nmap")
        if use_nmap and nmap_spec is not None:
            raw = ctx.run_process(
                nmap_spec.version_argv(),
                allowed_executables=[nmap_spec.executable],
                timeout=30,
                max_output_bytes=16 * 1024,
            )
            state.tool_versions["nmap"] = parse_version(raw.stdout) or "unknown"
        elif profile.port_method == "nmap":
            ctx.warn(
                "Nmap was requested but is not installed; TCP connect checks were used instead"
            )
        for index, host in enumerate(eligible):
            ctx.set_percent(30 + 35 * index / max(1, len(eligible)))
            self._ports(ctx, host, profile, state, inventory, nmap_spec if use_nmap else None)

        # ---------------- web origins
        ctx.stage("web origins", 68)
        if profile.probe_web:
            self._web(ctx, profile, state, inventory)

        ctx.stage("components", 88)
        state.results += state.components.results()
        state.results += cve_results(state.components.components(), self.cve_catalog)

    # ------------------------------------------------------------------ stages

    def _passive(self, ctx: JobContext, profile: SurfaceScanProfile, state: _State) -> None:
        source = self.crtsh_factory(ctx.resolver, ctx.sleep)
        domains = [r for r in profile.roots if normalize_host(r)[1] is None][:MAX_ROOTS_PER_SCAN]
        for root in domains:
            ctx.checkpoint()
            result = source.query(root)
            ctx.incr("passive_queries")
            entry = {
                "source": source.name,
                "label": source.label,
                "root": root,
                "sent": result.sent,
                "candidates": len(result.names),
                "error": result.error,
                "truncated": result.truncated,
                "disclosure": source.disclosure,
            }
            state.sources.append(entry)
            state.results.append(
                CheckResult(
                    "SURF-SRC-001",
                    Outcome.ERROR if result.error else Outcome.OBSERVATION,
                    f"crt.sh:{root}",
                    result.error or f"{len(result.names)} candidate name(s) for {root}",
                )
            )
            for name in result.names:
                state.candidates.setdefault(name, set()).add(source.name)

    def _resolve(
        self, ctx: JobContext, host: str, host_aid: str, state: _State, inventory: Inventory
    ) -> None:
        policy = ctx.guard.policy
        lookup = getattr(ctx.resolver, "records", None)
        try:
            if lookup is not None:
                records = lookup(host)
                addresses, cname = list(records.addresses), records.cname
            else:
                addresses, cname = list(ctx.resolver.resolve(host)), None
        except Exception as exc:  # noqa: BLE001 - any resolution failure = unresolved
            state.dns[host] = {"resolved": False, "error": str(exc)[:200]}
            inventory.upsert(
                AssetType.HOSTNAME,
                host,
                resolution_status="unresolved",
                attributes={"dns_error": str(exc)[:200]},
            )
            ctx.incr("dns_unresolved")
            return
        now = datetime.now(UTC).isoformat()
        allowed: list[str] = []
        blocked: dict[str, str] = {}
        for address in addresses[:32]:
            decision = policy.validate_resolved_ip(host, address)
            ip_aid = inventory.upsert(
                AssetType.IP,
                address,
                parent=host_aid,
                related=[host_aid],
                scope_status=ScopeStatus.IN_SCOPE
                if decision.allowed and state.status[host] == "in_scope"
                else (
                    ScopeStatus.EXCLUDED
                    if not decision.allowed
                    else ScopeStatus(state.status[host])
                ),
                attributes={
                    "ip_allowed": decision.allowed,
                    "ip_policy": decision.message[:200],
                    "family": "ipv6" if ":" in address else "ipv4",
                },
                observation=f"resolved from {host}",
            )
            state.asset_ids[("ip", address)] = ip_aid
            if decision.allowed:
                allowed.append(address)
            else:
                blocked[address] = decision.message[:200]
        state.dns[host] = {
            "resolved": True,
            "addresses": addresses[:32],
            "allowed": allowed,
            "blocked": blocked,
            "cname": cname,
            "ttl": None,
            "source": "os-resolver",
            "resolved_at": now,
        }
        inventory.upsert(
            AssetType.HOSTNAME,
            host,
            resolution_status="resolved",
            attributes={
                "cname": cname,
                "addresses": ",".join(addresses[:8]),
                "ttl": "unknown (OS resolver)",
                "resolved_at": now,
                "blocked_addresses": len(blocked),
            },
        )
        if blocked:
            ctx.warn(
                f"{host}: {len(blocked)} resolved address(es) blocked by the IP policy "
                "(never connected)"
            )

    def _ports(
        self,
        ctx: JobContext,
        host: str,
        profile: SurfaceScanProfile,
        state: _State,
        inventory: Inventory,
        nmap_spec: NmapSpec | None,
    ) -> None:
        ports = profile.ports.tested
        try:
            first = ctx.guard.authorize_connect(host, ports[0])
        except ScopeBlocked as blocked:
            state.hosts_not_checked[host] = f"blocked by scope: {blocked.decision.message}"[:300]
            return
        ips = list(first.pinned_ips)[:MAX_IPS_PER_HOST]
        record: dict[str, Any] = {
            "ips": ips,
            "ports_tested": ports,
            "method": "connect",
            "states": {},
            "open": [],
        }
        states: dict[tuple[str, int], str] = {}
        if nmap_spec is not None:
            try:
                ctx.guard.authorize_subprocess_targets([host], ports)
                argv = nmap_spec.argv(
                    ips, ports, max_rate=max(1, int(ctx.policy.requests_per_second))
                )
                proc = ctx.run_process(
                    argv,
                    allowed_executables=[nmap_spec.executable],
                    timeout=NMAP_TIMEOUT,
                    max_output_bytes=8 * 1024 * 1024,
                )
                if proc.timed_out or proc.stdout_truncated:
                    # A timed-out or over-cap run may emit parseable-but-partial XML; never
                    # trust it (it could report a host as having no further open ports).
                    raise NmapOutputError(
                        "timed out" if proc.timed_out else "output exceeded the size cap"
                    )
                parsed = parse_xml(proc.stdout)
                for ip, entries in parsed.hosts.items():
                    if ip in ips:
                        for entry in entries:
                            if entry.port in ports:
                                states[(ip, entry.port)] = entry.state
                record["method"] = "nmap"
                ctx.incr("nmap_runs")
                for ip in ips:  # nmap omits ports it did not report: mark them honestly
                    for port in ports:
                        states.setdefault((ip, port), "not reported by nmap")
            except (NmapPolicyError, NmapOutputError, ScopeBlocked) as exc:
                record["method"] = f"connect (nmap unusable: {str(exc)[:120]})"
                ctx.warn(
                    f"{host}: Nmap result unusable ({str(exc)[:160]}); falling back to TCP connect"
                )
                states = {}
        banners: dict[tuple[str, int], str] = {}
        for port in ports:
            nmap_ok = record["method"] == "nmap"
            need_connect = not nmap_ok or (
                profile.read_banners
                and any(states.get((ip, port), "").startswith("open") for ip in ips)
            )
            if not need_connect:
                continue
            try:
                authorized = ctx.guard.authorize_connect(host, port)
            except ScopeBlocked as blocked:
                for ip in ips:
                    states[(ip, port)] = f"not tested: {blocked.decision.message}"[:120]
                continue
            for ip in [i for i in ips if i in authorized.pinned_ips]:
                if nmap_ok and not states.get((ip, port), "").startswith("open"):
                    continue  # nmap said closed/filtered: no extra connection
                ctx.acquire_request(host)
                with ctx.slot():
                    probe = probe_port(
                        authorized,
                        ip,
                        port,
                        connect_timeout=self.connect_timeout,
                        banner_timeout=self.banner_timeout,
                        read_banner=profile.read_banners,
                    )
                ctx.incr("ports_probed")
                if not nmap_ok:
                    states[(ip, port)] = probe.state
                if probe.state == "open" and probe.banner:
                    banners[(ip, port)] = sanitize_banner(probe.banner)
        record["states"] = {f"{ip}:{port}": s for (ip, port), s in sorted(states.items())}
        host_aid = state.asset_ids.get(("host", host)) or state.asset_ids.get(("ip", host))
        for (ip, port), port_state in sorted(states.items()):
            if not port_state.startswith("open") or port_state == "open|filtered":
                continue
            banner = banners.get((ip, port), "")
            info = identify(port, banner)
            ip_aid = state.asset_ids.get(("ip", ip))
            port_aid = inventory.upsert(
                AssetType.PORT,
                port_locator(ip, port),
                parent=ip_aid,
                related=[a for a in (host_aid,) if a],
                scope_status=ScopeStatus.IN_SCOPE,
                attributes={
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": info.service,
                    "product": info.product,
                    "version": info.version,
                    "banner": banner or None,
                    "identified_by": info.source,
                    "method": record["method"][:60],
                    "hostname": host,
                },
                observation=f"open (seen via {host})",
            )
            state.asset_ids[("port", f"{ip}:{port}")] = port_aid
            record["open"].append(port)
            open_entry = {
                "host": host,
                "ip": ip,
                "port": port,
                "service": info.service,
                "product": info.product,
                "version": info.version,
                "banner": banner,
                "asset_id": port_aid,
            }
            state.open.append(open_entry)
            self._exposure(state, host, ip, port, info.service, banner, port_aid)
        record["open"] = sorted(set(record["open"]))
        state.hosts_checked[host] = record
        state.results.append(
            CheckResult(
                "SURF-COV-001",
                Outcome.OBSERVATION,
                host,
                f"{len(ports)} port(s) tested on {len(ips)} address(es) via {record['method']}; "
                f"open: {record['open'] or 'none'}",
                data={"tested": ports, "method": record["method"]},
            )
        )

    def _exposure(
        self, state: _State, host: str, ip: str, port: int, service: str, banner: str, port_aid: str
    ) -> None:
        subject = f"tcp://{host}:{port}"
        data = {"asset_ids": [port_aid]}
        evidence = EvidenceDraft(
            evidence_type="text_excerpt",
            response_excerpt=f"TCP connect to {ip}:{port} ({host}) succeeded"
            + (f"\nGreeting (sanitized): {banner}" if banner else ""),
        )
        # Classified by well-known port OR by the service identified from the greeting.
        db = DATABASE_PORTS.get(port) or (service if service in DATABASE_PORTS.values() else None)
        admin = ADMIN_PORTS.get(port) or (service if service in ADMIN_PORTS.values() else None)
        clear = CLEARTEXT_PORTS.get(port) or (
            service if service in CLEARTEXT_PORTS.values() else None
        )
        if db:
            state.results.append(
                CheckResult(
                    "SURF-SVC-001",
                    Outcome.FINDING,
                    subject,
                    f"{db} port {port} reachable on {host} ({ip})",
                    parameter=str(port),
                    evidence=evidence,
                    data=data,
                )
            )
        if admin:
            state.results.append(
                CheckResult(
                    "SURF-SVC-002",
                    Outcome.FINDING,
                    subject,
                    f"{admin} port {port} reachable on {host} ({ip})",
                    parameter=str(port),
                    evidence=evidence,
                    data=data,
                )
            )
        if clear:
            state.results.append(
                CheckResult(
                    "SURF-SVC-003",
                    Outcome.FINDING,
                    subject,
                    f"{clear} port {port} reachable on {host} ({ip})",
                    parameter=str(port),
                    evidence=evidence,
                    data=data,
                )
            )
        if banner and _VERSIONISH.search(banner):
            state.results.append(
                CheckResult(
                    "SURF-BANNER-001",
                    Outcome.FINDING,
                    subject,
                    f"{service} greeting discloses a version: {banner[:120]}",
                    parameter=str(port),
                    evidence=evidence,
                    data=data,
                )
            )

    def _web(
        self, ctx: JobContext, profile: SurfaceScanProfile, state: _State, inventory: Inventory
    ) -> None:
        verified = HttpService(
            ctx,
            self.transport_factory(HttpClientConfig.from_policy(ctx.policy, verify_tls=True)),
            max_redirects=ctx.policy.max_redirects,
            cache=True,
        )
        crawl = (
            verified
            if profile.tls_verify
            else HttpService(
                ctx,
                self.transport_factory(HttpClientConfig.from_policy(ctx.policy, verify_tls=False)),
                max_redirects=ctx.policy.max_redirects,
                cache=True,
            )
        )
        seen: set[str] = set()
        for entry in state.open:
            known = WEB_PORTS.get(entry["port"])
            if known:
                schemes = [known]
            elif entry["banner"].startswith("HTTP/"):
                schemes = ["http"]
            elif not entry["banner"] and entry["service"] in ("unknown", "http", "http-alt"):
                schemes = ["http", "https"]  # silent unknown port: one identification attempt each
            else:
                continue
            host = entry["host"]
            netloc = f"[{host}]" if ":" in host else host
            result = None
            for scheme in schemes:
                default = 443 if scheme == "https" else 80
                origin = f"{scheme}://{netloc}" + (
                    "" if entry["port"] == default else f":{entry['port']}"
                )
                if origin in seen:
                    break
                ctx.checkpoint()
                result, checks = probe_origin(
                    origin,
                    verified=verified,
                    crawl=crawl,
                    policy=ctx.guard.policy,
                    passive=state.passive,
                    components=state.components,
                    max_pages=profile.web_max_pages,
                    checkpoint=ctx.checkpoint,
                )
                if result.status is not None or result.tls or len(schemes) == 1:
                    seen.add(origin)
                    break
                result = None  # not this scheme: try the next one
            if result is None:
                continue
            state.results += checks
            ctx.incr("web_origins")
            origin_key = origin_of(origin + "/")
            origin_aid = inventory.upsert(
                AssetType.URL,
                origin_key,
                parent=entry["asset_id"],
                related=[a for a in (state.asset_ids.get(("host", host)),) if a],
                scope_status=ScopeStatus.IN_SCOPE,
                attributes={
                    "kind": "web_origin",
                    "status": result.status,
                    "title": result.title or None,
                    "server": result.server or None,
                    "tls_verified": result.tls.get("verified") if result.tls else None,
                    "cert_days_left": result.tls.get("days_to_expiry") if result.tls else None,
                    "error": result.error or None,
                },
                observation="web origin",
            )
            for page in result.endpoints:
                if page.url.rstrip("/") == origin_key.rstrip("/"):
                    continue
                inventory.upsert(
                    AssetType.URL,
                    page.url,
                    parent=origin_aid,
                    scope_status=ScopeStatus.IN_SCOPE,
                    attributes={
                        "kind": "endpoint",
                        "status": page.status,
                        "content_type": page.content_type or None,
                        "title": page.title or None,
                    },
                    observation="endpoint (bounded same-origin crawl)",
                )
            state.origins.append(result.as_dict())

    # ------------------------------------------------------------------ finish

    def _previous_snapshot(self, ctx: JobContext) -> dict[str, Any] | None:
        scans = ctx.repo.list_scans(
            ctx.project_id, sort="created_at", descending=True, limit=200
        ).items
        for scan in scans:
            if (
                scan.scan_id == ctx.scan_id
                or scan.module != ScanModule.ATTACK_SURFACE
                or scan.state not in (ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS)
            ):
                continue
            try:
                data = json.loads(
                    ctx.repo.read_scan_output(ctx.project_id, scan.scan_id, "inventory.json")
                )
            except Exception:  # noqa: BLE001 - a missing/corrupt snapshot just means "no baseline"
                ctx.emit("baseline", f"previous snapshot of {scan.scan_id} unreadable; skipped")
                continue
            return data if isinstance(data, dict) else None
        return None

    def _finish(
        self,
        ctx: JobContext,
        profile: SurfaceScanProfile,
        state: _State,
        inventory: Inventory,
        *,
        stopped: str,
    ) -> None:
        ctx.stage("inventory", 92)
        results = list(state.results) + state.passive.results()
        for rule_id in RULES:
            if rule_id.startswith(("SURF-", "WEB-COMP-002")) and not any(
                r.rule_id == rule_id for r in results
            ):
                results.append(
                    CheckResult(
                        rule_id,
                        Outcome.SKIPPED,
                        "-",
                        "scan stopped before this check ran"
                        if stopped
                        else "no applicable host, port or source in this scan",
                    )
                )
        writer = FindingWriter(
            ctx.repo,
            ctx.project_id,
            ctx.scan_id,
            tool_name="vapt-surface-mapper",
            tool_version=f"{CATALOG_ID} {CATALOG_VERSION}",
        )
        finding_ids: dict[int, str] = {}
        for index, result in enumerate(results):
            try:
                fid = writer.write(result)
            except Exception as exc:  # noqa: BLE001 - one bad record must not lose the rest
                ctx.error(f"could not store finding for {result.rule_id}: {type(exc).__name__}")
                continue
            if fid:
                finding_ids[index] = fid
        ctx.incr("findings_created", len(writer.created))
        ctx.incr("findings_reobserved", len(writer.reobserved))
        if state.tool_versions:
            ctx.repo.update_scan(
                ctx.project_id, ctx.scan_id, {"tool_versions": dict(state.tool_versions)}
            )

        snapshot = {
            "schema_version": 1,
            "scan_id": ctx.scan_id,
            "taken_at": datetime.now(UTC).isoformat(),
            "hosts": {
                host: {
                    "status": state.status.get(host),
                    "ips": state.dns.get(host, {}).get("addresses", []),
                    "open_ports": state.hosts_checked.get(host, {}).get("open", []),
                    "tested_ports": state.hosts_checked.get(host, {}).get("ports_tested", []),
                }
                for host in sorted(state.candidates)
            },
            "origins": sorted({o["origin"] for o in state.origins}),
        }
        changes = diff_snapshots(self._previous_snapshot(ctx), snapshot)
        status_counts = Counter(state.status.values())
        outcomes = summarize_outcomes(results)
        summary = {
            "schema_version": 1,
            "module": "attack_surface",
            "catalog_version": CATALOG_VERSION,
            "stopped_early": stopped,
            "roots": profile.roots,
            "candidates": len(state.candidates),
            "candidates_by_status": dict(status_counts),
            "rejected_inputs": state.rejected_inputs,
            "sources": [
                {
                    "name": "manual",
                    "label": "Targets and manual/imported host list",
                    "candidates": sum(
                        1 for s in state.candidates.values() if s & {"manual", "target"}
                    ),
                    "disclosure": "Local input only.",
                }
            ]
            + state.sources,
            "passive_sources_enabled": bool(ctx.scan.parameters.get("passive_crtsh")),
            "dns": {
                "resolved": sum(1 for d in state.dns.values() if d.get("resolved") is True),
                "unresolved": sum(1 for d in state.dns.values() if d.get("resolved") is False),
                "not_attempted": sum(1 for d in state.dns.values() if d.get("resolved") is None),
                "blocked_addresses": sum(len(d.get("blocked", {})) for d in state.dns.values()),
                "method": profile.dns,
            },
            "port_method": profile.port_method,
            "ports_requested": profile.ports.requested,
            "ports_tested": profile.ports.tested,
            "ports_not_tested": profile.ports.not_tested,
            "hosts_checked": {
                h: {k: v for k, v in r.items() if k != "states"}
                for h, r in state.hosts_checked.items()
            },
            "hosts_not_checked": state.hosts_not_checked,
            "open_services": state.open,
            "web_origins": state.origins,
            "check_outcomes": [
                {"outcome": o.value, "count": outcomes["by_outcome"].get(o.value, 0)}
                for o in Outcome
            ],
            "findings_created": len(writer.created),
            "findings_reobserved": len(writer.reobserved),
            "assets_created": inventory.created,
            "assets_updated": inventory.updated,
            "tool_versions": state.tool_versions,
            "components": [c.as_dict() for c in state.components.components()],
            "changes": {k: (len(v) if isinstance(v, list) else v) for k, v in changes.items()},
            "warnings": ctx.snapshot()["warnings"],
            "limitations": profile.limitations,
        }
        coverage = [
            {
                "rule_id": r.rule_id,
                "title": r.rule.title,
                "kind": r.rule.kind.value,
                "outcome": r.outcome.value,
                "subject": r.subject[:500],
                "rationale": r.rationale[:600],
                "parameter": r.parameter[:200],
                "severity": (r.severity or r.rule.severity).value
                if r.outcome == Outcome.FINDING
                else None,
                "finding_id": finding_ids.get(i),
            }
            for i, r in enumerate(results[:5000])
        ]
        hosts_detail = {
            "dns": state.dns,
            "port_states": {h: r.get("states", {}) for h, r in state.hosts_checked.items()},
        }
        ctx.stage("summary", 97)
        ctx.write_output("inventory.json", _json(snapshot))
        ctx.write_output("changes.json", _json(changes))
        ctx.write_output("summary.json", _json(summary))
        ctx.write_output(
            "coverage.json", _json({"catalog_version": CATALOG_VERSION, "results": coverage})
        )
        ctx.write_output("hosts.json", _json(hosts_detail))
        ctx.emit(
            "summary",
            f"{len(state.candidates)} candidates, {len(state.hosts_checked)} hosts checked, "
            f"{len(state.open)} open services, {len(state.origins)} web origins, "
            f"{len(writer.created)} new findings",
        )
        ctx.set_percent(100)
