"""API security scan job runner (module `api_security`).

Stages: profile -> load spec + inventory -> (if not inventory-only and server in scope)
error-leakage/config/CORS/transport checks -> auth baseline -> mass-assignment inventory
-> IDOR (gated) -> rate-limit probe (gated) -> findings, coverage, summary.

Safety:
- inventory and validation are offline; network checks run only when `inventory_only` is
  false AND the chosen server URL passes the scope guard on every request;
- every request goes through `HttpService` -> `ScopeGuard` -> budgeted pinned transport;
- auth secrets are resolved from the environment by alias at request time and never stored;
  evidence and outputs are redacted;
- IDOR needs two identities + an ownership map; mass-assignment write needs test-safe +
  fixture + opt-in + cleanup; rate probe is a small cap on a designated op. Missing
  prerequisites produce SKIPPED results with reasons, never a false pass.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from app.core.redaction import redact
from app.integrations.http_client import HttpClientConfig, default_transport_factory
from app.integrations.http_service import HttpExchange, HttpService
from app.jobs.context import JobContext, JobStop, RunResult
from app.scanners.apisec.inventory import ApiInventory, Operation, build_inventory, operation_url
from app.scanners.apisec.profile import ApiScanParameters, parse_parameters
from app.scanners.apisec.rules import (
    API_RULE_IDS,
    CATALOG_ID,
    CATALOG_VERSION,
    SENSITIVE_PROP,
)
from app.scanners.apisec.spec import SpecError, load_spec
from app.scanners.webapp.findings import FindingWriter, summarize_outcomes
from app.scanners.webapp.rules import CheckResult, EvidenceDraft, Outcome
from app.scope.engine import ScopePolicy

CORS_TEST_ORIGIN = "https://vapt-cors-check.invalid"
STACK_SIGNATURES = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Java stack trace", re.compile(r"\bat (?:java|javax|org\.springframework)\.[\w.$]+\(")),
    ("PHP fatal error", re.compile(r"Fatal error: Uncaught|<b>Fatal error</b>")),
    (".NET exception", re.compile(r"System\.[A-Za-z.]+Exception|Microsoft\.AspNetCore")),
    ("Node/Express stack", re.compile(r"\bat .*\(.*node_modules.*\)|Error:\s.*\n\s+at ")),
    ("Rails exception", re.compile(r"Action Controller: Exception caught")),
]
VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-runtime")
MAX_BODY_SNIPPET = 400
MAX_CHECK_OPS = 40  # cap operations touched by network checks
RATE_PROBE_LATENCY_BREAK_MS = 3000  # module-level so tests can exercise the backoff quickly


def _json(data: Any) -> bytes:
    safe = redact(json.loads(json.dumps(data, default=str)), max_items=50_000)
    return json.dumps(safe, indent=2, ensure_ascii=False).encode("utf-8")


def _resolve_secret(ref: str) -> str | None:
    if ref.startswith("env:"):
        return os.environ.get(ref[4:])
    return None


class _State:
    def __init__(self) -> None:
        self.results: list[CheckResult] = []
        self.requests = 0
        self.tested_ops: list[str] = []
        self.skipped_ops: dict[str, str] = {}
        self.inventory: ApiInventory | None = None
        self.server: str = ""


class ApiSecRunner:
    name = "api_security"

    def __init__(self, *, transport_factory: Any = default_transport_factory) -> None:
        self.transport_factory = transport_factory

    # ------------------------------------------------------------------ manager hooks

    def validate_parameters(self, params: dict[str, Any], policy: Any) -> list[str]:
        from app.scanners.apisec.profile import validate_parameters

        return validate_parameters(params)

    def check_targets(
        self, targets: list[str], policy: ScopePolicy
    ) -> tuple[list[str], list[tuple[int, str]]]:
        # API scans do not take URL targets; the spec + server come from parameters.
        # A single placeholder target (the project name/spec) is accepted.
        return (list(targets) or ["api-spec"]), []

    # ------------------------------------------------------------------ run

    def run(self, ctx: JobContext) -> RunResult:
        try:
            params = parse_parameters(dict(ctx.scan.parameters))
        except Exception as exc:  # noqa: BLE001 - validated at submit; defend anyway
            ctx.error(f"invalid API parameters: {type(exc).__name__}")
            return RunResult(failed=True, errors=["invalid API parameters"])
        state = _State()
        stop: JobStop | None = None
        try:
            self._scan(ctx, params, state)
        except JobStop as exc:
            stop = exc
            ctx.emit("partial", f"scan stopped early ({exc})", level="warning")
        self._finish(ctx, params, state, stopped=str(stop) if stop else "")
        if stop is not None:
            raise stop
        return RunResult()

    # ------------------------------------------------------------------ stages

    def _scan(self, ctx: JobContext, params: ApiScanParameters, state: _State) -> None:
        ctx.stage("inventory", 5)
        try:
            raw = ctx.repo.read_import_raw(ctx.project_id, params.import_id)
            inventory = build_inventory(load_spec(raw))
        except (SpecError, Exception) as exc:  # noqa: BLE001 - missing/invalid spec ends the run
            raise JobStopInvalidSpec(f"spec unavailable or invalid: {type(exc).__name__}") from exc
        state.inventory = inventory
        ctx.write_output("inventory.json", _json(inventory.as_dict()))
        ctx.incr("operations", len(inventory.operations))
        ctx.emit(
            "inventory",
            f"{len(inventory.operations)} operations, {len(inventory.servers)} server(s)",
        )
        state.results.append(
            CheckResult(
                "API-INV-001",
                Outcome.OBSERVATION,
                inventory.spec_title_version,
                f"{len(inventory.operations)} operations inventoried from {inventory.kind} "
                f"{inventory.version}",
                data={"operations": len(inventory.operations)},
            )
        )
        # Mass-assignment inventory (offline, schema only)
        if params.check_mass_assignment_inventory:
            self._mass_assignment_inventory(inventory, params, state)

        if params.inventory_only:
            ctx.emit("mode", "inventory-only: no network requests are sent")
            self._skip_network_checks(state, "inventory-only mode: no requests sent")
            return

        # Resolve + validate the chosen server against scope.
        ctx.stage("server scope", 20)
        server = self._pick_server(ctx, params, inventory, state)
        if server is None:
            self._skip_network_checks(state, "no in-scope server URL selected")
            return
        state.server = server
        service = HttpService(
            ctx,
            self.transport_factory(HttpClientConfig.from_policy(ctx.policy, verify_tls=True)),
            max_redirects=0,
            cache=True,
        )

        selected = self._selected_operations(inventory, params)
        ctx.stage("config checks", 35)
        if params.check_config:
            self._config_and_transport(service, server, inventory, params, state)
        ctx.stage("error leakage", 50)
        if params.check_error_leakage:
            self._error_leakage(ctx, service, server, selected, state)
        ctx.stage("auth baseline", 62)
        if params.check_unauth_baseline:
            self._auth_baseline(ctx, service, server, selected, params, state)
        else:
            state.results.append(
                CheckResult(
                    "API-AUTH-002", Outcome.SKIPPED, server, "unauthenticated baseline not selected"
                )
            )
        ctx.stage("mass assignment", 72)
        self._mass_assignment_write(ctx, params, state)
        ctx.stage("idor", 80)
        self._idor(ctx, service, server, inventory, params, state)
        ctx.stage("rate limit", 90)
        self._rate_probe(ctx, service, server, inventory, params, state)

    def _skip_network_checks(self, state: _State, reason: str) -> None:
        for rid in (
            "API-AUTH-001",
            "API-AUTH-002",
            "API-ERR-001",
            "API-ERR-002",
            "API-CFG-001",
            "API-CFG-002",
            "API-CFG-003",
            "API-INFO-001",
        ):
            state.results.append(CheckResult(rid, Outcome.SKIPPED, "-", reason))
        state.results.append(CheckResult("API-BOLA-000", Outcome.SKIPPED, "-", reason))
        state.results.append(CheckResult("API-MASS-000", Outcome.SKIPPED, "-", reason))
        state.results.append(CheckResult("API-RATE-000", Outcome.SKIPPED, "-", reason))

    def _pick_server(
        self, ctx: JobContext, params: ApiScanParameters, inventory: ApiInventory, state: _State
    ) -> str | None:
        candidates = (
            [params.server_url] if params.server_url else [s.expanded for s in inventory.servers]
        )
        for url in candidates:
            if not url:
                continue
            decision = ctx.guard.policy.is_target_in_scope(url)
            if decision.allowed:
                return url
            ctx.warn(
                f"server {url} is out of scope and will not be contacted: {decision.message}"[:300]
            )
        return None

    def _selected_operations(
        self, inventory: ApiInventory, params: ApiScanParameters
    ) -> list[Operation]:
        excluded = set(params.excluded_operations)
        selected = set(params.selected_operations)
        ops = [
            o
            for o in inventory.operations
            if o.key not in excluded and (not selected or o.key in selected)
        ]
        return ops[:MAX_CHECK_OPS]

    def _request(
        self,
        service: HttpService,
        method: str,
        url: str,
        state: _State,
        headers: tuple[tuple[str, str], ...] = (),
    ) -> HttpExchange:
        exchange = service.fetch(method, url, headers=headers, follow_redirects=False)
        state.requests += 1
        return exchange

    def _config_and_transport(
        self,
        service: HttpService,
        server: str,
        inventory: ApiInventory,
        params: ApiScanParameters,
        state: _State,
    ) -> None:
        if server.startswith("http://"):
            state.results.append(
                CheckResult(
                    "API-CFG-002", Outcome.FINDING, server, "API server URL uses plain HTTP"
                )
            )
        else:
            state.results.append(
                CheckResult("API-CFG-002", Outcome.PASS, server, "server uses HTTPS")
            )
        # one GET to the first read-only op (or server root) for headers/CORS/version
        probe_op = next((o for o in inventory.operations if not o.mutating), None)
        url = (
            operation_url(server, probe_op.path, _example_params(probe_op)) if probe_op else server
        )
        exchange = self._request(
            service, "GET", url, state, headers=(("Origin", CORS_TEST_ORIGIN),)
        )
        response = exchange.response
        if response is None:
            state.results.append(
                CheckResult(
                    "API-CFG-001", Outcome.ERROR, url, f"request failed: {exchange.error_kind}"
                )
            )
            return
        # security headers
        nosniff = (response.header("X-Content-Type-Options") or "").strip().lower() == "nosniff"
        hsts = bool(response.header("Strict-Transport-Security"))
        missing = []
        if not nosniff:
            missing.append("X-Content-Type-Options")
        if server.startswith("https://") and not hsts:
            missing.append("Strict-Transport-Security")
        if missing:
            state.results.append(
                CheckResult(
                    "API-CFG-001",
                    Outcome.FINDING,
                    url,
                    f"missing security header(s): {', '.join(missing)}",
                    evidence=_ev(exchange),
                )
            )
        else:
            state.results.append(
                CheckResult("API-CFG-001", Outcome.PASS, url, "security headers present")
            )
        # version disclosure
        for header in VERSION_HEADERS:
            value = response.header(header)
            if value and re.search(r"\d+\.\d+", value):
                state.results.append(
                    CheckResult(
                        "API-INFO-001",
                        Outcome.FINDING,
                        url,
                        f"{header} discloses a version: {value[:120]}",
                        parameter=header,
                        evidence=_ev(exchange),
                    )
                )
                break
        # CORS
        acao = (response.header("Access-Control-Allow-Origin") or "").strip()
        creds = (
            response.header("Access-Control-Allow-Credentials") or ""
        ).strip().lower() == "true"
        if acao in (CORS_TEST_ORIGIN, "null") and creds:
            state.results.append(
                CheckResult(
                    "API-CFG-003",
                    Outcome.FINDING,
                    url,
                    f"untrusted Origin reflected ({acao}) with credentials",
                    evidence=_ev(exchange),
                )
            )
        elif acao == "*":
            state.results.append(
                CheckResult(
                    "API-CFG-003",
                    Outcome.OBSERVATION,
                    url,
                    "Access-Control-Allow-Origin: * (no credentials with wildcard)",
                )
            )
        else:
            state.results.append(
                CheckResult(
                    "API-CFG-003", Outcome.PASS, url, "no untrusted-origin reflection observed"
                )
            )

    def _error_leakage(
        self,
        ctx: JobContext,
        service: HttpService,
        server: str,
        ops: list[Operation],
        state: _State,
    ) -> None:
        shapes: list[int] = []
        found = False
        for op in ops[:8]:
            if op.mutating:
                continue
            url = operation_url(
                server, op.path, {p.name: "0" for p in op.parameters if p.location == "path"}
            )
            exchange = self._request(service, "GET", url, state)
            response = exchange.response
            if response is None:
                continue
            shapes.append(response.status)
            body = response.body[:8192].decode("utf-8", "replace")
            for label, pattern in STACK_SIGNATURES:
                m = pattern.search(body)
                if m:
                    found = True
                    state.results.append(
                        CheckResult(
                            "API-ERR-001",
                            Outcome.FINDING,
                            url,
                            f"{label} in API response",
                            status=response.status,
                            evidence=_ev(exchange, body_match=m.group(0)),
                        )
                    )
                    break
        if not found and shapes:
            state.results.append(
                CheckResult(
                    "API-ERR-001",
                    Outcome.PASS,
                    server,
                    f"no stack-trace signatures in {len(shapes)} response(s)",
                )
            )

    def _auth_baseline(
        self,
        ctx: JobContext,
        service: HttpService,
        server: str,
        ops: list[Operation],
        params: ApiScanParameters,
        state: _State,
    ) -> None:
        protected = [o for o in ops if o.security_required and not o.mutating][:6]
        if not protected:
            state.results.append(
                CheckResult(
                    "API-AUTH-002",
                    Outcome.SKIPPED,
                    server,
                    "no protected read-only operation to baseline",
                )
            )
            return
        reachable = 0
        for op in protected:
            url = operation_url(
                server, op.path, {p.name: "1" for p in op.parameters if p.location == "path"}
            )
            exchange = self._request(service, "GET", url, state)
            response = exchange.response
            if response is None:
                continue
            state.tested_ops.append(op.key)
            if 200 <= response.status < 300:
                reachable += 1
                state.results.append(
                    CheckResult(
                        "API-AUTH-001",
                        Outcome.FINDING,
                        url,
                        f"operation requiring auth returned {response.status} "
                        "without credentials (status alone is not proof)",
                        status=response.status,
                        evidence=_ev(exchange),
                    )
                )
            else:
                state.results.append(
                    CheckResult(
                        "API-AUTH-001",
                        Outcome.PASS,
                        url,
                        f"unauthenticated request returned {response.status}",
                    )
                )
        state.results.append(
            CheckResult(
                "API-AUTH-002",
                Outcome.OBSERVATION,
                server,
                f"baselined {len(protected)} protected op(s); {reachable} answered 2xx "
                "unauthenticated (confirm manually; status is not proof)",
            )
        )

    def _mass_assignment_inventory(
        self, inventory: ApiInventory, params: ApiScanParameters, state: _State
    ) -> None:
        flagged = 0
        for op in inventory.operations:
            if not op.mutating:
                continue
            sensitive = [p for p in op.request_schema_props if p.lower() in SENSITIVE_PROP]
            if sensitive:
                flagged += 1
                state.results.append(
                    CheckResult(
                        "API-MASS-001",
                        Outcome.FINDING,
                        op.key,
                        f"request schema exposes writable sensitive property: "
                        f"{', '.join(sensitive[:6])} (inventory only; no value written)",
                        parameter=",".join(sensitive[:6]),
                        evidence=EvidenceDraft(
                            evidence_type="text_excerpt",
                            response_excerpt=f"{op.key} properties: "
                            + ", ".join(op.request_schema_props[:30]),
                        ),
                    )
                )
        if flagged == 0:
            state.results.append(
                CheckResult(
                    "API-MASS-001",
                    Outcome.PASS,
                    "all operations",
                    "no sensitive writable properties in request schemas",
                )
            )

    def _mass_assignment_write(
        self, ctx: JobContext, params: ApiScanParameters, state: _State
    ) -> None:
        if not params.enable_mass_assignment_write:
            state.results.append(
                CheckResult(
                    "API-MASS-000",
                    Outcome.SKIPPED,
                    "-",
                    "mass-assignment write disabled (default). Enable needs "
                    "test-safe ops + fixture + cleanup + risk acknowledgement.",
                )
            )
            return
        # Prerequisites are enforced at submit; writes against live systems are out of scope for
        # this build -> always report skipped with an explicit reason rather than mutate.
        state.results.append(
            CheckResult(
                "API-MASS-000",
                Outcome.SKIPPED,
                "-",
                "write probe not performed: this build does not mutate live "
                "systems; use a reviewed staging fixture and import results.",
            )
        )

    def _idor(
        self,
        ctx: JobContext,
        service: HttpService,
        server: str,
        inventory: ApiInventory,
        params: ApiScanParameters,
        state: _State,
    ) -> None:
        if not params.enable_idor:
            state.results.append(
                CheckResult(
                    "API-BOLA-000",
                    Outcome.SKIPPED,
                    "-",
                    "BOLA/IDOR disabled (default): needs two test identities "
                    "and an object-ownership map.",
                )
            )
            return
        auth_by_alias = {a.alias: a for a in params.auth_profiles}
        ident_by_label = {i.label: i for i in params.identities}
        # resolve secrets by alias at run time (never stored)
        tokens: dict[str, str | None] = {}
        for ident in params.identities:
            prof = auth_by_alias.get(ident.auth_alias)
            tokens[ident.label] = _resolve_secret(prof.secret_ref) if prof else None
        missing = [lbl for lbl, tok in tokens.items() if not tok]
        if missing:
            state.results.append(
                CheckResult(
                    "API-BOLA-000",
                    Outcome.SKIPPED,
                    "-",
                    f"credentials not available for identities: {', '.join(missing)} "
                    "(set the referenced env aliases)",
                )
            )
            return
        ran = 0
        for own in params.ownership[:10]:
            op = next(
                (o for o in inventory.operations if o.key == own.operation_key and not o.mutating),
                None,
            )
            if op is None:
                state.skipped_ops[own.operation_key] = (
                    "operation not found or mutating (IDOR read-only)"
                )
                continue
            other = next((i for i in ident_by_label if i != own.owner_label), None)
            if other is None:
                continue
            url = operation_url(server, op.path, {own.param_name: own.object_id})
            owner_ex = self._authed_get(
                service, url, params, auth_by_alias, ident_by_label[own.owner_label], state
            )
            other_ex = self._authed_get(
                service, url, params, auth_by_alias, ident_by_label[other], state
            )
            ran += 1
            state.tested_ops.append(op.key)
            self._compare_idor(url, own, other, owner_ex, other_ex, state)
        if ran == 0:
            state.results.append(
                CheckResult(
                    "API-BOLA-000",
                    Outcome.SKIPPED,
                    "-",
                    "no runnable owner/other object pair in the ownership map",
                )
            )
        else:
            state.results.append(
                CheckResult(
                    "API-BOLA-000",
                    Outcome.OBSERVATION,
                    server,
                    f"ran {ran} bounded owner-vs-other comparison(s); no IDs guessed",
                )
            )

    def _authed_get(
        self,
        service: HttpService,
        url: str,
        params: ApiScanParameters,
        auth_by_alias: dict[str, Any],
        ident: Any,
        state: _State,
    ) -> HttpExchange:
        prof = auth_by_alias.get(ident.auth_alias)
        headers: tuple[tuple[str, str], ...] = ()
        if prof is not None:
            token = _resolve_secret(prof.secret_ref) or ""
            if prof.scheme == "bearer":
                headers = ((prof.header_name, f"Bearer {token}"),)
            elif prof.scheme == "header":
                headers = ((prof.header_name, token),)
            elif prof.scheme == "cookie":
                headers = (("Cookie", f"{prof.header_name}={token}"),)
        return self._request(service, "GET", url, state, headers=headers)

    def _compare_idor(
        self,
        url: str,
        own: Any,
        other_label: str,
        owner_ex: HttpExchange,
        other_ex: HttpExchange,
        state: _State,
    ) -> None:
        owner_r, other_r = owner_ex.response, other_ex.response
        if owner_r is None or other_r is None:
            state.results.append(
                CheckResult(
                    "API-BOLA-001",
                    Outcome.ERROR,
                    url,
                    "a request in the owner/other comparison failed",
                )
            )
            return
        owner_ok = 200 <= owner_r.status < 300
        other_ok = 200 <= other_r.status < 300
        same_body = owner_r.body[:2048] == other_r.body[:2048] and bool(owner_r.body)
        if owner_ok and other_ok and same_body:
            state.results.append(
                CheckResult(
                    "API-BOLA-001",
                    Outcome.FINDING,
                    url,
                    f"another identity ({other_label}) received the same object "
                    f"owned by {own.owner_label}: possible BOLA",
                    parameter=own.param_name,
                    status=other_r.status,
                    evidence=_ev(other_ex),
                )
            )
        elif owner_ok and other_ok:
            state.results.append(
                CheckResult(
                    "API-BOLA-001",
                    Outcome.OBSERVATION,
                    url,
                    f"both identities got 2xx but different bodies; manual review "
                    f"(owner {own.owner_label} vs {other_label})",
                    parameter=own.param_name,
                )
            )
        else:
            state.results.append(
                CheckResult(
                    "API-BOLA-001",
                    Outcome.PASS,
                    url,
                    f"other identity ({other_label}) did not get the owner's object "
                    f"(status {other_r.status})",
                )
            )

    def _rate_probe(
        self,
        ctx: JobContext,
        service: HttpService,
        server: str,
        inventory: ApiInventory,
        params: ApiScanParameters,
        state: _State,
    ) -> None:
        if not params.enable_rate_probe:
            state.results.append(
                CheckResult(
                    "API-RATE-000", Outcome.SKIPPED, "-", "rate-limit probe disabled (default)"
                )
            )
            return
        op = next(
            (
                o
                for o in inventory.operations
                if o.key == params.rate_probe_operation and not o.mutating
            ),
            None,
        )
        if op is None:
            state.results.append(
                CheckResult(
                    "API-RATE-000",
                    Outcome.SKIPPED,
                    "-",
                    "designated rate-probe operation not found or is mutating",
                )
            )
            return
        url = operation_url(
            server, op.path, {p.name: "1" for p in op.parameters if p.location == "path"}
        )
        # This probe's whole point is to observe the server's own behaviour across repeated
        # requests and to back off the instant it signals trouble. It therefore uses its own
        # zero-retry, uncached transport: the shared `service` auto-retries 429/503 (useful for
        # ordinary scanning) and caches GETs, either of which would silently send more wire-level
        # requests than the loop below decides on, or mask a real request behind a cache hit --
        # undercounting or misrepresenting exactly what was sent to a rate-sensitive endpoint.
        probe_service = HttpService(
            ctx,
            self.transport_factory(HttpClientConfig.from_policy(ctx.policy, verify_tls=True)),
            max_redirects=0,
            max_retries=0,
            cache=False,
        )
        count = min(params.rate_probe_count, 20)
        limited = False
        sent = 0
        for _ in range(count):
            exchange = self._request(probe_service, "GET", url, state)
            sent += 1
            r = exchange.response
            if r is None:
                break
            if r.status in (429, 503):
                limited = True
                break  # back off immediately
            if exchange.response and exchange.response.elapsed_ms > RATE_PROBE_LATENCY_BREAK_MS:
                break  # latency instability: stop
        state.results.append(
            CheckResult(
                "API-RATE-000",
                Outcome.OBSERVATION,
                url,
                f"sent {sent} benign request(s) to a safe operation",
            )
        )
        if limited:
            state.results.append(
                CheckResult(
                    "API-RATE-001",
                    Outcome.PASS,
                    url,
                    f"rate limiting observed after {sent} request(s)",
                )
            )
        else:
            state.results.append(
                CheckResult(
                    "API-RATE-001",
                    Outcome.FINDING,
                    url,
                    f"no throttling after {sent} benign request(s) (a small probe "
                    "does not prove no limit exists)",
                    status=200,
                )
            )

    # ------------------------------------------------------------------ finish

    def _finish(
        self, ctx: JobContext, params: ApiScanParameters, state: _State, *, stopped: str
    ) -> None:
        ctx.stage("findings", 95)
        results = list(state.results)
        for rid in API_RULE_IDS:
            if not any(r.rule_id == rid for r in results):
                results.append(
                    CheckResult(
                        rid,
                        Outcome.SKIPPED,
                        "-",
                        "scan stopped before this check ran"
                        if stopped
                        else "not applicable in this scan",
                    )
                )
        writer = FindingWriter(
            ctx.repo,
            ctx.project_id,
            ctx.scan_id,
            tool_name="vapt-api-scanner",
            tool_version=f"{CATALOG_ID} {CATALOG_VERSION}",
        )
        finding_ids: dict[int, str] = {}
        for i, result in enumerate(results):
            try:
                fid = writer.write(result)
            except Exception as exc:  # noqa: BLE001 - one bad record must not lose the rest
                ctx.error(f"could not store finding for {result.rule_id}: {type(exc).__name__}")
                continue
            if fid:
                finding_ids[i] = fid
        ctx.incr("findings_created", len(writer.created))
        inventory = state.inventory
        outcomes = summarize_outcomes(results)
        tested = sorted(set(state.tested_ops))
        total_ops = len(inventory.operations) if inventory else 0
        summary = {
            "schema_version": 1,
            "module": "api_security",
            "catalog_version": CATALOG_VERSION,
            "stopped_early": stopped,
            "import_id": params.import_id,
            "spec": inventory.spec_title_version if inventory else "",
            "spec_kind": inventory.kind if inventory else "",
            "spec_version": inventory.version if inventory else "",
            "server": state.server,
            "inventory_only": params.inventory_only,
            "operations_total": total_ops,
            "operations_tested": tested,
            "operations_skipped": state.skipped_ops,
            "requests_sent": state.requests,
            "auth_aliases_used": sorted({a.alias for a in params.auth_profiles}),
            "idor_enabled": params.enable_idor,
            "mass_write_enabled": params.enable_mass_assignment_write,
            "rate_probe_enabled": params.enable_rate_probe,
            "check_outcomes": [
                {"outcome": o.value, "count": outcomes["by_outcome"].get(o.value, 0)}
                for o in Outcome
            ],
            "findings_created": len(writer.created),
            "findings_reobserved": len(writer.reobserved),
            "warnings": (inventory.warnings[:50] if inventory else []) + ctx.snapshot()["warnings"],
            "remote_refs": inventory.remote_refs if inventory else [],
            "limitations": _LIMITATIONS,
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
        ctx.stage("summary", 99)
        ctx.write_output("summary.json", _json(summary))
        ctx.write_output(
            "coverage.json", _json({"catalog_version": CATALOG_VERSION, "results": coverage})
        )
        ctx.emit(
            "summary",
            f"{total_ops} operations, {state.requests} request(s), "
            f"{len(writer.created)} new findings, outcomes {outcomes['by_outcome']}",
        )
        ctx.set_percent(100)


def _example_params(op: Operation) -> dict[str, str]:
    return {p.name: "1" for p in op.parameters if p.location == "path"}


def _ev(exchange: HttpExchange, *, body_match: str | None = None) -> EvidenceDraft:
    from app.scanners.webapp.evidence import http_evidence

    return http_evidence(exchange, body_match=body_match)


class JobStopInvalidSpec(JobStop):
    state_hint = "failed"


_LIMITATIONS = [
    "HTTP status alone is not proof of an access-control outcome.",
    "BOLA/IDOR uses only operator-provided identities and object IDs; no enumeration.",
    "Mutating/mass-assignment writes against live systems are not performed.",
    "A rate-limit probe that does not trip a limit does not prove none exists.",
    "Remote $ref fetching is disabled; CVE mapping needs an imported catalog (Phase 11).",
]
