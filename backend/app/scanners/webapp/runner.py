"""Web application scanner job runner (module `web_app`).

Stages: profile → transport (HTTPS/certificate) → crawl (+ passive checks, components)
→ CORS → TLS tool → components/CVE → skipped groups → findings → summary.

Safety properties:
- every HTTP request goes through `HttpService` → `ScopeGuard` → budgeted transport;
- the TLS tool runs only after `authorize_connect` and is given the pinned IP;
- cancellation, kill switch, authorization lapse, budget and duration limits surface as
  `JobStop` from any request or checkpoint. Partial results gathered so far are still
  written (findings + outputs; no further network activity), then the stop propagates.
"""

from __future__ import annotations

import base64
import json
import os
from collections import Counter
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from app.core.redaction import redact, redact_text
from app.integrations.http_client import HttpClientConfig, default_transport_factory
from app.integrations.http_service import HttpExchange, HttpService
from app.integrations.process import find_executable
from app.integrations.tls_tools import (
    MAX_TOOL_OUTPUT,
    TOOL_TIMEOUT_SECONDS,
    TlsToolSpec,
    ToolOutputError,
    detect_tls_tools,
)
from app.integrations.zap import ZapAvailability, check_availability
from app.jobs.context import JobContext, JobStop, RunResult
from app.models.project import ScanPolicy
from app.scanners.webapp.checks import PassiveChecks, origin_of
from app.scanners.webapp.components import (
    ComponentDetector,
    CveCatalog,
    NoCveCatalog,
    cve_results,
)
from app.scanners.webapp.crawler import Crawler, CrawlResult, PageRecord
from app.scanners.webapp.findings import FindingWriter, summarize_outcomes
from app.scanners.webapp.html import HtmlInfo
from app.scanners.webapp.probes import cors_check, http_methods_check, transport_checks
from app.scanners.webapp.profile import (
    WebScanProfile,
    build_profile,
    validate_parameters,
)
from app.scanners.webapp.rules import (
    CATALOG_VERSION,
    RULES,
    CheckResult,
    EvidenceDraft,
    Outcome,
)
from app.scanners.zap_dast.alerts import ZapReportError, parse_traditional_json_report
from app.scanners.zap_dast.findings import ZapFindingWriter
from app.scanners.zap_dast.plan import (
    REPORT_FILE_NAME,
    ZapPlanError,
    baseline_argv,
    build_baseline_plan,
)
from app.scope.guard import ScopeBlocked, Transport

TransportFactory = Callable[[HttpClientConfig], Transport]
MAX_COVERAGE_ROWS = 5000
MAX_RESOURCES_LISTED = 1000
#: generous: a real ZAP run on this project's development machine took JVM startup
#: (~1s) + spider (near-instant for a small site) + the configured passive-scan-wait
#: budget (confirmed directly, TBD-080); this is a ceiling, not an expected duration.
ZAP_PROCESS_TIMEOUT_SECONDS = 900.0
ZAP_MAX_OUTPUT_BYTES = 16 * 1024 * 1024


OUTPUT_MAX_ITEMS = 20_000


def _json(data: Any) -> bytes:
    """Serialize a scan output; every string is redacted (URLs may carry tokens)."""
    safe = redact(json.loads(json.dumps(data, default=str)), max_items=OUTPUT_MAX_ITEMS)
    return json.dumps(safe, indent=2, ensure_ascii=False).encode("utf-8")


def _resolve_secret(ref: str) -> str | None:
    """Mirrors `apisec/runner.py`'s own resolver: env-alias only, never a raw secret."""
    if ref.startswith("env:"):
        return os.environ.get(ref[4:])
    return None


def _auth_headers(params: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Build the one configured session-credential header, resolved at run time only.

    Raises if a scheme other than "none" is configured but its secret alias does not
    resolve, rather than silently crawling unauthenticated while the operator believes
    authentication is active.
    """
    scheme = params.get("auth_scheme") or "none"
    if scheme == "none":
        return ()
    ref = str(params.get("auth_secret_ref") or "")
    secret = _resolve_secret(ref)
    if not secret:
        raise RuntimeError(
            f"authenticated crawling is configured (auth_scheme={scheme!r}) but the "
            f"credential referenced by {ref!r} is not available; set that environment "
            "variable before starting the scan"
        )
    header_name = str(params.get("auth_header_name") or "Authorization")
    if scheme == "bearer":
        return ((header_name, f"Bearer {secret}"),)
    if scheme == "header":
        return ((header_name, secret),)
    if scheme == "cookie":
        return (("Cookie", f"{header_name}={secret}"),)
    if scheme == "basic":
        token = base64.b64encode(secret.encode("utf-8")).decode("ascii")
        return (("Authorization", f"Basic {token}"),)
    return ()


class WebAppRunner:
    name = "web_app"

    def __init__(
        self,
        *,
        transport_factory: TransportFactory = default_transport_factory,
        tls_tools: Callable[[], list[TlsToolSpec]] = detect_tls_tools,
        cve_catalog: CveCatalog | None = None,
        zap_availability: Callable[[], ZapAvailability] = lambda: check_availability(""),
    ) -> None:
        self.transport_factory = transport_factory
        self.tls_tools = tls_tools
        self.cve_catalog: CveCatalog = cve_catalog or NoCveCatalog()
        # A repo-bound closure built by `default_runners` checks the operator's actual
        # configured `zap_path`; the bare default above checks only common install
        # locations, same as every other caller of `detect_zap("")`.
        self.zap_availability = zap_availability

    def validate_parameters(self, params: dict[str, Any], policy: ScanPolicy) -> list[str]:
        errors = validate_parameters(params, policy)
        if not errors and params.get("engine") == "zap":
            avail = self.zap_availability()
            if not avail.available:
                errors.append(f"engine=zap is not available: {avail.reason}")
        return errors

    # ------------------------------------------------------------------ run

    def run(self, ctx: JobContext) -> RunResult:
        profile = build_profile(dict(ctx.scan.parameters), ctx.policy)
        ctx.write_output("profile.json", _json(profile.model_dump(mode="json")))
        ctx.emit(
            "profile",
            f"web scan profile (catalog {CATALOG_VERSION}, safe mode)",
            enabled=[c.group for c in profile.checks if c.enabled],
            disabled=[c.group for c in profile.checks if not c.enabled],
        )
        if profile.engine == "zap":
            return self._run_zap(ctx, profile)
        state = _RunState(profile)
        stop: JobStop | None = None
        try:
            self._scan(ctx, profile, state)
        except JobStop as exc:
            stop = exc
            ctx.emit(
                "partial", f"scan stopped early ({exc}); writing partial results", level="warning"
            )
        self._finish(ctx, profile, state, stopped=str(stop) if stop else "")
        if stop is not None:
            raise stop
        return RunResult()

    # ------------------------------------------------------------------ ZAP engine

    def _run_zap(self, ctx: JobContext, profile: WebScanProfile) -> RunResult:
        """`engine=zap`: Automation-Framework-driven Baseline/Passive scan. Availability was
        already checked at submission (`validate_parameters`); re-checked here as defense
        in depth against a race (uninstalled between submission and execution) -- a scan
        job must fail cleanly, never silently fall back to the native engine or fabricate
        a result."""
        ctx.stage("zap availability", 2)
        avail = self.zap_availability()
        if not avail.available or avail.installation is None:
            raise RuntimeError(f"ZAP engine is not available: {avail.reason}")
        installation = avail.installation

        targets = list(ctx.scan.authorized_targets)
        ctx.stage("zap plan", 5)
        report_dir = ctx.repo.scan_work_subdir(ctx.project_id, ctx.scan_id, "zap_report")
        home_dir = ctx.repo.scan_work_subdir(ctx.project_id, ctx.scan_id, "zap_home")
        try:
            plan_text = build_baseline_plan(
                targets,
                report_dir,
                spider_max_minutes=profile.zap_spider_max_minutes,
                passive_max_minutes=profile.zap_wait_max_minutes,
            )
        except ZapPlanError as exc:
            raise RuntimeError(f"could not build the ZAP plan: {exc}") from exc
        ctx.repo.write_scan_output(ctx.project_id, ctx.scan_id, "zap-plan.yaml", plan_text.encode())
        plan_path = ctx.repo.scan_work_dir(ctx.project_id, ctx.scan_id) / "zap-plan.yaml"
        java = find_executable(["java"])
        if not java:
            raise RuntimeError("no Java runtime found on PATH; ZAP requires one")
        try:
            argv = baseline_argv(java, installation.jar_path, plan_path, home_dir)
        except ZapPlanError as exc:
            raise RuntimeError(f"could not build the ZAP argv: {exc}") from exc

        ctx.stage("zap scan", 15)
        ctx.emit(
            "zap_profile",
            f"OWASP ZAP {installation.version} Baseline/Passive scan",
            targets=targets,
            spider_max_minutes=profile.zap_spider_max_minutes,
            passive_max_minutes=profile.zap_wait_max_minutes,
        )
        result = ctx.run_process(
            argv,
            allowed_executables=[java],
            timeout=ZAP_PROCESS_TIMEOUT_SECONDS,
            max_output_bytes=ZAP_MAX_OUTPUT_BYTES,
        )
        ctx.checkpoint()  # raises the right JobStop subclass if cancelled/budget-exhausted
        if result.timed_out:
            raise RuntimeError(f"ZAP did not finish within {ZAP_PROCESS_TIMEOUT_SECONDS:.0f}s")
        if result.exit_code != 0:
            raise RuntimeError(f"ZAP exited with status {result.exit_code}")

        ctx.stage("zap report", 85)
        report_bytes = ctx.repo.read_scan_work_file(
            ctx.project_id,
            ctx.scan_id,
            "zap_report",
            REPORT_FILE_NAME,
            max_bytes=ZAP_MAX_OUTPUT_BYTES,
        )
        try:
            alerts = parse_traditional_json_report(report_bytes)
        except ZapReportError as exc:
            raise RuntimeError(f"could not interpret the ZAP report: {exc}") from exc

        ctx.stage("findings", 95)
        writer = ZapFindingWriter(
            ctx.repo, ctx.project_id, ctx.scan_id, tool_version=f"OWASP ZAP {installation.version}"
        )
        for alert in alerts:
            writer.write(alert)
        ctx.write_output(
            "zap_summary.json",
            _json(
                {
                    "engine": "zap",
                    "zap_version": installation.version,
                    "targets": targets,
                    "alerts_found": len(alerts),
                    "findings_created": len(writer.created),
                    "findings_reobserved": len(writer.reobserved),
                    "limitations": [
                        "Baseline/Passive profile only: bounded spider plus passive "
                        "analysis. No active-scan input was sent to the target.",
                        "Severity/confidence come directly from ZAP's own rating; a "
                        "passive scan never confirms exploitation, so confidence is "
                        "never reported higher than 'probable'.",
                    ],
                }
            ),
        )
        return RunResult()

    # ------------------------------------------------------------------ stages

    def _services(
        self, ctx: JobContext, profile: WebScanProfile
    ) -> tuple[HttpService, HttpService]:
        crawl_cfg = HttpClientConfig.from_policy(ctx.policy, verify_tls=profile.tls_verify)
        verified_cfg = HttpClientConfig.from_policy(ctx.policy, verify_tls=True)
        # The configured session credential (if any) is applied to every crawl request via
        # `default_headers`; the certificate-only `verified` service deliberately does not
        # receive it -- transport checks don't need an authenticated session.
        auth_headers = _auth_headers(dict(ctx.scan.parameters))
        crawl = HttpService(
            ctx,
            self.transport_factory(crawl_cfg),
            max_redirects=profile.budgets.max_redirects,
            default_headers=auth_headers,
        )
        verified = HttpService(ctx, self.transport_factory(verified_cfg), max_redirects=0)
        return crawl, verified

    def _scan(self, ctx: JobContext, profile: WebScanProfile, state: _RunState) -> None:
        crawl_service, verified_service = self._services(ctx, profile)
        targets = list(ctx.scan.authorized_targets)
        origins = list(dict.fromkeys(origin_of(t) for t in targets))
        hosts = list(dict.fromkeys(urlsplit(t).netloc for t in targets))

        ctx.stage("transport security", 3)
        for target in targets:
            netloc = urlsplit(target).netloc
            if netloc not in hosts:
                continue
            hosts.remove(netloc)
            state.results += transport_checks(target, verified_service, ctx.guard.policy)

        ctx.stage("crawl", 10)
        passive = PassiveChecks()
        state.passive = passive

        def on_page(page: PageRecord, exchange: HttpExchange, info: HtmlInfo | None) -> None:
            passive.observe(page, exchange, info)
            if exchange.response is not None:
                state.components.observe_headers(exchange.final_url, exchange.response.headers)
            if info is not None:
                state.components.observe_generator(exchange.final_url, info.generator)
            ctx.incr("pages_fetched")

        def progress(done: int, total: int) -> None:
            ctx.set_percent(
                10 + 60 * min(1.0, done / max(1, min(total, profile.budgets.max_pages)))
            )

        crawler = Crawler(
            crawl_service,
            lambda: ctx.guard.policy,
            max_pages=profile.budgets.max_pages,
            max_depth=profile.budgets.max_depth,
            respect_robots=profile.respect_robots,
            checkpoint=ctx.checkpoint,
            progress=progress,
            on_page=on_page,
        )
        starts = [(t, "target") for t in targets]
        for origin in origins:
            starts += [(origin + p, "seed") for p in profile.seed_paths]
        state.crawl = crawler.result  # partial pages are kept if the crawl is stopped
        crawler.crawl(starts)
        for resource in sorted(state.crawl.resources)[:MAX_RESOURCES_LISTED]:
            state.components.observe_resource(resource)
        if state.crawl.limit_reached:
            ctx.warn(f"Crawl incomplete: {state.crawl.limit_reached}")

        ctx.stage("cors", 72)
        if profile.enabled("cors"):
            for origin in origins:
                html_pages = [
                    p.url
                    for p in state.crawl.pages
                    if origin_of(p.url) == origin and p.status and p.status < 300
                ]
                state.results.append(
                    cors_check(html_pages[0] if html_pages else origin + "/", crawl_service)
                )

        if profile.enabled("http_methods"):
            for origin in origins:
                html_pages = [
                    p.url
                    for p in state.crawl.pages
                    if origin_of(p.url) == origin and p.status and p.status < 300
                ]
                state.results.append(
                    http_methods_check(html_pages[0] if html_pages else origin + "/", crawl_service)
                )

        ctx.stage("tls tool", 80)
        if profile.enabled("tls_tool"):
            self._tls_tool(ctx, origins, state)

        ctx.stage("components", 88)
        state.results += state.components.results()
        state.results += cve_results(state.components.components(), self.cve_catalog)

    def _tls_tool(self, ctx: JobContext, origins: list[str], state: _RunState) -> None:
        https = [o for o in origins if o.startswith("https://")]
        tools = self.tls_tools()
        if not https:
            for rule in ("WEB-TLS-005", "WEB-TLS-006"):
                state.results.append(
                    CheckResult(rule, Outcome.SKIPPED, "-", "no HTTPS origin in this scan")
                )
            return
        if not tools:
            for origin in https:
                for rule in ("WEB-TLS-005", "WEB-TLS-006"):
                    state.results.append(
                        CheckResult(
                            rule,
                            Outcome.SKIPPED,
                            origin,
                            "neither sslyze nor testssl.sh is installed; no protocol or cipher "
                            "coverage is claimed",
                        )
                    )
            return
        spec = tools[0]
        version = self._tool_version(ctx, spec)
        state.tool_versions[spec.name] = version or "unknown"
        for origin in https:
            parts = urlsplit(origin)
            host, port = parts.hostname or "", parts.port or 443
            try:
                authorized = ctx.guard.authorize_connect(host, port)
            except ScopeBlocked as blocked:
                for rule in ("WEB-TLS-005", "WEB-TLS-006"):
                    state.results.append(
                        CheckResult(
                            rule,
                            Outcome.SKIPPED,
                            origin,
                            f"blocked by scope: {blocked.decision.message}",
                        )
                    )
                continue
            ip = authorized.pinned_ips[0]
            json_path = ""
            if spec.output_file:
                json_path = str(
                    ctx.repo.scan_work_dir(ctx.project_id, ctx.scan_id) / spec.output_file
                )
            argv = spec.argv(host, port, ip, json_path=json_path)
            result = ctx.run_process(
                argv,
                allowed_executables=[spec.executable],
                timeout=TOOL_TIMEOUT_SECONDS,
                max_output_bytes=MAX_TOOL_OUTPUT,
            )
            raw = result.stdout
            if spec.output_file:
                try:
                    raw = ctx.repo.read_scan_output(
                        ctx.project_id, ctx.scan_id, spec.output_file, max_bytes=MAX_TOOL_OUTPUT
                    )
                except Exception:  # noqa: BLE001 - missing file is reported below
                    raw = b""
            label = f"{spec.name} {version}".strip()
            if result.timed_out or not raw:
                reason = (
                    "timed out" if result.timed_out else f"exit code {result.exit_code}, no output"
                )
                for rule in ("WEB-TLS-005", "WEB-TLS-006"):
                    state.results.append(
                        CheckResult(
                            rule,
                            Outcome.ERROR,
                            origin,
                            f"{label} did not produce results ({reason})",
                        )
                    )
                continue
            # Raw tool output is kept for provenance, but redacted like every other output.
            ctx.write_output(
                f"tls-tool-{spec.name.replace('.', '_')}-{host[:60]}-{port}.json".replace(":", "_"),
                redact_text(raw.decode("utf-8", "replace"), max_chars=MAX_TOOL_OUTPUT).encode(),
            )
            try:
                report = spec.parse(raw, version)
            except ToolOutputError as exc:
                for rule in ("WEB-TLS-005", "WEB-TLS-006"):
                    state.results.append(
                        CheckResult(
                            rule,
                            Outcome.ERROR,
                            origin,
                            f"{label} output could not be parsed: {exc}",
                        )
                    )
                continue
            tested = ", ".join(
                f"{p}={'offered' if v else 'not offered'}" for p, v in report.protocols.items()
            )
            evidence = EvidenceDraft(
                evidence_type="tool_output",
                response_excerpt=f"{label}\n{tested}\n" + "\n".join(report.notes),
            )
            state.results.append(
                CheckResult(
                    "WEB-TLS-006",
                    Outcome.OBSERVATION,
                    origin,
                    f"{label}: {tested}",
                    evidence=evidence,
                    data={"tool": spec.name, "version": version},
                )
            )
            legacy = report.legacy_offered
            if legacy:
                state.results.append(
                    CheckResult(
                        "WEB-TLS-005",
                        Outcome.FINDING,
                        origin,
                        f"{label} reports legacy protocol(s) accepted: {', '.join(legacy)}",
                        parameter=",".join(legacy),
                        evidence=evidence,
                    )
                )
            else:
                state.results.append(
                    CheckResult(
                        "WEB-TLS-005", Outcome.PASS, origin, f"{label}: no legacy protocol accepted"
                    )
                )

    def _tool_version(self, ctx: JobContext, spec: TlsToolSpec) -> str:
        result = ctx.run_process(
            [spec.executable, *spec.version_args()],
            allowed_executables=[spec.executable],
            timeout=30,
            max_output_bytes=16 * 1024,
        )
        for stream in (result.stdout, result.stderr):
            for line in stream.decode("utf-8", "replace").splitlines():
                text = "".join(ch for ch in line.strip() if ch.isprintable())
                if text:
                    return text[:120]
        return ""

    # ------------------------------------------------------------------ finish

    def _finish(
        self, ctx: JobContext, profile: WebScanProfile, state: _RunState, *, stopped: str
    ) -> None:
        ctx.stage("findings", 92)
        results = list(state.results)
        if state.passive is not None:
            results += state.passive.results()
        for check in profile.checks:
            if not check.enabled:
                for rule_id in check.rule_ids:
                    results.append(
                        CheckResult(rule_id, Outcome.SKIPPED, "-", check.reason or "disabled")
                    )
        for rule_id in RULES:
            if not any(r.rule_id == rule_id for r in results):
                results.append(
                    CheckResult(
                        rule_id,
                        Outcome.SKIPPED,
                        "-",
                        "scan stopped before this check ran"
                        if stopped
                        else "no applicable response or subject was observed",
                    )
                )
        writer = FindingWriter(ctx.repo, ctx.project_id, ctx.scan_id)
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
        ctx.incr("checks_evaluated", len(results))
        if state.tool_versions:
            ctx.repo.update_scan(
                ctx.project_id, ctx.scan_id, {"tool_versions": dict(state.tool_versions)}
            )

        ctx.stage("summary", 98)
        crawl = state.crawl or CrawlResult()
        counters = ctx.snapshot()["progress"]["counters"]
        outcomes = summarize_outcomes(results)
        severities = Counter(
            (r.severity or r.rule.severity).value for r in results if r.outcome == Outcome.FINDING
        )
        endpoints = sorted({p.url for p in crawl.pages})
        parameters = sorted(
            {f"{urlsplit(p.url).path}?{n}" for p in crawl.pages for n in p.parameters}
        )
        summary = {
            "schema_version": 1,
            "module": "web_app",
            "catalog_version": CATALOG_VERSION,
            "safe_mode": profile.safe_mode,
            "stopped_early": stopped,
            "targets": list(ctx.scan.authorized_targets),
            "pages_fetched": len(crawl.pages),
            "endpoints_discovered": len(endpoints),
            "forms_discovered": len(crawl.forms),
            "parameters_discovered": len(parameters),
            "requests_sent": counters.get("requests_sent", 0),
            "request_errors": counters.get("request_errors", 0),
            "request_retries": counters.get("request_retries", 0),
            "rate_limited_responses": counters.get("rate_limited_responses", 0),
            "scope_blocked": counters.get("scope_blocked", 0),
            "redirects_blocked": counters.get("redirects_blocked", 0),
            "out_of_scope_links": sum(crawl.out_of_scope_links.values()),
            "out_of_scope_hosts": dict(crawl.out_of_scope_links.most_common(20)),
            "crawl_skipped": dict(crawl.skipped),
            "crawl_limit": crawl.limit_reached,
            "robots": crawl.robots,
            # A list, not a dict: a key named "pass" would be treated as secret by the redactor.
            "check_outcomes": [
                {"outcome": o.value, "count": outcomes["by_outcome"].get(o.value, 0)}
                for o in Outcome
            ],
            "findings_created": len(writer.created),
            "findings_reobserved": len(writer.reobserved),
            "findings_by_severity": dict(severities),
            "tool_versions": state.tool_versions,
            "components": [c.as_dict() for c in state.components.components()],
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
            for i, r in enumerate(results[:MAX_COVERAGE_ROWS])
        ]
        pages = {
            "pages": [p.as_dict() for p in crawl.pages],
            "forms": [f.__dict__ for f in crawl.forms[:2000]],
            "parameters": parameters[:5000],
            "resources": sorted(crawl.resources)[:MAX_RESOURCES_LISTED],
        }
        ctx.write_output("summary.json", _json(summary))
        ctx.write_output(
            "coverage.json", _json({"catalog_version": CATALOG_VERSION, "results": coverage})
        )
        ctx.write_output("pages.json", _json(pages))
        ctx.emit(
            "summary",
            f"{len(crawl.pages)} pages, {len(writer.created)} new findings, "
            f"{len(writer.reobserved)} re-observed, checks {outcomes['by_outcome']}",
        )
        ctx.set_percent(100)


class _RunState:
    def __init__(self, profile: WebScanProfile) -> None:
        self.profile = profile
        self.results: list[CheckResult] = []
        self.passive: PassiveChecks | None = None
        self.crawl: CrawlResult | None = None
        self.components = ComponentDetector()
        self.tool_versions: dict[str, str] = {}
