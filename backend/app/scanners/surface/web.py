"""Web-origin probing for the surface mapper, reusing Module 5 building blocks.

For each discovered in-scope HTTP(S) origin: one verified-TLS root fetch (status, title,
headers, TLS basics, certificate expiry), then a tiny same-origin crawl (`web_max_pages`,
depth 1) whose responses go through the web scanner's passive checks and component
detection. All requests use the shared `HttpService` (cached per run), so the scope gate,
budgets and pacing apply exactly as in the web scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.integrations.http_service import HttpExchange, HttpService
from app.scanners.webapp.checks import PassiveChecks
from app.scanners.webapp.components import ComponentDetector
from app.scanners.webapp.crawler import HTML_TYPES, Crawler, PageRecord
from app.scanners.webapp.html import HtmlInfo, parse_html
from app.scanners.webapp.probes import EXPIRY_WARNING_DAYS, _cert_time
from app.scanners.webapp.rules import CheckResult, EvidenceDraft, Outcome
from app.scope.engine import ScopePolicy


@dataclass
class OriginResult:
    origin: str
    status: int | None = None
    title: str = ""
    server: str = ""
    final_url: str = ""
    tls: dict[str, Any] = field(default_factory=dict)
    endpoints: list[PageRecord] = field(default_factory=list)
    error: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "status": self.status,
            "title": self.title,
            "server": self.server,
            "final_url": self.final_url,
            "tls": self.tls,
            "endpoints": [p.url for p in self.endpoints],
            "error": self.error,
            "headers": self.headers,
        }


INTERESTING_HEADERS = (
    "server",
    "x-powered-by",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "content-type",
)


def _tls_summary(exchange: HttpExchange, now: datetime) -> tuple[dict[str, Any], list[CheckResult]]:
    tls = exchange.tls
    results: list[CheckResult] = []
    if tls is None:
        return {}, results
    summary: dict[str, Any] = {
        "verified": tls.verified,
        "protocol": tls.version,
        "cipher": tls.cipher,
        "subject_cn": tls.subject_cn,
        "issuer_cn": tls.issuer_cn,
        "not_after": tls.not_after,
        "error": tls.error,
    }
    evidence = EvidenceDraft(
        evidence_type="tls_certificate",
        response_excerpt="\n".join(f"{k}: {v}" for k, v in summary.items() if v not in ("", None)),
    )
    if exchange.error_kind == "tls":
        results.append(
            CheckResult(
                "WEB-TLS-003",
                Outcome.FINDING,
                exchange.url,
                f"certificate verification failed: {tls.error or exchange.error}"[:400],
                evidence=evidence,
            )
        )
        return summary, results
    results.append(
        CheckResult(
            "WEB-TLS-003",
            Outcome.PASS,
            exchange.url,
            "certificate chain and hostname verified by the client",
        )
    )
    expires = _cert_time(tls.not_after)
    if expires is not None:
        days = (expires - now).days
        summary["days_to_expiry"] = days
        outcome = Outcome.FINDING if days < EXPIRY_WARNING_DAYS else Outcome.PASS
        results.append(
            CheckResult(
                "WEB-TLS-004",
                outcome,
                exchange.url,
                f"certificate expires in {days} day(s) ({tls.not_after})",
                evidence=evidence if outcome == Outcome.FINDING else None,
            )
        )
    return summary, results


def probe_origin(
    origin: str,
    *,
    verified: HttpService,
    crawl: HttpService,
    policy: ScopePolicy,
    passive: PassiveChecks,
    components: ComponentDetector,
    max_pages: int,
    checkpoint: Any,
    now: datetime | None = None,
) -> tuple[OriginResult, list[CheckResult]]:
    result = OriginResult(origin=origin)
    checks: list[CheckResult] = []
    root = origin.rstrip("/") + "/"
    first = verified.fetch("GET", root)
    if origin.startswith("https://"):
        result.tls, tls_checks = _tls_summary(first, now or datetime.now(UTC))
        checks += tls_checks
    exchange = first
    if first.error_kind == "tls" and crawl is not verified:
        exchange = crawl.fetch("GET", root)  # tls_verify=false for this scan: inventory anyway
    if exchange.response is None:
        result.error = f"{exchange.error_kind}: {exchange.error}"[:300]
        return result, checks
    response = exchange.response
    result.status = response.status
    result.final_url = exchange.final_url
    result.server = (response.header("Server") or "")[:200]
    result.headers = {
        h: (response.header(h) or "")[:200] for h in INTERESTING_HEADERS if response.header(h)
    }
    ctype = (response.header("Content-Type") or "").split(";", 1)[0].strip().lower()
    if ctype in HTML_TYPES and response.body:
        result.title = parse_html(response.body[: 512 * 1024].decode("utf-8", "replace")).title

    def on_page(page: PageRecord, ex: HttpExchange, info: HtmlInfo | None) -> None:
        passive.observe(page, ex, info)
        if ex.response is not None:
            components.observe_headers(ex.final_url, ex.response.headers)
        if info is not None:
            components.observe_generator(ex.final_url, info.generator)

    service = crawl if first.error_kind == "tls" else verified
    crawler = Crawler(
        service,
        lambda: policy,
        max_pages=max_pages,
        max_depth=1,
        respect_robots=True,
        checkpoint=checkpoint,
        on_page=on_page,
    )
    crawler.crawl([(root, "target")])
    result.endpoints = list(crawler.result.pages)
    for resource in sorted(crawler.result.resources)[:200]:
        components.observe_resource(resource)
    return result, checks
