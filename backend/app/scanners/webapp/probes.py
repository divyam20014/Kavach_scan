"""Checks that send a small, bounded number of benign extra requests.

- transport: HTTPS availability, HTTP→HTTPS redirect, certificate validity/hostname/expiry.
  Uses a service whose transport always verifies TLS, independent of the crawl setting;
- CORS: one GET per origin carrying a fixed test Origin (`https://vapt-cors-check.invalid`,
  a reserved name that cannot exist).

Every request goes through `HttpService` (scope check per hop, budgets, pacing). A scheme
or port that is not in scope is never contacted: the related check is SKIPPED.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urlsplit

from app.integrations.http_service import HttpExchange, HttpService
from app.models.common import Severity
from app.scanners.webapp.evidence import http_evidence
from app.scanners.webapp.rules import CheckResult, EvidenceDraft, Outcome
from app.scope.engine import ScopePolicy

CORS_TEST_ORIGIN = "https://vapt-cors-check.invalid"
EXPIRY_WARNING_DAYS = 30


def _cert_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(" ".join(value.split()), "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=UTC
        )
    except ValueError:
        return None


def _tls_evidence(exchange: HttpExchange) -> EvidenceDraft:
    tls = exchange.tls
    lines = [f"Handshake with {exchange.url}"]
    if tls is not None:
        lines += [
            f"verified: {tls.verified}",
            f"protocol: {tls.version or '-'}",
            f"cipher: {tls.cipher or '-'}",
            f"subject CN: {tls.subject_cn or '-'}",
            f"issuer CN: {tls.issuer_cn or '-'}",
            f"subjectAltName: {', '.join(tls.san) or '-'}",
            f"notBefore: {tls.not_before or '-'}",
            f"notAfter: {tls.not_after or '-'}",
        ]
        if tls.error:
            lines.append(f"verification error: {tls.error}")
    elif exchange.error:
        lines.append(f"error: {exchange.error_kind}: {exchange.error}")
    return EvidenceDraft(evidence_type="tls_certificate", response_excerpt="\n".join(lines))


def transport_checks(
    host_url: str,
    service: HttpService,
    policy: ScopePolicy,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> list[CheckResult]:
    """`service` must verify TLS. Returns results for TLS-001..004 for one host."""
    parts = urlsplit(host_url)
    hostname = parts.hostname or ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    https_url = f"https://{host}/"
    http_url = f"http://{host}/"
    if parts.scheme == "https" and parts.port:
        https_url = f"https://{parts.netloc}/"
    if parts.scheme == "http" and parts.port:
        http_url = f"http://{parts.netloc}/"
    results: list[CheckResult] = []
    https_in_scope = policy.is_target_in_scope(https_url).allowed
    http_in_scope = policy.is_target_in_scope(http_url).allowed

    https_ex: HttpExchange | None = None
    https_available = False
    if not https_in_scope:
        for rule in ("WEB-TLS-001", "WEB-TLS-003", "WEB-TLS-004"):
            results.append(
                CheckResult(
                    rule,
                    Outcome.SKIPPED,
                    https_url,
                    "HTTPS on this host/port is not in the approved scope",
                )
            )
    else:
        https_ex = service.fetch("GET", https_url, follow_redirects=False)
        tls_failed = https_ex.error_kind == "tls"
        https_available = https_ex.response is not None or tls_failed
        if https_available:
            results.append(
                CheckResult("WEB-TLS-001", Outcome.PASS, https_url, "an HTTPS endpoint answered")
            )
        elif https_ex.error_kind in ("connect", "timeout"):
            results.append(
                CheckResult(
                    "WEB-TLS-001",
                    Outcome.FINDING if parts.scheme == "http" else Outcome.ERROR,
                    https_url,
                    f"no HTTPS endpoint answered ({https_ex.error_kind})",
                    evidence=_tls_evidence(https_ex),
                )
            )
        else:
            results.append(
                CheckResult(
                    "WEB-TLS-001",
                    Outcome.ERROR,
                    https_url,
                    f"could not test HTTPS: {https_ex.error_kind} {https_ex.error}"[:300],
                )
            )
        if tls_failed:
            results.append(
                CheckResult(
                    "WEB-TLS-003",
                    Outcome.FINDING,
                    https_url,
                    f"certificate verification failed: {https_ex.error}"[:400],
                    detail=https_ex.tls.error if https_ex.tls else "",
                    evidence=_tls_evidence(https_ex),
                )
            )
            results.append(
                CheckResult(
                    "WEB-TLS-004",
                    Outcome.SKIPPED,
                    https_url,
                    "certificate is not valid; expiry window not evaluated",
                )
            )
        elif https_ex.response is not None and https_ex.tls is not None and https_ex.tls.verified:
            results.append(
                CheckResult(
                    "WEB-TLS-003",
                    Outcome.PASS,
                    https_url,
                    "certificate chain and hostname verified by the client",
                    evidence=_tls_evidence(https_ex),
                )
            )
            expires = _cert_time(https_ex.tls.not_after)
            if expires is None:
                results.append(
                    CheckResult(
                        "WEB-TLS-004",
                        Outcome.ERROR,
                        https_url,
                        "could not read the certificate expiry date",
                    )
                )
            else:
                days = (expires - now()).days
                if days < EXPIRY_WARNING_DAYS:
                    results.append(
                        CheckResult(
                            "WEB-TLS-004",
                            Outcome.FINDING,
                            https_url,
                            f"certificate expires in {days} day(s) ({https_ex.tls.not_after})",
                            evidence=_tls_evidence(https_ex),
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            "WEB-TLS-004",
                            Outcome.PASS,
                            https_url,
                            f"certificate valid for {days} more days",
                        )
                    )
        elif https_available is False:
            for rule in ("WEB-TLS-003", "WEB-TLS-004"):
                results.append(
                    CheckResult(rule, Outcome.SKIPPED, https_url, "no HTTPS endpoint to examine")
                )

    if not http_in_scope:
        results.append(
            CheckResult(
                "WEB-TLS-002",
                Outcome.SKIPPED,
                http_url,
                "plain HTTP on this host/port is not in the approved scope",
            )
        )
    elif not https_available:
        results.append(
            CheckResult(
                "WEB-TLS-002",
                Outcome.SKIPPED,
                http_url,
                "HTTPS is not available, so no redirect is expected",
            )
        )
    else:
        http_ex = service.fetch("GET", http_url, follow_redirects=False)
        response = http_ex.response
        if response is None:
            results.append(
                CheckResult(
                    "WEB-TLS-002",
                    Outcome.SKIPPED,
                    http_url,
                    f"plain HTTP did not answer ({http_ex.error_kind})",
                )
            )
        elif response.status in (301, 302, 303, 307, 308) and (
            response.location or ""
        ).lower().startswith("https://"):
            results.append(
                CheckResult(
                    "WEB-TLS-002",
                    Outcome.PASS,
                    http_url,
                    f"HTTP {response.status} redirect to HTTPS",
                )
            )
        else:
            results.append(
                CheckResult(
                    "WEB-TLS-002",
                    Outcome.FINDING,
                    http_url,
                    f"plain HTTP answered {response.status} without redirecting to HTTPS",
                    status=response.status,
                    evidence=http_evidence(http_ex),
                )
            )
    return results


def cors_check(url: str, service: HttpService) -> CheckResult:
    exchange = service.fetch(
        "GET", url, headers=(("Origin", CORS_TEST_ORIGIN),), follow_redirects=False
    )
    response = exchange.response
    if response is None:
        return CheckResult(
            "WEB-CORS-001",
            Outcome.ERROR,
            url,
            f"request failed: {exchange.error_kind} {exchange.error}"[:300],
        )
    acao = (response.header("Access-Control-Allow-Origin") or "").strip()
    credentials = (
        response.header("Access-Control-Allow-Credentials") or ""
    ).strip().lower() == "true"
    if not acao:
        return CheckResult(
            "WEB-CORS-001",
            Outcome.PASS,
            url,
            "no Access-Control-Allow-Origin for an untrusted origin",
        )
    if acao in (CORS_TEST_ORIGIN, "null"):
        if credentials:
            return CheckResult(
                "WEB-CORS-001",
                Outcome.FINDING,
                url,
                f"untrusted Origin reflected ({acao}) with Allow-Credentials: true",
                status=response.status,
                evidence=http_evidence(exchange),
            )
        return CheckResult(
            "WEB-CORS-001",
            Outcome.FINDING,
            url,
            f"untrusted Origin reflected ({acao}) without credentials",
            severity=Severity.LOW,
            status=response.status,
            evidence=http_evidence(exchange),
        )
    if acao == "*":
        return CheckResult(
            "WEB-CORS-001",
            Outcome.OBSERVATION,
            url,
            "Access-Control-Allow-Origin: * (public resource; browsers never "
            "send credentials with a wildcard)",
            status=response.status,
        )
    return CheckResult(
        "WEB-CORS-001", Outcome.PASS, url, f"only a fixed origin is allowed ({acao[:100]})"
    )
