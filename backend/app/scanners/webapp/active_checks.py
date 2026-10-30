"""Opt-in active confirmation checks (WEB-SQLI-001, WEB-XSS-001).

Disabled by default -- `ScanPolicy.active_probes.sqli_error_differential`/
`xss_reflection` (TBD-014, TBD-016, TBD-115). When explicitly enabled per probe type
on a project, this sends exactly one bounded confirmation request per query parameter
already observed by the passive crawl (never a fresh crawl, never a payload-fuzzing
loop, never blind/time-based injection):

- SQLi error-differential: append a single syntax-breaking character and look for a
  database error signature from the same catalog the passive WEB-DBERR-001 check uses,
  absent from the unmodified response.
- XSS reflection: send a unique, non-executing marker string and confirm it comes back
  unencoded. The marker never contains executable script.

Every request goes through the same `HttpService` (scope check per hop, budgets,
pacing) the rest of the scanner uses, plus its own tighter
`max_active_probe_requests_per_target` ceiling so active probing can never consume the
whole crawl's request budget.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.integrations.http_service import HttpService
from app.scanners.webapp.checks import DB_ERRORS
from app.scanners.webapp.crawler import HTML_TYPES, PageRecord
from app.scanners.webapp.evidence import http_evidence
from app.scanners.webapp.rules import CheckResult, Outcome
from app.scope.engine import ScopePolicy

SQLI_PROBE = "'"
XSS_MARKER_PREFIX = "vaptxss"
MAX_PARAMETERS_PER_PAGE = 10


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


class ActiveChecks:
    def __init__(
        self,
        service: HttpService,
        policy: Callable[[], ScopePolicy],
        *,
        sqli_enabled: bool,
        xss_enabled: bool,
        max_requests: int,
    ) -> None:
        self.service = service
        self.policy = policy
        self.sqli_enabled = sqli_enabled
        self.xss_enabled = xss_enabled
        self.max_requests = max_requests
        self.results: list[CheckResult] = []
        self._sent = 0
        self._tested: set[tuple[str, str, str]] = set()

    def run(self, pages: list[PageRecord]) -> None:
        if not self.sqli_enabled and not self.xss_enabled:
            return
        for page in pages:
            if self._sent >= self.max_requests:
                break
            if page.content_type not in HTML_TYPES:
                continue
            params = sorted({k for k, _ in parse_qsl(urlsplit(page.url).query, True)})
            for name in params[:MAX_PARAMETERS_PER_PAGE]:
                if self._sent >= self.max_requests:
                    break
                if self.sqli_enabled:
                    self._sqli(page.url, name)
                if self._sent >= self.max_requests:
                    break
                if self.xss_enabled:
                    self._xss(page.url, name)

    def _in_scope(self, url: str) -> bool:
        return self.policy().is_target_in_scope(url).allowed

    def _sqli(self, url: str, name: str) -> None:
        key = ("sqli", url, name)
        if key in self._tested:
            return
        self._tested.add(key)
        candidate = _with_param(url, name, SQLI_PROBE)
        if not self._in_scope(candidate):
            return
        self._sent += 1
        exchange = self.service.fetch("GET", candidate, follow_redirects=False)
        response = exchange.response
        if response is None:
            self.results.append(
                CheckResult(
                    "WEB-SQLI-001",
                    Outcome.ERROR,
                    url,
                    f"confirmation request failed: {exchange.error_kind} {exchange.error}"[:300],
                    parameter=name,
                )
            )
            return
        body = response.body.decode("utf-8", "replace") if response.body else ""
        for label, pattern in DB_ERRORS:
            m = pattern.search(body)
            if m:
                self.results.append(
                    CheckResult(
                        "WEB-SQLI-001",
                        Outcome.FINDING,
                        url,
                        f"{label} error signature appeared after sending a single "
                        f"syntax-breaking character in parameter {name} (absent from the "
                        "unmodified response)",
                        parameter=name,
                        status=response.status,
                        evidence=http_evidence(exchange, body_match=m.group(0)),
                    )
                )
                return
        self.results.append(
            CheckResult(
                "WEB-SQLI-001",
                Outcome.PASS,
                url,
                f"no database error signature after one confirmation request on parameter {name}",
                parameter=name,
            )
        )

    def _xss(self, url: str, name: str) -> None:
        key = ("xss", url, name)
        if key in self._tested:
            return
        self._tested.add(key)
        marker = f"{XSS_MARKER_PREFIX}{abs(hash((url, name))) % 100_000}"
        probe_value = f"<{marker}>"
        candidate = _with_param(url, name, probe_value)
        if not self._in_scope(candidate):
            return
        self._sent += 1
        exchange = self.service.fetch("GET", candidate, follow_redirects=False)
        response = exchange.response
        if response is None:
            self.results.append(
                CheckResult(
                    "WEB-XSS-001",
                    Outcome.ERROR,
                    url,
                    f"confirmation request failed: {exchange.error_kind} {exchange.error}"[:300],
                    parameter=name,
                )
            )
            return
        body = response.body.decode("utf-8", "replace") if response.body else ""
        if probe_value in body:
            self.results.append(
                CheckResult(
                    "WEB-XSS-001",
                    Outcome.FINDING,
                    url,
                    f"a unique marker sent in parameter {name} was reflected unencoded "
                    "(confirmed by direct request, not inferred)",
                    parameter=name,
                    status=response.status,
                    evidence=http_evidence(exchange, body_match=probe_value),
                )
            )
            return
        self.results.append(
            CheckResult(
                "WEB-XSS-001",
                Outcome.PASS,
                url,
                f"a unique marker sent in parameter {name} was not reflected unencoded",
                parameter=name,
            )
        )
