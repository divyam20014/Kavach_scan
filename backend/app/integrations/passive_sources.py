"""Optional passive subdomain sources (MASTER_SPEC Module 6.1).

Passive sources contact a THIRD PARTY, never the target. They are therefore:
- off by default; enabled per scan only by the operator (shown in the profile and the
  job manifest, and disclosed in the scan summary with exactly what was sent);
- limited to a fixed allowlist of endpoints (`crt.sh` only in this build);
- connected only to public (globally routable) addresses of that endpoint, pinned after
  resolution, through the same pinned transport as all other HTTP (no proxies,
  no redirects followed, byte caps, timeouts);
- rate-limited (one query per root domain, a minimum interval between queries);
- treated as untrusted input: results are only *candidates*, canonicalized and
  classified by the scope policy; discovery never grants scan permission.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.integrations.http_client import HttpClientConfig, PinnedHttpTransport, TransportError
from app.scope.canonical import CanonicalizationError, normalize_host, normalize_target
from app.scope.guard import AuthorizedTarget, RequestOptions, ResolutionError, Transport

MAX_RESULT_NAMES = 5000
MAX_ROOTS_PER_SCAN = 10


class _Resolver(Protocol):
    def resolve(self, host: str) -> list[str]: ...


@dataclass
class SourceResult:
    source: str
    root: str
    names: list[str] = field(default_factory=list)
    sent: str = ""  # exactly what was disclosed to the third party
    error: str = ""
    truncated: bool = False


class CrtShSource:
    name = "crtsh"
    label = "crt.sh (Certificate Transparency logs)"
    endpoint_host = "crt.sh"
    disclosure = (
        "Sends each authorized root domain name to crt.sh, a third-party Certificate "
        "Transparency search service. No request is sent to the target."
    )

    def __init__(
        self,
        resolver: _Resolver,
        *,
        transport: Transport | None = None,
        min_interval: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.resolver = resolver
        self.transport = transport or PinnedHttpTransport(
            HttpClientConfig(
                connect_timeout=10,
                read_timeout=30,
                total_timeout=60,
                max_response_bytes=8 * 1024 * 1024,
                max_decoded_bytes=16 * 1024 * 1024,
            )
        )
        self.min_interval = min_interval
        self.sleep = sleep
        self.clock = clock
        self._last = -1e9
        self.queries = 0

    def _authorized(self) -> AuthorizedTarget:
        target = normalize_target(f"https://{self.endpoint_host}/")
        try:
            addresses = self.resolver.resolve(self.endpoint_host)
        except ResolutionError as exc:
            raise TransportError(
                "refused", f"could not resolve {self.endpoint_host}: {exc}"
            ) from exc
        public = []
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise TransportError(
                    "refused", f"{self.endpoint_host} resolved to non-public {address}; refused"
                )
            public.append(address)
        if not public:
            raise TransportError("refused", f"{self.endpoint_host} has no addresses")
        return AuthorizedTarget(target=target, pinned_ips=tuple(public), decisions=())

    def query(self, root: str) -> SourceResult:
        query = f"q=%25.{root}&output=json"
        result = SourceResult(source=self.name, root=root, sent=f"GET https://crt.sh/?{query}")
        wait = self._last + self.min_interval - self.clock()
        if wait > 0:
            self.sleep(wait)
        self._last = self.clock()
        self.queries += 1
        try:
            response = self.transport.send(
                "GET",
                self._authorized(),
                RequestOptions(query=query, headers=(("Accept", "application/json"),)),
            )
        except TransportError as exc:
            result.error = f"{exc.kind}: {exc.message}"[:300]
            return result
        if response.status != 200:
            result.error = f"crt.sh answered HTTP {response.status}"
            return result
        result.truncated = response.truncated
        try:
            data: Any = json.loads(response.body.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            result.error = "crt.sh response is not valid JSON" + (
                " (truncated)" if response.truncated else ""
            )
            return result
        result.names = parse_crtsh(data, root)
        return result


def parse_crtsh(data: Any, root: str) -> list[str]:
    """Extract canonical hostnames under `root` from crt.sh JSON (untrusted input)."""
    if not isinstance(data, list):
        return []
    names: list[str] = []
    seen: set[str] = set()
    for entry in data[:50_000]:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value", ""))[:10_000].splitlines():
            candidate = raw.strip().lower()
            if candidate.startswith("*."):
                candidate = candidate[2:]
            try:
                host, ip = normalize_host(candidate)
            except CanonicalizationError:
                continue
            if ip is not None or not (host == root or host.endswith("." + root)):
                continue
            if host not in seen:
                seen.add(host)
                names.append(host)
                if len(names) >= MAX_RESULT_NAMES:
                    return names
    return names


PASSIVE_SOURCES = {CrtShSource.name: CrtShSource}
