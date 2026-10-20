"""DNS resolver adapter (MASTER_SPEC §4.2): the only place the application resolves names.

Behavior that matters for safety:
- The resolver only *answers*; it approves nothing. `ScopeGuard` validates EVERY returned
  address against the IP policy on EVERY request (cached answers included) and pins the
  approved addresses; the HTTP transport then connects to those pinned IPs only and never
  resolves again. A rebinding answer therefore cannot reach a socket unchecked.
- Answers are cached per scan job (a resolver instance is created per job) for at most
  `ttl_seconds` (default 30 s; the OS resolver does not expose record TTLs, so the cache
  window is a fixed upper bound). After expiry the name is re-resolved and re-validated.
- Failures are cached briefly (`negative_ttl_seconds`) so an unresolvable host cannot
  trigger a lookup storm, and the cache is bounded (`max_entries`, oldest evicted).
- Each lookup has a hard timeout (the OS call runs in a helper thread); a timeout is a
  resolution failure, which the guard turns into a blocked decision.
- IP literals are never sent to the resolver (the guard validates them directly).
"""

from __future__ import annotations

import ipaddress
import socket  # getaddrinfo only; this module is the sanctioned DNS adapter
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from app.scope.guard import ResolutionError

DEFAULT_TTL_SECONDS = 30.0
DEFAULT_NEGATIVE_TTL_SECONDS = 5.0
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_ADDRESSES = 32

Lookup = Callable[[str], list[str]]


def system_lookup(host: str) -> list[str]:
    """Resolve A and AAAA records through the operating system resolver."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise ResolutionError(str(exc) or "lookup failed") from exc
    out: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        address = str(sockaddr[0]).split("%", 1)[0]  # drop any IPv6 zone id
        if address not in out:
            out.append(address)
    return out


@dataclass
class _Entry:
    addresses: list[str] | None  # None = cached failure
    error: str
    expires: float


class CachingResolver:
    """Bounded, time-limited cache in front of a lookup function (one instance per job)."""

    def __init__(
        self,
        lookup: Lookup = system_lookup,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        negative_ttl_seconds: float = DEFAULT_NEGATIVE_TTL_SECONDS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_entries: int = 256,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.lookup = lookup
        self.ttl = max(0.0, ttl_seconds)
        self.negative_ttl = max(0.0, negative_ttl_seconds)
        self.timeout = timeout_seconds
        self.max_entries = max_entries
        self.clock = clock
        self._cache: OrderedDict[str, _Entry] = OrderedDict()
        self._lock = threading.Lock()
        self.lookups = 0  # real lookups performed (for tests and the scan summary)

    def resolve(self, host: str) -> list[str]:
        key = host.lower().rstrip(".")
        try:
            ipaddress.ip_address(key)
        except ValueError:
            pass
        else:
            return [key]
        now = self.clock()
        with self._lock:
            entry = self._cache.get(key)
            if entry is not None and entry.expires > now:
                if entry.addresses is None:
                    raise ResolutionError(entry.error)
                return list(entry.addresses)
        try:
            addresses = self._timed_lookup(key)
        except ResolutionError as exc:
            self._store(key, _Entry(None, str(exc), now + self.negative_ttl))
            raise
        self._store(key, _Entry(addresses, "", now + self.ttl))
        return list(addresses)

    def _store(self, key: str, entry: _Entry) -> None:
        with self._lock:
            self._cache[key] = entry
            self._cache.move_to_end(key)
            while len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)

    def _timed_lookup(self, host: str) -> list[str]:
        result: list[list[str]] = []
        error: list[BaseException] = []

        def work() -> None:
            try:
                result.append(self.lookup(host))
            except BaseException as exc:  # noqa: BLE001 - re-raised below as ResolutionError
                error.append(exc)

        self.lookups += 1
        worker = threading.Thread(target=work, name=f"dns-{host[:40]}", daemon=True)
        worker.start()
        worker.join(self.timeout)
        if worker.is_alive():
            raise ResolutionError(f"lookup timed out after {self.timeout:.0f}s")
        if error:
            exc = error[0]
            raise exc if isinstance(exc, ResolutionError) else ResolutionError(str(exc))
        addresses = [a for a in result[0] if isinstance(a, str)][:MAX_ADDRESSES]
        if not addresses:
            raise ResolutionError("no addresses")
        return addresses

    def invalidate(self, host: str | None = None) -> None:
        with self._lock:
            if host is None:
                self._cache.clear()
            else:
                self._cache.pop(host.lower().rstrip("."), None)


def default_resolver_factory() -> CachingResolver:
    """Resolver used by the job manager: one fresh cache per job."""
    return CachingResolver()
