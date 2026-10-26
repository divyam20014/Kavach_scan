"""Git-clone-from-URL roadmap, phase 4 of 6 (TBD-099): SSRF guard. Resolves the clone URL's
host and refuses it before any clone attempt if any resolved address falls in a blocked
range -- reusing TBD-037's existing blocked-IP-range policy (cloud metadata, private,
link-local, loopback, documentation, etc.) via `ScopePolicy.validate_resolved_ip`, exactly
as the operator-reviewed roadmap specified: a blocked-range check, never a hosting-provider
allowlist.

Deliberately **not** the project's in-scope allowlist (`ScopePolicy.is_host_port_allowed`/
`ScopeGuard.authorize_connect`): a repository legitimately lives outside the network target
a scan's scope describes (e.g. `github.com` for a project whose scope is some unrelated
internal web application), so requiring the clone host to already be "in scope" would make
this feature unusable for its own stated purpose. The project's own exclusions and
internal-target override are still honored, via the same `ScopePolicy` every other guarded
action in this application uses -- an operator who has explicitly authorized reaching a
given internal range for this project (`InternalTargetOverride`) gets the same exception
here, never a separate, parallel allowlist.

**Residual risk, disclosed rather than hidden**: this check and Git's own connection are two
separate operations. `nmap`/`sslyze`/`testssl.sh` (`app/integrations/nmap.py`,
`app/integrations/tls_tools.py`) never resolve DNS themselves -- they are handed the
already-validated IP literal directly, closing the DNS-rebinding window completely. Git's
own HTTPS client cannot be given a pinned IP the same way: TLS SNI and the HTTP Host header
both need the real hostname, and Git exposes no `--resolve`-style pin-to-IP mechanism the
way `curl` does. A DNS answer that changes in the short window between this check and Git's
own connection would not be caught here. Phase 5 narrows this window as far as this
application can: it re-runs this check immediately before starting the clone subprocess,
never once at project-configuration time, so the window is the clone's own short DNS TTL,
not however long a project has existed.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from app.models.project import Project
from app.scope.canonical import parse_ip
from app.scope.engine import ScopePolicy
from app.scope.guard import ResolutionError, Resolver


class CloneHostBlockedError(ValueError):
    """The clone URL's host is blocked (or could not be resolved); nothing is cloned."""


def extract_clone_host(url: str) -> str:
    host = urlsplit(url).hostname
    if not host:
        raise CloneHostBlockedError("repository URL has no host")
    return host


def check_clone_host_not_blocked(url: str, project: Project, resolver: Resolver) -> None:
    """Raise `CloneHostBlockedError` unless every address `url`'s host resolves to (or the
    literal IP itself) passes the project's existing blocked-IP-range policy."""
    host = extract_clone_host(url)
    policy = ScopePolicy(project)
    literal = parse_ip(host)
    if literal is not None:
        addresses = [str(literal)]
    else:
        try:
            addresses = resolver.resolve(host)
        except ResolutionError as exc:
            raise CloneHostBlockedError(f"could not resolve {host}: {exc}") from exc
    if not addresses:
        raise CloneHostBlockedError(f"{host} has no addresses")
    for address in addresses:  # ALL answers must pass, exactly like ScopeGuard._resolve_and_pin
        decision = policy.validate_resolved_ip(host, address)
        if not decision.allowed:
            raise CloneHostBlockedError(
                f"repository host {host} resolves to {address}, which is blocked: "
                f"{decision.message}"
            )
