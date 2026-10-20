"""Scope and authorization engine (MASTER_SPEC §4, Module 3).

Deny by default: a target is allowed only when it canonicalizes cleanly, its scheme,
host, port and path positively match the project scope, it matches no exclusion, the
project's authorization is active and attested, and (for network actions) every
resolved IP passes the IP policy. Every method returns a `Decision` with a stable
reason code so allow/block outcomes can be audited.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from collections.abc import Callable, Iterable
from datetime import datetime
from enum import StrEnum
from urllib.parse import urljoin

from pydantic import Field

from app.models.common import ScopeStatus, StrictModel, UtcDatetime, utc_now
from app.models.project import Project, ScopeDefinition
from app.scope.canonical import (
    CanonicalizationError,
    CanonicalTarget,
    host_matches_wildcard,
    normalize_host,
    normalize_target,
    parse_ip,
    path_matches_prefix,
)
from app.scope.ip_policy import IPAddress, IPNetwork, blocked_range_for, network_blocked_overlap


class Reason(StrEnum):
    ALLOWED = "allowed"
    KILL_SWITCH = "kill_switch"
    AUTHORIZATION_MISSING = "authorization_missing"
    ATTESTATION_MISSING = "attestation_missing"
    AUTHORIZATION_NOT_STARTED = "authorization_not_started"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    PROJECT_ARCHIVED = "project_archived"
    UNPARSEABLE = "unparseable"
    AMBIGUOUS_HOST = "ambiguous_host"
    INVALID_HOST = "invalid_host"
    AMBIGUOUS_PATH = "ambiguous_path"
    INVALID_PORT = "invalid_port"
    SCHEME_NOT_ALLOWED = "scheme_not_allowed"
    USERINFO_IN_URL = "userinfo_in_url"
    HOST_OUT_OF_SCOPE = "host_out_of_scope"
    HOST_EXCLUDED = "host_excluded"
    IP_OUT_OF_SCOPE = "ip_out_of_scope"
    IP_EXCLUDED = "ip_excluded"
    IP_BLOCKED_RANGE = "ip_blocked_range"
    IP_CLOUD_METADATA = "ip_cloud_metadata"
    PORT_NOT_ALLOWED = "port_not_allowed"
    PORT_EXCLUDED = "port_excluded"
    PATH_OUT_OF_SCOPE = "path_out_of_scope"
    PATH_EXCLUDED = "path_excluded"
    RESOLUTION_FAILED = "resolution_failed"
    NO_ADDRESSES = "no_addresses"
    REDIRECT_LIMIT = "redirect_limit"
    SCOPE_INVALID = "scope_invalid"


_CANON_REASONS = {r.value for r in Reason}


class Decision(StrictModel):
    """Auditable outcome of one policy check."""

    decision_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    at: UtcDatetime = Field(default_factory=utc_now)
    allowed: bool
    reason: Reason
    message: str
    check: str  # target / port / path / resolved_ip / redirect / connect / authorization ...
    input: str = ""  # the (bounded) raw input that was checked
    target: str | None = None  # canonical URL or host when known
    ip: str | None = None
    rule: str | None = None  # the scope rule that matched (allow) or blocked
    project_id: str | None = None
    scope_hash: str | None = None


class AuthorizationError(Exception):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.message)
        self.decision = decision


def scope_hash(scope: ScopeDefinition) -> str:
    return hashlib.sha256(
        json.dumps(scope.model_dump(mode="json"), sort_keys=True).encode()
    ).hexdigest()


def require_active_authorization(project: Project, now: datetime | None = None) -> Decision:
    """Raise AuthorizationError unless the project may start active work right now."""
    now = now or utc_now()

    def deny(reason: Reason, message: str) -> AuthorizationError:
        return AuthorizationError(
            Decision(
                allowed=False,
                reason=reason,
                message=message,
                check="authorization",
                project_id=project.project_id,
                scope_hash=scope_hash(project.scope),
            )
        )

    if project.status != "active":
        raise deny(Reason.PROJECT_ARCHIVED, "Archived projects cannot run active work")
    auth = project.authorization
    if auth is None:
        raise deny(Reason.AUTHORIZATION_MISSING, "No authorization is recorded for this project")
    if not auth.attestation_event_id:
        raise deny(
            Reason.ATTESTATION_MISSING, "The authorization has no recorded operator attestation"
        )
    if now < auth.window_start:
        raise deny(
            Reason.AUTHORIZATION_NOT_STARTED,
            f"Authorization window starts {auth.window_start.isoformat()}",
        )
    if now >= auth.window_end:
        raise deny(
            Reason.AUTHORIZATION_EXPIRED,
            f"Authorization window ended {auth.window_end.isoformat()}",
        )
    return Decision(
        allowed=True,
        reason=Reason.ALLOWED,
        message="Authorization is active",
        check="authorization",
        project_id=project.project_id,
        scope_hash=scope_hash(project.scope),
    )


class ScopePolicy:
    """Compiled, immutable view of one project's scope. Construct per project snapshot."""

    def __init__(self, project: Project, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.project = project
        self.scope = project.scope
        self.clock = clock
        self.hash = scope_hash(project.scope)
        self.errors: list[str] = []
        self.schemes = frozenset(self.scope.schemes)
        self.hosts: frozenset[str] = frozenset(self._compile_hosts(self.scope.hosts))
        self.wildcards: tuple[str, ...] = tuple(
            self._compile_wildcards(self.scope.wildcard_domains)
        )
        self.networks: tuple[IPNetwork, ...] = tuple(self.scope.ip_ranges)
        self.ports = frozenset(self.scope.ports)
        self.paths = tuple(self.scope.path_prefixes) or ("/",)
        ex = self.scope.exclusions
        self.ex_hosts = frozenset(self._compile_hosts(ex.hosts))
        self.ex_wildcards = tuple(self._compile_wildcards(ex.wildcard_domains))
        self.ex_networks: tuple[IPNetwork, ...] = tuple(ex.ip_ranges)
        self.ex_ports = frozenset(ex.ports)
        self.ex_paths = tuple(ex.path_prefixes)

    # ------------------------------------------------------------------ compilation

    def _compile_hosts(self, values: Iterable[str]) -> list[str]:
        out: list[str] = []
        for value in values:
            try:
                host, ip = normalize_host(value)
            except CanonicalizationError as exc:
                self.errors.append(f"scope host {value!r}: {exc.message}")
                continue
            if ip is not None:
                self.errors.append(
                    f"scope host {value!r} is an IP address; list it under IP ranges"
                )
                continue
            out.append(host)
        return out

    def _compile_wildcards(self, values: Iterable[str]) -> list[str]:
        out: list[str] = []
        for value in values:
            try:
                host, _ = normalize_host(value[2:] if value.startswith("*.") else value)
            except CanonicalizationError as exc:
                self.errors.append(f"scope wildcard {value!r}: {exc.message}")
                continue
            out.append("*." + host)
        return out

    @property
    def valid(self) -> bool:
        return not self.errors

    # ------------------------------------------------------------------ helpers

    def _decision(
        self,
        allowed: bool,
        reason: Reason,
        message: str,
        check: str,
        *,
        input: str = "",
        target: str | None = None,
        ip: str | None = None,
        rule: str | None = None,
    ) -> Decision:
        return Decision(
            allowed=allowed,
            reason=reason,
            message=message,
            check=check,
            input=str(input)[:500],
            target=target,
            ip=ip,
            rule=rule,
            project_id=self.project.project_id,
            scope_hash=self.hash,
        )

    def _override_covers(self, ip: IPAddress) -> str | None:
        override = self.scope.internal_override
        if override is None or self.clock() >= override.expires_at:
            return None
        for net in override.ip_ranges:
            if ip.version == net.version and ip in net:
                return str(net)
        return None

    # ------------------------------------------------------------------ public checks

    def normalize_target(self, url: str) -> CanonicalTarget:
        return normalize_target(url)

    def host_status(self, host: str) -> tuple[ScopeStatus, str | None]:
        """Classify a canonical hostname (no IP). Discovery never implies approval."""
        if host in self.ex_hosts:
            return ScopeStatus.EXCLUDED, f"exclusion host {host}"
        for wildcard in self.ex_wildcards:
            if host_matches_wildcard(host, wildcard):
                return ScopeStatus.EXCLUDED, f"exclusion wildcard {wildcard}"
        if host in self.hosts:
            return ScopeStatus.IN_SCOPE, f"host {host}"
        for wildcard in self.wildcards:
            if host_matches_wildcard(host, wildcard):
                return ScopeStatus.IN_SCOPE, f"wildcard {wildcard}"
        roots = list(self.hosts) + [w[2:] for w in self.wildcards]
        if any(host.endswith("." + root) or host == root for root in roots):
            return ScopeStatus.PENDING_APPROVAL, None  # related to scope, but not approved
        return ScopeStatus.OUT_OF_SCOPE, None

    def is_target_in_scope(self, url: str) -> Decision:
        """Static (no DNS) check of scheme, host, port and path for an absolute URL."""
        if not self.valid:
            return self._decision(
                False, Reason.SCOPE_INVALID, "; ".join(self.errors)[:480], "target", input=url
            )
        try:
            target = normalize_target(url)
        except CanonicalizationError as exc:
            reason = Reason(exc.code) if exc.code in _CANON_REASONS else Reason.UNPARSEABLE
            return self._decision(False, reason, exc.message, "target", input=url)
        if target.scheme not in self.schemes:
            return self._decision(
                False,
                Reason.SCHEME_NOT_ALLOWED,
                f"scheme {target.scheme} is not in scope",
                "target",
                input=url,
                target=target.url,
            )
        if target.ip is not None:
            host_decision = self._check_ip_literal(target.ip, url, target.url)
        else:
            status, rule = self.host_status(target.host)
            if status == ScopeStatus.EXCLUDED:
                host_decision = self._decision(
                    False,
                    Reason.HOST_EXCLUDED,
                    f"{target.host} is excluded",
                    "target",
                    input=url,
                    target=target.url,
                    rule=rule,
                )
            elif status != ScopeStatus.IN_SCOPE:
                host_decision = self._decision(
                    False,
                    Reason.HOST_OUT_OF_SCOPE,
                    f"{target.host} is not in scope ({status.value})",
                    "target",
                    input=url,
                    target=target.url,
                )
            else:
                host_decision = self._decision(
                    True,
                    Reason.ALLOWED,
                    "host in scope",
                    "target",
                    input=url,
                    target=target.url,
                    rule=rule,
                )
        if not host_decision.allowed:
            return host_decision
        port_decision = self.is_port_allowed(target.port, input=url, target=target.url)
        if not port_decision.allowed:
            return port_decision
        path_decision = self.is_path_allowed(target.path, input=url, target=target.url)
        if not path_decision.allowed:
            return path_decision
        return self._decision(
            True,
            Reason.ALLOWED,
            "target in scope",
            "target",
            input=url,
            target=target.url,
            rule=f"{host_decision.rule}; {path_decision.rule}",
        )

    def is_host_port_allowed(self, host: str, port: int, *, input: str = "") -> Decision:
        """Host + port check for raw connections (port probes, banners). No path/scheme involved."""
        label = input or f"{host}:{port}"
        if not self.valid:
            return self._decision(
                False, Reason.SCOPE_INVALID, "; ".join(self.errors)[:480], "connect", input=label
            )
        try:
            canonical, ip = normalize_host(host)
        except CanonicalizationError as exc:
            reason = Reason(exc.code) if exc.code in _CANON_REASONS else Reason.INVALID_HOST
            return self._decision(False, reason, exc.message, "connect", input=label)
        if ip is not None:
            host_decision = self._check_ip_literal(ip, label, canonical)
        else:
            status, rule = self.host_status(canonical)
            if status == ScopeStatus.EXCLUDED:
                host_decision = self._decision(
                    False,
                    Reason.HOST_EXCLUDED,
                    f"{canonical} is excluded",
                    "connect",
                    input=label,
                    target=canonical,
                    rule=rule,
                )
            elif status != ScopeStatus.IN_SCOPE:
                host_decision = self._decision(
                    False,
                    Reason.HOST_OUT_OF_SCOPE,
                    f"{canonical} is not in scope ({status.value})",
                    "connect",
                    input=label,
                    target=canonical,
                )
            else:
                host_decision = self._decision(
                    True,
                    Reason.ALLOWED,
                    "host in scope",
                    "connect",
                    input=label,
                    target=canonical,
                    rule=rule,
                )
        if not host_decision.allowed:
            return host_decision.model_copy(update={"check": "connect"})
        port_decision = self.is_port_allowed(port, input=label, target=canonical)
        if not port_decision.allowed:
            return port_decision.model_copy(update={"check": "connect"})
        return self._decision(
            True,
            Reason.ALLOWED,
            "host and port in scope",
            "connect",
            input=label,
            target=canonical,
            rule=f"{host_decision.rule}; port {port}",
        )

    def _check_ip_literal(self, ip: IPAddress, url: str, target: str) -> Decision:
        for net in self.ex_networks:
            if ip.version == net.version and ip in net:
                return self._decision(
                    False,
                    Reason.IP_EXCLUDED,
                    f"{ip} is excluded",
                    "target",
                    input=url,
                    target=target,
                    ip=str(ip),
                    rule=f"exclusion {net}",
                )
        matched = next((n for n in self.networks if ip.version == n.version and ip in n), None)
        if matched is None:
            return self._decision(
                False,
                Reason.IP_OUT_OF_SCOPE,
                f"{ip} is not in any in-scope IP range",
                "target",
                input=url,
                target=target,
                ip=str(ip),
            )
        ip_policy = self.validate_resolved_ip(str(ip), str(ip))
        if not ip_policy.allowed:
            return ip_policy.model_copy(
                update={"check": "target", "input": url[:500], "target": target}
            )
        return self._decision(
            True,
            Reason.ALLOWED,
            "IP in scope",
            "target",
            input=url,
            target=target,
            ip=str(ip),
            rule=f"ip_range {matched}; {ip_policy.rule}",
        )

    def is_port_allowed(self, port: int, *, input: str = "", target: str | None = None) -> Decision:
        if port in self.ex_ports:
            return self._decision(
                False,
                Reason.PORT_EXCLUDED,
                f"port {port} is excluded",
                "port",
                input=input or str(port),
                target=target,
                rule=f"exclusion port {port}",
            )
        if port not in self.ports:
            return self._decision(
                False,
                Reason.PORT_NOT_ALLOWED,
                f"port {port} is not in the allowed ports",
                "port",
                input=input or str(port),
                target=target,
            )
        return self._decision(
            True,
            Reason.ALLOWED,
            "port allowed",
            "port",
            input=input or str(port),
            target=target,
            rule=f"port {port}",
        )

    def is_path_allowed(self, path: str, *, input: str = "", target: str | None = None) -> Decision:
        from app.scope.canonical import normalize_path

        try:
            normalized = normalize_path(path)
        except CanonicalizationError as exc:
            return self._decision(
                False,
                Reason.AMBIGUOUS_PATH,
                exc.message,
                "path",
                input=input or path,
                target=target,
            )
        for prefix in self.ex_paths:
            if path_matches_prefix(normalized, prefix):
                return self._decision(
                    False,
                    Reason.PATH_EXCLUDED,
                    f"{normalized} is excluded",
                    "path",
                    input=input or path,
                    target=target,
                    rule=f"exclusion path {prefix}",
                )
        for prefix in self.paths:
            if path_matches_prefix(normalized, prefix):
                return self._decision(
                    True,
                    Reason.ALLOWED,
                    "path allowed",
                    "path",
                    input=input or path,
                    target=target,
                    rule=f"path {prefix}",
                )
        return self._decision(
            False,
            Reason.PATH_OUT_OF_SCOPE,
            f"{normalized} is outside the allowed path prefixes",
            "path",
            input=input or path,
            target=target,
        )

    def validate_resolved_ip(self, host: str, ip_text: str) -> Decision:
        """Check one address a hostname resolved to (or an IP literal) against the IP policy."""
        ip = parse_ip(ip_text.strip("[]"))
        if ip is None:
            return self._decision(
                False,
                Reason.RESOLUTION_FAILED,
                f"resolver returned a non-IP value for {host}",
                "resolved_ip",
                input=ip_text,
                target=host,
            )
        for net in self.ex_networks:
            if ip.version == net.version and ip in net:
                return self._decision(
                    False,
                    Reason.IP_EXCLUDED,
                    f"{ip} is excluded",
                    "resolved_ip",
                    input=ip_text,
                    target=host,
                    ip=str(ip),
                    rule=f"exclusion {net}",
                )
        blocked = blocked_range_for(ip)
        if blocked is not None:
            if not blocked.overridable:
                return self._decision(
                    False,
                    Reason.IP_CLOUD_METADATA,
                    f"{ip} is a cloud metadata address ({blocked.label}); never allowed",
                    "resolved_ip",
                    input=ip_text,
                    target=host,
                    ip=str(ip),
                    rule=f"blocked {blocked.network}",
                )
            override = self._override_covers(ip)
            if override is None:
                return self._decision(
                    False,
                    Reason.IP_BLOCKED_RANGE,
                    f"{ip} is in a blocked range ({blocked.label}); an internal-target "
                    "override is required",
                    "resolved_ip",
                    input=ip_text,
                    target=host,
                    ip=str(ip),
                    rule=f"blocked {blocked.network}",
                )
            return self._decision(
                True,
                Reason.ALLOWED,
                f"{ip} allowed by internal-target override",
                "resolved_ip",
                input=ip_text,
                target=host,
                ip=str(ip),
                rule=f"override {override}",
            )
        return self._decision(
            True,
            Reason.ALLOWED,
            "public address",
            "resolved_ip",
            input=ip_text,
            target=host,
            ip=str(ip),
            rule="public",
        )

    def validate_redirect(self, current_url: str, location: str) -> Decision:
        """Resolve a Location header against the current URL and re-check full scope."""
        absolute = urljoin(current_url, location.strip())
        decision = self.is_target_in_scope(absolute)
        return decision.model_copy(
            update={"check": "redirect", "input": f"{current_url} -> {location}"[:500]}
        )

    def authorization(self) -> Decision:
        try:
            return require_active_authorization(self.project, self.clock())
        except AuthorizationError as exc:
            return exc.decision

    # ------------------------------------------------------------------ reporting

    def warnings(self) -> list[str]:
        out = list(self.errors)
        for net in self.networks:
            for blocked in network_blocked_overlap(net):
                verb = (
                    "can never be reached"
                    if not blocked.overridable
                    else "is blocked unless an internal-target override covers it"
                )
                out.append(
                    f"In-scope range {net} overlaps {blocked.network} ({blocked.label}); it {verb}."
                )
        override = self.scope.internal_override
        if override is not None and self.clock() >= override.expires_at:
            out.append("The internal-target override has expired and no longer applies.")
        return out


def network_contains_any(networks: Iterable[IPNetwork], ip: IPAddress) -> bool:
    return any(ip.version == n.version and ip in n for n in networks)


def is_ip_network(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False
