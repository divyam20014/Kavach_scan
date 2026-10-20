"""Scope and authorization enforcement — the safety gate for all outbound activity.

Every future HTTP, DNS, port-probe and subprocess entrypoint MUST obtain an
`AuthorizedTarget` from `ScopeGuard` (or go through `GuardedRequester`) before acting.
"""

from app.scope.canonical import (
    CanonicalizationError,
    CanonicalTarget,
    normalize_host,
    normalize_path,
    normalize_target,
)
from app.scope.engine import (
    AuthorizationError,
    Decision,
    Reason,
    ScopePolicy,
    require_active_authorization,
    scope_hash,
)
from app.scope.guard import (
    AuthorizedTarget,
    DecisionSink,
    GuardedRequester,
    MemorySink,
    ResolutionError,
    Resolver,
    ScopeBlocked,
    ScopeGuard,
    Transport,
    TransportResponse,
)
from app.scope.ip_policy import BLOCKED_RANGES, BlockedRange, blocked_range_for, embedded_ipv4

__all__ = [
    "BLOCKED_RANGES",
    "AuthorizationError",
    "AuthorizedTarget",
    "BlockedRange",
    "CanonicalTarget",
    "CanonicalizationError",
    "Decision",
    "DecisionSink",
    "GuardedRequester",
    "MemorySink",
    "Reason",
    "ResolutionError",
    "Resolver",
    "ScopeBlocked",
    "ScopeGuard",
    "ScopePolicy",
    "Transport",
    "TransportResponse",
    "blocked_range_for",
    "embedded_ipv4",
    "normalize_host",
    "normalize_path",
    "normalize_target",
    "require_active_authorization",
    "scope_hash",
]
