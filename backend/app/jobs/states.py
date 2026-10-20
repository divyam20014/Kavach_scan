"""Scan job state machine (MASTER_SPEC Module 4). Invalid transitions are rejected."""

from __future__ import annotations

from app.models.common import ScanState

S = ScanState

TERMINAL: frozenset[ScanState] = frozenset(
    {
        S.COMPLETED,
        S.COMPLETED_WITH_WARNINGS,
        S.FAILED,
        S.CANCELLED,
        S.INTERRUPTED,
        S.BLOCKED_SCOPE,
        S.EXPIRED_AUTHORIZATION,
    }
)
ACTIVE: frozenset[ScanState] = frozenset({S.VALIDATING, S.RUNNING})

TRANSITIONS: dict[ScanState, frozenset[ScanState]] = {
    S.QUEUED: frozenset({S.VALIDATING, S.CANCELLED, S.EXPIRED_AUTHORIZATION, S.BLOCKED_SCOPE}),
    S.VALIDATING: frozenset(
        {S.RUNNING, S.BLOCKED_SCOPE, S.EXPIRED_AUTHORIZATION, S.CANCELLED, S.FAILED, S.INTERRUPTED}
    ),
    S.RUNNING: frozenset(
        {
            S.COMPLETED,
            S.COMPLETED_WITH_WARNINGS,
            S.FAILED,
            S.CANCELLED,
            S.INTERRUPTED,
            S.EXPIRED_AUTHORIZATION,
        }
    ),
    **{t: frozenset() for t in TERMINAL},
}


class InvalidTransitionError(ValueError):
    def __init__(self, current: ScanState, target: ScanState) -> None:
        super().__init__(f"Invalid scan state transition {current.value} -> {target.value}")
        self.current = current
        self.target = target


def check_transition(current: ScanState, target: ScanState) -> None:
    if target not in TRANSITIONS[current]:
        raise InvalidTransitionError(current, target)


def is_terminal(state: ScanState) -> bool:
    return state in TERMINAL
