"""A small, dependency-free version comparator for CVE `version_spec` matching.

Deliberately simple: dotted numeric versions only (no pre-release/build-metadata semantics,
no PEP 440). A version or condition this cannot parse is treated as "does not match" rather
than guessed at — matching must be defensible, never a heuristic best-effort.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_VERSION_RE = re.compile(r"^\d+(\.\d+){0,8}$")
_CONDITION_RE = re.compile(r"^(==|!=|<=|>=|<|>)\s*(\d+(?:\.\d+){0,8})$")
_OPS = ("==", "!=", "<=", ">=", "<", ">")  # order matters: check 2-char ops before 1-char


class VersionSpecError(ValueError):
    """A `version_spec` string could not be parsed as a defensible version condition."""


def _parse_version(text: str) -> tuple[int, ...] | None:
    text = text.strip()
    if not _VERSION_RE.fullmatch(text):
        return None
    return tuple(int(part) for part in text.split("."))


def _compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


@dataclass(frozen=True)
class VersionCondition:
    op: str  # one of _OPS
    version: tuple[int, ...]

    def satisfied_by(self, candidate: tuple[int, ...]) -> bool:
        cmp = _compare(candidate, self.version)
        return {
            "==": cmp == 0, "!=": cmp != 0,
            "<=": cmp <= 0, ">=": cmp >= 0,
            "<": cmp < 0, ">": cmp > 0,
        }[self.op]


def parse_version_spec(spec: str) -> list[VersionCondition]:
    """Parse a comma-separated AND-list of conditions, e.g. ">=1.0,<1.2.3" or "==2.4".

    Raises `VersionSpecError` for anything that is not a clean, explicit set of conditions —
    there is no fallback interpretation, so an unparseable spec never silently matches."""
    conditions: list[VersionCondition] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise VersionSpecError(f"empty condition in version_spec {spec!r}")
        m = _CONDITION_RE.match(part)
        if not m:
            raise VersionSpecError(f"unparseable version condition: {part!r}")
        op, version_text = m.group(1), m.group(2)
        version = _parse_version(version_text)
        if version is None:
            raise VersionSpecError(f"unparseable version in condition: {part!r}")
        conditions.append(VersionCondition(op=op, version=version))
    if not conditions:
        raise VersionSpecError(f"version_spec has no conditions: {spec!r}")
    return conditions


def version_satisfies_spec(version: str, spec: str) -> bool | None:
    """True/False if both parse and the comparison is defensible; None if either does not
    parse cleanly (caller must then skip the comparison, never guess)."""
    candidate = _parse_version(version)
    if candidate is None:
        return None
    try:
        conditions = parse_version_spec(spec)
    except VersionSpecError:
        return None
    return all(c.satisfied_by(candidate) for c in conditions)


def is_exact_spec(spec: str) -> bool:
    """True only for a spec that pins a single exact version (`==X`), the only case this
    module treats as a non-ambiguous, non-range match."""
    try:
        conditions = parse_version_spec(spec)
    except VersionSpecError:
        return False
    return len(conditions) == 1 and conditions[0].op == "=="
