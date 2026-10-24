"""Duplicate detection: strong fingerprints auto-unify; shared titles alone never do."""

from __future__ import annotations

from app.imports.base import ParsedFinding
from app.imports.dedup import fingerprint, title_only_candidates
from app.models.common import Confidence, Severity


def _f(**kw: object) -> ParsedFinding:
    base = {"title": "Example", "severity": Severity.MEDIUM, "confidence": Confidence.PROBABLE}
    base.update(kw)
    return ParsedFinding(**base)  # type: ignore[arg-type]


def test_fingerprint_matches_same_host_path_method_parameter() -> None:
    a = _f(title="XSS v1", url="http://x.test/search?q=1", method="get", parameter="q")
    b = _f(title="Totally different title", url="http://x.test/search?q=2", method="GET",
          parameter="q")
    assert fingerprint("p1", a) == fingerprint("p1", b)


def test_fingerprint_differs_across_projects() -> None:
    a = _f(url="http://x.test/a", parameter="q")
    assert fingerprint("p1", a) != fingerprint("p2", a)


def test_fingerprint_matches_on_shared_rule_id_even_without_url() -> None:
    a = _f(host="10.0.0.1", rule_id="nmap-open-mysql")
    b = _f(host="10.0.0.1", rule_id="nmap-open-mysql", title="different wording")
    assert fingerprint("p", a) == fingerprint("p", b)


def test_fingerprint_differs_when_no_strong_signal_is_shared() -> None:
    a = _f(title="A", host="10.0.0.1")
    b = _f(title="A", host="10.0.0.2")
    assert fingerprint("p", a) != fingerprint("p", b)


def test_title_only_candidates_never_includes_a_fingerprint_match() -> None:
    """The caller only passes records whose fingerprint did NOT match; title_only_candidates
    must never claim this is the same mechanism as fingerprint matching."""
    a = _f(title="Weak Default Credentials", host="10.0.0.1")
    b = _f(title="weak default credentials!!", host="10.0.0.9")  # same normalized title, diff host
    candidates = title_only_candidates([a, b], existing=[])
    assert len(candidates) == 1
    assert candidates[0].index_a == 0 and candidates[0].index_b == 1


def test_title_only_candidates_flags_match_against_existing_finding() -> None:
    a = _f(title="Outdated TLS Version")
    candidates = title_only_candidates([a], existing=[("finding_123", "outdated tls version")])
    assert len(candidates) == 1
    assert candidates[0].existing_finding_id == "finding_123"


def test_title_only_candidates_ignores_unrelated_titles() -> None:
    a = _f(title="Alpha")
    b = _f(title="Beta")
    assert title_only_candidates([a, b], existing=[]) == []
