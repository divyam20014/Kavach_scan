"""Duplicate detection for imported findings (MASTER_SPEC §8.3, item #8).

Two tiers, deliberately different from "similar title":
- `fingerprint()` is a composite of strong, independent signals (canonical host, canonical
  path, method, parameter, rule/plugin id, a shared CWE). A record whose fingerprint
  matches an existing `Finding.fingerprint` (or another record being imported in the same
  batch) is treated as the SAME finding and re-observed on commit — never a silent
  duplicate, never created twice. This mirrors the exact mechanism the live scanners
  already use (`app.scanners.webapp.findings.FindingWriter`).
- `title_only_candidates()` separately flags pairs that share only a normalized title with
  no other matching signal. These are never auto-merged; they are surfaced in the dry-run
  preview as "possible duplicates" for the operator to look at, and each becomes its own
  new Finding on commit unless the operator excludes it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.imports.base import ParsedFinding

_WS = re.compile(r"\s+")
_NON_WORD = re.compile(r"[^\w\s]")


def _canonical_title(title: str) -> str:
    return _WS.sub(" ", _NON_WORD.sub(" ", title.lower())).strip()


def _canonical_host(finding: ParsedFinding) -> str:
    if finding.url:
        try:
            host = urlsplit(finding.url).hostname or ""
        except ValueError:
            host = ""
        if host:
            return host.lower()
    return (finding.host or "").lower().strip()


def _canonical_path(finding: ParsedFinding) -> str:
    if not finding.url:
        return ""
    try:
        return urlsplit(finding.url).path.rstrip("/").lower()
    except ValueError:
        return ""


def fingerprint(project_id: str, finding: ParsedFinding) -> str:
    """A stable signature from signals that are independent of free-text title/summary.
    Two records that share a host+path+method+parameter, or a rule id, or an explicit
    source_finding_id, are the same underlying observation even if their titles differ."""
    host = _canonical_host(finding)
    path = _canonical_path(finding)
    strong = finding.source_finding_id.strip() or finding.rule_id.strip()
    parts = "|".join([
        project_id, host, path, (finding.method or "").upper(), finding.parameter.strip().lower(),
        strong, ",".join(str(c) for c in sorted(finding.cwe_ids)),
    ])
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TitleCandidate:
    index_a: int
    index_b: int | None  # None when the match is against an EXISTING finding, not this batch
    existing_finding_id: str | None
    title: str


def title_only_candidates(findings: list[ParsedFinding],
                          existing: list[tuple[str, str]]) -> list[TitleCandidate]:
    """`existing` is [(finding_id, title)] for findings already in the project. Flags pairs
    that share a normalized title but were NOT already unified by `fingerprint()` (the
    caller passes only findings whose fingerprint did not match)."""
    out: list[TitleCandidate] = []
    by_title: dict[str, int] = {}
    for i, f in enumerate(findings):
        key = _canonical_title(f.title)
        if not key:
            continue
        if key in by_title:
            out.append(TitleCandidate(by_title[key], i, None, f.title))
        else:
            by_title[key] = i
    existing_by_title = {_canonical_title(t): fid for fid, t in existing}
    for i, f in enumerate(findings):
        key = _canonical_title(f.title)
        if key in existing_by_title:
            out.append(TitleCandidate(i, None, existing_by_title[key], f.title))
    return out
