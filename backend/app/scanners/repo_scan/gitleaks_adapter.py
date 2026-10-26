"""Gitleaks adapter: argv construction/validation and JSON-report parsing only (roadmap
Phase 2 increment 2, TBD-085). Pure logic -- no file I/O, no process execution (see the
package docstring).

The output schema below was confirmed directly against a real local Gitleaks 8.30.1 run
(the official Windows x64 release binary, downloaded into a disposable scratchpad directory
and deleted afterward -- never installed into this project) -- `gitleaks dir <path>
--report-format json --report-path - --exit-code 0 --no-banner --redact --log-level error`
against a throwaway sample file containing a fake GitHub-PAT-shaped token, not assumed from
documentation alone. One safety-critical thing found only by that real run, not
documentation:

Gitleaks' own JSON report embeds the literal matched secret text in two fields, `Match` and
`Secret` -- unlike Semgrep or ZAP, whose reports never echo back sensitive source content.
Confirmed directly: `--redact` (gitleaks' own flag, 100% by default) replaces both fields
with the literal string `"REDACTED"` in the JSON report itself, not only in console/log
output as its `--help` text alone might suggest. `build_scan_argv` therefore makes
`--redact` and `--exit-code 0` **non-optional, always-appended** flags -- never a caller-
supplied parameter -- so a scan can never be invoked without them: `--redact` ensures a raw
secret value can never reach this application's own storage even if `Match`/`Secret` were
read, and `--exit-code 0` ensures "secrets were found" (gitleaks' own default exit code is 1
for that case) is never confused with a process execution failure, the same posture ZAP's
"Confirmed" risk already takes and Semgrep's `--metrics=off` already models for a different
kind of always-on safety flag. As additional defense in depth, `GitleaksFinding` below never
captures `Match`/`Secret` at all -- not even the post-redaction `"REDACTED"` placeholder --
so no code path can ever surface raw or near-raw secret material from this report, by
construction rather than by convention.

Gitleaks' JSON carries no severity/confidence field of its own (unlike Semgrep's
`extra.severity`/`extra.metadata.confidence` or ZAP's `riskcode`/`confidence`) -- every
confirmed rule match is treated as `Severity.HIGH` (an exposed secret is inherently
high-impact regardless of which rule matched) and `Confidence.POTENTIAL`, never
`CONFIRMED`: a pattern/entropy match proves a secret-shaped string was found in the
repository, not that the credential is still live or was ever exploited, the same
conservative posture already taken by the Semgrep and ZAP adapters.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.common import Confidence, Severity

MAX_TEXT_CHARS = 2000
MAX_TAGS = 20
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 3600
MIN_MAX_TARGET_MEGABYTES = 1
MAX_MAX_TARGET_MEGABYTES = 500


class GitleaksArgvError(ValueError):
    """The argv would be unsafe or invalid; nothing is executed."""


class GitleaksReportError(ValueError):
    """The report could not be interpreted; no finding may be claimed from it."""


def build_scan_argv(
    executable: str,
    repo_path: Path,
    *,
    timeout_seconds: int = 300,
    max_target_megabytes: int = 50,
) -> list[str]:
    """`gitleaks dir <repo_path> --report-format json --report-path - --exit-code 0
    --no-banner --redact --log-level error --timeout <n> --max-target-megabytes <n>`.
    `--report-path -` writes the JSON report to stdout only (confirmed directly: no log/
    banner lines are mixed into stdout with `--no-banner --log-level error`), read back by
    the caller through the storage layer, the same stdout-only pattern the Semgrep adapter
    already uses. `--redact` and `--exit-code 0` are always appended -- see the module
    docstring -- and are never parameters a caller could omit or disable."""
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise GitleaksArgvError(
            f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}"
        )
    if not MIN_MAX_TARGET_MEGABYTES <= max_target_megabytes <= MAX_MAX_TARGET_MEGABYTES:
        raise GitleaksArgvError(
            f"max_target_megabytes must be between {MIN_MAX_TARGET_MEGABYTES} and "
            f"{MAX_MAX_TARGET_MEGABYTES}"
        )
    return [
        executable,
        "dir",
        str(repo_path),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--exit-code",
        "0",
        "--no-banner",
        "--redact",
        "--log-level",
        "error",
        "--timeout",
        str(timeout_seconds),
        "--max-target-megabytes",
        str(max_target_megabytes),
    ]


def _string_list(raw: object, limit: int) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item)[:200] for item in raw][:limit]


@dataclass(frozen=True)
class GitleaksFinding:
    rule_id: str
    description: str
    path: str
    start_line: int
    end_line: int
    tags: list[str] = field(default_factory=list)
    commit: str = ""
    author: str = ""
    fingerprint_raw: str = ""

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def confidence(self) -> Confidence:
        return Confidence.POTENTIAL

    @property
    def fingerprint_key(self) -> str:
        """Gitleaks' own `Fingerprint` field (e.g. `path:rule-id:line`) is already stable
        and locally computed by gitleaks itself (not dependent on a login, unlike Semgrep's),
        so it is reused directly rather than recomputed -- falling back to the same
        `(rule_id, path, start_line)` shape every other adapter in this project builds when
        a fingerprint is missing or empty."""
        return self.fingerprint_raw or f"{self.rule_id}|{self.path}|{self.start_line}"


def _finding(raw: Any) -> GitleaksFinding | None:
    if not isinstance(raw, dict):
        return None
    start_line = raw.get("StartLine")
    end_line = raw.get("EndLine")
    # Deliberately never read: "Match", "Secret" -- see the module docstring. "Email" and
    # "Message" (commit message) are also never read: this project's import adapters do not
    # surface git-history personal/free-text metadata beyond author name and commit hash.
    return GitleaksFinding(
        rule_id=str(raw.get("RuleID", ""))[:200],
        description=str(raw.get("Description", ""))[:MAX_TEXT_CHARS],
        path=str(raw.get("File", ""))[:1024],
        start_line=start_line if isinstance(start_line, int) else 0,
        end_line=end_line if isinstance(end_line, int) else 0,
        tags=_string_list(raw.get("Tags"), MAX_TAGS),
        commit=str(raw.get("Commit", ""))[:64],
        author=str(raw.get("Author", ""))[:200],
        fingerprint_raw=str(raw.get("Fingerprint", ""))[:500],
    )


def parse_gitleaks_json(data: bytes) -> list[GitleaksFinding]:
    """Raises `GitleaksReportError` on anything unparseable -- a malformed or unexpected
    report shape must never silently yield "no findings" (indistinguishable from a
    genuinely clean scan). Gitleaks' own top-level report shape is a bare JSON array (`[]`
    when clean, confirmed directly), unlike Semgrep/ZAP's `{"results": [...]}` object."""
    try:
        parsed: Any = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitleaksReportError("Gitleaks output is not valid JSON") from exc
    if not isinstance(parsed, list):
        raise GitleaksReportError("Gitleaks output is not a JSON array")
    return [f for f in (_finding(raw) for raw in parsed) if f is not None]
