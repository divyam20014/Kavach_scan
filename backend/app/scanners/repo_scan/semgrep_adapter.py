"""Semgrep Community Edition adapter: argv construction/validation and JSON-report parsing
only (roadmap Phase 2 increment 1, TBD-084). Pure logic -- no file I/O, no process
execution (see the package docstring).

The output schema below was confirmed directly against a real local Semgrep 1.182.1 run
(`semgrep scan --config p/security-audit --json --metrics=off <dir>` against a throwaway
two-line Python file with an obvious shell-invoking `subprocess.call()` call and a bare
`eval()`), not assumed from documentation alone. Two things found during that real run
that are not obvious from documentation:

1. Semgrep Community Edition's JSON output always reports `"fingerprint": "requires login"`
   and `"lines": "requires login"` for every finding -- both fields require a
   `semgrep login` (semgrep.dev account) to be populated, even in fully local, offline
   scans. This adapter therefore never reads either field: a stable fingerprint is built
   from `(check_id, path, start_line)` instead (the same kind of locally-computed
   fingerprint every import adapter in this project already builds for an external tool
   that does not supply one of its own), and matched source lines are not surfaced here at
   all in this increment -- see TBD-084 for what that means it cannot do yet.
2. `extra.severity` is one of `"ERROR"`, `"WARNING"`, `"INFO"` (confirmed directly; no
   `"CRITICAL"` value was observed from the Community Edition `p/security-audit` ruleset).
   `extra.metadata.confidence` is one of `"HIGH"`, `"MEDIUM"`, `"LOW"`. Mapped conservatively
   below: Semgrep's own "HIGH" confidence is still only `Confidence.PROBABLE`, never
   `CONFIRMED` -- a static pattern match is not a verified exploit, the same posture this
   project's own passive rules and the ZAP adapter already take.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.common import Confidence, Severity

MAX_TEXT_CHARS = 4000
MAX_REFERENCES = 20
MAX_CWE_IDS = 20
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 3600
MIN_MAX_TARGET_BYTES = 1024
MAX_MAX_TARGET_BYTES = 50 * 1024 * 1024

#: A fixed, documented allowlist of rulesets -- never an arbitrary path or URL. Semgrep's
#: `--config` can fetch a ruleset by name from its registry or load an arbitrary local/
#: remote ruleset file; restricting to these named registry rulesets means a scan can never
#: be pointed at an attacker- or operator-supplied ruleset path, matching the project's
#: "never run an arbitrary/attacker-influenced command" posture for every other adapter.
ALLOWED_CONFIGS: tuple[str, ...] = (
    "auto",
    "p/security-audit",
    "p/owasp-top-ten",
    "p/secrets",
    "p/python",
    "p/javascript",
    "p/default",
)

#: ZAP's own riskcode-style mapping, but for Semgrep's severity string.
SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}
CONFIDENCE_MAP: dict[str, Confidence] = {
    "HIGH": Confidence.PROBABLE,
    "MEDIUM": Confidence.POTENTIAL,
    "LOW": Confidence.POTENTIAL,
}


class SemgrepArgvError(ValueError):
    """The argv would be unsafe or invalid; nothing is executed."""


class SemgrepReportError(ValueError):
    """The report could not be interpreted; no finding may be claimed from it."""


def build_scan_argv(
    executable: str,
    repo_path: Path,
    *,
    config: str = "p/security-audit",
    timeout_seconds: int = 300,
    max_target_bytes: int = 5_000_000,
) -> list[str]:
    """`semgrep scan --config <allowlisted> --json --metrics=off --timeout <n>
    --max-target-bytes <n> <repo_path>`. Metrics are always off: this project never sends
    telemetry about what it scanned anywhere. No `--autofix`/`--sarif-output` writing to an
    operator-uncontrolled path, no `--oss-only` ambiguity -- JSON to stdout only, read back
    by the caller through the storage layer."""
    if config not in ALLOWED_CONFIGS:
        raise SemgrepArgvError(f"config must be one of {ALLOWED_CONFIGS}, got {config!r}")
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise SemgrepArgvError(
            f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}"
        )
    if not MIN_MAX_TARGET_BYTES <= max_target_bytes <= MAX_MAX_TARGET_BYTES:
        raise SemgrepArgvError(
            f"max_target_bytes must be between {MIN_MAX_TARGET_BYTES} and {MAX_MAX_TARGET_BYTES}"
        )
    return [
        executable,
        "scan",
        "--config",
        config,
        "--json",
        "--metrics=off",
        "--timeout",
        str(timeout_seconds),
        "--max-target-bytes",
        str(max_target_bytes),
        str(repo_path),
    ]


def _cwe_ids(raw: object) -> list[int]:
    """Semgrep's own `cwe` metadata is a list of strings like
    "CWE-78: Improper Neutralization of Special Elements..." -- confirmed directly."""
    out: list[int] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        text = str(item)
        if not text.startswith("CWE-"):
            continue
        digits = text[4:].split(":", 1)[0].strip()
        if digits.isdigit():
            out.append(int(digits))
    return out[:MAX_CWE_IDS]


def _string_list(raw: object, limit: int) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item)[:500] for item in raw][:limit]


@dataclass(frozen=True)
class SemgrepFinding:
    check_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity_raw: str
    confidence_raw: str
    cwe_ids: list[int] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source_url: str = ""

    @property
    def severity(self) -> Severity:
        return SEVERITY_MAP.get(self.severity_raw, Severity.INFORMATIONAL)

    @property
    def confidence(self) -> Confidence:
        return CONFIDENCE_MAP.get(self.confidence_raw, Confidence.NEEDS_REVIEW)

    @property
    def fingerprint_key(self) -> str:
        """Semgrep's own `fingerprint` field requires `semgrep login` to be populated
        (confirmed directly: it is the literal string "requires login" otherwise) -- a
        locally-computed key is used instead, the same approach every import adapter in
        this project already takes for a tool that supplies no fingerprint of its own."""
        return f"{self.check_id}|{self.path}|{self.start_line}"


def _finding(raw: Any) -> SemgrepFinding | None:
    if not isinstance(raw, dict):
        return None
    extra_raw = raw.get("extra")
    extra: dict[str, Any] = extra_raw if isinstance(extra_raw, dict) else {}
    metadata_raw = extra.get("metadata")
    metadata: dict[str, Any] = metadata_raw if isinstance(metadata_raw, dict) else {}
    start_raw = raw.get("start")
    start: dict[str, Any] = start_raw if isinstance(start_raw, dict) else {}
    end_raw = raw.get("end")
    end: dict[str, Any] = end_raw if isinstance(end_raw, dict) else {}
    start_line = start.get("line")
    end_line = end.get("line")
    return SemgrepFinding(
        check_id=str(raw.get("check_id", ""))[:200],
        path=str(raw.get("path", ""))[:1024],
        start_line=start_line if isinstance(start_line, int) else 0,
        end_line=end_line if isinstance(end_line, int) else 0,
        message=str(extra.get("message", ""))[:MAX_TEXT_CHARS],
        severity_raw=str(extra.get("severity", "")),
        confidence_raw=str(metadata.get("confidence", "")),
        cwe_ids=_cwe_ids(metadata.get("cwe")),
        owasp=_string_list(metadata.get("owasp"), 10),
        references=_string_list(metadata.get("references"), MAX_REFERENCES),
        source_url=str(metadata.get("source", ""))[:500],
    )


def parse_semgrep_json(data: bytes) -> list[SemgrepFinding]:
    """Raises `SemgrepReportError` on anything unparseable -- a malformed or unexpected
    report shape must never silently yield "no findings" (indistinguishable from a
    genuinely clean scan)."""
    try:
        parsed: Any = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SemgrepReportError("Semgrep output is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise SemgrepReportError("Semgrep output is not a JSON object")
    results = parsed.get("results")
    if not isinstance(results, list):
        raise SemgrepReportError("Semgrep output has no 'results' list")
    return [f for f in (_finding(raw) for raw in results) if f is not None]


def report_errors(data: bytes) -> list[str]:
    """Semgrep's own `errors` list (e.g. a file that failed to parse) -- surfaced
    separately from findings so a partial scan is never silently reported as fully clean."""
    try:
        parsed: Any = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(parsed, dict):
        return []
    errors = parsed.get("errors")
    if not isinstance(errors, list):
        return []
    return [str(e)[:500] for e in errors][:100]
