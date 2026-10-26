"""Trivy adapter: argv construction/validation and JSON-report parsing only (roadmap
Phase 2 increment 3, TBD-086). Pure logic -- no file I/O, no process execution (see the
package docstring).

The output schema below was confirmed directly against a real local Trivy 0.76.1 run (the
official Windows x64 release binary, downloaded into a disposable scratchpad directory and
deleted afterward -- never installed into this project) -- `trivy fs <path> --scanners vuln
--format json --output <file> --cache-dir <dir> --disable-telemetry` against a throwaway
`requirements.txt` pinning a deliberately old, vulnerable Django version, not assumed from
documentation alone. Two things found only by that real run, not documentation:

1. **A safety-relevant discovery more significant than any prior adapter's**: on its very
   first invocation with a fresh `--cache-dir`, Trivy silently downloaded a **~1.6 GB**
   vulnerability database from the network (`ghcr.io`/`mirror.gcr.io`) before scanning --
   confirmed directly by inspecting the cache directory's size afterward. This is a
   materially larger and more consequential automatic network operation than Semgrep's
   small ruleset-registry fetch or Gitleaks' fully offline operation (no network use at
   all). `build_scan_argv` therefore makes `skip_db_update` a caller-supplied parameter
   that **defaults to `True`** (i.e. `--skip-db-update` is appended by default) -- the
   safest default is to never trigger a multi-gigabyte automatic download unless a caller
   explicitly opts in (`skip_db_update=False`). The actual "operator must explicitly
   consent to the first download" UX (mirroring this project's existing CVE-catalog-import
   affordance, TBD-023) is built in TBD-087 as a dedicated Integrations-page action, never
   triggered implicitly by a scan -- `build_download_db_argv` below is that action's own
   argv, independently verified against a second real, disposable Trivy run.
2. Trivy's own default `--scanners` value is `vuln,secret` -- it has a built-in secret
   scanner that would materially overlap with the dedicated Gitleaks adapter (TBD-085).
   `build_scan_argv` always passes `--scanners vuln` explicitly, never the tool's own
   default, to keep this adapter's scope to dependency/supply-chain vulnerabilities only
   and avoid two engines silently producing overlapping/duplicate secret findings.

Trivy's own JSON report has no need for a redaction flag the way Gitleaks did: a
vulnerability finding never embeds source secret material, only package name/version and
public vulnerability-database metadata (CVE/GHSA IDs, CVSS scores, public reference URLs).
Trivy's own `Severity` field is one of `UNKNOWN`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`
(`LOW`/`MEDIUM`/`HIGH`/`CRITICAL` all confirmed directly against the real sample;
`UNKNOWN` is documented but was not observed) -- mapped directly to this project's own
`Severity` enum of the same names, with `Confidence` always capped at `PROBABLE`, never
`CONFIRMED`: a version-based vulnerability-database match is a well-sourced fact about
what package/version is present, not proof the vulnerable code path is reachable or was
ever exploited -- the same conservative posture already taken by the Semgrep, ZAP, and
Gitleaks adapters.
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

SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFORMATIONAL,
}


class TrivyArgvError(ValueError):
    """The argv would be unsafe or invalid; nothing is executed."""


class TrivyReportError(ValueError):
    """The report could not be interpreted; no finding may be claimed from it."""


def build_scan_argv(
    executable: str,
    repo_path: Path,
    report_path: Path,
    cache_dir: Path,
    *,
    skip_db_update: bool = True,
    timeout_seconds: int = 300,
) -> list[str]:
    """`trivy fs <repo_path> --scanners vuln --format json --output <report_path>
    --cache-dir <cache_dir> --disable-telemetry --no-progress --skip-version-check --timeout
    <n>s`, plus `--skip-db-update` unless the caller explicitly opts into the database's own
    (potentially multi-gigabyte) first-time download -- see the module docstring. Both
    `report_path` and `cache_dir` are always caller-supplied, never Trivy's own
    machine-wide default locations (`%LOCALAPPDATA%\\trivy`, confirmed directly), so every
    file this invocation touches stays under a path the caller's own storage layer manages.
    `--scanners` is always exactly `vuln`, never Trivy's own default of `vuln,secret` -- see
    the module docstring."""
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise TrivyArgvError(
            f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}"
        )
    argv = [
        executable,
        "fs",
        str(repo_path),
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--output",
        str(report_path),
        "--cache-dir",
        str(cache_dir),
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
        "--timeout",
        f"{timeout_seconds}s",
    ]
    if skip_db_update:
        argv.append("--skip-db-update")
    return argv


def build_download_db_argv(executable: str, cache_dir: Path) -> list[str]:
    """`trivy fs . --download-db-only --cache-dir <cache_dir> --disable-telemetry
    --no-progress --skip-version-check` -- confirmed directly against a second real,
    disposable Trivy 0.76.1 run (TBD-087): this downloads/updates the database only, runs
    no scan of any path, and exits 0 once complete. The positional path argument is
    required by the `fs` subcommand's own usage even though `--download-db-only` means it
    is never read -- `"."` is passed and nothing under it is touched."""
    return [
        executable,
        "fs",
        ".",
        "--download-db-only",
        "--cache-dir",
        str(cache_dir),
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
    ]


def _cwe_ids(raw: object) -> list[int]:
    """Trivy's own `CweIDs` metadata is a list of bare strings like "CWE-89" -- confirmed
    directly (no description suffix, unlike Semgrep's own `cwe` metadata)."""
    out: list[int] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        text = str(item)
        if not text.startswith("CWE-"):
            continue
        digits = text[4:].strip()
        if digits.isdigit():
            out.append(int(digits))
    return out[:MAX_CWE_IDS]


def _string_list(raw: object, limit: int) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item)[:500] for item in raw][:limit]


@dataclass(frozen=True)
class TrivyFinding:
    vulnerability_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    target: str
    title: str
    severity_raw: str
    status: str
    cwe_ids: list[int] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    fingerprint_raw: str = ""

    @property
    def severity(self) -> Severity:
        return SEVERITY_MAP.get(self.severity_raw, Severity.INFORMATIONAL)

    @property
    def confidence(self) -> Confidence:
        return Confidence.PROBABLE

    @property
    def fingerprint_key(self) -> str:
        """Trivy's own `Fingerprint` field (confirmed directly: a stable `sha256:...` hash)
        is reused when present, falling back to the same locally-built
        `(vulnerability_id, pkg_name, target)` shape every other adapter in this project
        builds when a tool's own fingerprint is missing."""
        return self.fingerprint_raw or f"{self.vulnerability_id}|{self.pkg_name}|{self.target}"


def _findings_for_result(result: Any) -> list[TrivyFinding]:
    if not isinstance(result, dict):
        return []
    target = str(result.get("Target", ""))[:1024]
    vulns = result.get("Vulnerabilities")
    if not isinstance(vulns, list):
        return []
    out: list[TrivyFinding] = []
    for raw in vulns:
        if not isinstance(raw, dict):
            continue
        out.append(
            TrivyFinding(
                vulnerability_id=str(raw.get("VulnerabilityID", ""))[:200],
                pkg_name=str(raw.get("PkgName", ""))[:500],
                installed_version=str(raw.get("InstalledVersion", ""))[:200],
                fixed_version=str(raw.get("FixedVersion", ""))[:500],
                target=target,
                title=str(raw.get("Title", ""))[:MAX_TEXT_CHARS],
                severity_raw=str(raw.get("Severity", "")),
                status=str(raw.get("Status", ""))[:100],
                cwe_ids=_cwe_ids(raw.get("CweIDs")),
                references=_string_list(raw.get("References"), MAX_REFERENCES),
                fingerprint_raw=str(raw.get("Fingerprint", ""))[:500],
            )
        )
    return out


def parse_trivy_json(data: bytes) -> list[TrivyFinding]:
    """Raises `TrivyReportError` on anything unparseable -- a malformed or unexpected report
    shape must never silently yield "no findings" (indistinguishable from a genuinely clean
    scan). Trivy's own `Results` field may be entirely absent or `null` for a scan that
    found nothing to analyze (confirmed by Trivy's own documented schema) -- that case alone
    is treated as zero findings, not an error; any other non-list value is still rejected."""
    try:
        parsed: Any = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrivyReportError("Trivy output is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise TrivyReportError("Trivy output is not a JSON object")
    results = parsed.get("Results")
    if results is None:
        return []
    if not isinstance(results, list):
        raise TrivyReportError("Trivy output has a non-list 'Results' field")
    findings: list[TrivyFinding] = []
    for result in results:
        findings.extend(_findings_for_result(result))
    return findings
