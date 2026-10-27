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

**IaC/misconfiguration scanning (security/reliability/scope roadmap Phase 4, TBD-111)**:
confirmed directly against a second real, disposable Trivy 0.76.1 run (`trivy fs <dir>
--scanners vuln,misconfig ...` against a throwaway Terraform file and Dockerfile with known
misconfigurations) that a single `fs` invocation can report both vulnerabilities and
misconfigurations together -- `Vulnerabilities[]` and `Misconfigurations[]` are simply two
different, optional fields on the same per-file `Results[]` entry (`"Class": "lang-pkgs"`
vs. `"Class": "config"`), so `build_scan_argv` gained a `scanners` parameter rather than a
parallel argv builder. Two more things found only by that real run:
1. Enabling `misconfig` triggers a **second, independent** automatic network fetch the
   first time it runs -- a ~235 KiB OPA/rego "checks bundle" from `mirror.gcr.io/aquasec/
   trivy-checks`, entirely separate from the vulnerability database (confirmed directly:
   it lives under `<cache_dir>/policy/`, the vulnerability DB under `<cache_dir>/db/`,
   both inside the same shared cache root). `build_scan_argv` always appends
   `--skip-check-update` whenever `"misconfig"` is requested, mirroring `--skip-db-update`'s
   same "never an implicit multi-step network fetch during a scan" rule; the explicit
   "operator downloads it from Integrations" action is `build_download_checks_argv` below.
2. **A materially different failure mode than the vulnerability database, confirmed
   directly and the reason the download route below checks the cache directory itself
   rather than trusting Trivy's own exit code**: `--skip-db-update` with no cached
   vulnerability database is a hard `FATAL` error (exit 1) -- but `--skip-check-update`
   (or a genuine network failure during the real download, confirmed directly with
   `docker run --network none`) makes Trivy log `ERROR ... Falling back to embedded
   checks` and still **exit 0**, silently scanning with whatever checks are built into the
   binary itself instead of the downloaded bundle. An exit code of 0 from the download
   action therefore does not by itself prove the bundle was actually fetched.

**SBOM/license inventory (security/reliability/scope roadmap Phase 5, TBD-112)**: confirmed
directly against a third real, disposable Trivy 0.76.1 run (`trivy fs <dir> --scanners
vuln,misconfig,license --license-full ...` against a mixed pip/npm/Dockerfile/LICENSE
fixture) that all three scanners combine into one report (`"Class"` values `lang-pkgs`,
`config`, `license-file`), and two more things found only by that real run:
1. **Package inventory (`Packages[]`) is already present on every `lang-pkgs` result
   regardless of which scanners are enabled** -- it is produced by Trivy's own dependency-
   file parsing step, not gated behind `--scanners vuln`. `TrivyPackage`/
   `parse_trivy_packages_json` below extract it unconditionally; no `--format cyclonedx`/
   `spdx-json` export was needed, since the native JSON report already carries name,
   version, PURL and (when detectable) declared license per package.
2. **Per-package license detection is markedly inconsistent across ecosystems, confirmed
   directly, not assumed**: an npm `package-lock.json` with an explicit `"license"` field
   populated `Packages[].Licenses` correctly; a bare `requirements.txt` did not --
   `WARN [pip] Unable to find python 'site-packages' directory. License detection is
   skipped.` -- pip license detection needs an actually-installed environment, which a
   repository scan never has. This gap is disclosed in `RepoScanProfile.LIMITATIONS`,
   never silently presented as "no license found."
3. **The dedicated `license` scanner (`--scanners license --license-full`) is a
   fundamentally different, more reliable mechanism**: it classifies license *text*
   (LICENSE files, source headers) against Google's `licenseclassifier` corpus (confirmed
   directly: the `trivy` binary itself embeds the string `"Permissive, Version 1.0"`,
   that corpus's own category label), returning a `Name` (SPDX id), `Category` (one of
   `forbidden`/`restricted`/`reciprocal`/`notice`/`permissive`/`unencumbered` -- that
   library's real taxonomy, not invented here) and a `Confidence` score (0-1; a truncated,
   non-matching excerpt of a real MIT license confirmed directly to score low/no match,
   while the complete real text scored `Confidence: 1`). Unlike the vulnerability database
   and the misconfiguration checks bundle, this needs **no network fetch at all** --
   confirmed directly with `docker run --network none` against a completely empty cache
   dir -- so no new "operator downloads this from Integrations" action was needed for this
   phase; `--license-full` is simply appended whenever `"license"` is requested.
`TrivyLicenseFinding`/`parse_trivy_license_json` below extract only the `Results[].
Licenses[]` *object* array (`Class: "license-file"`) -- never to be confused with
`Packages[].Licenses`, a plain list of strings at a different nesting level with the same
field name.

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
    scanners: tuple[str, ...] = ("vuln",),
    skip_db_update: bool = True,
    timeout_seconds: int = 300,
) -> list[str]:
    """`trivy fs <repo_path> --scanners <scanners> --format json --output <report_path>
    --cache-dir <cache_dir> --disable-telemetry --no-progress --skip-version-check --timeout
    <n>s`, plus `--skip-db-update` unless the caller explicitly opts into the database's own
    (potentially multi-gigabyte) first-time download, and `--skip-check-update` whenever
    `"misconfig"` is requested (its own, independent checks-bundle fetch -- see the module
    docstring) -- see the module docstring for both. Both `report_path` and `cache_dir` are
    always caller-supplied, never Trivy's own machine-wide default locations
    (`%LOCALAPPDATA%\\trivy`, confirmed directly), so every file this invocation touches
    stays under a path the caller's own storage layer manages. `scanners` defaults to
    exactly `("vuln",)`, never Trivy's own default of `vuln,secret` -- see the module
    docstring; `"misconfig"` and `"license"` are the only other values this project ever
    passes (TBD-111/TBD-112)."""
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise TrivyArgvError(
            f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}"
        )
    argv = [
        executable,
        "fs",
        str(repo_path),
        "--scanners",
        ",".join(scanners),
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
    if "misconfig" in scanners:
        argv.append("--skip-check-update")
    if "license" in scanners:
        # Eagerly scans LICENSE files/source headers, not only already-detected packages'
        # own metadata -- confirmed directly (TBD-112): without this flag, license
        # scanning of loose files produces no results at all.
        argv.append("--license-full")
    return argv


def build_download_checks_argv(executable: str, cache_dir: Path) -> list[str]:
    """`trivy fs . --scanners misconfig --cache-dir <cache_dir> --disable-telemetry
    --no-progress --skip-version-check` -- confirmed directly (TBD-111): scanning any
    directory (even an empty one) with misconfig scanning enabled triggers the checks-
    bundle fetch before any file-type detection happens, so no real IaC files are needed.
    No `--format`/`--output` is set -- the scan's own findings are discarded; only the
    bundle download (a side effect of initializing the misconfig scanner) matters. The
    caller must run this with a safe, harmless `cwd` (an empty diagnostics temp directory,
    never a real project path) since `.` is the scan target. Unlike `build_download_db_argv`,
    **a 0 exit code here does not by itself prove the download succeeded** -- see the module
    docstring's point 2; the caller must verify the cache directory was actually populated."""
    return [
        executable,
        "fs",
        ".",
        "--scanners",
        "misconfig",
        "--cache-dir",
        str(cache_dir),
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
    ]


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


def _parse_results(data: bytes) -> list[Any]:
    """Shared by `parse_trivy_json` and `parse_trivy_misconfig_json`: both read the exact
    same report bytes (a single `trivy fs ... --scanners vuln,misconfig` invocation can
    report both in one `Results[]` array, confirmed directly, TBD-111) and must apply the
    identical malformed-shape checks, never two independently-diverging ones. Raises
    `TrivyReportError` on anything unparseable -- a malformed or unexpected report shape
    must never silently yield "no findings" (indistinguishable from a genuinely clean
    scan). Trivy's own `Results` field may be entirely absent or `null` for a scan that
    found nothing to analyze (confirmed by Trivy's own documented schema) -- that case alone
    is treated as zero results, not an error; any other non-list value is still rejected."""
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
    return results


def parse_trivy_json(data: bytes) -> list[TrivyFinding]:
    findings: list[TrivyFinding] = []
    for result in _parse_results(data):
        findings.extend(_findings_for_result(result))
    return findings


# ---------------------------------------------------------------------- misconfiguration / IaC


@dataclass(frozen=True)
class TrivyMisconfigFinding:
    check_id: str
    title: str
    message: str
    description: str
    resolution: str
    severity_raw: str
    target: str  # the file, e.g. "main.tf", "Dockerfile" -- the Result-level `Target`
    resource: str  # `CauseMetadata.Resource`, e.g. "aws_s3_bucket.bad"; "" if absent
    start_line: int
    end_line: int
    references: list[str] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return SEVERITY_MAP.get(self.severity_raw, Severity.INFORMATIONAL)

    @property
    def confidence(self) -> Confidence:
        # A static policy match against declared infrastructure-as-code, never a verified
        # live state -- the same conservative cap every other adapter in this project uses.
        return Confidence.PROBABLE

    @property
    def fingerprint_key(self) -> str:
        """Trivy gives misconfigurations no `Fingerprint` field of its own (unlike
        vulnerability findings) -- confirmed directly, TBD-111. Built locally from the
        check ID, file, resource and line, mirroring `TrivyFinding.fingerprint_key`'s own
        fallback shape for when a tool has no stable fingerprint to reuse."""
        return f"{self.check_id}|{self.target}|{self.resource}|{self.start_line}"


def _misconfig_findings_for_result(result: Any) -> list[TrivyMisconfigFinding]:
    if not isinstance(result, dict):
        return []
    target = str(result.get("Target", ""))[:1024]
    items = result.get("Misconfigurations")
    if not isinstance(items, list):
        return []
    out: list[TrivyMisconfigFinding] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue
        cause = raw.get("CauseMetadata")
        cause = cause if isinstance(cause, dict) else {}
        start_line = cause.get("StartLine")
        end_line = cause.get("EndLine")
        out.append(
            TrivyMisconfigFinding(
                check_id=str(raw.get("ID", ""))[:200],
                title=str(raw.get("Title", ""))[:MAX_TEXT_CHARS],
                message=str(raw.get("Message", ""))[:MAX_TEXT_CHARS],
                description=str(raw.get("Description", ""))[:MAX_TEXT_CHARS],
                resolution=str(raw.get("Resolution", ""))[:MAX_TEXT_CHARS],
                severity_raw=str(raw.get("Severity", "")),
                target=target,
                resource=str(cause.get("Resource", ""))[:300],
                start_line=start_line if isinstance(start_line, int) else 0,
                end_line=end_line if isinstance(end_line, int) else 0,
                references=_string_list(raw.get("References"), MAX_REFERENCES),
            )
        )
    return out


def parse_trivy_misconfig_json(data: bytes) -> list[TrivyMisconfigFinding]:
    findings: list[TrivyMisconfigFinding] = []
    for result in _parse_results(data):
        findings.extend(_misconfig_findings_for_result(result))
    return findings


# ---------------------------------------------------------------------- SBOM / license (TBD-112)

MAX_PACKAGES = 20_000
MAX_LICENSE_FINDINGS = 5_000

#: Google `licenseclassifier`'s own category taxonomy (confirmed directly, TBD-112 -- the
#: `trivy` binary embeds this library's category labels; not invented here). Only these two
#: ever become a canonical Finding; the rest (`reciprocal`/`notice`/`permissive`/
#: `unencumbered`) are recorded in `licenses.json` as inventory only -- see the module
#: docstring and `RepoScanProfile.LIMITATIONS`.
LICENSE_ACTIONABLE_CATEGORIES: dict[str, Severity] = {
    "forbidden": Severity.HIGH,
    "restricted": Severity.MEDIUM,
}


@dataclass(frozen=True)
class TrivyPackage:
    name: str
    version: str
    ecosystem: str  # the Result-level `Type`, e.g. "pip", "npm", "apk"
    target: str  # the Result-level `Target` (file/path this package was found in)
    purl: str = ""
    licenses: list[str] = field(default_factory=list)  # as declared by the package itself;
    # absent entirely for some ecosystems without an installed environment -- see the
    # module docstring's point 2. Never a substitute for `TrivyLicenseFinding`'s own
    # classifier-confirmed license-file matches.


def _packages_for_result(result: Any) -> list[TrivyPackage]:
    if not isinstance(result, dict):
        return []
    target = str(result.get("Target", ""))[:1024]
    ecosystem = str(result.get("Type", ""))[:100]
    items = result.get("Packages")
    if not isinstance(items, list):
        return []
    out: list[TrivyPackage] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue
        identifier = raw.get("Identifier")
        purl = identifier.get("PURL") if isinstance(identifier, dict) else None
        out.append(
            TrivyPackage(
                name=str(raw.get("Name", ""))[:500],
                version=str(raw.get("Version", ""))[:200],
                ecosystem=ecosystem,
                target=target,
                purl=str(purl)[:500] if purl else "",
                licenses=_string_list(raw.get("Licenses"), MAX_REFERENCES),
            )
        )
    return out[:MAX_PACKAGES]


def parse_trivy_packages_json(data: bytes) -> list[TrivyPackage]:
    """Package inventory (the SBOM) -- present on every `lang-pkgs`-class result regardless
    of which scanners were enabled (confirmed directly, TBD-112); not gated behind
    `scanners=("license",)` the way `parse_trivy_license_json` below is."""
    packages: list[TrivyPackage] = []
    for result in _parse_results(data):
        packages.extend(_packages_for_result(result))
        if len(packages) >= MAX_PACKAGES:
            break
    return packages[:MAX_PACKAGES]


@dataclass(frozen=True)
class TrivyLicenseFinding:
    name: str  # SPDX id, e.g. "MIT", "GPL-3.0"
    category: str  # licenseclassifier's own category -- see LICENSE_ACTIONABLE_CATEGORIES
    confidence: float  # 0-1, the classifier's own match confidence
    file_path: str
    pkg_name: str  # "" for a loose LICENSE file not tied to a specific package
    link: str = ""

    @property
    def severity(self) -> Severity:
        return LICENSE_ACTIONABLE_CATEGORIES.get(self.category, Severity.INFORMATIONAL)

    @property
    def is_actionable(self) -> bool:
        """Only `forbidden`/`restricted` categories ever become a canonical Finding -- see
        the module docstring. Every match, actionable or not, is still recorded in full in
        `licenses.json` for transparency."""
        return self.category in LICENSE_ACTIONABLE_CATEGORIES

    @property
    def confidence_level(self) -> Confidence:
        # A classifier's text match, never a verified legal determination -- the same
        # conservative cap every other adapter in this project uses for a non-exploitation-
        # confirmed signal.
        return Confidence.PROBABLE

    @property
    def fingerprint_key(self) -> str:
        return f"{self.name}|{self.file_path}|{self.pkg_name}"


def _license_findings_for_result(result: Any) -> list[TrivyLicenseFinding]:
    if not isinstance(result, dict) or result.get("Class") != "license-file":
        return []
    items = result.get("Licenses")
    if not isinstance(items, list):
        return []
    out: list[TrivyLicenseFinding] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue
        confidence = raw.get("Confidence")
        out.append(
            TrivyLicenseFinding(
                name=str(raw.get("Name", ""))[:200],
                category=str(raw.get("Category", "")),
                confidence=float(confidence) if isinstance(confidence, (int, float)) else 0.0,
                file_path=str(raw.get("FilePath", ""))[:1024],
                pkg_name=str(raw.get("PkgName", ""))[:500],
                link=str(raw.get("Link", ""))[:500],
            )
        )
    return out


def parse_trivy_license_json(data: bytes) -> list[TrivyLicenseFinding]:
    """Only the `Class: "license-file"` object-shaped `Licenses[]` array -- never
    `Packages[].Licenses`, a plain list of strings at a different nesting level with the
    same field name (see the module docstring)."""
    findings: list[TrivyLicenseFinding] = []
    for result in _parse_results(data):
        findings.extend(_license_findings_for_result(result))
        if len(findings) >= MAX_LICENSE_FINDINGS:
            break
    return findings[:MAX_LICENSE_FINDINGS]
