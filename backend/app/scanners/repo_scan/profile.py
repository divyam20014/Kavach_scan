"""Repository scan profile: which engines run, with which bounded per-engine options,
derived from the start request's parameters (roadmap Phase 2, TBD-087). Mirrors
`app/scanners/webapp/profile.py`'s own parameter-parsing shape.

One module, three engines -- not three modules -- the same "one module bundles many
internal checks" shape `web_app` already has for its own rule groups (TBD-086's own design
note). `engines` is a list, not a scalar, which `ScanJob.parameters`' own `ParamValue`
type (`app/models/scan.py`) already permits.

`docker_engines` (Docker-based execution roadmap, phase 4 of 5, TBD-093) selects which of
the *selected* `engines` run via a pulled Docker image instead of a native install --
per-engine, confirmed by the operator (TBD-090): an operator can run Semgrep natively and
Gitleaks via Docker in the same scan. Defaults to empty (every engine runs natively,
unchanged from before this parameter existed) -- Docker is strictly additive, never a
silent default, matching the same operator-confirmed design.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from app.models.common import StrictModel
from app.models.project import ScanPolicy
from app.scanners.repo_scan.semgrep_adapter import ALLOWED_CONFIGS as SEMGREP_CONFIGS

PROFILE_VERSION = 1
Engine = Literal["semgrep", "gitleaks", "trivy"]
ENGINES: tuple[Engine, ...] = ("semgrep", "gitleaks", "trivy")
DEFAULT_ENGINES: list[Engine] = ["semgrep"]

MIN_TIMEOUT_MINUTES = 1
MAX_TIMEOUT_MINUTES = 60

# parameter name -> (type, default, description). Unknown names are rejected at submit.
PARAMETERS: dict[str, tuple[type, Any, str]] = {
    "engines": (list, DEFAULT_ENGINES, "Which engines to run: semgrep, gitleaks, trivy"),
    "docker_engines": (
        list,
        [],
        "Which of the selected engines run via a pulled Docker image instead of a "
        "native install (subset of `engines`; default: none, all native)",
    ),
    "semgrep_config": (str, "p/security-audit", f"Semgrep ruleset, one of {SEMGREP_CONFIGS}"),
    "semgrep_timeout_minutes": (int, 5, "Bounded Semgrep scan duration, minutes"),
    "gitleaks_timeout_minutes": (int, 5, "Bounded Gitleaks scan duration, minutes"),
    "trivy_timeout_minutes": (int, 5, "Bounded Trivy scan duration, minutes"),
}

LIMITATIONS = [
    "Static analysis only: Semgrep's pattern matches and Gitleaks' secret-pattern matches "
    "are never confirmed as exploitable or live; confidence is never reported higher than "
    "'probable'.",
    "Trivy's vulnerability matches are based on package name/version against its own "
    "database; a match proves a vulnerable version is present, not that the vulnerable "
    "code path is reachable or was ever exploited.",
    "Gitleaks' own matched secret text is never stored or displayed by this application, "
    "even in redacted form -- only the rule, file and line are recorded.",
    "Trivy's vulnerability database is downloaded once, explicitly, from the Integrations "
    "page -- never automatically by a scan -- and may be out of date if not refreshed.",
]


class RepoScanProfile(StrictModel):
    profile_version: int = PROFILE_VERSION
    engines: list[Engine] = Field(default_factory=lambda: list(DEFAULT_ENGINES))
    docker_engines: list[Engine] = Field(default_factory=list)
    semgrep_config: str = "p/security-audit"
    semgrep_timeout_minutes: int = 5
    gitleaks_timeout_minutes: int = 5
    trivy_timeout_minutes: int = 5
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))


def validate_parameters(params: dict[str, Any], policy: ScanPolicy) -> list[str]:
    """Return human-readable problems; empty means the parameters are acceptable. Tool
    *availability* (is the engine installed? has Trivy's database been downloaded?) is
    checked separately by `RepoScanRunner.validate_parameters`, not here -- this function
    only checks the shape of the parameters themselves."""
    errors: list[str] = []
    for name, value in params.items():
        if name not in PARAMETERS:
            errors.append(f"unknown parameter {name!r} for the repository scanner")
            continue
        kind = PARAMETERS[name][0]
        if value is None:
            continue
        if kind is int and (isinstance(value, bool) or not isinstance(value, int)):
            errors.append(f"{name} must be an integer")
        elif kind is str and not isinstance(value, str):
            errors.append(f"{name} must be text")
        elif kind is list and not isinstance(value, list):
            errors.append(f"{name} must be a list")
    engines = params.get("engines")
    if isinstance(engines, list):
        if not engines:
            errors.append("engines must select at least one engine")
        if len(engines) > len(ENGINES):
            errors.append(f"engines must list at most {len(ENGINES)} entries")
        for e in engines:
            if e not in ENGINES:
                errors.append(f"engines must be a subset of {ENGINES}, got {e!r}")
        if len(set(engines)) != len(engines):
            errors.append("engines must not repeat an entry")
    docker_engines = params.get("docker_engines")
    if isinstance(docker_engines, list):
        for e in docker_engines:
            if e not in ENGINES:
                errors.append(f"docker_engines must be a subset of {ENGINES}, got {e!r}")
        if len(set(docker_engines)) != len(docker_engines):
            errors.append("docker_engines must not repeat an entry")
        effective_engines = engines if isinstance(engines, list) and engines else DEFAULT_ENGINES
        if any(e not in effective_engines for e in docker_engines):
            errors.append("docker_engines must be a subset of the selected engines")
    config = params.get("semgrep_config")
    if isinstance(config, str) and config not in SEMGREP_CONFIGS:
        errors.append(f"semgrep_config must be one of {SEMGREP_CONFIGS}, got {config!r}")
    for minutes_param in (
        "semgrep_timeout_minutes",
        "gitleaks_timeout_minutes",
        "trivy_timeout_minutes",
    ):
        minutes = params.get(minutes_param)
        if (
            isinstance(minutes, int)
            and not isinstance(minutes, bool)
            and not MIN_TIMEOUT_MINUTES <= minutes <= MAX_TIMEOUT_MINUTES
        ):
            errors.append(
                f"{minutes_param} must be between {MIN_TIMEOUT_MINUTES} and {MAX_TIMEOUT_MINUTES}"
            )
    return errors


def build_profile(params: dict[str, Any]) -> RepoScanProfile:
    engines_raw = params.get("engines")
    engines: list[Engine] = (
        [e for e in engines_raw if e in ENGINES]
        if isinstance(engines_raw, list) and engines_raw
        else list(DEFAULT_ENGINES)
    )
    if not engines:
        engines = list(DEFAULT_ENGINES)
    docker_engines_raw = params.get("docker_engines")
    docker_engines: list[Engine] = (
        [e for e in docker_engines_raw if e in engines]
        if isinstance(docker_engines_raw, list)
        else []
    )
    config = params.get("semgrep_config")
    semgrep_timeout = params.get("semgrep_timeout_minutes")
    gitleaks_timeout = params.get("gitleaks_timeout_minutes")
    trivy_timeout = params.get("trivy_timeout_minutes")
    return RepoScanProfile(
        engines=engines,
        docker_engines=docker_engines,
        semgrep_config=config
        if isinstance(config, str) and config in SEMGREP_CONFIGS
        else ("p/security-audit"),
        semgrep_timeout_minutes=(int(semgrep_timeout) if isinstance(semgrep_timeout, int) else 5),
        gitleaks_timeout_minutes=(
            int(gitleaks_timeout) if isinstance(gitleaks_timeout, int) else 5
        ),
        trivy_timeout_minutes=(int(trivy_timeout) if isinstance(trivy_timeout, int) else 5),
    )
