"""OWASP ZAP Automation Framework plan generation and the fixed-flag argv used to run it.

This module only builds text and lists; it never writes a file, creates a directory, or
runs anything (see the package docstring). The YAML shape, job types, and report template
below were confirmed directly against a real local ZAP 2.17.0 install run end to end
against a local fixture server (a bounded spider job, a passive-scan-wait job, and a
`traditional-json` report job — "Automation plan succeeded!"), not assumed from
documentation alone.

Only the "Baseline/Passive" profile (roadmap §4.2.A) is built here: bounded discovery plus
passive analysis only. No active-scan job type is ever added to a plan by this module —
active DAST testing stays out of scope for this increment exactly as it does for the
native scanner (TBD-049/050); building an active-scan plan is a separate, later increment
that needs its own explicit authorization/impact-acknowledgement handling (roadmap §4.2.E).
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

MAX_TARGETS = 10
MIN_MINUTES = 1
MAX_MINUTES = 60
DEFAULT_SPIDER_MAX_MINUTES = 2
DEFAULT_PASSIVE_MAX_MINUTES = 2
CONTEXT_NAME = "vapt-context"
REPORT_TEMPLATE = "traditional-json"
REPORT_FILE_STEM = "zap-report"
#: the `traditional-json` template always appends this extension (confirmed directly).
REPORT_FILE_NAME = f"{REPORT_FILE_STEM}.json"

#: the only flags this module will ever place in an argv; anything else is refused. No
#: `-config`/`-port`/`-host` (no API exposed), no `-daemon` (one-shot `-cmd` run only).
_ALLOWED_FLAGS = frozenset({"-cmd", "-autorun", "-dir", "-silent"})


class ZapPlanError(ValueError):
    """The plan or argv would be unsafe or invalid; nothing is executed."""


def _include_pattern(target: str) -> str:
    """A regex matching only this target's origin, built with `re.escape` so a crafted
    target can never widen the pattern beyond its own scheme+host+port."""
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ZapPlanError(f"target must be an absolute http(s) URL: {target!r}")
    origin = f"{parts.scheme}://{parts.netloc}"
    return re.escape(origin) + ".*"


def build_baseline_plan(
    targets: list[str],
    report_dir: Path,
    *,
    spider_max_minutes: int = DEFAULT_SPIDER_MAX_MINUTES,
    passive_max_minutes: int = DEFAULT_PASSIVE_MAX_MINUTES,
) -> str:
    """Builds a "Baseline/Passive" Automation Framework plan as YAML text: one bounded
    spider job per target, then one passive-scan-wait job, then one `traditional-json`
    report job. Returns text only -- the caller writes it to disk (through the storage
    layer) and is responsible for `report_dir` already existing."""
    if not targets:
        raise ZapPlanError("at least one target is required")
    if len(targets) > MAX_TARGETS:
        raise ZapPlanError(f"at most {MAX_TARGETS} targets are supported in one plan")
    if not MIN_MINUTES <= spider_max_minutes <= MAX_MINUTES:
        raise ZapPlanError(f"spider_max_minutes must be between {MIN_MINUTES} and {MAX_MINUTES}")
    if not MIN_MINUTES <= passive_max_minutes <= MAX_MINUTES:
        raise ZapPlanError(f"passive_max_minutes must be between {MIN_MINUTES} and {MAX_MINUTES}")
    include_paths = [_include_pattern(t) for t in targets]
    plan: dict[str, object] = {
        "env": {
            "contexts": [
                {"name": CONTEXT_NAME, "urls": list(targets), "includePaths": include_paths}
            ],
            "parameters": {"failOnError": True, "progressToStdout": True},
        },
        "jobs": [
            {
                "type": "spider",
                "parameters": {
                    "context": CONTEXT_NAME,
                    "url": target,
                    "maxDuration": spider_max_minutes,
                },
            }
            for target in targets
        ]
        + [
            {"type": "passiveScan-wait", "parameters": {"maxDuration": passive_max_minutes}},
            {
                "type": "report",
                "parameters": {
                    "template": REPORT_TEMPLATE,
                    "reportDir": str(report_dir).replace("\\", "/"),
                    "reportFile": REPORT_FILE_STEM,
                    "reportTitle": "VAPT Workbench — ZAP Baseline/Passive",
                    "reportDescription": (
                        "Bounded spider plus passive analysis only; no active-scan input "
                        "was sent to the target."
                    ),
                },
            },
        ],
    }
    return yaml.safe_dump(plan, default_flow_style=False, sort_keys=False)


def validate_argv(argv: list[str]) -> None:
    """Defense in depth, in the same style as `app/integrations/nmap.py::validate_argv`,
    even though this module is currently the only caller: `argv[0]` is the `java`
    executable, `argv[1:3]` must be `-jar <path>`, and every flag after that must be on
    the fixed allowlist, with `-cmd`/`-autorun`/`-dir` all required."""
    if len(argv) < 3 or argv[1] != "-jar":
        raise ZapPlanError("argv must start with <java> -jar <jar-path>")
    rest = argv[3:]
    seen: set[str] = set()
    i = 0
    while i < len(rest):
        flag = rest[i]
        if flag not in _ALLOWED_FLAGS:
            raise ZapPlanError(f"unsafe or unrecognized ZAP flag: {flag!r}")
        seen.add(flag)
        if flag in ("-autorun", "-dir"):
            if i + 1 >= len(rest):
                raise ZapPlanError(f"{flag} requires a value")
            i += 2
        else:
            i += 1
    missing = {"-cmd", "-autorun", "-dir"} - seen
    if missing:
        raise ZapPlanError(f"argv is missing required flag(s): {sorted(missing)}")


def baseline_argv(java: str, jar_path: str, plan_path: Path, home_dir: Path) -> list[str]:
    """`java -jar <jar> -cmd -autorun <plan_path> -dir <home_dir> -silent`. `home_dir` must
    be an app-managed scratch directory, never the operator's own ZAP profile (same
    requirement as the self-test, see `app/integrations/zap.py`)."""
    argv = [
        java,
        "-jar",
        jar_path,
        "-cmd",
        "-autorun",
        str(plan_path),
        "-dir",
        str(home_dir),
        "-silent",
    ]
    validate_argv(argv)
    return argv
