"""Container image scan job runner (module `container_image`, security/reliability/scope
roadmap Phase 3, TBD-110).

Safety properties:
- the subprocess call goes through `ctx.run_process` (the same cancellation/timeout/
  deadline-aware wrapper every other runner in this project uses);
- Trivy's vulnerability database is read from the shared, app-managed cache directory
  (`ctx.repo.trivy_db_dir()`) and never downloaded by this runner -- identical to
  `app/scanners/repo_scan/runner.py`'s own Trivy usage;
- the image must already be present on the local Docker daemon -- `--image-src docker`
  (`trivy_argv.py`) never falls back to a remote registry pull; see that module's own
  docstring for what was independently confirmed and what was deliberately deferred
  (Docker-mode execution, registry-pull support);
- `targets` carries no real meaning for this module (the real "target" is the operator-
  supplied `image` parameter, not a URL) -- `check_targets` accepts a single placeholder,
  the same pattern `app/scanners/repo_scan/runner.py` and `app/scanners/apisec/runner.py`
  already use for their own non-URL target shapes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.core.redaction import redact
from app.jobs.context import JobContext, RunResult
from app.models.project import ScanPolicy
from app.scanners.container_image.findings import ContainerImageFindingWriter
from app.scanners.container_image.profile import build_profile, validate_parameters
from app.scanners.container_image.trivy_argv import TrivyArgvError, build_image_scan_argv
from app.scanners.repo_scan.trivy_adapter import TrivyReportError, parse_trivy_json
from app.scope.engine import ScopePolicy

MAX_PROCESS_OUTPUT_BYTES = 16 * 1024 * 1024
OUTPUT_MAX_ITEMS = 2000


def _json(data: Any) -> bytes:
    safe = redact(json.loads(json.dumps(data, default=str)), max_items=OUTPUT_MAX_ITEMS)
    return json.dumps(safe, indent=2, ensure_ascii=False).encode("utf-8")


@dataclass
class ContainerImageRunner:
    name: str = "container_image"
    trivy_availability: Callable[[], str] = field(default=lambda: "")
    trivy_db_ready: Callable[[], bool] = field(default=lambda: False)

    def check_targets(
        self, targets: list[str], policy: ScopePolicy
    ) -> tuple[list[str], list[tuple[int, str]]]:
        # Container image scans do not take URL targets; the real target is the operator's
        # own `image` parameter (see module docstring).
        return (list(targets) or ["container-image-scan"]), []

    def validate_parameters(self, params: dict[str, Any], policy: ScanPolicy) -> list[str]:
        errors = validate_parameters(params, policy)
        if errors:
            return errors
        if not self.trivy_availability():
            errors.append("trivy is not available (not installed or not configured)")
        if not self.trivy_db_ready():
            errors.append(
                "Trivy's vulnerability database has not been downloaded yet -- download it "
                "from the Integrations page first"
            )
        return errors

    # ------------------------------------------------------------------ run

    def run(self, ctx: JobContext) -> RunResult:
        profile = build_profile(dict(ctx.scan.parameters))
        ctx.write_output("profile.json", _json(profile.model_dump(mode="json")))
        ctx.emit("profile", f"container image scan profile: image={profile.image}")

        if not self.trivy_db_ready():
            ctx.error(
                "Trivy's vulnerability database has not been downloaded -- download it from "
                "the Integrations page first"
            )
            return RunResult(failed=True, errors=["trivy database not downloaded"])
        executable = self.trivy_availability()
        if not executable:
            ctx.error("trivy is not available (not installed or not configured)")
            return RunResult(failed=True, errors=["trivy not available"])

        ctx.stage("trivy scan", 10)
        timeout_seconds = profile.timeout_minutes * 60
        report_dir = ctx.repo.scan_work_subdir(ctx.project_id, ctx.scan_id, "trivy_report")
        report_path = report_dir / "report.json"
        try:
            argv = build_image_scan_argv(
                executable,
                profile.image,
                report_path,
                ctx.repo.trivy_db_dir(),
                timeout_seconds=timeout_seconds,
            )
        except TrivyArgvError as exc:
            ctx.error(f"could not build the trivy command: {exc}")
            return RunResult(failed=True, errors=[str(exc)[:500]])
        result = ctx.run_process(
            argv,
            allowed_executables=[executable],
            timeout=timeout_seconds + 30,
            max_output_bytes=MAX_PROCESS_OUTPUT_BYTES,
        )
        ctx.checkpoint()
        if result.timed_out:
            ctx.error(f"trivy did not finish within {timeout_seconds}s")
            return RunResult(failed=True, errors=["trivy timed out"])
        if result.exit_code != 0:
            # Deliberately no stderr text in the error here -- same convention as every
            # other adapter's `_run_*` in this project (repo_scan's own semgrep/gitleaks/
            # trivy, the web scanner's ZAP engine). The most likely real-world cause (the
            # image is not present on the local Docker daemon) is addressed in the
            # LIMITATIONS text instead of being special-cased into the error message.
            ctx.error(f"trivy exited with status {result.exit_code}")
            return RunResult(failed=True, errors=[f"trivy exited with status {result.exit_code}"])

        ctx.stage("findings", 90)
        report_bytes = ctx.repo.read_scan_work_file(
            ctx.project_id,
            ctx.scan_id,
            "trivy_report",
            "report.json",
            max_bytes=MAX_PROCESS_OUTPUT_BYTES,
        )
        try:
            findings = parse_trivy_json(report_bytes)
        except TrivyReportError as exc:
            ctx.error(f"could not interpret the trivy report: {exc}")
            return RunResult(failed=True, errors=["could not interpret the trivy report"])

        writer = ContainerImageFindingWriter(ctx.repo, ctx.project_id, ctx.scan_id)
        for f in findings:
            writer.write_trivy(f, tool_version="Trivy")

        ctx.write_output(
            "container_image_summary.json",
            _json(
                {
                    "image": profile.image,
                    "findings_total": len(findings),
                    "findings_created": len(writer.created),
                    "findings_reobserved": len(writer.reobserved),
                    "limitations": profile.limitations,
                }
            ),
        )
        return RunResult()
