"""Repository scan job runner (module `repo_scan`, roadmap Phase 2, TBD-087).

Runs each selected engine (Semgrep, Gitleaks, Trivy) against the project's configured
`repository_path`, one after another; a failure in one engine never aborts the others --
each is reported independently in `repo_scan_summary.json`, mirroring how the native web
scanner continues past a single failed check rather than aborting the whole scan.

Safety properties:
- every subprocess call goes through `ctx.run_process` (the same cancellation/timeout/
  deadline-aware wrapper every other runner in this project uses);
- Trivy's vulnerability database is read from the shared, app-managed cache directory
  (`ctx.repo.trivy_db_dir()`) and never downloaded by this runner -- see
  `app/scanners/repo_scan/trivy_adapter.py`'s own module docstring and TBD-087's own
  "operator downloads it explicitly from Integrations" decision;
- `targets` carries no real meaning for this module (the real "target" is the project's
  `repository_path`, not a URL) -- `check_targets` accepts a single placeholder, the same
  pattern `app/scanners/apisec/runner.py` already uses for its own non-URL target shape.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.redaction import redact
from app.jobs.context import JobContext, JobStop, RunResult
from app.models.project import ScanPolicy
from app.scanners.repo_scan.findings import RepoScanFindingWriter
from app.scanners.repo_scan.gitleaks_adapter import (
    GitleaksReportError,
    parse_gitleaks_json,
)
from app.scanners.repo_scan.gitleaks_adapter import (
    build_scan_argv as gitleaks_argv,
)
from app.scanners.repo_scan.profile import RepoScanProfile, build_profile, validate_parameters
from app.scanners.repo_scan.semgrep_adapter import (
    SemgrepReportError,
    parse_semgrep_json,
)
from app.scanners.repo_scan.semgrep_adapter import (
    build_scan_argv as semgrep_argv,
)
from app.scanners.repo_scan.trivy_adapter import (
    TrivyReportError,
    parse_trivy_json,
)
from app.scanners.repo_scan.trivy_adapter import (
    build_scan_argv as trivy_argv,
)
from app.scope.engine import ScopePolicy

OUTPUT_MAX_ITEMS = 2000
MAX_PROCESS_OUTPUT_BYTES = 16 * 1024 * 1024


def _json(data: Any) -> bytes:
    safe = redact(json.loads(json.dumps(data, default=str)), max_items=OUTPUT_MAX_ITEMS)
    return json.dumps(safe, indent=2, ensure_ascii=False).encode("utf-8")


@dataclass
class RepoScanRunner:
    name: str = "repo_scan"
    semgrep_availability: Callable[[], str] = field(default=lambda: "")
    gitleaks_availability: Callable[[], str] = field(default=lambda: "")
    trivy_availability: Callable[[], str] = field(default=lambda: "")
    trivy_db_ready: Callable[[], bool] = field(default=lambda: False)

    def check_targets(
        self, targets: list[str], policy: ScopePolicy
    ) -> tuple[list[str], list[tuple[int, str]]]:
        # Repo scans do not take URL targets; the real target is the project's own
        # `repository_path`. A single placeholder target is accepted (see module docstring).
        return (list(targets) or ["repo-scan"]), []

    def validate_parameters(self, params: dict[str, Any], policy: ScanPolicy) -> list[str]:
        errors = validate_parameters(params, policy)
        if errors:
            return errors
        profile = build_profile(params)
        availability: dict[str, Callable[[], str]] = {
            "semgrep": self.semgrep_availability,
            "gitleaks": self.gitleaks_availability,
            "trivy": self.trivy_availability,
        }
        for engine in profile.engines:
            if not availability[engine]():
                errors.append(f"{engine} is not available (not installed or not configured)")
        if "trivy" in profile.engines and not self.trivy_db_ready():
            errors.append(
                "Trivy's vulnerability database has not been downloaded yet -- download it "
                "from the Integrations page first"
            )
        return errors

    # ------------------------------------------------------------------ run

    def run(self, ctx: JobContext) -> RunResult:
        project = ctx.repo.get_project(ctx.project_id)
        if not project.repository_path:
            ctx.error("no repository path is configured for this project")
            return RunResult(failed=True, errors=["no repository path configured"])
        repo_path = Path(project.repository_path)
        if not repo_path.is_dir():
            ctx.error(f"configured repository path is not a directory: {project.repository_path}")
            return RunResult(failed=True, errors=["repository path not found"])

        profile = build_profile(dict(ctx.scan.parameters))
        ctx.write_output("profile.json", _json(profile.model_dump(mode="json")))
        ctx.emit("profile", f"repo scan profile: engines={profile.engines}")

        writer = RepoScanFindingWriter(ctx.repo, ctx.project_id, ctx.scan_id)
        summary: dict[str, Any] = {}
        stop: JobStop | None = None
        try:
            for engine in profile.engines:
                ctx.checkpoint()
                ctx.stage(f"{engine} scan")
                try:
                    if engine == "semgrep":
                        count = self._run_semgrep(ctx, profile, repo_path, writer)
                    elif engine == "gitleaks":
                        count = self._run_gitleaks(ctx, profile, repo_path, writer)
                    else:
                        count = self._run_trivy(ctx, profile, repo_path, writer)
                    summary[engine] = {"status": "completed", "findings": count}
                except RuntimeError as exc:
                    ctx.error(f"{engine} failed: {exc}")
                    summary[engine] = {"status": "failed", "error": str(exc)[:500]}
        except JobStop as exc:
            stop = exc
            ctx.emit("partial", f"repo scan stopped early ({exc})", level="warning")

        ctx.stage("findings", 95)
        ctx.write_output(
            "repo_scan_summary.json",
            _json(
                {
                    "engines": summary,
                    "findings_created": len(writer.created),
                    "findings_reobserved": len(writer.reobserved),
                    "limitations": profile.limitations,
                }
            ),
        )
        if stop is not None:
            raise stop
        return RunResult()

    def _run_semgrep(
        self,
        ctx: JobContext,
        profile: RepoScanProfile,
        repo_path: Path,
        writer: RepoScanFindingWriter,
    ) -> int:
        executable = self.semgrep_availability()
        if not executable:
            raise RuntimeError("semgrep is not available")
        timeout_seconds = profile.semgrep_timeout_minutes * 60
        argv = semgrep_argv(
            executable, repo_path, config=profile.semgrep_config, timeout_seconds=timeout_seconds
        )
        result = ctx.run_process(
            argv,
            allowed_executables=[executable],
            timeout=timeout_seconds + 30,
            max_output_bytes=MAX_PROCESS_OUTPUT_BYTES,
        )
        ctx.checkpoint()
        if result.timed_out:
            raise RuntimeError(f"semgrep did not finish within {timeout_seconds}s")
        if result.exit_code != 0:
            raise RuntimeError(f"semgrep exited with status {result.exit_code}")
        try:
            findings = parse_semgrep_json(result.stdout)
        except SemgrepReportError as exc:
            raise RuntimeError(f"could not interpret the semgrep report: {exc}") from exc
        for f in findings:
            writer.write_semgrep(f, tool_version="Semgrep")
        return len(findings)

    def _run_gitleaks(
        self,
        ctx: JobContext,
        profile: RepoScanProfile,
        repo_path: Path,
        writer: RepoScanFindingWriter,
    ) -> int:
        executable = self.gitleaks_availability()
        if not executable:
            raise RuntimeError("gitleaks is not available")
        timeout_seconds = profile.gitleaks_timeout_minutes * 60
        argv = gitleaks_argv(executable, repo_path, timeout_seconds=timeout_seconds)
        result = ctx.run_process(
            argv,
            allowed_executables=[executable],
            timeout=timeout_seconds + 30,
            max_output_bytes=MAX_PROCESS_OUTPUT_BYTES,
        )
        ctx.checkpoint()
        if result.timed_out:
            raise RuntimeError(f"gitleaks did not finish within {timeout_seconds}s")
        if result.exit_code != 0:
            raise RuntimeError(f"gitleaks exited with status {result.exit_code}")
        try:
            findings = parse_gitleaks_json(result.stdout)
        except GitleaksReportError as exc:
            raise RuntimeError(f"could not interpret the gitleaks report: {exc}") from exc
        for f in findings:
            writer.write_gitleaks(f, tool_version="Gitleaks")
        return len(findings)

    def _run_trivy(
        self,
        ctx: JobContext,
        profile: RepoScanProfile,
        repo_path: Path,
        writer: RepoScanFindingWriter,
    ) -> int:
        executable = self.trivy_availability()
        if not executable:
            raise RuntimeError("trivy is not available")
        if not self.trivy_db_ready():
            raise RuntimeError(
                "Trivy's vulnerability database has not been downloaded -- download it from "
                "the Integrations page first"
            )
        timeout_seconds = profile.trivy_timeout_minutes * 60
        report_dir = ctx.repo.scan_work_subdir(ctx.project_id, ctx.scan_id, "trivy_report")
        report_path = report_dir / "report.json"
        argv = trivy_argv(
            executable,
            repo_path,
            report_path,
            ctx.repo.trivy_db_dir(),
            skip_db_update=True,
            timeout_seconds=timeout_seconds,
        )
        result = ctx.run_process(
            argv,
            allowed_executables=[executable],
            timeout=timeout_seconds + 30,
            max_output_bytes=MAX_PROCESS_OUTPUT_BYTES,
        )
        ctx.checkpoint()
        if result.timed_out:
            raise RuntimeError(f"trivy did not finish within {timeout_seconds}s")
        if result.exit_code != 0:
            raise RuntimeError(f"trivy exited with status {result.exit_code}")
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
            raise RuntimeError(f"could not interpret the trivy report: {exc}") from exc
        for f in findings:
            writer.write_trivy(f, tool_version="Trivy")
        return len(findings)
