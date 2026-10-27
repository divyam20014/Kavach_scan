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

Docker-based execution (roadmap phase 4 of 5, TBD-093): any engine in
`profile.docker_engines` runs via its pulled, pinned Docker image (`app/scanners/
repo_scan/docker_argv.py`) instead of a native executable -- per-engine, confirmed by the
operator (TBD-090). Availability for a Docker-mode engine requires both Docker itself and
that specific engine's image to have been explicitly pulled (TBD-091); Trivy's own
vulnerability-database requirement applies identically in both modes, since the database
is data the host manages, not something tied to which binary runs the scan.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.redaction import redact
from app.jobs.context import JobContext, JobStop, RunResult
from app.models.project import Project, ScanPolicy
from app.scanners.repo_scan.docker_argv import (
    build_gitleaks_docker_argv,
    build_semgrep_docker_argv,
    build_trivy_docker_argv,
)
from app.scanners.repo_scan.docker_images import image_for
from app.scanners.repo_scan.findings import RepoScanFindingWriter
from app.scanners.repo_scan.git_clone import GIT_CLONE_ENV, GitCloneArgvError, build_clone_argv
from app.scanners.repo_scan.git_credentials import (
    ASKPASS_HELPER_SOURCE,
    build_credential_env,
    resolve_credential_alias,
)
from app.scanners.repo_scan.git_ssrf_guard import (
    CloneHostBlockedError,
    check_clone_host_not_blocked,
)
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
from app.scanners.repo_scan.semgrep_adapter import (
    report_errors as semgrep_report_errors,
)
from app.scanners.repo_scan.trivy_adapter import (
    TrivyReportError,
    parse_trivy_json,
    parse_trivy_license_json,
    parse_trivy_misconfig_json,
    parse_trivy_packages_json,
)
from app.scanners.repo_scan.trivy_adapter import (
    build_scan_argv as trivy_argv,
)
from app.scope.engine import ScopePolicy

OUTPUT_MAX_ITEMS = 2000
MAX_PROCESS_OUTPUT_BYTES = 16 * 1024 * 1024
CLONE_TIMEOUT_SECONDS = 300
ASKPASS_HELPER_NAME = "git_askpass_helper.py"
ASKPASS_LAUNCHER_NAME = "git_askpass_helper.cmd"  # Windows only -- see git_credentials.py


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
    trivy_checks_ready: Callable[[], bool] = field(default=lambda: False)
    docker_availability: Callable[[], str] = field(default=lambda: "")
    docker_image_ready: Callable[[str], bool] = field(default=lambda engine: False)
    git_availability: Callable[[], str] = field(default=lambda: "")

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
            if engine in profile.docker_engines:
                if not self.docker_availability():
                    errors.append("docker is not available (not installed or not configured)")
                elif not self.docker_image_ready(engine):
                    errors.append(
                        f"{engine}'s Docker image has not been pulled yet -- pull it from "
                        "the Integrations page first"
                    )
            elif not availability[engine]():
                errors.append(f"{engine} is not available (not installed or not configured)")
        if "trivy" in profile.engines and not self.trivy_db_ready():
            errors.append(
                "Trivy's vulnerability database has not been downloaded yet -- download it "
                "from the Integrations page first"
            )
        if profile.trivy_iac and not self.trivy_checks_ready():
            errors.append(
                "Trivy's IaC/misconfiguration checks bundle has not been downloaded yet -- "
                "download it from the Integrations page first"
            )
        return errors

    # ------------------------------------------------------------------ run

    def run(self, ctx: JobContext) -> RunResult:
        project = ctx.repo.get_project(ctx.project_id)
        if project.repository_url:
            repo_path = self._clone_repository(ctx, project)
            if repo_path is None:
                return RunResult(failed=True, errors=["repository clone failed"])
        elif project.repository_path:
            repo_path = Path(project.repository_path)
            if not repo_path.is_dir():
                ctx.error(
                    f"configured repository path is not a directory: {project.repository_path}"
                )
                return RunResult(failed=True, errors=["repository path not found"])
        else:
            ctx.error("no repository path or repository URL is configured for this project")
            return RunResult(failed=True, errors=["no repository configured"])

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
                        count, tool_errors = self._run_semgrep(ctx, profile, repo_path, writer)
                    elif engine == "gitleaks":
                        count, tool_errors = self._run_gitleaks(ctx, profile, repo_path, writer)
                    else:
                        count, tool_errors = self._run_trivy(ctx, profile, repo_path, writer)
                    summary[engine] = {"status": "completed", "findings": count}
                    if tool_errors:
                        # The tool's own report named specific files it could not analyze
                        # (e.g. a parse failure) -- a partial scan must never look identical
                        # to a fully clean one, so these are surfaced both in the summary and
                        # as scan-level warnings, never silently dropped.
                        summary[engine]["errors"] = tool_errors[:20]
                        for e in tool_errors[:20]:
                            ctx.warn(f"{engine}: {e}")
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

    def _clone_repository(self, ctx: JobContext, project: Project) -> Path | None:
        """Clone `project.repository_url` into an ephemeral, per-scan work directory
        (git-clone-from-URL roadmap, phase 5 of 6, TBD-100). The SSRF guard (phase 4) is
        re-run here, immediately before the clone attempt, never once at project-
        configuration time -- narrowing the DNS-rebinding window `git_ssrf_guard`'s own
        docstring discloses as far as this application can."""
        ctx.stage("cloning repository")
        try:
            check_clone_host_not_blocked(project.repository_url, project, ctx.resolver)
        except CloneHostBlockedError as exc:
            ctx.error(f"repository URL is blocked: {exc}")
            return None
        git_executable = self.git_availability()
        if not git_executable:
            ctx.error("git is not available (not installed or not configured)")
            return None

        secret: str | None = None
        if project.repository_credential_alias:
            secret = resolve_credential_alias(project.repository_credential_alias)
            if secret is None:
                ctx.error(
                    f"could not resolve credential alias "
                    f"'{project.repository_credential_alias}' (only 'env:NAME' aliases are "
                    "supported; ensure the environment variable is set)"
                )
                return None

        env: dict[str, str] = {**GIT_CLONE_ENV, **build_credential_env(secret)}
        if secret is not None:
            # Phase 3's helper source is a fixed string this module ships; only its on-disk
            # location is decided here, at clone time, through the storage layer -- never a
            # direct file write (see tests/test_static_guards.py's file-I/O confinement).
            ctx.repo.write_scan_output(
                ctx.project_id, ctx.scan_id, ASKPASS_HELPER_NAME, ASKPASS_HELPER_SOURCE.encode()
            )
            work_dir = ctx.repo.scan_work_dir(ctx.project_id, ctx.scan_id)
            helper_path = work_dir / ASKPASS_HELPER_NAME
            if os.name == "nt":
                # Confirmed directly (TBD-098): a bare "<python> <script.py>" GIT_ASKPASS
                # value is not split into program+argument by Git for Windows.
                launcher = f'@"{sys.executable}" "{helper_path}" %*\r\n'
                ctx.repo.write_scan_output(
                    ctx.project_id, ctx.scan_id, ASKPASS_LAUNCHER_NAME, launcher.encode()
                )
                env["GIT_ASKPASS"] = str(work_dir / ASKPASS_LAUNCHER_NAME)
            else:
                env["GIT_ASKPASS"] = f"{sys.executable} {helper_path}"

        dest_dir = ctx.repo.scan_work_subdir(ctx.project_id, ctx.scan_id, "git_clone_repo")
        try:
            argv = build_clone_argv(
                git_executable,
                project.repository_url,
                dest_dir,
                timeout_seconds=CLONE_TIMEOUT_SECONDS,
            )
        except GitCloneArgvError as exc:
            ctx.error(f"could not build the clone command: {exc}")
            return None
        result = ctx.run_process(
            argv,
            allowed_executables=[git_executable],
            timeout=CLONE_TIMEOUT_SECONDS + 30,
            max_output_bytes=MAX_PROCESS_OUTPUT_BYTES,
            extra_env=env,
        )
        ctx.checkpoint()
        if result.timed_out:
            ctx.error(f"git clone did not finish within {CLONE_TIMEOUT_SECONDS}s")
            return None
        if result.exit_code != 0:
            ctx.error(f"git clone exited with status {result.exit_code}")
            return None
        return dest_dir

    def _run_semgrep(
        self,
        ctx: JobContext,
        profile: RepoScanProfile,
        repo_path: Path,
        writer: RepoScanFindingWriter,
    ) -> tuple[int, list[str]]:
        timeout_seconds = profile.semgrep_timeout_minutes * 60
        if "semgrep" in profile.docker_engines:
            docker_executable = self.docker_availability()
            if not docker_executable:
                raise RuntimeError("docker is not available")
            argv = build_semgrep_docker_argv(
                docker_executable,
                image_for("semgrep"),
                repo_path,
                config=profile.semgrep_config,
                timeout_seconds=timeout_seconds,
            )
            allowed = [docker_executable]
        else:
            executable = self.semgrep_availability()
            if not executable:
                raise RuntimeError("semgrep is not available")
            argv = semgrep_argv(
                executable,
                repo_path,
                config=profile.semgrep_config,
                timeout_seconds=timeout_seconds,
            )
            allowed = [executable]
        result = ctx.run_process(
            argv,
            allowed_executables=allowed,
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
        # Semgrep's own `errors` list (e.g. a file it could not parse) is surfaced
        # separately from a hard failure -- a scan can produce real findings AND report
        # that some files were skipped; TBD-084 parsed this but never wired it anywhere.
        return len(findings), semgrep_report_errors(result.stdout)

    def _run_gitleaks(
        self,
        ctx: JobContext,
        profile: RepoScanProfile,
        repo_path: Path,
        writer: RepoScanFindingWriter,
    ) -> tuple[int, list[str]]:
        timeout_seconds = profile.gitleaks_timeout_minutes * 60
        if "gitleaks" in profile.docker_engines:
            docker_executable = self.docker_availability()
            if not docker_executable:
                raise RuntimeError("docker is not available")
            argv = build_gitleaks_docker_argv(
                docker_executable, image_for("gitleaks"), repo_path, timeout_seconds=timeout_seconds
            )
            allowed = [docker_executable]
        else:
            executable = self.gitleaks_availability()
            if not executable:
                raise RuntimeError("gitleaks is not available")
            argv = gitleaks_argv(executable, repo_path, timeout_seconds=timeout_seconds)
            allowed = [executable]
        result = ctx.run_process(
            argv,
            allowed_executables=allowed,
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
        return len(findings), []  # Gitleaks' own JSON report has no "errors" list of its own

    def _run_trivy(
        self,
        ctx: JobContext,
        profile: RepoScanProfile,
        repo_path: Path,
        writer: RepoScanFindingWriter,
    ) -> tuple[int, list[str]]:
        if not self.trivy_db_ready():
            raise RuntimeError(
                "Trivy's vulnerability database has not been downloaded -- download it from "
                "the Integrations page first"
            )
        if profile.trivy_iac and not self.trivy_checks_ready():
            raise RuntimeError(
                "Trivy's IaC/misconfiguration checks bundle has not been downloaded -- "
                "download it from the Integrations page first"
            )
        scanners: list[str] = ["vuln"]
        if profile.trivy_iac:
            scanners.append("misconfig")
        if profile.trivy_sbom:
            scanners.append("license")
        scanners_t: tuple[str, ...] = tuple(scanners)
        timeout_seconds = profile.trivy_timeout_minutes * 60
        report_dir = ctx.repo.scan_work_subdir(ctx.project_id, ctx.scan_id, "trivy_report")
        if "trivy" in profile.docker_engines:
            docker_executable = self.docker_availability()
            if not docker_executable:
                raise RuntimeError("docker is not available")
            argv = build_trivy_docker_argv(
                docker_executable,
                image_for("trivy"),
                repo_path,
                ctx.repo.trivy_db_dir(),
                report_dir,
                scanners=scanners_t,
                timeout_seconds=timeout_seconds,
            )
            allowed = [docker_executable]
        else:
            executable = self.trivy_availability()
            if not executable:
                raise RuntimeError("trivy is not available")
            report_path = report_dir / "report.json"
            argv = trivy_argv(
                executable,
                repo_path,
                report_path,
                ctx.repo.trivy_db_dir(),
                scanners=scanners_t,
                skip_db_update=True,
                timeout_seconds=timeout_seconds,
            )
            allowed = [executable]
        result = ctx.run_process(
            argv,
            allowed_executables=allowed,
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
            misconfig_findings = (
                parse_trivy_misconfig_json(report_bytes) if profile.trivy_iac else []
            )
            license_findings = parse_trivy_license_json(report_bytes) if profile.trivy_sbom else []
            packages = parse_trivy_packages_json(report_bytes) if profile.trivy_sbom else []
        except TrivyReportError as exc:
            raise RuntimeError(f"could not interpret the trivy report: {exc}") from exc
        for f in findings:
            writer.write_trivy(f, tool_version="Trivy")
        for mf in misconfig_findings:
            writer.write_trivy_misconfig(mf, tool_version="Trivy")
        actionable_licenses = [lf for lf in license_findings if lf.is_actionable]
        for lf in actionable_licenses:
            writer.write_trivy_license(lf, tool_version="Trivy")
        if profile.trivy_sbom:
            # Full inventory, regardless of actionability -- never only the subset that
            # became a Finding (security/reliability/scope roadmap Phase 5, TBD-112).
            ctx.write_output(
                "sbom.json",
                _json(
                    {
                        "packages": [
                            {
                                "name": p.name,
                                "version": p.version,
                                "ecosystem": p.ecosystem,
                                "target": p.target,
                                "purl": p.purl,
                                "licenses": p.licenses,
                            }
                            for p in packages
                        ],
                    }
                ),
            )
            ctx.write_output(
                "licenses.json",
                _json(
                    {
                        "licenses": [
                            {
                                "name": lf.name,
                                "category": lf.category,
                                "confidence": lf.confidence,
                                "file_path": lf.file_path,
                                "pkg_name": lf.pkg_name,
                                "actionable": lf.is_actionable,
                            }
                            for lf in license_findings
                        ],
                    }
                ),
            )
        # Trivy's own JSON report has no "errors" list of its own.
        total = len(findings) + len(misconfig_findings) + len(actionable_licenses)
        return total, []
