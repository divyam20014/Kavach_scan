"""Native Trivy `image` argv builder (security/reliability/scope roadmap Phase 3, TBD-110).
Pure logic -- no file I/O, no process execution, mirrors
`app/scanners/repo_scan/trivy_adapter.py::build_scan_argv`'s own shape for the `fs`
subcommand. The JSON report schema is identical between `trivy fs` and `trivy image`
(`Results[].Vulnerabilities[]`), confirmed directly against a real local Trivy 0.76.1 run
(`docker run aquasec/trivy:0.76.1 image alpine:3.18 ...`, TBD-110) -- so this module reuses
`app.scanners.repo_scan.trivy_adapter.parse_trivy_json`/`TrivyFinding` as-is; only a new argv
builder is needed, not a new parser.

**Local images only, confirmed directly, not assumed from documentation**: `--image-src
docker` restricts Trivy to the local Docker daemon only (never containerd/podman/a remote
registry). Scanning a reference that is not present on the local daemon fails cleanly and
immediately (confirmed: `unable to find the specified image "..." in ["docker"]: ... No
such image`) -- it never falls back to pulling the image from anywhere. This is the
operator-confirmed scope for this phase (TBD-110): Docker-mode execution (mounting the
host's Docker socket into a container -- a materially bigger privilege than anything the
existing Docker-execution roadmap, TBD-090-094, ever needed) and registry-pull support were
both deliberately deferred, not built here.

The vulnerability-database cache directory is the exact same one `repo_scan`'s own Trivy
usage already manages (`ctx.repo.trivy_db_dir()`) -- confirmed directly that `--download-db-
only`/`--skip-db-update` behave identically for the `image` subcommand, so no separate
database-management action was needed for this phase.
"""

from __future__ import annotations

from pathlib import Path

from app.scanners.repo_scan.trivy_adapter import (
    MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    TrivyArgvError,
)

__all__ = ["TrivyArgvError", "build_image_scan_argv"]


def build_image_scan_argv(
    executable: str,
    image: str,
    report_path: Path,
    cache_dir: Path,
    *,
    timeout_seconds: int = 300,
) -> list[str]:
    """`trivy image <image> --image-src docker --scanners vuln --format json --output
    <report_path> --cache-dir <cache_dir> --disable-telemetry --no-progress
    --skip-version-check --skip-db-update --timeout <n>s`. `--skip-db-update` is never a
    caller-supplied toggle here (unlike the `fs` adapter's own `skip_db_update` parameter):
    this module has no "operator opts into a direct download" path of its own at all -- the
    database only ever reaches this scan via the shared cache directory `repo_scan`'s own
    download action (TBD-087) already manages, so skipping its own update is always
    correct, never optional."""
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise TrivyArgvError(
            f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}"
        )
    return [
        executable,
        "image",
        image,
        "--image-src",
        "docker",
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
        "--skip-db-update",
        "--timeout",
        f"{timeout_seconds}s",
    ]
