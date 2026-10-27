"""Docker-mode argv builders for the three repo_scan engines (Docker-based execution
roadmap, phase 3 of 5, TBD-092). Pure logic -- no file I/O, no process execution (see the
package docstring). Mirrors each engine's own native argv builder
(`semgrep_adapter.py`/`gitleaks_adapter.py`/`trivy_adapter.py`) but wraps it in
`docker run --rm -v ...` instead of invoking the tool directly.

Every mount and flag below was independently verified against real `docker run` invocations
on this machine (TBD-092), not assumed from documentation. Two real, non-obvious things
found only by that verification:

1. **`docker run --rm <image> <tool> ... --output -` does not work for Trivy** -- unlike
   Semgrep and Gitleaks (whose own `--json`/`--report-path -` flags genuinely write to
   stdout inside a container exactly as they do natively), Trivy's own `--output -` silently
   produces no output at all when run this way (confirmed directly: the command returns
   with no error, but nothing is written to stdout or any file). Trivy's Docker-mode argv
   therefore mounts a dedicated, writable report directory (`/report`) and always writes to
   a real file inside it (`/report/report.json`), read back by the caller through the
   storage layer exactly as the native Trivy adapter's own `report_path` already is.
2. **The repository mount, and Trivy's own vulnerability-database cache mount, can both be
   fully read-only (`:ro`)** -- confirmed directly: a `--skip-db-update` Trivy run against a
   `:ro`-mounted cache directory completes successfully (Trivy does not need to write a
   lock file or anything else into the cache directory for a scan-only, no-update run).
   Mounting both `:ro` is strictly safer than a writable mount for no loss of functionality:
   the scanned repository can never be modified by a compromised or malfunctioning
   container, and the host's own downloaded vulnerability database (TBD-087/091) can never
   be corrupted by one either.

A real, Windows-specific path handled correctly and confirmed directly: a `-v` mount's host
side accepts a plain Windows absolute path with a drive letter and backslashes
(`C:\\Users\\...\\repo`) exactly as-is -- Docker Desktop's own path translation handles it;
this module never attempts its own path rewriting or POSIX-style conversion.

Container-side mount points are fixed, internal implementation details, never derived from
or influenced by operator input -- a scan can never be pointed at an arbitrary in-container
path.
"""

from __future__ import annotations

from pathlib import Path

from app.scanners.repo_scan.gitleaks_adapter import (
    MAX_MAX_TARGET_MEGABYTES,
    MIN_MAX_TARGET_MEGABYTES,
)
from app.scanners.repo_scan.gitleaks_adapter import (
    MAX_TIMEOUT_SECONDS as GITLEAKS_MAX_TIMEOUT_SECONDS,
)
from app.scanners.repo_scan.gitleaks_adapter import (
    MIN_TIMEOUT_SECONDS as GITLEAKS_MIN_TIMEOUT_SECONDS,
)
from app.scanners.repo_scan.semgrep_adapter import (
    ALLOWED_CONFIGS,
    MAX_MAX_TARGET_BYTES,
    MIN_MAX_TARGET_BYTES,
)
from app.scanners.repo_scan.semgrep_adapter import (
    MAX_TIMEOUT_SECONDS as SEMGREP_MAX_TIMEOUT_SECONDS,
)
from app.scanners.repo_scan.semgrep_adapter import (
    MIN_TIMEOUT_SECONDS as SEMGREP_MIN_TIMEOUT_SECONDS,
)
from app.scanners.repo_scan.trivy_adapter import (
    MAX_TIMEOUT_SECONDS as TRIVY_MAX_TIMEOUT_SECONDS,
)
from app.scanners.repo_scan.trivy_adapter import (
    MIN_TIMEOUT_SECONDS as TRIVY_MIN_TIMEOUT_SECONDS,
)

CONTAINER_REPO_PATH = "/src"
CONTAINER_CACHE_PATH = "/cache"
CONTAINER_REPORT_DIR = "/report"
TRIVY_REPORT_FILE_NAME = "report.json"


class DockerArgvError(ValueError):
    """The argv would be unsafe or invalid; nothing is executed."""


def _repo_mount(repo_path: Path) -> str:
    return f"{repo_path}:{CONTAINER_REPO_PATH}:ro"


def build_semgrep_docker_argv(
    docker_executable: str,
    image: str,
    repo_path: Path,
    *,
    config: str = "p/security-audit",
    timeout_seconds: int = 300,
    max_target_bytes: int = 5_000_000,
) -> list[str]:
    """`docker run --rm -v <repo>:/src:ro <image> semgrep scan --config <allowlisted>
    --json --metrics=off --timeout <n> --max-target-bytes <n> /src`. The leading `semgrep`
    is mandatory -- see the module docstring's entrypoint discovery (TBD-091/092): this
    image has no `ENTRYPOINT`, so omitting it would try to exec `scan` as a program."""
    if config not in ALLOWED_CONFIGS:
        raise DockerArgvError(f"config must be one of {ALLOWED_CONFIGS}, got {config!r}")
    if not SEMGREP_MIN_TIMEOUT_SECONDS <= timeout_seconds <= SEMGREP_MAX_TIMEOUT_SECONDS:
        raise DockerArgvError(
            f"timeout_seconds must be between {SEMGREP_MIN_TIMEOUT_SECONDS} and "
            f"{SEMGREP_MAX_TIMEOUT_SECONDS}"
        )
    if not MIN_MAX_TARGET_BYTES <= max_target_bytes <= MAX_MAX_TARGET_BYTES:
        raise DockerArgvError(
            f"max_target_bytes must be between {MIN_MAX_TARGET_BYTES} and {MAX_MAX_TARGET_BYTES}"
        )
    return [
        docker_executable,
        "run",
        "--rm",
        "-v",
        _repo_mount(repo_path),
        image,
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--metrics=off",
        "--timeout",
        str(timeout_seconds),
        "--max-target-bytes",
        str(max_target_bytes),
        CONTAINER_REPO_PATH,
    ]


def build_gitleaks_docker_argv(
    docker_executable: str,
    image: str,
    repo_path: Path,
    *,
    timeout_seconds: int = 300,
    max_target_megabytes: int = 50,
) -> list[str]:
    """`docker run --rm -v <repo>:/src:ro <image> dir /src --report-format json
    --report-path - --exit-code 0 --no-banner --redact --log-level error --timeout <n>
    --max-target-megabytes <n>` -- confirmed directly that Gitleaks' own image already
    defaults to running `gitleaks` itself (unlike Semgrep's), and that `--report-path -`
    genuinely writes to stdout inside a container, same as natively."""
    if not GITLEAKS_MIN_TIMEOUT_SECONDS <= timeout_seconds <= GITLEAKS_MAX_TIMEOUT_SECONDS:
        raise DockerArgvError(
            f"timeout_seconds must be between {GITLEAKS_MIN_TIMEOUT_SECONDS} and "
            f"{GITLEAKS_MAX_TIMEOUT_SECONDS}"
        )
    if not MIN_MAX_TARGET_MEGABYTES <= max_target_megabytes <= MAX_MAX_TARGET_MEGABYTES:
        raise DockerArgvError(
            f"max_target_megabytes must be between {MIN_MAX_TARGET_MEGABYTES} and "
            f"{MAX_MAX_TARGET_MEGABYTES}"
        )
    return [
        docker_executable,
        "run",
        "--rm",
        "-v",
        _repo_mount(repo_path),
        image,
        "dir",
        CONTAINER_REPO_PATH,
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


def build_trivy_docker_argv(
    docker_executable: str,
    image: str,
    repo_path: Path,
    cache_dir: Path,
    report_dir: Path,
    *,
    scanners: tuple[str, ...] = ("vuln",),
    timeout_seconds: int = 300,
) -> list[str]:
    """`docker run --rm -v <repo>:/src:ro -v <cache_dir>:/cache:ro -v <report_dir>:/report
    <image> fs /src --scanners <scanners> --format json --output /report/report.json
    --cache-dir /cache --disable-telemetry --no-progress --skip-version-check --timeout
    <n>s --skip-db-update`, plus `--skip-check-update` whenever `"misconfig"` is requested
    (security/reliability/scope roadmap Phase 4, TBD-111 -- mirrors the native adapter's
    own rule). Neither skip flag is ever a parameter here (unlike the native adapter's own
    `skip_db_update` toggle): Docker mode has no equivalent to the native "operator opts
    into a direct download" path at all -- both the vulnerability database and the
    misconfiguration checks bundle only ever reach a container by mounting the host's own
    already-downloaded cache (TBD-087/091/111), read-only, so skipping their own update is
    always correct, never optional. The report directory mount is the only writable one in
    this module -- see the module docstring for why Trivy's own `--output -` could not be
    used."""
    if not TRIVY_MIN_TIMEOUT_SECONDS <= timeout_seconds <= TRIVY_MAX_TIMEOUT_SECONDS:
        raise DockerArgvError(
            f"timeout_seconds must be between {TRIVY_MIN_TIMEOUT_SECONDS} and "
            f"{TRIVY_MAX_TIMEOUT_SECONDS}"
        )
    argv = [
        docker_executable,
        "run",
        "--rm",
        "-v",
        _repo_mount(repo_path),
        "-v",
        f"{cache_dir}:{CONTAINER_CACHE_PATH}:ro",
        "-v",
        f"{report_dir}:{CONTAINER_REPORT_DIR}",
        image,
        "fs",
        CONTAINER_REPO_PATH,
        "--scanners",
        ",".join(scanners),
        "--format",
        "json",
        "--output",
        f"{CONTAINER_REPORT_DIR}/{TRIVY_REPORT_FILE_NAME}",
        "--cache-dir",
        CONTAINER_CACHE_PATH,
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
        "--timeout",
        f"{timeout_seconds}s",
        "--skip-db-update",
    ]
    if "misconfig" in scanners:
        argv.append("--skip-check-update")
    if "license" in scanners:
        argv.append("--license-full")  # mirrors the native adapter's own rule (TBD-112)
    return argv


def build_trivy_db_download_docker_argv(
    docker_executable: str, image: str, cache_dir: Path
) -> list[str]:
    """`docker run --rm -v <cache_dir>:/cache <image> fs . --download-db-only --cache-dir
    /cache --disable-telemetry --no-progress --skip-version-check` -- the Docker-mode
    equivalent of the native adapter's own `build_download_db_argv` (operator fix, same
    increment as TBD-091's own Docker-image-pull action: an operator who only has the
    Trivy *image* pulled, with no native `trivy` binary installed at all, had no way to
    ever download the vulnerability database, since the download route only ever checked
    for a native executable). Confirmed directly against the real pinned image: the cache
    mount here is writable (unlike the scan-time `:ro` mount in `build_trivy_docker_argv`)
    because this is the one operation that is actually supposed to write into it."""
    return [
        docker_executable,
        "run",
        "--rm",
        "-v",
        f"{cache_dir}:{CONTAINER_CACHE_PATH}",
        image,
        "fs",
        ".",
        "--download-db-only",
        "--cache-dir",
        CONTAINER_CACHE_PATH,
        "--disable-telemetry",
        "--no-progress",
        "--skip-version-check",
    ]
