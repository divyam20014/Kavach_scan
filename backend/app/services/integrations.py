"""Integrations status and the no-target-traffic self-test (MASTER_SPEC Module 11/12).

Detection (`list_integration_statuses`) is PATH/path-existence lookup only — no subprocess is
ever run just to render the status list. A deliberate, explicit self-test
(`run_selftest`) is the only thing that executes `<tool> --version`; it never resolves,
connects to, or sends anything toward a scan target.

No integration here is ever shown as a green "working" success unless a self-test actually
ran and succeeded in this process's lifetime (`verified`). Being found on PATH only earns
`detected` — present, but unverified.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from app.integrations.nmap import NmapSpec, detect_nmap
from app.integrations.process import ProcessPolicyError, run_process
from app.integrations.tls_tools import TlsToolSpec, detect_tls_tools
from app.integrations.zap import (
    SELFTEST_TIMEOUT_SECONDS as _ZAP_SELFTEST_TIMEOUT_SECONDS,
)
from app.integrations.zap import (
    detect_zap,
    find_java,
    parse_selftest_output,
    selftest_argv,
)
from app.models.settings import IntegrationsSettings
from app.storage.atomic import ensure_dir
from app.storage.repository import StorageRepository

IntegrationStatusValue = Literal["not_configured", "not_found", "detected", "verified", "error"]
TOOL_IDS: tuple[str, ...] = ("nmap", "sslyze", "testssl.sh", "zap")

_CAPABILITIES: dict[str, str] = {
    "nmap": "Bounded TCP connect port/service mapping for the attack surface mapper "
    "(Module 6.2) — TCP connect only, never raw sockets or stealth scans.",
    "sslyze": "TLS protocol/cipher detail for the web scanner's certificate checks "
    "(Module 5.3). Preferred over testssl.sh when both are available.",
    "testssl.sh": "TLS protocol/cipher detail for the web scanner's certificate checks "
    "(Module 5.3). Used when sslyze is unavailable.",
    "zap": "OWASP ZAP for deep web application DAST (detection/self-test only in this "
    "release — Automation-Framework-driven scanning is a separate, later increment).",
}
_TROUBLESHOOTING: dict[str, str] = {
    "nmap": "Install Nmap and ensure it is on PATH, or set an explicit path in Settings. "
    "If Nmap is missing, port/service checks fall back to a built-in TCP connect probe.",
    "sslyze": "Install sslyze (`pip install sslyze`) or set an explicit path in Settings. "
    "If neither TLS tool is available, protocol/cipher checks are reported skipped.",
    "testssl.sh": "Install testssl.sh (a bash script; not native on Windows — use WSL) or set "
    "an explicit path in Settings.",
    "zap": "Install OWASP ZAP (https://www.zaproxy.org/download/) and a Java runtime, then "
    "set the ZAP install directory (or a specific zap-*.jar) in Settings if it is not one of "
    "the common install locations already checked.",
}

_SELFTEST_TIMEOUT_SECONDS = 20.0
_SELFTEST_MAX_OUTPUT = 16 * 1024


@dataclass(frozen=True)
class ToolUsage:
    project_id: str
    scan_id: str
    at: str  # ISO-8601
    version: str


@dataclass(frozen=True)
class IntegrationStatus:
    id: str
    label: str
    capability: str
    configured_path: str
    detected_path: str
    status: IntegrationStatusValue
    version: str
    last_used: ToolUsage | None
    last_error: str
    troubleshooting: str


def _configured_path(settings: IntegrationsSettings, tool_id: str) -> str:
    return {
        "nmap": settings.nmap_path,
        "sslyze": settings.sslyze_path,
        "testssl.sh": settings.testssl_path,
        "zap": settings.zap_path,
    }[tool_id]


def _detect_path(tool_id: str, configured: str) -> str:
    """An explicit configured path must exist and be a file; otherwise fall back to the same
    PATH-based auto-detection the scanners themselves already use (Phase 05/06). ZAP has no
    single executable and no PATH registration (see `app/integrations/zap.py`): "detected"
    is the located jar file, found via `detect_zap` (filename parsing only, no JVM launch)."""
    if tool_id == "zap":
        installation = detect_zap(configured)
        return installation.jar_path if installation else ""
    if configured:
        return configured if Path(configured).is_file() else ""
    if tool_id == "nmap":
        spec = detect_nmap()
        return spec.executable if spec else ""
    found = detect_tls_tools()
    match = next((t for t in found if t.name == tool_id), None)
    return match.executable if match else ""


def _last_use(repo: StorageRepository, tool_id: str) -> ToolUsage | None:
    """Looks at the most recently updated scans for a tool-version record left by a real
    run (Phase 05/06 already write `ScanJob.tool_versions`); this is a read-only lookup over
    existing data, so no change was needed in the already-verified scanner runners."""
    page = repo.list_across_projects(
        "scan", sort="updated_at", descending=True, offset=0, limit=200
    )
    best: ToolUsage | None = None
    for scan in page.items:
        version = scan.tool_versions.get(tool_id)
        if not version:
            continue
        at = scan.finished_at or scan.started_at or scan.queued_at
        if at is None:
            continue
        iso = at.isoformat()
        if best is None or iso > best.at:
            best = ToolUsage(
                project_id=scan.project_id, scan_id=scan.scan_id, at=iso, version=version
            )
    return best


def _status_for(tool_id: str, configured: str, detected: str) -> IntegrationStatusValue:
    if configured and not detected:
        return "not_found"  # explicitly configured, but nothing usable found there
    if detected:
        return "detected"  # found, but a self-test has not (yet, in this process) verified it
    return "not_configured" if not configured else "not_found"


def list_integration_statuses(repo: StorageRepository) -> list[IntegrationStatus]:
    settings = repo.get_settings().integrations
    out: list[IntegrationStatus] = []
    for tool_id in TOOL_IDS:
        configured = _configured_path(settings, tool_id)
        detected = _detect_path(tool_id, configured)
        out.append(
            IntegrationStatus(
                id=tool_id,
                label=tool_id,
                capability=_CAPABILITIES[tool_id],
                configured_path=configured,
                detected_path=detected,
                status=_status_for(tool_id, configured, detected),
                version="",
                last_used=_last_use(repo, tool_id),
                last_error="",
                troubleshooting=_TROUBLESHOOTING[tool_id],
            )
        )
    return out


class UnknownIntegrationError(ValueError):
    pass


def _version_args(tool_id: str, executable: str) -> list[str]:
    if tool_id == "nmap":
        return NmapSpec(executable).version_argv()[1:]
    return TlsToolSpec(tool_id, executable).version_args()


def _zap_selftest(
    repo: StorageRepository, base: IntegrationStatus, configured: str
) -> IntegrationStatus:
    """`java -jar <jar> -cmd -version -dir <isolated home>`. Unlike nmap/sslyze/testssl.sh,
    ZAP needs a second executable (`java`) resolved separately, and a home directory that is
    never the operator's own ZAP profile (see `app/integrations/zap.py`)."""
    installation = detect_zap(configured)
    if installation is None:
        return replace(base, status="error", last_error="the detected ZAP jar disappeared")
    java = find_java()
    if not java:
        return replace(
            base,
            status="error",
            last_error="no Java runtime found on PATH; ZAP requires one (installed separately)",
        )
    home_dir = repo.diagnostics_temp_dir() / "zap_home"
    ensure_dir(home_dir, parents=True)
    try:
        result = run_process(
            selftest_argv(java, installation, home_dir),
            allowed_executables=[java],
            cwd=repo.diagnostics_temp_dir(),
            timeout=_ZAP_SELFTEST_TIMEOUT_SECONDS,
            max_output_bytes=_SELFTEST_MAX_OUTPUT,
        )
    except ProcessPolicyError as exc:
        return replace(base, status="error", last_error=str(exc))
    except OSError as exc:
        return replace(base, status="error", last_error=f"could not run java: {exc}")
    if result.timed_out:
        return replace(
            base,
            status="error",
            last_error=f"ZAP did not respond within {_ZAP_SELFTEST_TIMEOUT_SECONDS:.0f}s",
        )
    if result.exit_code != 0:
        detail = _first_printable_line(result.stderr) or _first_printable_line(result.stdout)
        message = f"exited with status {result.exit_code}"
        if detail:
            message += f": {detail}"
        return replace(base, status="error", last_error=message)
    version = parse_selftest_output(result.stdout, result.stderr)
    if not version:
        return replace(base, status="error", last_error="ZAP produced no readable version output")
    return replace(base, status="verified", version=version)


def run_selftest(repo: StorageRepository, tool_id: str) -> IntegrationStatus:
    """Runs `<tool> --version` only. No host, port, or scan target is ever involved."""
    if tool_id not in TOOL_IDS:
        raise UnknownIntegrationError(tool_id)
    settings = repo.get_settings().integrations
    configured = _configured_path(settings, tool_id)
    detected = _detect_path(tool_id, configured)
    base = IntegrationStatus(
        id=tool_id,
        label=tool_id,
        capability=_CAPABILITIES[tool_id],
        configured_path=configured,
        detected_path=detected,
        status=_status_for(tool_id, configured, detected),
        version="",
        last_used=_last_use(repo, tool_id),
        last_error="",
        troubleshooting=_TROUBLESHOOTING[tool_id],
    )
    if not detected:
        return base
    if tool_id == "zap":
        return _zap_selftest(repo, base, configured)
    try:
        result = run_process(
            [detected, *_version_args(tool_id, detected)],
            allowed_executables=[detected],
            cwd=repo.diagnostics_temp_dir(),
            timeout=_SELFTEST_TIMEOUT_SECONDS,
            max_output_bytes=_SELFTEST_MAX_OUTPUT,
        )
    except ProcessPolicyError as exc:
        return replace(base, status="error", last_error=str(exc))
    except OSError as exc:
        # A "configured path" is operator-supplied free text (TBD-… tool-path setting) and
        # may point at something that exists but is not a real, runnable executable (wrong
        # architecture, a text file renamed with an .exe extension, no execute permission).
        # The OS rejects launching it before this app's own process ever starts, which
        # `subprocess.Popen` surfaces as a plain `OSError` — this must become a clean
        # self-test error, never an unhandled exception.
        return replace(base, status="error", last_error=f"could not run the executable: {exc}")
    if result.timed_out:
        return replace(
            base,
            status="error",
            last_error=f"the tool did not respond within {_SELFTEST_TIMEOUT_SECONDS:.0f}s",
        )
    if result.exit_code != 0:
        # A non-zero exit means the invocation itself failed (wrong/unsupported flag, a
        # corrupt or non-executable binary masquerading as the tool, an incompatible
        # version that doesn't understand `--version`, ...). Whatever text came out — often
        # an error message, not a version — must never be reported as a verified version:
        # that would be exactly the false pass this self-test exists to prevent.
        detail = _first_printable_line(result.stderr) or _first_printable_line(result.stdout)
        message = f"exited with status {result.exit_code}"
        if detail:
            message += f": {detail}"
        return replace(base, status="error", last_error=message)
    version = _first_printable_line(result.stdout) or _first_printable_line(result.stderr)
    if not version:
        return replace(
            base, status="error", last_error="the tool produced no readable version output"
        )
    return replace(base, status="verified", version=version)


def _first_printable_line(data: bytes) -> str:
    for raw in data.decode("utf-8", "replace").splitlines():
        text = "".join(ch for ch in raw.strip() if ch.isprintable())
        if text:
            return text[:200]
    return ""
