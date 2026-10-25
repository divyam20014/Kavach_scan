"""Optional OWASP ZAP integration — detection and self-test only (Module 11 extension).

This is deliberately the *first*, smallest safe increment toward a ZAP-powered web scanner
(see TBD-079): detection and an explicit self-test, following the exact same safety posture
already established for nmap/sslyze/testssl.sh (`app/services/integrations.py`). Running an
actual Automation-Framework-driven scan is a separate, later increment — nothing in this
module ever scans a target.

Two things make ZAP different from every other integration in this project and drove the
design below:

1. ZAP has no single "executable" on PATH the way nmap/sslyze do. It ships as a versioned
   jar (`zap-X.Y.Z.jar`) inside an install directory, launched via `java -jar <jar> ...`.
   Detection therefore never launches the JVM at all — the version is parsed straight from
   the jar's own filename, which is both faster and more honest than nmap/sslyze's PATH
   lookup (zero subprocess calls instead of zero subprocess calls for a *different* reason:
   there is nothing to look up on PATH).
2. ZAP's own command-line flag for "just print the version and exit" is `-cmd -version`
   (confirmed by direct test against a real local ZAP 2.17.0 install — omitting `-cmd`
   makes ZAP attempt to start its full GUI instead, which never exits quickly). ZAP also
   always needs a home directory (`-dir`) to write its config/session scaffolding into; the
   self-test always points this at an app-managed scratch directory, **never** the
   operator's own `~/ZAP` (or Windows user-profile `ZAP`) installation — a self-test must
   never read, lock, or alter the operator's real ZAP profile or any session they have open
   there.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from app.integrations.process import find_executable

#: `-cmd -version` prints the version to stdout and exits; no scan, no network, no GUI.
#: Confirmed directly against a real ZAP 2.17.0 install pointed at an isolated `-dir`.
SELFTEST_TIMEOUT_SECONDS = 120.0
_JAR_RE = re.compile(r"^zap-(\d+\.\d+\.\d+)\.jar$", re.IGNORECASE)

# ZAP does not register itself on PATH on any platform by default (unlike nmap/sslyze), so
# there is no PATH lookup to fall back to -- only a short list of well-known install
# locations for the three major desktop platforms.
_CANDIDATE_DIRS: tuple[str, ...] = (
    r"C:\Program Files\ZAP\Zed Attack Proxy",
    r"C:\Program Files (x86)\ZAP\Zed Attack Proxy",
    "/opt/zaproxy",
    "/usr/share/zaproxy",
    "/Applications/OWASP ZAP.app/Contents/Java",
)


@dataclass(frozen=True)
class ZapInstallation:
    jar_path: str
    version: str
    install_dir: str


def _newest_jar(directory: Path) -> ZapInstallation | None:
    """The highest-version `zap-*.jar` directly inside `directory` (never recursive: a
    install directory can carry an older jar left over from an in-place upgrade, as seen on
    a real installation during development of this module)."""
    try:
        if not directory.is_dir():
            return None
        entries = list(directory.glob("zap-*.jar"))
    except OSError:
        return None
    best: tuple[tuple[int, ...], Path, str] | None = None
    for entry in entries:
        m = _JAR_RE.match(entry.name)
        if not m:
            continue
        version = m.group(1)
        key = tuple(int(part) for part in version.split("."))
        if best is None or key > best[0]:
            best = (key, entry, version)
    if best is None:
        return None
    _, path, version = best
    return ZapInstallation(jar_path=str(path), version=version, install_dir=str(directory))


def detect_zap(configured: str = "") -> ZapInstallation | None:
    """Detection only: never launches the JVM, never executes anything. `configured` (the
    operator's explicit setting) may be either the ZAP install directory or a specific jar
    file path; when empty, a short list of common install locations is checked instead of a
    PATH lookup (see module docstring for why)."""
    if configured:
        p = Path(configured)
        if p.is_file():
            m = _JAR_RE.match(p.name)
            return (
                ZapInstallation(jar_path=str(p), version=m.group(1), install_dir=str(p.parent))
                if m
                else None
            )
        return _newest_jar(p)
    for candidate in _CANDIDATE_DIRS:
        found = _newest_jar(Path(candidate))
        if found:
            return found
    return None


def find_java() -> str | None:
    """PATH lookup only (no execution). ZAP requires a Java runtime the operator installs
    and manages separately -- this project never bundles or installs one."""
    return find_executable(["java"])


def selftest_argv(java_executable: str, installation: ZapInstallation, home_dir: Path) -> list[str]:
    """`java -jar <jar> -cmd -version -dir <home_dir>`. `home_dir` must be an app-managed
    scratch directory, never the operator's own ZAP profile -- see module docstring."""
    return [
        java_executable,
        "-jar",
        installation.jar_path,
        "-cmd",
        "-version",
        "-dir",
        str(home_dir),
    ]


def parse_selftest_output(stdout: bytes, stderr: bytes) -> str:
    """ZAP's `-cmd -version` prints a bare version line (e.g. `2.17.0`) on success, possibly
    preceded by JVM/addon warning lines on stderr (observed directly: deprecated-API and
    native-access warnings from bundled addons) -- those are not a failure, just noise to
    skip past. Returns "" when no version-shaped line was found."""
    for stream in (stdout, stderr):
        for raw in stream.decode("utf-8", "replace").splitlines():
            line = "".join(ch for ch in raw.strip() if ch.isprintable())
            if re.fullmatch(r"\d+(\.\d+){1,3}", line):
                return line[:40]
    return ""
