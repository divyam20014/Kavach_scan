"""The only sanctioned way to run an external process (MASTER_SPEC §4.3, Module 11).

Rules enforced here:
- argv is a list; `shell=False` always; no string command lines are accepted;
- the executable must resolve to an entry in an explicit allowlist (absolute paths);
- runs in a caller-provided working directory (a per-scan dir inside the data root);
- a minimal environment is passed (PATH/SYSTEMROOT/TEMP plus VAPT_CORRELATION_ID);
- stdout/stderr are captured with byte caps (excess is discarded and flagged);
- timeout or cancellation terminates the WHOLE process tree (Windows: taskkill /T /F,
  POSIX: process group SIGTERM then SIGKILL), then the process is reaped.

Callers that touch targets must first obtain permission from ScopeGuard
(`authorize_subprocess_targets`); this module does not interpret arguments.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess  # noqa: S404 - this module is the sanctioned subprocess adapter
import sys
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MAX_OUTPUT = 4 * 1024 * 1024
KILL_GRACE_SECONDS = 2.0
_IS_WINDOWS = sys.platform.startswith("win")
_killpg = getattr(os, "killpg", None) or (lambda _pid, _sig: None)  # POSIX only
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)
_ENV_PASSTHROUGH = (
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
)


class ProcessPolicyError(ValueError):
    """The requested invocation violates the subprocess policy (not executed)."""


@dataclass
class ProcessResult:
    argv: list[str]
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    cancelled: bool
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float
    killed_tree: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not (self.timed_out or self.cancelled)


@dataclass
class _Capture:
    limit: int
    chunks: list[bytes] = field(default_factory=list)
    size: int = 0
    truncated: bool = False

    def feed(self, stream: object) -> None:
        read = stream.read  # type: ignore[attr-defined]
        while True:
            chunk = read(65536)
            if not chunk:
                return
            room = self.limit - self.size
            if room > 0:
                self.chunks.append(chunk[:room])
                self.size += min(len(chunk), room)
            if len(chunk) > room:
                self.truncated = True  # keep draining so the child never blocks on a full pipe

    @property
    def data(self) -> bytes:
        return b"".join(self.chunks)


def resolve_executable(name: str, allowed: Iterable[str]) -> str:
    """Resolve `name` and require it to be one of the allowlisted absolute paths."""
    allowed_paths = {os.path.normcase(os.path.realpath(a)) for a in allowed}
    candidate = name if os.path.isabs(name) else shutil.which(name)
    if not candidate:
        raise ProcessPolicyError(f"executable {name!r} not found")
    real = os.path.normcase(os.path.realpath(candidate))
    if real not in allowed_paths:
        raise ProcessPolicyError(f"executable {name!r} is not in the allowlist")
    return candidate


def _kill_tree(proc: subprocess.Popen[bytes]) -> bool:
    if proc.poll() is not None:
        return False
    if _IS_WINDOWS:
        taskkill = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
        subprocess.run(  # noqa: S603 - fixed argv, absolute system binary, no shell
            [str(taskkill), "/PID", str(proc.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    else:
        try:
            _killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return False
        deadline = time.monotonic() + KILL_GRACE_SECONDS
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.05)
        if proc.poll() is None:
            try:
                _killpg(proc.pid, _SIGKILL)
            except ProcessLookupError:
                pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    return True


def run_process(
    argv: Sequence[str],
    *,
    allowed_executables: Iterable[str],
    cwd: Path,
    timeout: float,
    cancelled: Callable[[], bool] = lambda: False,
    correlation_id: str | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT,
    extra_env: dict[str, str] | None = None,
    on_start: Callable[[subprocess.Popen[bytes]], None] | None = None,
) -> ProcessResult:
    if isinstance(argv, str) or not argv or not all(isinstance(a, str) for a in argv):
        raise ProcessPolicyError(
            "argv must be a non-empty list of strings (no shell command lines)"
        )
    if any("\x00" in a for a in argv):
        raise ProcessPolicyError("NUL bytes are not allowed in arguments")
    if not cwd.is_dir():
        raise ProcessPolicyError("working directory does not exist")
    if timeout <= 0:
        raise ProcessPolicyError("timeout must be positive")
    executable = resolve_executable(argv[0], allowed_executables)
    env = {k: v for k, v in os.environ.items() if k.upper() in _ENV_PASSTHROUGH}
    if correlation_id:
        env["VAPT_CORRELATION_ID"] = correlation_id
    env.update(extra_env or {})
    kwargs: dict[str, object] = {}
    if _IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True  # own process group -> killpg reaches grandchildren
    start = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False, allowlisted executable
        [executable, *argv[1:]],
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        **kwargs,  # type: ignore[call-overload]
    )
    if on_start is not None:
        on_start(proc)
    out, err = _Capture(max_output_bytes), _Capture(max_output_bytes)
    readers = [
        threading.Thread(target=out.feed, args=(proc.stdout,), daemon=True),
        threading.Thread(target=err.feed, args=(proc.stderr,), daemon=True),
    ]
    for r in readers:
        r.start()
    timed_out = was_cancelled = killed = False
    while proc.poll() is None:
        if cancelled():
            was_cancelled = True
        elif time.monotonic() - start > timeout:
            timed_out = True
        if was_cancelled or timed_out:
            killed = _kill_tree(proc)
            break
        time.sleep(0.05)
    for r in readers:
        r.join(timeout=5)
    return ProcessResult(
        argv=[executable, *argv[1:]],
        exit_code=proc.returncode,
        stdout=out.data,
        stderr=err.data,
        timed_out=timed_out,
        cancelled=was_cancelled,
        stdout_truncated=out.truncated,
        stderr_truncated=err.truncated,
        duration_seconds=round(time.monotonic() - start, 3),
        killed_tree=killed,
    )
