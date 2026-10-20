"""Phase 04: subprocess adapter — argv-only, allowlist, caps, timeout/cancel kill the whole tree."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

from app.integrations.process import ProcessPolicyError, run_process

PY = sys.executable


def pid_alive(pid: int) -> bool:
    if sys.platform.startswith("win"):
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


SPAWN_GRANDCHILD = (
    "import subprocess, sys, time\n"
    "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
    "print(g.pid, flush=True)\n"
    "time.sleep(120)\n"
)


def _wait_dead(pid: int, timeout: float = 10) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.1)
    return False


def test_normal_run_captures_output_and_exit_code(tmp_path: Path) -> None:
    result = run_process(
        [PY, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"],
        allowed_executables=[PY],
        cwd=tmp_path,
        timeout=30,
    )
    assert (
        result.exit_code == 3
        and result.stdout.strip() == b"out"
        and result.stderr.strip() == b"err"
    )
    assert not result.timed_out and not result.cancelled and not result.ok


def test_timeout_kills_the_whole_process_tree(tmp_path: Path) -> None:
    start = time.monotonic()
    result = run_process(
        [PY, "-c", SPAWN_GRANDCHILD], allowed_executables=[PY], cwd=tmp_path, timeout=2
    )
    assert result.timed_out and result.killed_tree
    assert time.monotonic() - start < 20
    grandchild = int(result.stdout.split()[0])
    assert _wait_dead(grandchild), "grandchild survived the timeout kill"


def test_cancellation_kills_the_whole_process_tree(tmp_path: Path) -> None:
    flag = threading.Event()
    threading.Timer(1.0, flag.set).start()
    result = run_process(
        [PY, "-c", SPAWN_GRANDCHILD],
        allowed_executables=[PY],
        cwd=tmp_path,
        timeout=60,
        cancelled=flag.is_set,
    )
    assert result.cancelled and not result.timed_out and result.killed_tree
    assert _wait_dead(int(result.stdout.split()[0]))


def test_output_is_capped_and_child_does_not_block(tmp_path: Path) -> None:
    result = run_process(
        [PY, "-c", "import sys; sys.stdout.write('x' * 5_000_000)"],
        allowed_executables=[PY],
        cwd=tmp_path,
        timeout=30,
        max_output_bytes=1000,
    )
    assert result.exit_code == 0 and len(result.stdout) == 1000 and result.stdout_truncated


def test_correlation_id_and_minimal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-leak")
    result = run_process(
        [
            PY,
            "-c",
            "import os; print(os.environ.get('VAPT_CORRELATION_ID')); print(os.environ.get('AWS_SECRET_ACCESS_KEY'))",
        ],
        allowed_executables=[PY],
        cwd=tmp_path,
        timeout=30,
        correlation_id="corr-123456",
    )
    lines = result.stdout.decode().split()
    assert lines == [
        "corr-123456",
        "None",
    ]  # correlation passed; unrelated secrets are not inherited


def test_runs_in_the_given_working_directory(tmp_path: Path) -> None:
    result = run_process(
        [PY, "-c", "import os; print(os.getcwd())"],
        allowed_executables=[PY],
        cwd=tmp_path,
        timeout=30,
    )
    assert Path(result.stdout.decode().strip()).resolve() == tmp_path.resolve()


@pytest.mark.parametrize(
    "argv",
    [
        "python -c print(1)",  # a shell-style string is refused
        [],
        [PY, "-c", "print(1)\x00"],
        [PY, 5],  # type: ignore[list-item]
    ],
)
def test_policy_rejects_unsafe_invocations(tmp_path: Path, argv: object) -> None:
    with pytest.raises(ProcessPolicyError):
        run_process(argv, allowed_executables=[PY], cwd=tmp_path, timeout=5)  # type: ignore[arg-type]


def test_executable_must_be_allowlisted(tmp_path: Path) -> None:
    with pytest.raises(ProcessPolicyError, match="not in the allowlist"):
        run_process([PY, "-c", "print(1)"], allowed_executables=[], cwd=tmp_path, timeout=5)
    with pytest.raises(ProcessPolicyError, match="not found"):
        run_process(
            ["definitely-not-a-real-tool-xyz", "--x"],
            allowed_executables=[PY],
            cwd=tmp_path,
            timeout=5,
        )


def test_shell_metacharacters_are_passed_literally(tmp_path: Path) -> None:
    marker = tmp_path / "pwned.txt"
    payload = f"; echo pwned > {marker} && echo pwned"
    result = run_process(
        [PY, "-c", "import sys; print(sys.argv[1])", payload],
        allowed_executables=[PY],
        cwd=tmp_path,
        timeout=30,
    )
    assert result.stdout.decode().strip() == payload and not marker.exists()
