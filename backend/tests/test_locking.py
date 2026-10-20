import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from app.core.settings import RuntimeSettings
from app.storage.errors import InstanceLockedError, LockTimeoutError
from app.storage.locking import InstanceLock, exclusive, sidecar_lock_path
from app.storage.repository import StorageRepository
from tests.conftest import make_project

BACKEND = Path(__file__).resolve().parents[1]


def _spawn(code: str, *args: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-c", code, *args],
        cwd=BACKEND,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _wait_for_line(proc: subprocess.Popen[str], expected: str, timeout: float = 30) -> None:
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if line.strip() == expected:
            return
        if proc.poll() is not None:
            break
    err = proc.stderr.read() if proc.stderr else ""
    raise AssertionError(f"subprocess did not print {expected!r}; stderr: {err[-2000:]}")


HOLD_INSTANCE = """
import sys, time
from app.core.settings import RuntimeSettings
from app.storage.repository import StorageRepository
repo = StorageRepository.open(RuntimeSettings(data_dir=sys.argv[1]))
print("ready", flush=True)
time.sleep(120)
"""

HOLD_RECORD = """
import sys, time
from pathlib import Path
from app.storage.locking import exclusive
with exclusive(Path(sys.argv[1]), 10):
    print("ready", flush=True)
    time.sleep(120)
"""

INCREMENT = """
import sys
from pathlib import Path
from app.core.settings import RuntimeSettings
from app.storage.repository import StorageRepository
settings = RuntimeSettings(data_dir=sys.argv[1], lock_timeout_seconds=60)
repo = StorageRepository(Path(sys.argv[1]), settings)  # no instance lock: exercises record locks only
for _ in range(int(sys.argv[3])):
    repo.update_project(sys.argv[2], lambda p: p.model_copy(update={"notes": str(int(p.notes) + 1)}))
print("done", flush=True)
"""


def test_second_instance_refused_in_process(
    settings: RuntimeSettings, repo: StorageRepository
) -> None:
    with pytest.raises(InstanceLockedError, match="already using this data directory"):
        StorageRepository.open(settings)


def test_second_instance_refused_across_processes_and_recovers_after_crash(tmp_path: Path) -> None:
    data = tmp_path / "data"
    holder = _spawn(HOLD_INSTANCE, str(data))
    try:
        _wait_for_line(holder, "ready")
        with pytest.raises(InstanceLockedError) as info:
            StorageRepository.open(RuntimeSettings(data_dir=str(data)))
        # Holder pid is reported (on Windows venvs Popen's pid is the launcher, not the
        # interpreter that holds the lock, so only the format is asserted).
        assert re.search(r"\(pid \d+, started \d{4}-\d\d-\d\dT", info.value.message)
        assert InstanceLock.probe(data) == "held"
    finally:
        holder.kill()  # simulated crash: no clean release
        holder.wait()
    assert InstanceLock.probe(data) == "free"
    with StorageRepository.open(RuntimeSettings(data_dir=str(data))) as repo:
        assert repo.instance_lock.held


def test_leftover_lock_files_do_not_block(settings: RuntimeSettings, tmp_path: Path) -> None:
    data = tmp_path / "data"
    StorageRepository.open(settings).close()
    (data / "instance.lock").write_text("stale")  # file exists but no OS lock is held
    unit = data / "projects" / "x.json"
    sidecar_lock_path(unit).write_text("stale")
    with StorageRepository.open(settings) as repo:
        assert repo.instance_lock.held
        with exclusive(unit, 1):
            pass


def test_record_lock_released_when_holder_process_killed(tmp_path: Path) -> None:
    unit = tmp_path / "record.json"
    holder = _spawn(HOLD_RECORD, str(unit))
    try:
        _wait_for_line(holder, "ready")
        with pytest.raises(LockTimeoutError):
            with exclusive(unit, 0.2):
                pass
    finally:
        holder.kill()
        holder.wait()
    with exclusive(unit, 5):
        pass


def test_record_lock_timeout_and_no_reentrancy(tmp_path: Path) -> None:
    unit = tmp_path / "r.json"
    with exclusive(unit, 1):
        with pytest.raises(LockTimeoutError):
            with exclusive(unit, 0.1):
                pass
    held = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with exclusive(unit, 1):
            held.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    held.wait(5)
    start = time.monotonic()
    with pytest.raises(LockTimeoutError):
        with exclusive(unit, 0.3):
            pass
    assert time.monotonic() - start < 2
    release.set()
    t.join()


def test_concurrent_thread_updates_lose_nothing(repo: StorageRepository) -> None:
    project = repo.create_project(make_project(notes="0"))
    threads, per_thread = 6, 15

    def work() -> None:
        for _ in range(per_thread):
            repo.update_project(
                project.project_id, lambda p: p.model_copy(update={"notes": str(int(p.notes) + 1)})
            )

    workers = [threading.Thread(target=work) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    final = repo.get_project(project.project_id)
    assert final.notes == str(threads * per_thread)
    assert final.revision == 1 + threads * per_thread


def test_concurrent_process_updates_lose_nothing(
    repo: StorageRepository, settings: RuntimeSettings
) -> None:
    project = repo.create_project(make_project(notes="0"))
    procs, per_proc = 4, 15
    workers = [
        _spawn(INCREMENT, str(repo.root), project.project_id, str(per_proc)) for _ in range(procs)
    ]
    for w in workers:
        out, err = w.communicate(timeout=300)
        assert w.returncode == 0, err[-2000:]
        assert out.strip() == "done"
    final = repo.get_project(project.project_id)
    assert final.notes == str(procs * per_proc)
    assert final.revision == 1 + procs * per_proc
