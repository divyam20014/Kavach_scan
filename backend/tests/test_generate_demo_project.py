"""`scripts/generate_demo_project.py` (Phase 13): a standalone, no-network demo-data generator.

Run as a real subprocess (not imported) because it is explicitly a standalone operator tool,
never wired into the application — this is the same faithfulness bar `test_main_entrypoint.py`
applies to `python -m app diagnose`/`--version`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from app.core.settings import RuntimeSettings
from app.storage.repository import StorageRepository

BACKEND = Path(__file__).resolve().parents[1]
SCRIPT = BACKEND / "scripts" / "generate_demo_project.py"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        check=False,
    )


def test_generate_demo_project_creates_readable_synthetic_data(tmp_path: Path) -> None:
    data_dir = tmp_path / "demo-data"
    result = _run(["--data-dir", str(data_dir)])
    assert result.returncode == 0, result.stderr
    assert "Created demo project" in result.stdout
    assert "Nothing here was scanned" in result.stdout

    repo = StorageRepository.open(RuntimeSettings(data_dir=str(data_dir)))
    try:
        projects, _errors = repo.project_summaries()
        assert len(projects) == 1
        pid = next(iter(projects))
        project = repo.get_project(pid)
        assert "synthetic" in project.name.lower()
        assert project.scope.hosts == ["demo.example.test"]
        assert repo.list_assets(pid).total == 2
        assert repo.list_scans(pid).total == 1
        findings = repo.list_findings(pid).items
        assert len(findings) == 4
        assert all(f.sources[0].tool == "demo-data-generator" for f in findings)
    finally:
        repo.close()


def test_generate_demo_project_never_touches_the_network(tmp_path: Path) -> None:
    """The generator's own code never imports a network/subprocess adapter; confirmed here by
    running it with no network available to the test process is impractical, so this instead
    asserts the one documented target is an RFC 2606 reserved, unresolvable domain."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'DEMO_HOST = "demo.example.test"' in text
    assert "socket" not in text and "httpx" not in text and "requests" not in text


def test_generate_demo_project_rejects_a_relative_data_dir_cleanly(tmp_path: Path) -> None:
    result = _run(["--data-dir", "relative/path/not/allowed"])
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "error: could not open --data-dir" in result.stderr
