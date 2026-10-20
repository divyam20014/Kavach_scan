"""`python -m app` must refuse unsafe config before uvicorn is ever started."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import app.__main__ as entry
from app import __version__

BACKEND = Path(__file__).resolve().parents[1]


def _fail_if_called(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("uvicorn.run must not be called")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in list(__import__("os").environ):
        if key.upper().startswith("VAPT_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("VAPT_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(entry, "configure_logging", lambda *_a, **_k: None)


@pytest.mark.parametrize(
    ("env", "fragment", "code"),
    [
        ({"VAPT_HOST": "0.0.0.0"}, "non-loopback", 2),  # noqa: S104 - asserted to be refused
        ({"VAPT_PORT": "not-a-port"}, "VAPT_PORT", 2),
        ({"VAPT_DATADIR": "/typo"}, "Unknown configuration variable", 2),
        ({"VAPT_DATA_DIR": "relative/dir"}, "absolute", 3),
    ],
)
def test_main_refuses_bad_config_without_starting_server(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    env: dict[str, str],
    fragment: str,
    code: int,
) -> None:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(entry.uvicorn, "run", _fail_if_called)
    assert entry.main([]) == code
    assert fragment in capsys.readouterr().err


def test_main_starts_uvicorn_on_loopback_with_storage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(entry.uvicorn, "run", lambda app, **kw: calls.append(kw))
    assert entry.main([]) == 0
    assert calls and calls[0]["host"] == "127.0.0.1" and calls[0]["port"] == 8765
    assert calls[0]["access_log"] is False  # raw query strings never reach logs
    assert (tmp_path / "data" / "storage.json").is_file()


def test_main_refuses_second_instance(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    from app.core.settings import RuntimeSettings
    from app.storage.repository import StorageRepository

    monkeypatch.setattr(entry.uvicorn, "run", _fail_if_called)
    with StorageRepository.open(RuntimeSettings(data_dir=str(tmp_path / "data"))):
        assert entry.main([]) == 3
    assert "already using this data directory" in capsys.readouterr().err


def test_version_flag() -> None:
    out = subprocess.run(
        [sys.executable, "-m", "app", "--version"],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0 and out.stdout.strip() == f"vapt-workbench {__version__}"


def test_diagnose_command_reports_readiness(tmp_path: Path) -> None:
    env = {k: v for k, v in __import__("os").environ.items() if not k.upper().startswith("VAPT_")}
    env["VAPT_DATA_DIR"] = str(tmp_path / "fresh")
    first = subprocess.run(
        [sys.executable, "-m", "app", "diagnose"],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 1  # not initialized yet: honest "not ready"
    report = json.loads(first.stdout)
    assert report["exists"] is False and report["ready"] is False
    assert not (tmp_path / "fresh").exists()  # diagnose is read-only

    from app.core.settings import RuntimeSettings
    from app.storage.repository import StorageRepository

    StorageRepository.open(RuntimeSettings(data_dir=env["VAPT_DATA_DIR"])).close()
    second = subprocess.run(
        [sys.executable, "-m", "app", "diagnose"],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    report = json.loads(second.stdout)
    assert second.returncode == 0 and report["ready"] is True
    assert report["instance_lock"] == "free" and report["storage_version"] == 1
    assert report["free_bytes"] > 0
