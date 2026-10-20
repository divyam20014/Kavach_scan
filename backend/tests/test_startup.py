import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.core.settings import RuntimeSettings, SettingsError, load_settings
from app.models import AuditAction
from app.storage.errors import StorageVersionError
from app.storage.repository import LAYOUT_DIRS, StorageRepository

BACKEND = Path(__file__).resolve().parents[1]


def test_first_run_creates_layout_metadata_settings_and_audit(settings: RuntimeSettings) -> None:
    with StorageRepository.open(settings) as repo:
        assert repo.first_run
        meta = json.loads((repo.root / "storage.json").read_text())
        assert meta["storage_version"] == 1
        for name in LAYOUT_DIRS:
            assert (repo.root / name).is_dir()
        assert (repo.root / "settings" / "settings.json").is_file()
        assert [e.action for e in repo.audit.list().items] == [AuditAction.STORAGE_INITIALIZED]
    with StorageRepository.open(settings) as again:
        assert not again.first_run
        assert len(again.audit.list().items) == 1


def test_startup_removes_temp_files_and_trash(settings: RuntimeSettings) -> None:
    StorageRepository.open(settings).close()
    root = Path(settings.data_dir or "")
    (root / "projects" / ".x.json.0123456789ab.tmp").write_text("partial")
    (root / "trash" / "prj_old-1").mkdir()
    (root / "trash" / "prj_old-1" / "f.json").write_text("{}")
    with StorageRepository.open(settings) as repo:
        assert repo.temp_files_removed == 1
        assert list((root / "trash").iterdir()) == []


def test_newer_storage_version_refused_and_untouched(settings: RuntimeSettings) -> None:
    StorageRepository.open(settings).close()
    meta_path = Path(settings.data_dir or "") / "storage.json"
    meta = json.loads(meta_path.read_text())
    meta["storage_version"] = 2
    meta_path.write_text(json.dumps(meta))
    with pytest.raises(StorageVersionError, match="downgrades are not supported"):
        StorageRepository.open(settings)
    assert json.loads(meta_path.read_text())["storage_version"] == 2


def test_corrupt_storage_metadata_refuses_start_without_reinitializing(
    settings: RuntimeSettings,
) -> None:
    StorageRepository.open(settings).close()
    meta_path = Path(settings.data_dir or "") / "storage.json"
    meta_path.write_text("{garbage")
    with pytest.raises(StorageVersionError, match="corrupt"):
        StorageRepository.open(settings)
    assert meta_path.read_text() == "{garbage"


def test_failed_start_releases_instance_lock(settings: RuntimeSettings) -> None:
    StorageRepository.open(settings).close()
    meta_path = Path(settings.data_dir or "") / "storage.json"
    good = meta_path.read_text()
    meta_path.write_text("{garbage")
    with pytest.raises(StorageVersionError):
        StorageRepository.open(settings)
    meta_path.write_text(good)
    StorageRepository.open(settings).close()  # not blocked by a leaked lock


def test_unknown_vapt_env_vars_rejected() -> None:
    with pytest.raises(SettingsError, match="VAPT_DATADIR"):
        load_settings({"VAPT_DATADIR": "/x"})
    with pytest.raises(SettingsError, match="VAPT_LOCK_TIMEOUT_SECONDS"):
        load_settings({"VAPT_LOCK_TIMEOUT_SECONDS": "-1"})
    assert load_settings({"VAPT_LOG_LEVEL": "debug", "OTHER": "ignored"}).log_level == "DEBUG"


def test_importing_app_loads_no_database_or_broker_modules() -> None:
    code = (
        "import sys, json\n"
        "import app.main, app.__main__\n"
        "from app.storage.repository import StorageRepository\n"
        "banned = ['sqlite3', '_sqlite3', 'redis', 'celery', 'kombu', 'sqlalchemy', 'psycopg', "
        "'psycopg2', 'pymongo', 'shelve', 'dbm', 'pymysql', 'asyncpg']\n"
        "print(json.dumps([m for m in banned if m in sys.modules]))\n"
    )
    out = subprocess.run(
        [sys.executable, "-I", "-c", code], cwd=BACKEND, capture_output=True, text=True, check=True
    )
    assert json.loads(out.stdout) == []
