import json
from collections.abc import Iterator
from typing import Any

import pytest

from app.storage import migrations
from app.storage.errors import InvalidRecordError, UnsupportedSchemaVersionError
from app.storage.migrations import migrate, register, unregister
from app.storage.repository import StorageRepository
from tests.conftest import make_project


@pytest.fixture
def v0_project_migration(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pretend an older on-disk format existed: v0 stored `title` instead of `name`."""

    @register("project", 0)
    def _v0_to_v1(data: dict[str, Any]) -> dict[str, Any]:
        data["name"] = data.pop("title")
        data["schema_version"] = 1
        return data

    yield
    unregister("project", 0)


def test_current_version_passes_through() -> None:
    data, changed = migrate("project", {"schema_version": 1, "x": 1})
    assert data == {"schema_version": 1, "x": 1} and not changed


@pytest.mark.parametrize("bad", [None, "1", True, -1, 1.0])
def test_invalid_schema_version_rejected(bad: object) -> None:
    with pytest.raises(InvalidRecordError):
        migrate("project", {"schema_version": bad})


def test_newer_version_refused_never_downgraded() -> None:
    with pytest.raises(UnsupportedSchemaVersionError, match="supports up to 1"):
        migrate("finding", {"schema_version": 2})


def test_missing_migration_path_refused() -> None:
    with pytest.raises(UnsupportedSchemaVersionError, match="No migration"):
        migrate("asset", {"schema_version": 0})


def test_old_record_read_through_migration_and_persisted_with_backup(
    repo: StorageRepository, v0_project_migration: None
) -> None:
    project = repo.create_project(make_project(name="Legacy"))
    path = repo.paths.path("projects", project.project_id, "project.json")
    legacy = json.loads(path.read_text())
    legacy["title"] = legacy.pop("name")
    legacy["schema_version"] = 0
    path.write_text(json.dumps(legacy))

    assert repo.get_project(project.project_id).name == "Legacy"  # migrated in memory
    assert json.loads(path.read_text())["schema_version"] == 0  # not yet persisted

    assert repo.migrate_all() == 1
    assert json.loads(path.read_text())["schema_version"] == 1
    backups = list(repo.paths.path("backups", "migrations").rglob("project.json"))
    assert len(backups) == 1 and json.loads(backups[0].read_text())["title"] == "Legacy"
    assert repo.migrate_all() == 0  # idempotent
    assert repo.audit.list(action=migrations_action()).items


def migrations_action() -> Any:
    from app.models import AuditAction

    return AuditAction.STORAGE_MIGRATED


def test_registry_consistency() -> None:
    assert set(migrations.CURRENT_VERSIONS) >= {
        "project",
        "finding",
        "asset",
        "scan",
        "evidence",
        "import",
        "report",
    }
