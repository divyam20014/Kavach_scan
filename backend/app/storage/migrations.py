"""Schema-version registry and migration hooks.

Each document type has a current `schema_version`. Reading an older document
runs registered `vN -> vN+1` functions in memory; `StorageRepository.migrate_all()`
persists upgrades after copying originals to `backups/migrations/<timestamp>/`.
Documents newer than this build supports are refused, never downgraded.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.storage.errors import InvalidRecordError, UnsupportedSchemaVersionError

STORAGE_VERSION = 1

CURRENT_VERSIONS: dict[str, int] = {
    "project": 1,
    "scan": 1,
    "asset": 1,
    "finding": 1,
    "evidence": 1,
    "import": 1,
    "report": 1,
    "settings": 1,
    "audit": 1,
    "cve_catalog": 1,
    "trivy_db_status": 1,
    "docker_image_status": 1,
}

Migration = Callable[[dict[str, Any]], dict[str, Any]]
_REGISTRY: dict[tuple[str, int], Migration] = {}


def register(kind: str, from_version: int) -> Callable[[Migration], Migration]:
    def decorator(fn: Migration) -> Migration:
        _REGISTRY[(kind, from_version)] = fn
        return fn

    return decorator


def unregister(kind: str, from_version: int) -> None:
    _REGISTRY.pop((kind, from_version), None)


def migrate(kind: str, data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Return (data at current version, whether any migration ran)."""
    current = CURRENT_VERSIONS[kind]
    version = data.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise InvalidRecordError(f"{kind} record has a missing or invalid schema_version")
    if version > current:
        raise UnsupportedSchemaVersionError(
            f"{kind} record has schema_version {version}; this build supports up to {current}"
        )
    migrated = False
    while version < current:
        step = _REGISTRY.get((kind, version))
        if step is None:
            raise UnsupportedSchemaVersionError(
                f"No migration for {kind} v{version} -> v{version + 1}"
            )
        data = step(dict(data))
        if data.get("schema_version") != version + 1:
            raise UnsupportedSchemaVersionError(
                f"Migration {kind} v{version} did not produce v{version + 1}"
            )
        version += 1
        migrated = True
    return data, migrated
