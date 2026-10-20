"""Static architecture guards over the application source.

- Only `app/storage/` may write to the filesystem (no ad hoc file writes elsewhere).
- Only `app/storage/locking.py` may import `filelock`; banned lock types never appear.
- No database/broker modules are imported anywhere in `app/`.
- No network or subprocess modules exist in `app/` yet (scanner adapters arrive in Phase 05).
- The dependency manifest contains no database/broker packages.
"""

import ast
import re
import tomllib
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "app"
SOURCES = sorted(APP.rglob("*.py"))


def _code(path: Path) -> str:
    # strip comments and docstring-ish lines conservatively: guard on code tokens only
    lines = []
    for line in path.read_text("utf-8").splitlines():
        stripped = line.split("#", 1)[0]
        lines.append(stripped)
    return "\n".join(lines)


FILE_WRITE = re.compile(
    r"(?<![\w.])open\(|\.write_text\(|\.write_bytes\(|os\.replace\(|os\.rename\(|\bshutil\.|"
    r"\.unlink\(|\.mkdir\(|os\.makedirs\(|os\.remove\(|rmtree\(|os\.open\("
)
ALLOWED_WRITERS = {APP / "storage"}


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(APP).as_posix())
def test_no_file_io_outside_storage(path: Path) -> None:
    if any(path.is_relative_to(a) for a in ALLOWED_WRITERS):
        return
    hits = FILE_WRITE.findall(_code(path))
    assert not hits, f"{path.relative_to(APP)} performs file I/O ({hits}); use StorageRepository"


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(APP).as_posix())
def test_lock_library_confined(path: Path) -> None:
    code = _code(path)
    # AST check so documentation that *names* the banned types is not flagged.
    names = {n.id for n in ast.walk(ast.parse(path.read_text("utf-8"))) if isinstance(n, ast.Name)}
    names |= {
        n.attr for n in ast.walk(ast.parse(path.read_text("utf-8"))) if isinstance(n, ast.Attribute)
    }
    names |= {
        a.name
        for n in ast.walk(ast.parse(path.read_text("utf-8")))
        if isinstance(n, ast.ImportFrom)
        for a in n.names
    }
    assert not names & {"ReadWriteLock", "AsyncReadWriteLock", "SoftFileLock"}, path
    if path != APP / "storage" / "locking.py":
        assert not re.search(r"^\s*(import|from)\s+filelock", code, re.M), path


BANNED_IMPORTS = re.compile(
    r"^\s*(?:import|from)\s+(sqlite3|_sqlite3|shelve|dbm|redis|celery|kombu|rq|dramatiq|huey|"
    r"sqlalchemy|sqlmodel|alembic|psycopg2?|asyncpg|pymysql|MySQLdb|pymongo|motor|tinydb|peewee|"
    r"tortoise|duckdb|lmdb)\b",
    re.M,
)
NETWORK_OR_PROCESS = re.compile(
    r"^\s*(?:import|from)\s+(httpx|requests|aiohttp|urllib3|socket|subprocess|dns|http\.client|"
    r"urllib\.request|asyncio\.subprocess)\b",
    re.M,
)
# socket is used only for gethostname() in the instance lease; it opens no connections.
NETWORK_ALLOWED = {APP / "storage" / "locking.py": {"socket"}}


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(APP).as_posix())
def test_no_database_imports(path: Path) -> None:
    assert not BANNED_IMPORTS.findall(_code(path)), path


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(APP).as_posix())
def test_no_network_or_subprocess_modules_yet(path: Path) -> None:
    found = set(NETWORK_OR_PROCESS.findall(_code(path))) - NETWORK_ALLOWED.get(path, set())
    assert not found, (
        f"{path.relative_to(APP)} imports {found}; outbound I/O must wait for Phase 05 adapters"
    )


def test_manifest_has_no_database_or_broker_dependencies() -> None:
    pyproject = tomllib.loads((APP.parent / "pyproject.toml").read_text("utf-8"))
    deps = " ".join(pyproject["project"]["dependencies"]).lower()
    lock = (APP.parent / "poetry.lock").read_text("utf-8").lower()
    names = set(re.findall(r'^name = "([^"]+)"', lock, re.M))
    banned = {
        "sqlalchemy",
        "sqlmodel",
        "alembic",
        "psycopg",
        "psycopg2",
        "psycopg2-binary",
        "asyncpg",
        "pymysql",
        "mysqlclient",
        "pymongo",
        "motor",
        "redis",
        "celery",
        "kombu",
        "rq",
        "dramatiq",
        "huey",
        "tinydb",
        "peewee",
        "tortoise-orm",
        "duckdb",
        "lmdb",
        "portalocker",
    }
    assert not (names & banned), names & banned
    assert not any(b in deps for b in banned)
