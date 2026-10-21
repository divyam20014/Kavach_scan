"""Static architecture guards over the application source.

- Only `app/storage/` may write to the filesystem (no ad hoc file writes elsewhere).
- Only `app/storage/locking.py` may import `filelock`; banned lock types never appear.
- No database/broker modules are imported anywhere in `app/`.
- Network and subprocess modules are imported ONLY by the sanctioned adapters in
  `app/integrations/` (DNS, pinned HTTP transport, subprocess); scanners must use them.
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
# process.py uses shutil.which() only (no file writes); it is checked separately below.
READ_ONLY_SHUTIL = {APP / "integrations" / "process.py"}


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(APP).as_posix())
def test_no_file_io_outside_storage(path: Path) -> None:
    if any(path.is_relative_to(a) for a in ALLOWED_WRITERS):
        return
    code = _code(path)
    if path in READ_ONLY_SHUTIL:
        code = code.replace("shutil.which(", "WHICH(")
    hits = FILE_WRITE.findall(code)
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
    r"^\s*(?:import|from)\s+(httpx|requests|aiohttp|urllib3|socket|ssl|subprocess|dns|http\.client|"
    r"urllib\.request|asyncio\.subprocess|asyncio)\b",
    re.M,
)
# socket is used only for gethostname() in the instance lease; it opens no connections.
NETWORK_ALLOWED = {
    APP / "storage" / "locking.py": {"socket"},
    # The sanctioned subprocess adapter (argv lists, allowlist, caps, tree kill).
    APP / "integrations" / "process.py": {"subprocess"},
    # The DNS adapter (getaddrinfo behind a bounded cache; answers validated by ScopeGuard).
    APP / "integrations" / "dns.py": {"socket"},
    # The pinned HTTP(S) transport (connects only to guard-pinned IPs).
    APP / "integrations" / "http_client.py": {"socket", "ssl", "http.client"},
    # The TCP connect adapter (pinned IPs only, passive banner read, never sends data).
    APP / "integrations" / "tcp.py": {"socket"},
}


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(APP).as_posix())
def test_no_database_imports(path: Path) -> None:
    assert not BANNED_IMPORTS.findall(_code(path)), path


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(APP).as_posix())
def test_network_and_subprocess_only_in_adapters(path: Path) -> None:
    found = set(NETWORK_OR_PROCESS.findall(_code(path))) - NETWORK_ALLOWED.get(path, set())
    assert not found, (
        f"{path.relative_to(APP)} imports {found}; use the adapters in app/integrations/"
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


def test_subprocess_only_in_process_adapter_and_never_with_shell() -> None:
    for path in SOURCES:
        code = _code(path)
        if re.search(r"^\s*(import|from)\s+subprocess", code, re.M):
            assert path == APP / "integrations" / "process.py", path
        assert "shell=True" not in code, path
        assert "os.system(" not in code and "os.popen(" not in code, path


SCANNERS = APP / "scanners"


@pytest.mark.parametrize(
    "path", sorted(SCANNERS.rglob("*.py")), ids=lambda p: p.relative_to(APP).as_posix()
)
def test_scanners_never_touch_raw_transport_or_dns(path: Path) -> None:
    """Scanner code must go through HttpService/JobContext (scope + budgets on every hop)."""
    code = _code(path)
    for banned in (
        r"PinnedHttpTransport\(",
        r"system_lookup\(",
        r"getaddrinfo",
        r"(?<!\.)run_process\(",
    ):
        assert not re.search(banned, code), f"{path.relative_to(APP)} matches {banned}"


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(APP).as_posix())
def test_yaml_is_loaded_safely(path: Path) -> None:
    """YAML must be parsed with safe_load only; the unsafe loaders are never used."""
    code = _code(path)
    for banned in (
        "yaml.load(",
        "yaml.unsafe_load(",
        "yaml.full_load(",
        "Loader=yaml.Loader",
        "Loader=yaml.UnsafeLoader",
        "Loader=yaml.FullLoader",
    ):
        assert banned not in code, f"{path.relative_to(APP)} uses an unsafe YAML load ({banned})"
