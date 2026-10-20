"""Phase 01 verification: adversarial edge cases found during the verification pass."""

from __future__ import annotations

import json
import logging
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.log_config import RedactingJsonFormatter
from app.core.settings import RuntimeSettings
from app.main import create_app
from app.models import EvidenceMetadata, ImportArtifact, ReportMetadata, ScanJob, new_id
from app.storage import atomic
from app.storage.errors import (
    AlreadyExistsError,
    CorruptRecordError,
    InstanceLockedError,
    InvalidIdError,
    RecordNotFoundError,
    StorageError,
    UnsafePathError,
)
from app.storage.integrity import check_integrity
from app.storage.repository import StorageRepository
from tests.conftest import LOCAL_BASE_URL, LOCAL_CLIENT, make_asset, make_finding, make_project


def _junction_or_symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except OSError:
        pass
    if sys.platform.startswith("win"):
        import _winapi

        _winapi.CreateJunction(str(target), str(link))  # type: ignore[attr-defined]
        return
    pytest.skip("cannot create links here")


# ------------------------------------------------------------------ every path-taking service

BAD_IDS = [
    "../../outside",
    "..\\..\\outside",
    "/etc/passwd",
    "C:\\Windows\\System32\\config",
    "\\\\server\\share\\x",
    "%2e%2e%2f%2e%2e%2fetc",
    "%252e%252e%252f",
    "..%c0%af..",
    "\uff0e\uff0e\uff0f",  # fullwidth ../
    "prj_" + "a" * 32 + ":stream",  # NTFS alternate data stream
    "prj_" + "a" * 32 + "/../x",
    "prj_" + "a" * 31,
    "fnd_" + "a" * 32,  # right shape, wrong type for a project id
]


def _calls(repo: StorageRepository, pid: str, rid: str) -> dict[str, Callable[[], Any]]:
    """Every repository method that turns an id into a filesystem path."""
    return {
        "get_project": lambda: repo.get_project(pid),
        "update_project": lambda: repo.update_project(pid, {"name": "x"}),
        "delete_project": lambda: repo.delete_project(pid),
        "list_scans": lambda: repo.list_scans(pid),
        "get_scan": lambda: repo.get_scan(pid, rid),
        "update_scan": lambda: repo.update_scan(pid, rid, {}),
        "list_findings": lambda: repo.list_findings(pid),
        "get_finding": lambda: repo.get_finding(pid, rid),
        "update_finding": lambda: repo.update_finding(pid, rid, {}),
        "delete_finding": lambda: repo.delete_finding(pid, rid),
        "list_assets": lambda: repo.list_assets(pid),
        "get_asset": lambda: repo.get_asset(pid, rid),
        "update_asset": lambda: repo.update_asset(pid, rid, {}),
        "delete_asset": lambda: repo.delete_asset(pid, rid),
        "list_evidence": lambda: repo.list_evidence(pid),
        "get_evidence": lambda: repo.get_evidence(pid, rid),
        "read_evidence_blob": lambda: repo.read_evidence_blob(pid, rid),
        "delete_evidence": lambda: repo.delete_evidence(pid, rid),
        "list_imports": lambda: repo.list_imports(pid),
        "get_import": lambda: repo.get_import(pid, rid),
        "read_import_raw": lambda: repo.read_import_raw(pid, rid),
        "update_import": lambda: repo.update_import(pid, rid, {}),
        "list_reports": lambda: repo.list_reports(pid),
        "get_report_metadata": lambda: repo.get_report_metadata(pid, rid),
    }


@pytest.mark.parametrize("bad", BAD_IDS)
def test_every_id_taking_method_rejects_bad_project_ids(repo: StorageRepository, bad: str) -> None:
    for name, call in _calls(repo, bad, "fnd_" + "0" * 32).items():
        with pytest.raises(InvalidIdError):
            call()
        assert not list(repo.root.parent.glob("outside*")), name


@pytest.mark.parametrize("bad", BAD_IDS)
def test_every_id_taking_method_rejects_bad_record_ids(repo: StorageRepository, bad: str) -> None:
    pid = repo.create_project(make_project()).project_id
    for name, call in _calls(repo, pid, bad).items():
        if name.startswith(("list_", "get_project", "update_project", "delete_project")):
            continue
        if bad.startswith("fnd_") and "finding" in name:
            continue  # a well-formed finding id is valid for finding methods (-> not found)
        with pytest.raises(InvalidIdError):
            call()


@pytest.mark.parametrize(
    "factory",
    [
        lambda pid: make_finding(pid, finding_id="fnd_../../x"),
        lambda pid: make_project(project_id="../../x"),
    ],
)
def test_models_reject_traversal_ids_before_storage(
    repo: StorageRepository, factory: Callable[[str], Any]
) -> None:
    pid = repo.create_project(make_project()).project_id
    with pytest.raises(Exception, match="(?i)pattern|validation"):
        factory(pid)


def test_data_dir_with_dotdot_resolving_into_repo_is_refused() -> None:
    from app.core.settings import repo_root
    from app.storage.errors import DataRootError
    from app.storage.paths import resolve_data_root

    sneaky = repo_root() / "docs" / ".." / "backend" / ".." / "data"
    with pytest.raises(DataRootError, match="source checkout"):
        resolve_data_root(RuntimeSettings(data_dir=str(sneaky)))


def test_link_planted_at_record_level_is_rejected(tmp_path: Path, repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    f = repo.create_finding(make_finding(pid))
    outside = tmp_path / "evil"
    outside.mkdir()
    findings_dir = repo.paths.path("projects", pid, "findings")
    # replace the whole collection directory with a link to an outside directory
    (outside / f"{f.finding_id}.json").write_text(
        (findings_dir / f"{f.finding_id}.json").read_text()
    )
    for p in findings_dir.iterdir():
        p.unlink()
    findings_dir.rmdir()
    _junction_or_symlink(findings_dir, outside)
    with pytest.raises(UnsafePathError):
        repo.get_finding(pid, f.finding_id)
    with pytest.raises(UnsafePathError):
        repo.create_finding(make_finding(pid))
    with pytest.raises(UnsafePathError):
        repo.delete_project(pid)
    assert sorted(p.name for p in outside.iterdir()) == [f"{f.finding_id}.json"]


def test_integrity_check_survives_link_named_like_a_project(
    tmp_path: Path, repo: StorageRepository
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "project.json").write_text("{}")
    _junction_or_symlink(repo.paths.root / "projects" / new_id("project"), outside)
    report = check_integrity(repo, repair=True)  # must not raise
    assert [i.kind for i in report.issues] == ["link_in_data_dir"]
    listing = repo.list_projects()
    assert listing.items == []
    assert (outside / "project.json").read_text() == "{}"


def test_trash_purge_removes_link_without_touching_target(
    tmp_path: Path, settings: RuntimeSettings
) -> None:
    StorageRepository.open(settings).close()
    root = Path(settings.data_dir or "")
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")
    _junction_or_symlink(root / "trash" / "prj_x-1", victim)
    StorageRepository.open(settings).close()
    assert (victim / "keep.txt").read_text() == "keep"
    assert list((root / "trash").iterdir()) == []


# ------------------------------------------------------------------ truncated JSON, every record type


def _record_paths(repo: StorageRepository) -> dict[str, tuple[Path, Callable[[], Any]]]:
    pid = repo.create_project(make_project()).project_id
    scan = repo.create_scan(ScanJob(scan_id=new_id("scan"), project_id=pid, module="web_app"))
    finding = repo.create_finding(make_finding(pid))
    asset = repo.create_asset(make_asset(pid))
    ev = repo.save_evidence(
        EvidenceMetadata(
            evidence_id=new_id("evidence"), project_id=pid, evidence_type="text_excerpt"
        )
    )
    raw = b"x"
    imp = repo.create_import(
        ImportArtifact(
            import_id=new_id("import"),
            project_id=pid,
            display_filename="a.json",
            sha256=__import__("hashlib").sha256(raw).hexdigest(),
            size_bytes=1,
        ),
        raw,
    )
    rpt = repo.save_report_metadata(
        ReportMetadata(report_id=new_id("report"), project_id=pid, title="r", formats=["html"])
    )
    p = repo.paths.path
    return {
        "project": (p("projects", pid, "project.json"), lambda: repo.get_project(pid)),
        "scan": (
            p("projects", pid, "scans", scan.scan_id, "scan.json"),
            lambda: repo.get_scan(pid, scan.scan_id),
        ),
        "finding": (
            p("projects", pid, "findings", f"{finding.finding_id}.json"),
            lambda: repo.get_finding(pid, finding.finding_id),
        ),
        "asset": (
            p("projects", pid, "assets", f"{asset.asset_id}.json"),
            lambda: repo.get_asset(pid, asset.asset_id),
        ),
        "evidence": (
            p("projects", pid, "evidence", f"{ev.evidence_id}.json"),
            lambda: repo.get_evidence(pid, ev.evidence_id),
        ),
        "import": (
            p("projects", pid, "imports", imp.import_id, "import.json"),
            lambda: repo.get_import(pid, imp.import_id),
        ),
        "report": (
            p("projects", pid, "reports", rpt.report_id, "report.json"),
            lambda: repo.get_report_metadata(pid, rpt.report_id),
        ),
        "settings": (p("settings", "settings.json"), repo.get_settings),
    }


@pytest.mark.parametrize(
    "kind", ["project", "scan", "finding", "asset", "evidence", "import", "report", "settings"]
)
def test_truncated_json_for_every_record_type(repo: StorageRepository, kind: str) -> None:
    paths = _record_paths(repo)
    path, read = paths[kind]
    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2])
    with pytest.raises(CorruptRecordError):
        read()
    for other, (_, other_read) in paths.items():
        if other not in (kind, "project") and not (kind == "project"):
            other_read()  # unrelated records still readable


@pytest.mark.parametrize(
    "kind", ["project", "scan", "finding", "asset", "evidence", "import", "report", "settings"]
)
def test_schema_invalid_data_for_every_record_type(repo: StorageRepository, kind: str) -> None:
    path, read = _record_paths(repo)[kind]
    data = json.loads(path.read_text())
    data["unexpected_field"] = "x"
    path.write_text(json.dumps(data))
    with pytest.raises(StorageError) as info:
        read()
    assert info.value.code == "record_invalid"


# ------------------------------------------------------------------ write failures through the repository


def _fail_replace(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(atomic.os, "replace", boom)


def test_failed_update_leaves_record_and_index_untouched(
    repo: StorageRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = repo.create_project(make_project()).project_id
    f = repo.create_finding(make_finding(pid, severity="low"))
    repo.list_findings(pid)
    _fail_replace(monkeypatch)
    with pytest.raises(OSError, match="No space"):
        repo.update_finding(pid, f.finding_id, {"severity": "critical"})
    monkeypatch.undo()
    assert repo.get_finding(pid, f.finding_id) == f
    assert repo.list_findings(pid, severity={"critical"}).total == 0
    assert not list(repo.root.rglob("*.tmp"))


@pytest.mark.parametrize("what", ["project", "finding", "scan", "evidence_with_blob", "import"])
def test_failed_create_leaves_nothing_behind(
    repo: StorageRepository, monkeypatch: pytest.MonkeyPatch, what: str
) -> None:
    pid = repo.create_project(make_project()).project_id
    before = sorted(
        p.relative_to(repo.root).as_posix() for p in repo.root.rglob("*") if ".lock" not in p.name
    )
    _fail_replace(monkeypatch)
    with pytest.raises(OSError):
        if what == "project":
            repo.create_project(make_project())
        elif what == "finding":
            repo.create_finding(make_finding(pid))
        elif what == "scan":
            repo.create_scan(ScanJob(scan_id=new_id("scan"), project_id=pid, module="web_app"))
        elif what == "evidence_with_blob":
            repo.save_evidence(
                EvidenceMetadata(
                    evidence_id=new_id("evidence"), project_id=pid, evidence_type="text_excerpt"
                ),
                blob=b"b",
            )
        else:
            repo.create_import(
                ImportArtifact(
                    import_id=new_id("import"),
                    project_id=pid,
                    display_filename="a",
                    sha256=__import__("hashlib").sha256(b"r").hexdigest(),
                    size_bytes=1,
                ),
                b"r",
            )
    monkeypatch.undo()
    after = sorted(
        p.relative_to(repo.root).as_posix() for p in repo.root.rglob("*") if ".lock" not in p.name
    )
    created_dirs = set(after) - set(before)
    assert all(not (repo.root / c).is_file() for c in created_dirs), created_dirs
    assert not list(repo.root.rglob("*.tmp"))
    assert check_integrity(repo, repair=False).ok


# ------------------------------------------------------------------ simultaneous operations


def test_racing_creates_of_same_id_exactly_one_wins(repo: StorageRepository) -> None:
    project = make_project()
    results: list[str] = []

    def attempt() -> None:
        try:
            repo.create_project(project)
            results.append("ok")
        except AlreadyExistsError:
            results.append("exists")

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["exists"] * 7 + ["ok"]


def test_writes_racing_project_delete_never_resurrect_it(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    existing = [repo.create_finding(make_finding(pid)) for _ in range(5)]
    stop = threading.Event()
    unexpected: list[BaseException] = []

    def writer() -> None:
        i = 0
        while not stop.is_set():
            try:
                repo.create_finding(make_finding(pid))
                repo.update_finding(pid, existing[i % 5].finding_id, {"title": f"t{i}"})
            except RecordNotFoundError:
                pass
            except BaseException as exc:  # noqa: BLE001 - collected and asserted below
                unexpected.append(exc)
            i += 1

    threads = [threading.Thread(target=writer) for _ in range(3)]
    for t in threads:
        t.start()
    threading.Event().wait(0.3)
    repo.delete_project(pid)
    threading.Event().wait(0.3)
    stop.set()
    for t in threads:
        t.join()
    assert not unexpected, unexpected[:3]
    leftovers = [
        p.name for p in repo.paths.path("projects").iterdir() if not p.name.startswith(".")
    ]
    assert leftovers == [], leftovers
    assert check_integrity(repo, repair=False).ok


# ------------------------------------------------------------------ redaction in logs


@pytest.mark.parametrize(
    ("message", "args", "secret"),
    [
        (
            "request headers: %s",
            ({"Authorization": "Bearer abcdefghijklmnop", "Accept": "*/*"},),
            "abcdefghijklmnop",
        ),
        ("headers %s", ({"Cookie": "session=s3cr3tcookie"},), "s3cr3tcookie"),
        ("payload %s", ({"password": "hunter2pass"},), "hunter2pass"),
        ("payload %s", ('{"password": "hunter2pass", "user": "bob"}',), "hunter2pass"),
        ("payload %s", ('{"api_key":"AbCdEfGhIjKlMnOp"}',), "AbCdEfGhIjKlMnOp"),
        ("payload %s", ({"client_secret": "zzzsecretzzz"},), "zzzsecretzzz"),
        ("payload %s", ({"refresh_token": "rt_123456789"},), "rt_123456789"),
        ("sent Cookie: sid=midlinesecret; x=1", (), "midlinesecret"),
        ("response Set-Cookie: auth=setcookievalue; HttpOnly", (), "setcookievalue"),
        ("calling https://user:pa55word@api.example.com/v1", (), "pa55word"),
        ("GET /x?api_key=querysecret123&page=2", (), "querysecret123"),
        ("aws key AKIAIOSFODNN7EXAMPLE configured", (), "AKIAIOSFODNN7EXAMPLE"),
        ("X-Api-Key: headerkey123456", (), "headerkey123456"),
    ],
)
def test_log_formatter_redacts_secrets(message: str, args: tuple[Any, ...], secret: str) -> None:
    record = logging.LogRecord("app.test", logging.INFO, __file__, 1, message, args, None)
    line = RedactingJsonFormatter().format(record)
    assert secret not in line, line
    json.loads(line)  # still valid JSON


def test_log_formatter_redacts_extra_fields_and_exceptions() -> None:
    try:
        raise ValueError("token=exc_secret_value leaked")
    except ValueError:
        exc_info = sys.exc_info()
    record = logging.LogRecord("app.test", logging.ERROR, __file__, 1, "failed", (), exc_info)
    record.headers = {"Authorization": "Bearer extra_secret_token"}
    line = RedactingJsonFormatter().format(record)
    assert "exc_secret_value" not in line and "extra_secret_token" not in line
    assert "Traceback" not in line


# ------------------------------------------------------------------ second instance via the ASGI lifespan path


def test_lifespan_refuses_to_start_when_data_root_is_in_use(settings: RuntimeSettings) -> None:
    with StorageRepository.open(settings):
        with pytest.raises(InstanceLockedError):
            with TestClient(create_app(settings), base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT):
                pass
