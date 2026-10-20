import json

from app.storage.repository import StorageRepository
from tests.conftest import make_finding, make_project


def _index(repo: StorageRepository, pid: str) -> dict:  # type: ignore[type-arg]
    return json.loads(repo.paths.path("projects", pid, "index", "findings.json").read_text())


def test_missing_index_rebuilt(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    for i in range(3):
        repo.create_finding(make_finding(pid, title=f"F{i}"))
    repo.list_findings(pid)
    repo.list_projects()  # indexes are built lazily on first listing
    repo.paths.path("projects", pid, "index", "findings.json").unlink()
    repo.paths.path("index", "projects.json").unlink()
    assert repo.list_findings(pid).total == 3
    assert repo.list_projects().total == 1
    assert len(_index(repo, pid)["entries"]) == 3


def test_corrupt_index_rebuilt(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    repo.create_finding(make_finding(pid))
    repo.list_findings(pid)
    repo.paths.path("projects", pid, "index", "findings.json").write_text("{not json")
    repo.paths.path("index", "projects.json").write_text('{"kind": "project", "entries": []}')
    assert repo.list_findings(pid).total == 1
    assert repo.list_projects().total == 1


def test_index_out_of_sync_with_files_rebuilt(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    f1 = repo.create_finding(make_finding(pid, title="kept"))
    f2 = repo.create_finding(make_finding(pid, title="removed behind our back"))
    repo.list_findings(pid)
    repo.paths.path(
        "projects", pid, "findings", f"{f2.finding_id}.json"
    ).unlink()  # manual deletion
    page = repo.list_findings(pid)
    assert [f.finding_id for f in page.items] == [f1.finding_id] and page.total == 1


def test_stale_index_entry_detected_by_revision(repo: StorageRepository) -> None:
    pid = repo.create_project(make_project()).project_id
    f = repo.create_finding(make_finding(pid, severity="low"))
    repo.list_findings(pid)
    # Simulate a crash after the canonical write but before the index update.
    path = repo.paths.path("projects", pid, "findings", f"{f.finding_id}.json")
    data = json.loads(path.read_text())
    data.update(revision=2, severity="critical")
    path.write_text(json.dumps(data))
    page = repo.list_findings(pid)
    assert page.items[0].severity == "critical"
    assert _index(repo, pid)["entries"][f.finding_id]["revision"] == 2
    assert repo.list_findings(pid, severity={"critical"}).total == 1


def test_rebuild_all_indexes(repo: StorageRepository) -> None:
    for _ in range(2):
        pid = repo.create_project(make_project()).project_id
        repo.create_finding(make_finding(pid))
    assert repo.rebuild_all_indexes() >= 3
