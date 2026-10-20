import os
import sys
from pathlib import Path

import pytest

from app.core.settings import RuntimeSettings, repo_root
from app.storage.errors import DataRootError, InvalidIdError, UnsafePathError
from app.storage.paths import SafePaths, default_data_dir, resolve_data_root, validate_id
from app.storage.repository import StorageRepository
from tests.conftest import make_project


def _make_link(link: Path, target: Path) -> None:
    """Create a directory symlink, or a junction on Windows when symlinks need privileges."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except OSError:
        pass
    if sys.platform.startswith("win"):
        import _winapi

        _winapi.CreateJunction(str(target), str(link))  # type: ignore[attr-defined]
        return
    pytest.skip("cannot create symlinks or junctions on this platform/account")


# ---------------------------------------------------------------- data root resolution


def test_default_data_dir_is_per_user_and_outside_repo() -> None:
    win = default_data_dir({"LOCALAPPDATA": r"C:\Users\u\AppData\Local"}, platform="win32")
    assert win == Path(r"C:\Users\u\AppData\Local") / "VAPTWorkbench" / "data"
    linux = default_data_dir({"HOME": "/home/u"}, platform="linux")
    assert linux == Path("/home/u/.local/share/vapt-workbench")
    xdg = default_data_dir({"HOME": "/home/u", "XDG_DATA_HOME": "/data/x"}, platform="linux")
    assert xdg == Path("/data/x/vapt-workbench")
    mac = default_data_dir({"HOME": "/Users/u"}, platform="darwin")
    assert mac == Path("/Users/u/Library/Application Support/VAPTWorkbench")
    assert not default_data_dir().resolve().is_relative_to(repo_root())


def test_relative_data_dir_rejected() -> None:
    with pytest.raises(DataRootError, match="absolute"):
        resolve_data_root(RuntimeSettings(data_dir="relative/data"))


def test_data_dir_inside_repository_refused_unless_allowed() -> None:
    inside = str(repo_root() / "data")
    with pytest.raises(DataRootError, match="source checkout"):
        resolve_data_root(RuntimeSettings(data_dir=inside))
    assert (
        resolve_data_root(RuntimeSettings(data_dir=inside, allow_repo_data_dir=True))
        == Path(inside).resolve()
    )


def test_filesystem_root_refused() -> None:
    root = Path(Path.cwd().anchor)
    with pytest.raises(DataRootError, match="root"):
        resolve_data_root(RuntimeSettings(data_dir=str(root)))


def test_data_dir_that_is_a_file_refused(tmp_path: Path) -> None:
    f = tmp_path / "afile"
    f.write_text("x")
    with pytest.raises(DataRootError, match="not a directory"):
        resolve_data_root(RuntimeSettings(data_dir=str(f)))


def test_non_empty_foreign_directory_refused(tmp_path: Path) -> None:
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "thesis.docx").write_text("precious")
    with pytest.raises(DataRootError, match="not empty"):
        StorageRepository.open(RuntimeSettings(data_dir=str(tmp_path / "Documents")))
    assert (tmp_path / "Documents" / "thesis.docx").read_text() == "precious"
    assert not (tmp_path / "Documents" / "storage.json").exists()


# ---------------------------------------------------------------- safe joins

ESCAPES = [
    "..",
    "../outside",
    "..\\outside",
    "/etc/passwd",
    "C:\\Windows",
    "C:",
    "\\\\server\\share",
    "a/b",
    "%2e%2e",
    "%2e%2e%2fetc",
    "..%2f..%2f",
    "\x00",
    "name\x00.json",
    "CON",
    "nul.json",
    "com1",
    "trailing.",
    "trailing ",
    "",
    "~",
    "*",
    "a" * 300,
]


@pytest.mark.parametrize("part", ESCAPES)
def test_unsafe_components_rejected(tmp_path: Path, part: str) -> None:
    with pytest.raises(UnsafePathError):
        SafePaths(tmp_path).path("projects", part)


@pytest.mark.parametrize("kind", ["project", "finding"])
@pytest.mark.parametrize(
    "bad", ["../prj", "prj_../../x", "/abs", "C:\\x", "%2e%2e", "prj_" + "A" * 32]
)
def test_untrusted_ids_rejected_before_path_building(kind: str, bad: str) -> None:
    with pytest.raises(InvalidIdError):
        validate_id(kind, bad)


@pytest.mark.parametrize(
    "bad", ["../../outside", "..", "/etc/passwd", "C:\\Windows\\System32", "prj_x"]
)
def test_repository_rejects_traversal_ids(repo: StorageRepository, bad: str) -> None:
    for call in (
        lambda: repo.get_project(bad),
        lambda: repo.delete_project(bad),
        lambda: repo.list_findings(bad),
        lambda: repo.get_finding(bad, "fnd_" + "0" * 32),
    ):
        with pytest.raises(InvalidIdError):
            call()
    project = repo.create_project(make_project())
    with pytest.raises(InvalidIdError):
        repo.get_finding(project.project_id, bad)


def test_symlink_or_junction_escape_rejected(tmp_path: Path, repo: StorageRepository) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("do not touch")
    link_name = "prj_" + "e" * 32
    _make_link(repo.paths.path("projects") / link_name, outside)
    with pytest.raises(UnsafePathError):
        repo.paths.path("projects", link_name, "project.json")
    with pytest.raises(UnsafePathError):
        repo.get_project(link_name)
    with pytest.raises(UnsafePathError):
        repo.delete_project(link_name)
    assert (outside / "secret.txt").read_text() == "do not touch"


def test_link_inside_project_blocks_delete(tmp_path: Path, repo: StorageRepository) -> None:
    project = repo.create_project(make_project())
    outside = tmp_path / "victim"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    _make_link(repo.paths.path("projects", project.project_id) / "findings", outside)
    with pytest.raises(UnsafePathError):
        repo.delete_project(project.project_id)
    assert (outside / "keep.txt").read_text() == "keep"
    assert repo.get_project(project.project_id) == project


def test_relative_display_never_absolute(tmp_path: Path) -> None:
    paths = SafePaths(tmp_path)
    assert paths.relative(paths.path("projects", "x.json")) == "projects/x.json"
    assert paths.relative(Path("/somewhere/else")) == "<outside-data-root>"
