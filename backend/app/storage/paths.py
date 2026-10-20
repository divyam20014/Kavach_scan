"""Data-root resolution and path-safe joins.

Every filesystem path under the data root is produced by `SafePaths.path()`.
Untrusted strings never become path components: IDs are validated against
their type pattern first, and each component must also match a strict
allowlist. After joining, every existing component is `lstat`-checked for
symlinks/junctions and the result must stay inside the resolved root.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

from app.core.settings import RuntimeSettings, repo_root
from app.models.common import ID_PREFIXES, is_valid_id
from app.storage.errors import DataRootError, InvalidIdError, UnsafePathError

APP_DIR_NAME = "VAPTWorkbench"

_PART_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,199}$")
_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$", re.IGNORECASE)


def default_data_dir(env: dict[str, str] | None = None, platform: str = sys.platform) -> Path:
    source = dict(os.environ) if env is None else env
    home = Path(source.get("USERPROFILE") or source.get("HOME") or Path.home())
    if platform.startswith("win"):
        base = source.get("LOCALAPPDATA")
        return (Path(base) if base else home / "AppData" / "Local") / APP_DIR_NAME / "data"
    if platform == "darwin":
        return home / "Library" / "Application Support" / APP_DIR_NAME
    xdg = source.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else home / ".local" / "share") / "vapt-workbench"


def _checkout_root() -> Path | None:
    root = repo_root()
    if (root / ".git").exists() or (root / "MASTER_SPEC.md").exists():
        return root
    return None


def resolve_data_root(settings: RuntimeSettings, env: dict[str, str] | None = None) -> Path:
    """Resolve VAPT_DATA_DIR (or the per-user default) to a safe absolute directory."""
    raw = settings.data_dir
    candidate = Path(raw).expanduser() if raw else default_data_dir(env)
    if not candidate.is_absolute():
        raise DataRootError(f"VAPT_DATA_DIR must be an absolute path, got {raw!r}")
    resolved = candidate.resolve(strict=False)
    if resolved.parent == resolved:
        raise DataRootError("Refusing to use a filesystem or drive root as the data directory")
    if resolved.exists() and not resolved.is_dir():
        raise DataRootError(f"Data directory path exists and is not a directory: {resolved}")
    checkout = _checkout_root()
    if (
        checkout is not None
        and resolved.is_relative_to(checkout)
        and not settings.allow_repo_data_dir
    ):
        raise DataRootError(
            "Refusing to store runtime data inside the source checkout. Set VAPT_DATA_DIR to a "
            "directory outside the repository (see docs/STORAGE_FORMATS.md §1)."
        )
    return resolved


def is_link_like(path: Path) -> bool:
    """True for symlinks and (on Windows) directory junctions, without following them."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return path.is_junction()


def validate_id(kind: str, value: str) -> str:
    if kind not in ID_PREFIXES or not isinstance(value, str) or not is_valid_id(kind, value):
        raise InvalidIdError(f"Invalid {kind} id")
    return value


class SafePaths:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=False)

    @staticmethod
    def check_part(part: str) -> str:
        if (
            not isinstance(part, str)
            or not _PART_RE.fullmatch(part)
            or ".." in part
            or part.endswith((".", " "))
            or _WINDOWS_RESERVED.match(part)
        ):
            raise UnsafePathError("Unsafe path component rejected")
        return part

    def path(self, *parts: str) -> Path:
        for part in parts:
            self.check_part(part)
        candidate = self.root.joinpath(*parts)
        current = self.root
        for part in parts:
            current = current / part
            if is_link_like(current):
                raise UnsafePathError("Symlink or junction inside the data directory rejected")
        # Lexical containment (defense in depth). resolve() is deliberately not used: the
        # components are allowlisted and link-checked above, and on Windows resolve() of a
        # path inside a directory being renamed concurrently can return an unrelated path.
        normalized = Path(os.path.normpath(candidate))
        if normalized != candidate or not normalized.is_relative_to(self.root):
            raise UnsafePathError("Path escapes the data directory")
        return candidate

    def relative(self, path: Path) -> str:
        """Display form relative to the root (never exposes the absolute path)."""
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return "<outside-data-root>"


def display_path(path: Path) -> str:
    """Show a path with the user's home directory collapsed to `~`."""
    try:
        return "~/" + path.relative_to(Path.home()).as_posix()
    except ValueError:
        return path.as_posix()
