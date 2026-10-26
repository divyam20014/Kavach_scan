"""Git-clone-from-URL roadmap, phase 2 of 6 (TBD-097): pure argv builder and URL
validation. Every flag and the scheme restriction were confirmed directly against real
`git clone` invocations against a tiny public test repository
(`https://github.com/octocat/Hello-World.git`) on this machine -- see the module docstring
for the three real discoveries (blocked transport schemes, the credential-prompt hang risk,
and the confirmed-working shallow/partial-clone flags).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.scanners.repo_scan.git_clone import (
    GIT_CLONE_ENV,
    GitCloneArgvError,
    build_clone_argv,
    validate_https_url,
)


def test_build_clone_argv_matches_the_confirmed_working_invocation(tmp_path: Path) -> None:
    dest = tmp_path / "repo"
    argv = build_clone_argv("git", "https://github.com/octocat/Hello-World.git", dest)
    assert argv == [
        "git",
        "-c",
        "core.longpaths=true",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--filter=blob:limit=52428800",
        "https://github.com/octocat/Hello-World.git",
        str(dest),
    ]


def test_git_clone_env_always_disables_the_terminal_prompt() -> None:
    """Confirmed directly: without this, a repository requiring credentials Git doesn't
    have would otherwise prompt interactively and hang -- never an argv flag, since Git
    reads it as an environment variable."""
    assert GIT_CLONE_ENV == {"GIT_TERMINAL_PROMPT": "0"}


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/octocat/Hello-World.git",  # plain http, not https
        "git://github.com/octocat/Hello-World.git",
        "ssh://git@github.com/octocat/Hello-World.git",
        "file:///etc/passwd",
        "ext::sh -c id",
        "https://user:pass@github.com/octocat/Hello-World.git",  # embedded credentials
        "https://github.com/octocat/Hello-World.git with a space",
        "not-a-url-at-all",
        "",
    ],
)
def test_validate_https_url_rejects_every_non_plain_https_scheme(url: str) -> None:
    """Confirmed directly (TBD-097): a current Git install already refuses `ext::` by its
    own default, and still accepts `file://` -- this validator never relies on either of
    those being true on whatever machine runs this application."""
    with pytest.raises(GitCloneArgvError, match="https://"):
        validate_https_url(url)


def test_validate_https_url_accepts_a_plain_https_url() -> None:
    validate_https_url("https://github.com/octocat/Hello-World.git")  # must not raise


def test_build_clone_argv_rejects_a_non_https_url(tmp_path: Path) -> None:
    with pytest.raises(GitCloneArgvError, match="https://"):
        build_clone_argv("git", "file:///etc/passwd", tmp_path / "repo")


def test_build_clone_argv_rejects_out_of_range_timeout(tmp_path: Path) -> None:
    with pytest.raises(GitCloneArgvError, match="timeout_seconds"):
        build_clone_argv(
            "git",
            "https://github.com/octocat/Hello-World.git",
            tmp_path / "repo",
            timeout_seconds=1,
        )
    with pytest.raises(GitCloneArgvError, match="timeout_seconds"):
        build_clone_argv(
            "git",
            "https://github.com/octocat/Hello-World.git",
            tmp_path / "repo",
            timeout_seconds=99999,
        )


def test_build_clone_argv_rejects_out_of_range_max_blob_bytes(tmp_path: Path) -> None:
    with pytest.raises(GitCloneArgvError, match="max_blob_bytes"):
        build_clone_argv(
            "git",
            "https://github.com/octocat/Hello-World.git",
            tmp_path / "repo",
            max_blob_bytes=1,
        )
