"""Pinned Docker images and argv builders for the repo_scan engines (Docker-based execution
roadmap, phase 2 of 5, TBD-091). Every pinned tag below was independently confirmed by a
real `docker pull`/`docker run` on the development machine (see TBD-091) -- this file
exercises the pure argv-building logic only.
"""

from __future__ import annotations

import pytest

from app.scanners.repo_scan.docker_images import (
    DOCKER_IMAGES,
    DockerImageError,
    build_pull_argv,
    build_verify_argv,
    image_for,
)


def test_every_engine_has_a_pinned_image() -> None:
    assert set(DOCKER_IMAGES) == {"semgrep", "gitleaks", "trivy"}
    for image in DOCKER_IMAGES.values():
        assert ":" in image  # always a pinned tag, never a bare/implicit "latest"


def test_image_for_rejects_an_unknown_engine() -> None:
    with pytest.raises(DockerImageError):
        image_for("nuclei")


def test_build_pull_argv_is_exactly_docker_pull_the_pinned_image() -> None:
    argv = build_pull_argv("/usr/bin/docker", "semgrep")
    assert argv == ["/usr/bin/docker", "pull", "semgrep/semgrep:1.182.1"]


def test_build_verify_argv_for_semgrep_always_prefixes_the_tool_name() -> None:
    """Confirmed directly (TBD-091): the official semgrep/semgrep image has no ENTRYPOINT,
    only a default CMD of `semgrep --help` -- `docker run --rm <image> --version` would
    replace the whole command and fail trying to exec "--version" as a program. Every
    invocation must start with the literal word "semgrep" itself."""
    argv = build_verify_argv("/usr/bin/docker", "semgrep")
    assert argv == [
        "/usr/bin/docker",
        "run",
        "--rm",
        "semgrep/semgrep:1.182.1",
        "semgrep",
        "--version",
    ]


def test_build_verify_argv_for_gitleaks_and_trivy_use_their_own_entrypoints() -> None:
    gitleaks_argv = build_verify_argv("/usr/bin/docker", "gitleaks")
    assert gitleaks_argv == [
        "/usr/bin/docker",
        "run",
        "--rm",
        "ghcr.io/gitleaks/gitleaks:v8.30.1",
        "version",
    ]
    trivy_argv = build_verify_argv("/usr/bin/docker", "trivy")
    assert trivy_argv == [
        "/usr/bin/docker",
        "run",
        "--rm",
        "aquasec/trivy:0.76.1",
        "--version",
    ]


def test_build_verify_argv_rejects_an_unknown_engine() -> None:
    with pytest.raises(DockerImageError):
        build_verify_argv("/usr/bin/docker", "nuclei")
