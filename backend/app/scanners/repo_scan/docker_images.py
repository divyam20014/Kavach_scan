"""Pinned Docker images for the repo_scan engines, and their pure argv builders (roadmap
Phase 2 enhancement, Docker-based execution phase 2 of 5, TBD-091).

Every tag below was independently pulled for real on this machine and confirmed to exist
and run correctly -- never assumed from a registry's web page. Pinned, not operator-
configurable (operator-confirmed design, TBD-090): an image tag is a dependency like any
other in this project, and this project pins every dependency it has.

A real, non-obvious discovery from that verification: the official `semgrep/semgrep` image
has **no `ENTRYPOINT`** -- only a default `CMD` of `["semgrep", "--help"]`. Running
`docker run --rm <image> --version` therefore replaces the *entire* command with the single
word `--version`, which Docker tries to exec as a program and fails ("executable file not
found in $PATH: --version") -- confirmed directly, not guessed. Every invocation of this
image must therefore always start with the literal word `semgrep` itself
(`docker run --rm <image> semgrep <args...>`), unlike Gitleaks' and Trivy's own images,
whose entrypoints already default to running their own tool.
"""

from __future__ import annotations

# engine -> pinned "repository:tag" reference, each confirmed by a real `docker pull` on
# this machine, matching the exact native-binary versions already verified in TBD-084/085/086.
DOCKER_IMAGES: dict[str, str] = {
    "semgrep": "semgrep/semgrep:1.182.1",
    "gitleaks": "ghcr.io/gitleaks/gitleaks:v8.30.1",
    "trivy": "aquasec/trivy:0.76.1",
}

ENGINES: tuple[str, ...] = ("semgrep", "gitleaks", "trivy")

# engine -> the argv appended after `docker run --rm <image>` to print a bare version
# string, confirmed directly against each real pulled image.
_VERIFY_ARGS: dict[str, list[str]] = {
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["version"],
    "trivy": ["--version"],
}


class DockerImageError(ValueError):
    """An unknown engine was requested; nothing is executed."""


def image_for(engine: str) -> str:
    if engine not in DOCKER_IMAGES:
        raise DockerImageError(f"engine must be one of {ENGINES}, got {engine!r}")
    return DOCKER_IMAGES[engine]


def build_pull_argv(docker_executable: str, engine: str) -> list[str]:
    """`docker pull <pinned image>` -- the only argv this module ever builds that reaches
    the network; always the exact pinned reference, never an operator-supplied one."""
    return [docker_executable, "pull", image_for(engine)]


def build_verify_argv(docker_executable: str, engine: str) -> list[str]:
    """`docker run --rm <pinned image> <engine's own version check>` -- run once right
    after a pull to prove the image doesn't just exist locally but actually executes in
    this environment (platform mismatch, missing permissions, etc. would otherwise only
    surface much later, during an actual scan)."""
    image = image_for(engine)
    return [docker_executable, "run", "--rm", image, *_VERIFY_ARGS[engine]]
