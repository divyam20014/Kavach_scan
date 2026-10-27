"""Container image scan profile and parameters (security/reliability/scope roadmap Phase 3,
TBD-110). Mirrors `app/scanners/repo_scan/profile.py`'s own parameter-parsing shape, trimmed
to Trivy only -- one engine, one operator-supplied target (an image reference), not three
engines against a project's own repository.

Safety posture: the image must already be present on the local Docker daemon. This module
never triggers a registry pull -- see `app/scanners/container_image/trivy_argv.py`'s own
`--image-src docker` flag, confirmed directly against a real Trivy 0.76.1 run (TBD-110): a
locally-absent image fails cleanly with no fallback to a remote source, rather than this
application deciding whether to validate or restrict a registry URL itself (an operator-
confirmed scope decision -- Docker-mode execution and remote-pull support were both
deliberately deferred).
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import Field

from app.models.common import StrictModel
from app.models.project import ScanPolicy

PROFILE_VERSION = 1
MIN_TIMEOUT_MINUTES = 1
MAX_TIMEOUT_MINUTES = 60
DEFAULT_TIMEOUT_MINUTES = 5
MAX_IMAGE_REF_LENGTH = 255

# A deliberately conservative subset of Docker's own reference grammar: lowercase
# registry/repository path components (optionally with a `:port` on the first one),
# an optional `:tag`, and/or an optional `@sha256:<64 hex>` digest. Permissive enough for
# real-world references (`alpine:3.18`, `myregistry.local:5000/team/app:1.2.3`,
# `app@sha256:...`) without accepting shell metacharacters or anything else that would be
# unsafe to place directly into an argv list (not a shell string, but still validated as a
# defense-in-depth input shape check, consistent with every other adapter in this project).
IMAGE_REF_PATTERN = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?"
    r"(?:@sha256:[0-9a-f]{64})?$"
)

# parameter name -> (type, default, description). Unknown names are rejected at submit.
PARAMETERS: dict[str, tuple[type, Any, str]] = {
    "image": (str, "", "The already-pulled image reference to scan, e.g. 'myapp:1.2.3'"),
    "timeout_minutes": (int, DEFAULT_TIMEOUT_MINUTES, "Bounded Trivy scan duration, minutes"),
}

LIMITATIONS = [
    "The image must already be present on the local Docker daemon (`docker pull`/`docker "
    "build` it first); this scan never triggers a registry pull itself.",
    "Trivy's vulnerability matches are based on package name/version against its own "
    "database; a match proves a vulnerable version is present, not that the vulnerable "
    "code path is reachable or was ever exploited.",
    "Trivy's vulnerability database is downloaded once, explicitly, from the Integrations "
    "page -- never automatically by a scan -- and may be out of date if not refreshed.",
    "Only the image's OS/language packages are checked for known vulnerabilities "
    "(`--scanners vuln`); misconfiguration and secret scanning of the image are not run.",
]


class ContainerImageProfile(StrictModel):
    profile_version: int = PROFILE_VERSION
    image: str
    timeout_minutes: int = DEFAULT_TIMEOUT_MINUTES
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))


def validate_parameters(params: dict[str, Any], policy: ScanPolicy) -> list[str]:
    """Return human-readable problems; empty means the parameters are acceptable. Tool
    *availability* (is trivy installed? has its database been downloaded?) is checked
    separately by `ContainerImageRunner.validate_parameters`, not here."""
    errors: list[str] = []
    for name, value in params.items():
        if name not in PARAMETERS:
            errors.append(f"unknown parameter {name!r} for the container image scanner")
            continue
        kind = PARAMETERS[name][0]
        if value is None:
            continue
        if kind is int and (isinstance(value, bool) or not isinstance(value, int)):
            errors.append(f"{name} must be an integer")
        elif kind is str and not isinstance(value, str):
            errors.append(f"{name} must be text")
    image = params.get("image")
    if not isinstance(image, str) or not image.strip():
        errors.append("image is required")
    elif len(image) > MAX_IMAGE_REF_LENGTH:
        errors.append(f"image must be at most {MAX_IMAGE_REF_LENGTH} characters")
    elif not IMAGE_REF_PATTERN.match(image):
        errors.append("image does not look like a valid image reference")
    minutes = params.get("timeout_minutes")
    if (
        isinstance(minutes, int)
        and not isinstance(minutes, bool)
        and not MIN_TIMEOUT_MINUTES <= minutes <= MAX_TIMEOUT_MINUTES
    ):
        errors.append(
            f"timeout_minutes must be between {MIN_TIMEOUT_MINUTES} and {MAX_TIMEOUT_MINUTES}"
        )
    return errors


def build_profile(params: dict[str, Any]) -> ContainerImageProfile:
    image = params.get("image")
    minutes = params.get("timeout_minutes")
    return ContainerImageProfile(
        image=image.strip() if isinstance(image, str) else "",
        timeout_minutes=(int(minutes) if isinstance(minutes, int) else DEFAULT_TIMEOUT_MINUTES),
    )
