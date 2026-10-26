"""Status record for a pulled, pinned Docker image used by a repo_scan engine (Docker-based
execution roadmap, phase 2 of 5, TBD-091). Mirrors `app/models/trivy_db.py`'s own "presence
of this record is proof the operator explicitly triggered the action" shape -- pulling an
image is a real network fetch, so it is never triggered silently by a scan; see
`app/scanners/repo_scan/docker_images.py`'s own module docstring."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from app.models.common import ShortText, StrictModel, UtcDatetime, utc_now

DOCKER_IMAGE_STATUS_SCHEMA_VERSION: Literal[1] = 1


class DockerImageStatusRecord(StrictModel):
    schema_version: Literal[1] = DOCKER_IMAGE_STATUS_SCHEMA_VERSION
    image: ShortText  # the pinned "repository:tag" reference that was pulled
    digest: ShortText = ""  # "sha256:..." from the real pulled image, confirmed directly
    size_bytes: int = Field(default=0, ge=0)
    verified_version: ShortText = ""  # output of the post-pull verification run
    pulled_at: UtcDatetime = Field(default_factory=utc_now)
    revision: int = Field(default=1, ge=1)
