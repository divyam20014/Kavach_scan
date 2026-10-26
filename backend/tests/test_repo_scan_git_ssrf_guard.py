"""Git-clone-from-URL roadmap, phase 4 of 6 (TBD-099): SSRF guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.models.project import InternalTargetOverride, ScopeDefinition, ScopeExclusions
from app.scanners.repo_scan.git_ssrf_guard import (
    CloneHostBlockedError,
    check_clone_host_not_blocked,
    extract_clone_host,
)
from app.scope.guard import ResolutionError
from tests.conftest import make_project


@dataclass
class FakeResolver:
    answers: dict[str, list[str]] = field(default_factory=dict)

    def resolve(self, host: str) -> list[str]:
        if host not in self.answers:
            raise ResolutionError("NXDOMAIN")
        return self.answers[host]


def test_extract_clone_host_reads_the_hostname_from_a_plain_https_url() -> None:
    assert extract_clone_host("https://github.com/octocat/Hello-World.git") == "github.com"


def test_extract_clone_host_rejects_a_url_with_no_host() -> None:
    with pytest.raises(CloneHostBlockedError):
        extract_clone_host("https:///no-host")


def test_allows_a_host_resolving_only_to_public_addresses() -> None:
    project = make_project()
    resolver = FakeResolver(answers={"github.com": ["140.82.121.3"]})
    check_clone_host_not_blocked("https://github.com/x/y.git", project, resolver)  # no raise


def test_blocks_a_host_resolving_to_a_private_range() -> None:
    project = make_project()
    resolver = FakeResolver(answers={"internal.example": ["10.0.0.5"]})
    with pytest.raises(CloneHostBlockedError, match="blocked"):
        check_clone_host_not_blocked("https://internal.example/x/y.git", project, resolver)


def test_blocks_a_host_resolving_to_cloud_metadata_even_with_an_override() -> None:
    project = make_project(
        scope=ScopeDefinition(
            internal_override=InternalTargetOverride(
                ip_ranges=["169.254.169.254/32"],
                reason="explicitly authorized internal target for this engagement",
                expires_at=datetime.now(UTC) + timedelta(days=1),
                audit_event_id="evt_" + "0" * 32,
            )
        )
    )
    resolver = FakeResolver(answers={"metadata.internal": ["169.254.169.254"]})
    with pytest.raises(CloneHostBlockedError, match="never allowed|cloud metadata"):
        check_clone_host_not_blocked("https://metadata.internal/x.git", project, resolver)


def test_blocks_a_literal_private_ip_in_the_url_without_any_dns_lookup() -> None:
    project = make_project()
    resolver = FakeResolver(answers={})  # never consulted: literal IP needs no resolution
    with pytest.raises(CloneHostBlockedError, match="blocked"):
        check_clone_host_not_blocked("https://127.0.0.1/x/y.git", project, resolver)


def test_blocks_when_any_one_of_multiple_resolved_addresses_is_blocked() -> None:
    project = make_project()
    resolver = FakeResolver(answers={"multi.example": ["8.8.8.8", "127.0.0.1"]})
    with pytest.raises(CloneHostBlockedError, match="blocked"):
        check_clone_host_not_blocked("https://multi.example/x.git", project, resolver)


def test_blocks_when_resolution_fails() -> None:
    project = make_project()
    resolver = FakeResolver(answers={})
    with pytest.raises(CloneHostBlockedError, match="could not resolve"):
        check_clone_host_not_blocked("https://no-such-host.invalid/x.git", project, resolver)


def test_honors_the_project_s_own_exclusions() -> None:
    """A host excluded by the project (normally an exclusion from an otherwise-allowed
    scope) is denied for the same reason an excluded IP is denied in `ScopePolicy` -- this
    guard reuses the exact same policy object, not a parallel implementation."""
    project = make_project(
        scope=ScopeDefinition(exclusions=ScopeExclusions(ip_ranges=["8.8.8.8/32"]))
    )
    resolver = FakeResolver(answers={"excluded.example": ["8.8.8.8"]})
    with pytest.raises(CloneHostBlockedError, match="excluded"):
        check_clone_host_not_blocked("https://excluded.example/x.git", project, resolver)


def test_real_dns_resolution_of_localhost_is_blocked_end_to_end() -> None:
    """Exercises the real OS resolver (`app.integrations.dns.system_lookup`), not a fake,
    to prove the end-to-end wiring -- `localhost` must resolve to a loopback address and
    must be blocked, on every real machine this runs on."""
    from app.integrations.dns import system_lookup

    class RealResolver:
        def resolve(self, host: str) -> list[str]:
            return system_lookup(host)

    project = make_project()
    with pytest.raises(CloneHostBlockedError, match="blocked"):
        check_clone_host_not_blocked("https://localhost/x/y.git", project, RealResolver())
