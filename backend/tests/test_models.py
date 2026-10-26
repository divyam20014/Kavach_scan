import os
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.models import (
    AuditAction,
    AuditEvent,
    CvssRecord,
    EvidenceMetadata,
    Finding,
    ImportArtifact,
    Project,
    ScanJob,
    ScanPolicy,
    ScopeDefinition,
    new_id,
    sanitize_display_filename,
    severity_from_cvss,
)
from app.models.common import is_valid_id
from app.models.project import AuthorizationRecord, InternalTargetOverride
from tests.conftest import make_finding, make_project


def test_project_round_trip_and_defaults() -> None:
    project = make_project()
    again = Project.model_validate_json(project.model_dump_json())
    assert again == project
    assert project.schema_version == 1
    assert project.scope.schemes == ["https"]
    assert project.scan_policy.active_probes.sqli_error_differential is False
    assert project.scan_policy.max_concurrency == 2


def test_repository_path_accepts_an_absolute_path_and_rejects_a_relative_one() -> None:
    """Roadmap Phase 2 (TBD-087): mirrors `ToolPath`'s own posture -- never required to
    exist at model-validation time (that's a runtime check, see `RepoScanRunner`), but
    always absolute, never a bare relative path."""
    abs_path = str(Path("srv", "some-repo").absolute())
    assert os.path.isabs(abs_path)
    project = make_project(repository_path=abs_path)
    assert project.repository_path == abs_path
    project_empty = make_project()
    assert project_empty.repository_path == ""
    with pytest.raises(ValidationError):
        make_project(repository_path="relative/path")


def test_repository_url_accepts_a_plain_https_url_and_rejects_other_schemes() -> None:
    """Git-clone-from-URL roadmap, phase 5 (TBD-100): mirrors
    `app.scanners.repo_scan.git_clone.validate_https_url`'s own restriction, independently."""
    project = make_project(repository_url="https://github.com/octocat/Hello-World.git")
    assert project.repository_url == "https://github.com/octocat/Hello-World.git"
    assert make_project().repository_url == ""
    with pytest.raises(ValidationError):
        make_project(repository_url="http://github.com/octocat/Hello-World.git")
    with pytest.raises(ValidationError):
        make_project(repository_url="https://user:pass@github.com/x.git")


def test_repository_path_and_repository_url_are_mutually_exclusive() -> None:
    abs_path = str(Path("srv", "some-repo").absolute())
    with pytest.raises(ValidationError, match="mutually exclusive"):
        make_project(
            repository_path=abs_path, repository_url="https://github.com/octocat/Hello-World.git"
        )


def test_repository_credential_alias_requires_a_repository_url() -> None:
    with pytest.raises(ValidationError, match="requires repository_url"):
        make_project(repository_credential_alias="env:SOME_TOKEN")
    # with a URL, a valid alias is accepted
    project = make_project(
        repository_url="https://github.com/octocat/Hello-World.git",
        repository_credential_alias="env:SOME_TOKEN",
    )
    assert project.repository_credential_alias == "env:SOME_TOKEN"


def test_allowed_modules_permits_all_four_modules_including_repo_scan() -> None:
    policy = ScanPolicy(allowed_modules=["web_app", "attack_surface", "api_security", "repo_scan"])
    assert len(policy.allowed_modules) == 4
    with pytest.raises(ValidationError):
        ScanPolicy(
            allowed_modules=[
                "web_app",
                "attack_surface",
                "api_security",
                "repo_scan",
                "self_test",
            ]
        )


def test_unknown_keys_rejected_everywhere() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        Project.model_validate(make_project().model_dump() | {"db_url": "x"})
    with pytest.raises(ValidationError):
        ScanPolicy(threads=50)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "kind", ["project", "scan", "asset", "finding", "evidence", "import", "report", "event"]
)
def test_ids_are_prefixed_and_validated(kind: str) -> None:
    value = new_id(kind)
    assert is_valid_id(kind, value)
    assert not is_valid_id(kind, value.upper())
    assert not is_valid_id(kind, "../" + value)


@pytest.mark.parametrize("bad", ["prj_123", "PRJ_" + "a" * 32, "prj_" + "g" * 32, "../etc", ""])
def test_bad_project_ids_rejected(bad: str) -> None:
    with pytest.raises(ValidationError):
        make_project(project_id=bad)


def test_bounded_strings_and_lists() -> None:
    with pytest.raises(ValidationError):
        make_project(name="x" * 201)
    with pytest.raises(ValidationError):
        make_project(name="")
    with pytest.raises(ValidationError):
        make_project(name="bad\x00name")
    with pytest.raises(ValidationError):
        make_project(labels=["ok"] * 51)


def test_enums_enforced() -> None:
    pid = new_id("project")
    with pytest.raises(ValidationError):
        make_finding(pid, severity="severe")
    with pytest.raises(ValidationError):
        make_finding(pid, confidence="certain")
    with pytest.raises(ValidationError):
        ScanJob(scan_id=new_id("scan"), project_id=pid, module="exploit")  # type: ignore[arg-type]


def test_authorization_window_must_be_ordered() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="window_end"):
        AuthorizationRecord(
            organization="a", target_owner="b", authorized_by="c", window_start=now, window_end=now
        )


def test_naive_datetimes_rejected_and_aware_normalized_to_utc() -> None:
    with pytest.raises(ValidationError):
        AuthorizationRecord(
            organization="a",
            target_owner="b",
            authorized_by="c",
            window_start=datetime(2026, 1, 1),
            window_end=datetime(2026, 2, 1),
        )
    ist = timezone(timedelta(hours=5, minutes=30))
    rec = AuthorizationRecord(
        organization="a",
        target_owner="b",
        authorized_by="c",
        window_start=datetime(2026, 1, 1, 5, 30, tzinfo=ist),
        window_end=datetime(2026, 2, 1, tzinfo=ist),
    )
    assert rec.window_start == datetime(2026, 1, 1, tzinfo=UTC)
    assert rec.window_start.tzinfo == UTC


@pytest.mark.parametrize(
    "field,value",
    [
        ("hosts", ["trusted.example.attacker.test/../x"]),
        ("hosts", ["has space.example"]),
        ("hosts", ["-bad.example"]),
        ("wildcard_domains", ["example.com"]),
        ("path_prefixes", ["no-leading-slash"]),
        ("path_prefixes", ["/a\\b"]),
        ("api_server_urls", ["ftp://example.com"]),
        ("api_server_urls", ["https://user:pass@example.com/api"]),
        ("schemes", ["file"]),
        ("ports", [0]),
        ("ports", [70000]),
    ],
)
def test_scope_syntax_rejects_bad_values(field: str, value: list[object]) -> None:
    with pytest.raises(ValidationError):
        ScopeDefinition(**{field: value})


def test_scope_normalizes_case_and_trailing_dot() -> None:
    scope = ScopeDefinition(hosts=["App.Example.COM."], wildcard_domains=["*.Example.com"])
    assert scope.hosts == ["app.example.com"]
    assert scope.wildcard_domains == ["*.example.com"]


def test_internal_override_requires_reason_and_audit() -> None:
    with pytest.raises(ValidationError):
        InternalTargetOverride(
            ip_ranges=["10.0.0.0/24"],
            reason="short",
            expires_at=datetime.now(UTC),
            audit_event_id=new_id("event"),
        )


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, "informational"),
        (0.1, "low"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (10.0, "critical"),
    ],
)
def test_severity_from_cvss_bands(score: float, expected: str) -> None:
    assert severity_from_cvss(score) == expected


@pytest.mark.parametrize("score", [-0.1, 10.1])
def test_severity_from_cvss_rejects_out_of_range(score: float) -> None:
    with pytest.raises(ValueError):
        severity_from_cvss(score)


def test_cvss_requires_valid_vector_for_version() -> None:
    ok = CvssRecord(
        version="3.1",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
        source="supplied",
    )
    assert ok.base_score == 9.8
    with pytest.raises(ValidationError):  # v4 vector labelled 3.1
        CvssRecord(
            version="3.1",
            vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            base_score=9.3,
            source="supplied",
        )
    with pytest.raises(ValidationError):  # garbage
        CvssRecord(version="3.1", vector="9.8", base_score=9.8, source="supplied")
    with pytest.raises(ValidationError):  # calculated without naming calculator
        CvssRecord(
            version="3.1",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
            source="calculated",
        )


def test_finding_has_no_bare_cvss_number() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(make_finding(new_id("project")).model_dump() | {"cvss_score": 9.8})


def test_evidence_excerpt_bounded() -> None:
    with pytest.raises(ValidationError):
        EvidenceMetadata(
            evidence_id=new_id("evidence"),
            project_id=new_id("project"),
            evidence_type="http_exchange",
            response_excerpt="x" * 9000,
        )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("report.xml", "report.xml"),
        ("..\\..\\windows\\evil.xml", "evil.xml"),
        ("/etc/passwd", "passwd"),
        ("a<b>:c|d?.json", "a_b__c_d_.json"),
        ("...", "upload"),
        ("\x00nul.txt", "_nul.txt"),
    ],
)
def test_display_filename_sanitized(raw: str, expected: str) -> None:
    assert sanitize_display_filename(raw) == expected


def test_import_requires_sanitized_filename() -> None:
    with pytest.raises(ValidationError):
        ImportArtifact(
            import_id=new_id("import"),
            project_id=new_id("project"),
            display_filename="../evil.xml",
            sha256="0" * 64,
            size_bytes=1,
        )


def test_audit_event_actions_are_enumerated() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(event_id=new_id("event"), action="drop_tables")  # type: ignore[arg-type]
    assert (
        AuditEvent(event_id=new_id("event"), action=AuditAction.PROJECT_CREATED).outcome
        == "success"
    )
