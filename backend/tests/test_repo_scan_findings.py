"""RepoScanFindingWriter: Semgrep/Gitleaks/Trivy findings -> canonical Finding records,
with dedup/reobserve on a second scan (roadmap Phase 2, TBD-087)."""

from __future__ import annotations

from app.models.common import Confidence, Severity, new_id
from app.scanners.repo_scan.findings import RepoScanFindingWriter
from app.scanners.repo_scan.gitleaks_adapter import GitleaksFinding
from app.scanners.repo_scan.semgrep_adapter import SemgrepFinding
from app.scanners.repo_scan.trivy_adapter import (
    TrivyFinding,
    TrivyLicenseFinding,
    TrivyMisconfigFinding,
)
from app.storage.repository import StorageRepository
from tests.conftest import make_project


def _project(repo: StorageRepository) -> str:
    return repo.create_project(make_project()).project_id


def test_write_semgrep_creates_a_finding_with_no_url_and_correct_fields(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    writer = RepoScanFindingWriter(repo, pid, new_id("scan"))
    f = SemgrepFinding(
        check_id="python.lang.security.audit.eval-detected.eval-detected",
        path="app.py",
        start_line=3,
        end_line=3,
        message="Detected the use of eval().",
        severity_raw="WARNING",
        confidence_raw="MEDIUM",
        cwe_ids=[95],
    )
    finding_id = writer.write_semgrep(f, tool_version="Semgrep 1.182.1")
    finding = repo.get_finding(pid, finding_id)
    assert finding.url is None
    assert finding.component == "app.py:3"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.POTENTIAL
    assert finding.rule_id == f.check_id
    assert finding.cwe_ids == [95]
    assert finding.category == "repo_scan_semgrep"


def test_write_gitleaks_never_stores_a_secret_value(repo: StorageRepository) -> None:
    pid = _project(repo)
    writer = RepoScanFindingWriter(repo, pid, new_id("scan"))
    f = GitleaksFinding(
        rule_id="generic-api-key",
        description="Detected a Generic API Key.",
        path="config.py",
        start_line=2,
        end_line=2,
        fingerprint_raw="config.py:generic-api-key:2",
    )
    finding_id = writer.write_gitleaks(f, tool_version="Gitleaks 8.30.1")
    finding = repo.get_finding(pid, finding_id)
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.POTENTIAL
    assert finding.component == "config.py:2"
    dump = finding.model_dump_json()
    assert "REDACTED" not in dump  # never even the post-redaction placeholder, by construction


def test_write_trivy_sets_component_to_package_at_version_and_remediation(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    writer = RepoScanFindingWriter(repo, pid, new_id("scan"))
    f = TrivyFinding(
        vulnerability_id="CVE-2019-14234",
        pkg_name="django",
        installed_version="1.11.0",
        fixed_version="1.11.23, 2.1.11, 2.2.4",
        target="requirements.txt",
        title="Django: SQL injection",
        severity_raw="CRITICAL",
        status="fixed",
        cwe_ids=[89],
    )
    finding_id = writer.write_trivy(f, tool_version="Trivy 0.76.1")
    finding = repo.get_finding(pid, finding_id)
    assert finding.component == "django@1.11.0"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == Confidence.PROBABLE
    assert "1.11.23" in finding.remediation
    assert finding.cwe_ids == [89]


def test_write_trivy_misconfig_has_no_cwe_mapping_and_a_separate_category(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    writer = RepoScanFindingWriter(repo, pid, new_id("scan"))
    f = TrivyMisconfigFinding(
        check_id="DS-0002",
        title="Image user should not be 'root'",
        message="Last USER command in Dockerfile should not be 'root'",
        description="Running containers with 'root' user can lead to a container escape.",
        resolution="Add 'USER <non root user name>' line to the Dockerfile",
        severity_raw="HIGH",
        target="Dockerfile",
        resource="",
        start_line=2,
        end_line=2,
    )
    finding_id = writer.write_trivy_misconfig(f, tool_version="Trivy 0.76.1")
    finding = repo.get_finding(pid, finding_id)
    assert finding.category == "repo_scan_trivy_iac"  # never conflated with repo_scan_trivy
    assert finding.component == "Dockerfile"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.PROBABLE
    assert finding.cwe_ids == []  # Trivy gives no CWE mapping for misconfigurations
    assert "USER" in finding.remediation
    assert finding.rule_id == "DS-0002"


def test_write_trivy_license_uses_a_separate_category_and_namespace(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    writer = RepoScanFindingWriter(repo, pid, new_id("scan"))
    f = TrivyLicenseFinding(
        name="GPL-3.0",
        category="restricted",
        confidence=0.95,
        file_path="vendor/COPYING",
        pkg_name="",
        link="https://spdx.org/licenses/GPL-3.0-only.html",
    )
    assert f.is_actionable is True
    finding_id = writer.write_trivy_license(f, tool_version="Trivy 0.76.1")
    finding = repo.get_finding(pid, finding_id)
    assert finding.category == "repo_scan_trivy_license"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.PROBABLE
    assert finding.rule_id == "GPL-3.0"
    assert finding.references == ["https://spdx.org/licenses/GPL-3.0-only.html"]


def test_a_second_write_of_the_same_finding_reobserves_rather_than_duplicates(
    repo: StorageRepository,
) -> None:
    pid = _project(repo)
    f = SemgrepFinding(
        check_id="x",
        path="a.py",
        start_line=1,
        end_line=1,
        message="m",
        severity_raw="ERROR",
        confidence_raw="HIGH",
    )
    writer1 = RepoScanFindingWriter(repo, pid, new_id("scan"))
    id1 = writer1.write_semgrep(f, tool_version="Semgrep")
    second_scan_id = new_id("scan")
    writer2 = RepoScanFindingWriter(repo, pid, second_scan_id)
    id2 = writer2.write_semgrep(f, tool_version="Semgrep")
    assert id1 == id2
    assert writer2.reobserved == [id1]
    assert writer2.created == []
    finding = repo.get_finding(pid, id1)
    assert finding.scan_id == second_scan_id
    assert len(finding.sources) == 2
