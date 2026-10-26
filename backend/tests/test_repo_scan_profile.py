"""Repository scan profile parameter validation/building (roadmap Phase 2, TBD-087)."""

from __future__ import annotations

from app.models.project import ScanPolicy
from app.scanners.repo_scan.profile import build_profile, validate_parameters

POLICY = ScanPolicy()


def test_default_profile_runs_semgrep_only() -> None:
    profile = build_profile({})
    assert profile.engines == ["semgrep"]
    assert profile.semgrep_config == "p/security-audit"
    assert profile.semgrep_timeout_minutes == 5


def test_build_profile_accepts_an_explicit_engine_list() -> None:
    profile = build_profile({"engines": ["gitleaks", "trivy"]})
    assert profile.engines == ["gitleaks", "trivy"]


def test_build_profile_ignores_unknown_engine_names_falling_back_to_default() -> None:
    profile = build_profile({"engines": ["not-a-real-engine"]})
    assert profile.engines == ["semgrep"]


def test_validate_parameters_rejects_an_empty_engines_list() -> None:
    errors = validate_parameters({"engines": []}, POLICY)
    assert any("at least one engine" in e for e in errors)


def test_validate_parameters_rejects_an_engine_outside_the_allowed_set() -> None:
    errors = validate_parameters({"engines": ["nuclei"]}, POLICY)
    assert any("subset of" in e for e in errors)


def test_validate_parameters_rejects_a_repeated_engine() -> None:
    errors = validate_parameters({"engines": ["semgrep", "semgrep"]}, POLICY)
    assert any("not repeat" in e for e in errors)


def test_validate_parameters_rejects_an_unknown_semgrep_config() -> None:
    errors = validate_parameters({"semgrep_config": "file:///etc/passwd"}, POLICY)
    assert any("semgrep_config" in e for e in errors)


def test_validate_parameters_rejects_an_out_of_range_timeout() -> None:
    errors = validate_parameters({"trivy_timeout_minutes": 0}, POLICY)
    assert any("trivy_timeout_minutes" in e for e in errors)
    errors = validate_parameters({"trivy_timeout_minutes": 999}, POLICY)
    assert any("trivy_timeout_minutes" in e for e in errors)


def test_validate_parameters_rejects_an_unknown_parameter_name() -> None:
    errors = validate_parameters({"not_a_real_parameter": 1}, POLICY)
    assert any("unknown parameter" in e for e in errors)


def test_validate_parameters_accepts_a_full_valid_set() -> None:
    errors = validate_parameters(
        {
            "engines": ["semgrep", "gitleaks", "trivy"],
            "semgrep_config": "p/owasp-top-ten",
            "semgrep_timeout_minutes": 10,
            "gitleaks_timeout_minutes": 10,
            "trivy_timeout_minutes": 10,
        },
        POLICY,
    )
    assert errors == []
