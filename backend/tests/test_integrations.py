"""Phase 11: integrations status, no-target-traffic self-test, and settings validation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import app.services.integrations as integrations_mod
from app.models.settings import IntegrationsSettings
from app.services.integrations import (
    TOOL_IDS,
    UnknownIntegrationError,
    list_integration_statuses,
    run_selftest,
)
from app.storage.repository import StorageRepository


def _set_tool_path(repo: StorageRepository, tool_id: str, path: str) -> None:
    field = {"nmap": "nmap_path", "sslyze": "sslyze_path", "testssl.sh": "testssl_path"}[tool_id]
    settings = repo.get_settings()
    settings.integrations = IntegrationsSettings(**{field: path})
    repo.save_settings(settings)


def _write_script(tmp_path: Path, code: str) -> Path:
    script = tmp_path / "fake_tool.py"
    script.write_text(code)
    return script


# ---------------------------------------------------------------- detection status


def test_list_integration_statuses_reports_not_configured_when_nothing_is_set(
    repo: StorageRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(integrations_mod, "detect_nmap", lambda: None)
    monkeypatch.setattr(integrations_mod, "detect_tls_tools", lambda: [])
    statuses = {s.id: s for s in list_integration_statuses(repo)}
    assert set(statuses) == set(TOOL_IDS)
    for s in statuses.values():
        assert s.status == "not_configured"
        assert s.version == ""  # detection never runs a subprocess


def test_list_integration_statuses_reports_not_found_for_a_configured_missing_path(
    repo: StorageRepository,
) -> None:
    _set_tool_path(repo, "nmap", str(Path("does", "not", "exist", "nmap.exe").absolute()))
    statuses = {s.id: s for s in list_integration_statuses(repo)}
    assert statuses["nmap"].status == "not_found"
    assert statuses["nmap"].configured_path


def test_list_integration_statuses_reports_detected_for_a_real_configured_path(
    repo: StorageRepository,
) -> None:
    _set_tool_path(repo, "nmap", sys.executable)
    statuses = {s.id: s for s in list_integration_statuses(repo)}
    assert statuses["nmap"].status == "detected"
    assert statuses["nmap"].version == ""  # still unverified: no self-test ran


def test_list_never_shows_a_merely_detected_tool_as_verified(repo: StorageRepository) -> None:
    _set_tool_path(repo, "sslyze", sys.executable)
    statuses = {s.id: s for s in list_integration_statuses(repo)}
    assert statuses["sslyze"].status != "verified"


# ---------------------------------------------------------------- self-test


def test_selftest_rejects_an_unknown_tool(repo: StorageRepository) -> None:
    with pytest.raises(UnknownIntegrationError):
        run_selftest(repo, "not-a-real-tool")


def test_selftest_missing_binary_reports_not_configured_not_an_error(
    repo: StorageRepository,
) -> None:
    result = run_selftest(repo, "nmap")
    assert result.status == "not_configured"
    assert result.version == ""
    assert result.last_error == ""  # missing is not an "error" state; it's a clear skip


def test_selftest_succeeds_against_a_real_executable(repo: StorageRepository) -> None:
    _set_tool_path(repo, "nmap", sys.executable)
    result = run_selftest(repo, "nmap")
    assert result.status == "verified"
    assert result.version  # python's own --version banner, used as a generic smoke test
    assert result.last_error == ""


def test_selftest_reports_an_error_for_a_tool_that_produces_no_version_output(
    repo: StorageRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_script(tmp_path, "pass\n")  # exits silently, no output at all
    _set_tool_path(repo, "nmap", sys.executable)
    monkeypatch.setattr(
        integrations_mod, "_version_args", lambda tool_id, executable: [str(script)]
    )
    result = run_selftest(repo, "nmap")
    assert result.status == "error"
    assert "no readable version output" in result.last_error


def test_selftest_never_reports_verified_for_an_invalid_executable_that_exits_nonzero(
    repo: StorageRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A binary that doesn't understand `--version` (wrong/unsupported version, or an
    invalid executable masquerading as the tool) often still prints *something* — usually an
    error message, to stderr, with a non-zero exit code. That text must never be reported as
    a verified version: this is exactly the false-pass the self-test exists to prevent."""
    script = _write_script(
        tmp_path,
        "import sys\nprint('Error: unrecognized option --version', file=sys.stderr)\nsys.exit(2)\n",
    )
    _set_tool_path(repo, "nmap", sys.executable)
    monkeypatch.setattr(
        integrations_mod, "_version_args", lambda tool_id, executable: [str(script)]
    )
    result = run_selftest(repo, "nmap")
    assert result.status == "error"
    assert result.version == ""
    assert "exited with status 2" in result.last_error
    assert "unrecognized option" in result.last_error


def test_selftest_reports_a_clean_error_for_an_invalid_executable(
    repo: StorageRepository,
    tmp_path: Path,
) -> None:
    """A configured path can point at a file that exists but is not a real, runnable
    executable (wrong format, no execute permission). The OS rejects launching it before a
    process ever starts, surfaced by `subprocess.Popen` as a plain `OSError` — this must
    become a clean self-test error, never an unhandled exception / 500."""
    bogus = tmp_path / "fake_nmap.exe"
    bogus.write_text("this is not a real executable\n")
    _set_tool_path(repo, "nmap", str(bogus))
    result = run_selftest(repo, "nmap")
    assert result.status == "error"
    assert result.last_error
    assert result.version == ""


def test_selftest_times_out_on_a_hanging_tool(
    repo: StorageRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_script(tmp_path, "import time\ntime.sleep(30)\n")
    _set_tool_path(repo, "nmap", sys.executable)
    monkeypatch.setattr(
        integrations_mod, "_version_args", lambda tool_id, executable: [str(script)]
    )
    monkeypatch.setattr(integrations_mod, "_SELFTEST_TIMEOUT_SECONDS", 0.5)
    result = run_selftest(repo, "nmap")
    assert result.status == "error"
    assert "did not respond" in result.last_error


def test_selftest_handles_binary_garbage_output_without_crashing(
    repo: StorageRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed (non-UTF-8) output must be decoded defensively, never crash the self-test."""
    script = _write_script(
        tmp_path,
        "import sys\nsys.stdout.buffer.write(bytes([0xff, 0xfe, 0x00, 0x01, 0x02]))\n",
    )
    _set_tool_path(repo, "nmap", sys.executable)
    monkeypatch.setattr(
        integrations_mod, "_version_args", lambda tool_id, executable: [str(script)]
    )
    result = run_selftest(repo, "nmap")
    assert result.status in ("verified", "error")  # must not raise


def test_selftest_handles_oversized_output_without_hanging_or_crashing(
    repo: StorageRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _write_script(
        tmp_path,
        'print("Fake Tool 9.9.9")\nimport sys\nsys.stdout.write("x" * (64 * 1024 * 1024))\n',
    )
    _set_tool_path(repo, "nmap", sys.executable)
    monkeypatch.setattr(
        integrations_mod, "_version_args", lambda tool_id, executable: [str(script)]
    )
    result = run_selftest(repo, "nmap")
    assert result.status == "verified"
    assert result.version == "Fake Tool 9.9.9"  # first line captured despite megabytes after it


def test_selftest_result_is_reflected_immediately_without_restart(
    repo: StorageRepository,
) -> None:
    assert run_selftest(repo, "nmap").status == "not_configured"
    _set_tool_path(repo, "nmap", sys.executable)
    assert run_selftest(repo, "nmap").status == "verified"


# ---------------------------------------------------------------- last-use lookup


def test_last_used_reflects_a_real_scan_without_any_runner_code_change(
    repo: StorageRepository,
) -> None:
    from tests.conftest import new_id
    from tests.surfacefixtures import surface_project

    pid = repo.create_project(surface_project([80], hosts=["x.test"])).project_id
    from app.models.common import ScanModule, utc_now
    from app.models.scan import ScanJob

    scan = repo.create_scan(
        ScanJob(
            scan_id=new_id("scan"),
            project_id=pid,
            module=ScanModule.ATTACK_SURFACE,
            tool_versions={"nmap": "Nmap 7.93"},
            queued_at=utc_now(),
        )
    )
    statuses = {s.id: s for s in list_integration_statuses(repo)}
    assert statuses["nmap"].last_used is not None
    assert statuses["nmap"].last_used.scan_id == scan.scan_id
    assert statuses["nmap"].last_used.version == "Nmap 7.93"


# ---------------------------------------------------------------- settings validation


def test_tool_path_setting_rejects_a_relative_path() -> None:
    with pytest.raises(Exception, match="absolute"):
        IntegrationsSettings(nmap_path="relative/path/nmap")


def test_tool_path_setting_accepts_empty_string_for_auto_detect() -> None:
    assert IntegrationsSettings(nmap_path="").nmap_path == ""


def test_credential_alias_rejects_a_raw_looking_secret() -> None:
    # Built from fragments at runtime (never a single secret-shaped literal in source) so a
    # secret scanner never mistakes this synthetic test value for a real provider credential.
    not_a_real_key = "-".join(("not", "a", "real", "credential", "0123456789abcdef"))
    with pytest.raises(Exception, match="reference"):
        IntegrationsSettings(online_lookup_credential_alias=not_a_real_key)


def test_credential_alias_accepts_env_and_keychain_references() -> None:
    assert (
        IntegrationsSettings(
            online_lookup_credential_alias="env:MY_API_KEY"
        ).online_lookup_credential_alias
        == "env:MY_API_KEY"
    )
    assert (
        IntegrationsSettings(
            online_lookup_credential_alias="keychain:my-entry"
        ).online_lookup_credential_alias
        == "keychain:my-entry"
    )


def test_app_settings_round_trips_integrations_through_storage(repo: StorageRepository) -> None:
    settings = repo.get_settings()
    settings.integrations = IntegrationsSettings(nmap_path=sys.executable)
    saved = repo.save_settings(settings)
    assert saved.integrations.nmap_path == sys.executable
    reloaded = repo.get_settings()
    assert reloaded.integrations.nmap_path == sys.executable
