"""ZAP integration: detection-only (no JVM launch), argv construction, output parsing.

This is the first increment of a ZAP-powered web scanner (TBD-079) — detection and an
explicit self-test only, following the same safety posture as nmap/sslyze/testssl.sh. No
test here launches a real JVM; `test_integrations.py` covers the self-test's wiring with a
mocked process, and this file covers the pure, JVM-free logic in `app/integrations/zap.py`.
"""

from __future__ import annotations

from pathlib import Path

from app.integrations.zap import (
    detect_zap,
    parse_selftest_output,
    selftest_argv,
)


def _touch_jar(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    jar = directory / name
    jar.write_bytes(b"not a real jar, just a filename-detection fixture")
    return jar


def test_detect_zap_picks_the_newest_jar_in_an_install_directory(tmp_path: Path) -> None:
    install_dir = tmp_path / "zap_install"
    _touch_jar(install_dir, "zap-2.16.1.jar")  # an older jar left over from an upgrade
    _touch_jar(install_dir, "zap-2.17.0.jar")
    found = detect_zap(str(install_dir))
    assert found is not None
    assert found.version == "2.17.0"
    assert found.jar_path.endswith("zap-2.17.0.jar")
    assert found.install_dir == str(install_dir)


def test_detect_zap_accepts_a_direct_jar_path(tmp_path: Path) -> None:
    jar = _touch_jar(tmp_path, "zap-2.17.0.jar")
    found = detect_zap(str(jar))
    assert found is not None and found.version == "2.17.0"


def test_detect_zap_returns_none_for_an_empty_or_non_matching_directory(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert detect_zap(str(empty)) is None
    # a file that isn't a zap-*.jar-shaped name is never mistaken for one
    not_zap = tmp_path / "not-zap.jar"
    not_zap.write_bytes(b"x")
    assert detect_zap(str(not_zap)) is None


def test_detect_zap_rejects_a_nonexistent_configured_path(tmp_path: Path) -> None:
    assert detect_zap(str(tmp_path / "does-not-exist")) is None


def test_detect_zap_with_no_configuration_never_searches_an_arbitrary_directory(
    tmp_path: Path,
) -> None:
    # A directory that is not one of the documented candidate locations and was never
    # configured must never be found — detection must not silently search the filesystem.
    # (The environment this test runs in may genuinely have ZAP installed in one of the
    # real candidate locations; the only thing asserted here is that this unrelated,
    # never-configured directory is not what detection found.)
    install_dir = tmp_path / "some_random_place"
    _touch_jar(install_dir, "zap-2.17.0.jar")
    found = detect_zap("")
    if found is not None:
        assert found.install_dir != str(install_dir)


def test_selftest_argv_never_touches_the_operators_real_zap_profile(tmp_path: Path) -> None:
    jar = _touch_jar(tmp_path, "zap-2.17.0.jar")
    installation = detect_zap(str(jar))
    assert installation is not None
    isolated_home = tmp_path / "app_managed_scratch"
    argv = selftest_argv("/usr/bin/java", installation, isolated_home)
    assert argv[0] == "/usr/bin/java"
    assert argv[1:4] == ["-jar", installation.jar_path, "-cmd"]
    assert "-version" in argv
    # `-dir` always points at the caller-supplied, app-managed scratch directory — never
    # a bare "ZAP" default that would resolve to the operator's own profile.
    assert argv[argv.index("-dir") + 1] == str(isolated_home)
    for unsafe in ("-daemon", "-port", "-config", "-autorun"):
        assert unsafe not in argv


def test_parse_selftest_output_finds_the_version_among_jvm_log_noise() -> None:
    # Observed directly against a real ZAP 2.17.0 install: INFO log lines and deprecation
    # warnings surround the actual version line, which must still be the one line selected.
    stdout = (
        b"887 [main] INFO  org.parosproxy.paros.Constant - Copying default configuration\n2.17.0\n"
    )
    stderr = (
        b"WARNING: A terminally deprecated method in sun.misc.Unsafe has been called\n"
        b"WARNING: sun.misc.Unsafe::objectFieldOffset has been called\n"
    )
    assert parse_selftest_output(stdout, stderr) == "2.17.0"


def test_parse_selftest_output_never_mistakes_a_log_line_for_a_version() -> None:
    stdout = b"887 [main] INFO  org.parosproxy.paros.Constant - Copying default configuration\n"
    stderr = b"WARNING: something failed\n"
    assert parse_selftest_output(stdout, stderr) == ""


def test_parse_selftest_output_handles_empty_output() -> None:
    assert parse_selftest_output(b"", b"") == ""
