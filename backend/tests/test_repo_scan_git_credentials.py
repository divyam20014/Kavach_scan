"""Git-clone-from-URL roadmap, phase 3 of 6 (TBD-098): credential-alias resolution.

The end-to-end test below reproduces, with the exact shipped `ASKPASS_HELPER_SOURCE` and
`GIT_CREDENTIAL_ENV_VAR`, the real verification done directly on this machine before writing
`app/scanners/repo_scan/git_credentials.py`: a local HTTP server that challenges every
request with `401` + `WWW-Authenticate: Basic` until it sees the expected
`Authorization: Basic <...>` header, then serves a minimal, real git smart-HTTP
`info/refs` advertisement. `git ls-remote` against it, with `GIT_ASKPASS` pointed at the
shipped helper and the secret supplied only through `GIT_CREDENTIAL_ENV_VAR`, must receive
exactly that header on the retry -- proving Git invokes the helper, uses what it returns for
Basic auth, and that the secret never has to appear in this module's or `git clone`'s own
argv to get there.
"""

from __future__ import annotations

import base64
import http.server
import os
import shutil
import stat
import subprocess  # noqa: S404 - test-only call to the local git binary, fixed argv
import sys
import threading
from pathlib import Path

import pytest

from app.scanners.repo_scan.git_credentials import (
    ASKPASS_HELPER_SOURCE,
    ASKPASS_USERNAME_PLACEHOLDER,
    GIT_CREDENTIAL_ENV_VAR,
    build_credential_env,
    resolve_credential_alias,
)

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git binary not available")


def test_resolve_credential_alias_reads_the_named_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAVACH_TEST_ALIAS_TARGET", "s3cr3t-value")
    assert resolve_credential_alias("env:KAVACH_TEST_ALIAS_TARGET") == "s3cr3t-value"


def test_resolve_credential_alias_treats_an_unset_env_var_as_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KAVACH_TEST_ALIAS_ABSENT", raising=False)
    assert resolve_credential_alias("env:KAVACH_TEST_ALIAS_ABSENT") is None


def test_resolve_credential_alias_does_not_support_keychain_yet() -> None:
    """No resolver for `keychain:` exists anywhere in this codebase (see the module
    docstring) -- it must resolve the same way an unset `env:` variable does, never raise."""
    assert resolve_credential_alias("keychain:anything") is None


def test_resolve_credential_alias_treats_empty_as_unresolved() -> None:
    assert resolve_credential_alias("") is None


def test_build_credential_env_is_empty_without_a_secret() -> None:
    assert build_credential_env(None) == {}


def test_build_credential_env_carries_the_secret_only_in_the_named_var() -> None:
    env = build_credential_env("s3cr3t-value")
    assert env == {GIT_CREDENTIAL_ENV_VAR: "s3cr3t-value"}


def test_askpass_helper_source_never_echoes_the_prompt_text_itself() -> None:
    """Git passes the prompt text as argv[1]; the helper must never write that back out
    verbatim as if it were a credential, only the fixed placeholder or the env var."""
    assert "sys.argv[1]" not in ASKPASS_HELPER_SOURCE.split("\n", 1)[-1].replace(
        'prompt = sys.argv[1] if len(sys.argv) > 1 else ""', ""
    )


class _BasicAuthChallengeServer(http.server.HTTPServer):
    expected_auth_header: str = ""
    seen_auth_headers: list[str]

    def __init__(self, *a: object, **kw: object) -> None:
        super().__init__(*a, **kw)  # type: ignore[arg-type]
        self.seen_auth_headers = []


def _pkt_line(payload: bytes) -> bytes:
    return f"{len(payload) + 4:04x}".encode() + payload


_ADVERTISEMENT = _pkt_line(b"# service=git-upload-pack\n") + b"0000"


class _Handler(http.server.BaseHTTPRequestHandler):
    server: _BasicAuthChallengeServer

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's own naming
        auth = self.headers.get("Authorization", "")
        self.server.seen_auth_headers.append(auth)
        if auth != self.server.expected_auth_header:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="test"')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/x-git-upload-pack-advertisement")
        self.end_headers()
        self.wfile.write(_ADVERTISEMENT)

    def log_message(self, fmt: str, *args: object) -> None:  # quiet test output
        pass


def test_the_shipped_askpass_helper_authenticates_a_real_git_clone_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "testpass-from-env-alias"  # noqa: S105 - synthetic test fixture value, not a real credential
    expected = (
        "Basic " + base64.b64encode(f"{ASKPASS_USERNAME_PLACEHOLDER}:{secret}".encode()).decode()
    )

    server = _BasicAuthChallengeServer(("127.0.0.1", 0), _Handler)
    server.expected_auth_header = expected
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if os.name == "nt":
            # Confirmed directly: GIT_ASKPASS as a bare "<python> <script.py>" string is
            # NOT split into program+argument by this machine's Git for Windows -- a thin
            # .cmd launcher is required (see the module docstring).
            helper_path = tmp_path / "askpass_helper.py"
            helper_path.write_text(ASKPASS_HELPER_SOURCE, encoding="utf-8")
            launcher_path = tmp_path / "askpass_helper.cmd"
            launcher_path.write_text(f'@"{sys.executable}" "{helper_path}" %*\n', encoding="utf-8")
            askpass_value = str(launcher_path)
        else:
            launcher_path = tmp_path / "askpass_helper"
            launcher_path.write_text(
                f"#!{sys.executable}\n{ASKPASS_HELPER_SOURCE}", encoding="utf-8"
            )
            launcher_path.chmod(launcher_path.stat().st_mode | stat.S_IEXEC)
            askpass_value = str(launcher_path)

        env = {
            **dict(os.environ),
            "GIT_ASKPASS": askpass_value,
            "GIT_TERMINAL_PROMPT": "0",
            **build_credential_env(secret),
        }
        port = server.server_address[1]
        result = subprocess.run(  # noqa: S603 - fixed argv, local-only test server
            [GIT, "-c", "credential.helper=", "ls-remote", f"http://127.0.0.1:{port}/repo.git"],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert expected in server.seen_auth_headers, (
        "git never sent the expected Authorization header derived from the resolved "
        f"credential; headers actually seen: {server.seen_auth_headers!r}, "
        f"stderr: {result.stderr!r}"
    )
