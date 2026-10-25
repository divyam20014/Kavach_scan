"""Checks that runtime artifacts and secrets are git-ignored and source is not."""

import shutil
import subprocess  # noqa: S404 - test-only call to the local git binary, fixed argv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GIT = shutil.which("git")

pytestmark = pytest.mark.skipif(
    GIT is None or not (REPO_ROOT / ".gitignore").is_file(),
    reason="git binary or repository .gitignore not available",
)

MUST_IGNORE = [
    "data/projects/p1/project.json",
    "backend/data/x.json",
    "vapt-data/x.json",
    "uploads/report.xml",
    "imports/nessus.xml",
    "jobs/spool/j1.json",
    "scans/s1/events.jsonl",
    "evidence/e1.bin",
    "reports/client.pdf",
    "exports/project.zip",
    "backups/b.vaptbak",
    "support-bundle.zip",
    "backend/support-bundle.zip",
    "backend/support-bundle-2026-10-25.zip",
    "logs/app.log",
    "backend/server.log",
    "tmp/nmap-out.xml",
    "nmap-123.xml",
    "capture.har",
    ".env",
    "backend/.env.local",
    "secrets/token.txt",
    "client.key",
    "credentials-test.json",
    "backend/.venv/pyvenv.cfg",
    "frontend/node_modules/x/index.js",
    "frontend/coverage/index.html",
    "backend/secrets/api.txt",
    # secrets stay ignored even inside fixture directories
    "backend/tests/fixtures/.env",
    "backend/tests/fixtures/tls/server.key",
    "backend/tests/fixtures/tls/server.pem",
]

MUST_TRACK = [
    ".env.example",
    "backend/app/reports/html.py",
    "backend/app/imports/nmap.py",
    "backend/app/jobs/worker.py",
    "backend/app/storage/evidence.py",
    "backend/tests/fixtures/imports/sample.har",
    "backend/tests/fixtures/imports/nmap.xml",
    "backend/poetry.lock",
    "backend/poetry.toml",
    "backend/pyproject.toml",
    "docs/STORAGE_FORMATS.md",
    # realistic future fixture names for Phase 05/06/08 adapters
    "backend/tests/fixtures/imports/nmap-basic.xml",
    "backend/tests/fixtures/tools/sslyze-out.json",
    "backend/tests/fixtures/tools/testssl-out.json",
    "backend/tests/fixtures/logs/console.log",
    # source packages whose names overlap runtime-ish words
    "backend/app/scanners/api_security/coverage/__init__.py",
    "backend/app/core/secrets.py",
    "backend/app/storage/backups.py",
    "backend/app/storage/uploads.py",
]


def _ignored(path: str) -> bool:
    assert GIT is not None
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [GIT, "check-ignore", "--no-index", "-q", path],
        cwd=REPO_ROOT,
        check=False,
    )
    return result.returncode == 0


@pytest.mark.parametrize("path", MUST_IGNORE)
def test_runtime_and_secret_paths_ignored(path: str) -> None:
    assert _ignored(path), f"{path} should be git-ignored"


@pytest.mark.parametrize("path", MUST_TRACK)
def test_source_and_fixture_paths_not_ignored(path: str) -> None:
    assert not _ignored(path), f"{path} must not be git-ignored"
