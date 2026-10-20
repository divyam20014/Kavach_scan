"""Command-line entry point.

    python -m app [serve]      start the API on 127.0.0.1 (default command)
    python -m app diagnose     read-only data-directory readiness report (JSON)
    python -m app --version

Exit codes: 0 ok · 1 not ready (diagnose) · 2 configuration error · 3 storage error.
"""

from __future__ import annotations

import argparse
import json
import sys

import uvicorn

from app import __version__
from app.core.config import InsecureBindError
from app.core.log_config import configure_logging
from app.core.settings import SettingsError, load_settings
from app.storage.errors import StorageError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app", description="VAPT Workbench backend")
    parser.add_argument("--version", action="version", version=f"vapt-workbench {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="start the local API (default)")
    sub.add_parser("diagnose", help="print data-directory diagnostics as JSON (read-only)")
    return parser


def _serve() -> int:
    try:
        settings = load_settings()
        bind = settings.bind()
    except (SettingsError, InsecureBindError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    configure_logging(settings.log_level)
    from app.main import create_app
    from app.storage.repository import StorageRepository

    try:
        repo = StorageRepository.open(settings)
    except StorageError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 3
    try:
        app = create_app(settings, repository=repo, serve_ui=True)
        uvicorn.run(app, host=bind.host, port=bind.port, access_log=False, log_config=None)
    finally:
        repo.close()
    return 0


def _diagnose() -> int:
    try:
        settings = load_settings()
    except (SettingsError, InsecureBindError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    from app.storage.diagnostics import diagnose
    from app.storage.paths import resolve_data_root

    try:
        root = resolve_data_root(settings)
    except StorageError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 3
    report = diagnose(root, settings, lock_held_here=False)
    print(json.dumps(report.model_dump(mode="json"), indent=2))
    return 0 if report.ready else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "diagnose":
        return _diagnose()
    return _serve()


if __name__ == "__main__":
    raise SystemExit(main())
