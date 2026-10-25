"""Command-line entry point.

    python -m app [serve]      start the API on 127.0.0.1 (default command)
    python -m app diagnose     read-only data-directory readiness report (JSON)
    python -m app integrations  run the external-tool self-test (version only; no target
                                 traffic) and print integration status as JSON
    python -m app support-bundle [--output PATH] [--include-findings]
                                 write a redacted diagnostic ZIP for troubleshooting (never a
                                 restorable backup; no evidence blobs; full finding records
                                 only with --include-findings)
    python -m app --version

Exit codes: 0 ok · 1 not ready (diagnose) · 2 configuration error (including an unwritable
`support-bundle --output` path) · 3 storage error.
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
    sub.add_parser(
        "integrations",
        help="run the external-tool self-test (version capture only; no target traffic)",
    )
    bundle = sub.add_parser(
        "support-bundle", help="write a redacted diagnostic ZIP (never a restorable backup)"
    )
    bundle.add_argument(
        "--output",
        default="support-bundle.zip",
        help="output file path (default: ./support-bundle.zip)",
    )
    bundle.add_argument(
        "--include-findings",
        action="store_true",
        help="include full (redacted) finding records per project; never evidence blobs",
    )
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


def _integrations() -> int:
    try:
        settings = load_settings()
    except (SettingsError, InsecureBindError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    from app.services.integrations import TOOL_IDS, run_selftest
    from app.storage.repository import StorageRepository

    try:
        repo = StorageRepository.open(settings)
    except StorageError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 3
    try:
        results = [run_selftest(repo, tool_id).__dict__ for tool_id in TOOL_IDS]
        for row in results:
            if row["last_used"] is not None:
                row["last_used"] = row["last_used"].__dict__
    finally:
        repo.close()
    print(json.dumps(results, indent=2))
    return 0


def _support_bundle(output: str, include_findings: bool) -> int:
    try:
        settings = load_settings()
    except (SettingsError, InsecureBindError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    from pathlib import Path

    from app.storage.atomic import write_bytes_to_external_path
    from app.storage.repository import StorageRepository
    from app.support_bundle import build_support_bundle

    try:
        repo = StorageRepository.open(settings)
    except StorageError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 3
    try:
        archive = build_support_bundle(repo, settings, include_findings=include_findings)
    finally:
        repo.close()
    try:
        write_bytes_to_external_path(Path(output), archive)
    except OSError as exc:
        print(f"error: could not write {output}: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {output} ({len(archive)} bytes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "diagnose":
        return _diagnose()
    if args.command == "integrations":
        return _integrations()
    if args.command == "support-bundle":
        return _support_bundle(args.output, args.include_findings)
    return _serve()


if __name__ == "__main__":
    raise SystemExit(main())
