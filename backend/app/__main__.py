"""Local dev entry point: `python -m app` (binds to 127.0.0.1 by default)."""

from __future__ import annotations

import sys

import uvicorn

from app.core.config import InsecureBindError, load_bind_config


def main() -> int:
    try:
        bind = load_bind_config()
    except (InsecureBindError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    uvicorn.run("app.main:app", host=bind.host, port=bind.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
