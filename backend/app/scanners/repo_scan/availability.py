"""Executable lookup for the three repo_scan engines (roadmap Phase 2, TBD-087).

All three (Semgrep, Gitleaks, Trivy) are plain PATH-registered executables -- none needs
ZAP's jar-filename detection (`app/integrations/zap.py`) -- so one small, shared lookup
covers all three for the job system's own availability checks (used by `RepoScanRunner`,
mirroring `app/integrations/zap.py::check_availability`'s role for the `web_app` runner).
`app/services/integrations.py`'s own Settings-page detection keeps its separate, already-
tested per-tool branches (TBD-084/085/086) rather than being refactored to share this.
"""

from __future__ import annotations

from pathlib import Path

from app.integrations.process import find_executable


def find_tool(configured: str, names: list[str]) -> str:
    if configured:
        return configured if Path(configured).is_file() else ""
    return find_executable(names) or ""
