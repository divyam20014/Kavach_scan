"""Runtime settings loaded from `VAPT_*` environment variables.

Strict by design: an unknown `VAPT_*` variable (usually a typo such as
`VAPT_DATADIR`) is an error, not something silently ignored. Persisted,
operator-editable settings live in `models.settings.AppSettings` instead.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.config import DEFAULT_PORT, BindConfig, load_bind_config

ENV_PREFIX = "VAPT_"

_ENV_FIELDS: dict[str, str] = {
    "VAPT_HOST": "host",
    "VAPT_PORT": "port",
    "VAPT_DATA_DIR": "data_dir",
    "VAPT_ALLOW_REPO_DATA_DIR": "allow_repo_data_dir",
    "VAPT_LOG_LEVEL": "log_level",
    "VAPT_LOCK_TIMEOUT_SECONDS": "lock_timeout_seconds",
    "VAPT_AUDIT_ROTATE_BYTES": "audit_rotate_bytes",
    "VAPT_MAX_RECORD_BYTES": "max_record_bytes",
    "VAPT_MAX_REQUEST_BYTES": "max_request_bytes",
    "VAPT_DISK_WARNING_BYTES": "disk_warning_bytes",
}


class SettingsError(ValueError):
    """Invalid or unknown runtime configuration."""


class RuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    data_dir: str | None = None
    allow_repo_data_dir: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    lock_timeout_seconds: float = Field(default=10.0, gt=0, le=300)
    audit_rotate_bytes: int = Field(default=10 * 1024 * 1024, ge=64 * 1024, le=1024**3)
    max_record_bytes: int = Field(default=5 * 1024 * 1024, ge=64 * 1024, le=100 * 1024 * 1024)
    max_request_bytes: int = Field(default=1024 * 1024, ge=16 * 1024, le=100 * 1024 * 1024)
    disk_warning_bytes: int = Field(default=2 * 1024**3, ge=0)

    def bind(self) -> BindConfig:
        return load_bind_config({"VAPT_HOST": self.host, "VAPT_PORT": str(self.port)})


def load_settings(env: Mapping[str, str] | None = None) -> RuntimeSettings:
    source = os.environ if env is None else env
    unknown = sorted(
        k for k in source if k.upper().startswith(ENV_PREFIX) and k.upper() not in _ENV_FIELDS
    )
    if unknown:
        raise SettingsError(
            f"Unknown configuration variable(s): {', '.join(unknown)}. "
            f"Known: {', '.join(sorted(_ENV_FIELDS))}."
        )
    raw: dict[str, object] = {}
    for env_name, field in _ENV_FIELDS.items():
        value = source.get(env_name)
        if value is None:
            continue
        if field == "allow_repo_data_dir":
            raw[field] = value.strip().lower() in {"1", "true", "yes"}
        elif field == "log_level":
            raw[field] = value.strip().upper()
        else:
            raw[field] = value.strip()
    try:
        settings = RuntimeSettings.model_validate(raw)
    except ValidationError as exc:
        field_to_env = {field: env for env, field in _ENV_FIELDS.items()}

        def where(loc: tuple[int | str, ...]) -> str:
            return field_to_env.get(str(loc[0]), str(loc[0])) if loc else "?"

        problems = "; ".join(f"{where(e['loc'])}: {e['msg']}" for e in exc.errors())
        raise SettingsError(f"Invalid configuration: {problems}") from exc
    settings.bind()  # enforce the loopback policy early
    return settings


def repo_root() -> Path:
    """The source checkout root (two levels above the `app` package)."""
    return Path(__file__).resolve().parents[3]
