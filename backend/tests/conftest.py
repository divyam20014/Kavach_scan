"""Shared fixtures. Every test gets an isolated temporary data root; the suite is offline."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.settings import RuntimeSettings
from app.main import create_app
from app.models import Asset, AuthorizationRecord, Finding, Project, new_id
from app.storage.repository import StorageRepository

LOCAL_CLIENT = ("127.0.0.1", 50000)
LOCAL_BASE_URL = "http://127.0.0.1"


@pytest.fixture(autouse=True)
def _offline_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any test that tries to open a non-loopback network connection."""
    real_connect = socket.socket.connect

    def guarded(self: socket.socket, address: Any) -> Any:
        host = address[0] if isinstance(address, tuple) else None
        if host is not None:
            try:
                if not ipaddress.ip_address(host).is_loopback:
                    raise AssertionError(f"test attempted a non-loopback connection to {host}")
            except ValueError as exc:
                raise AssertionError(f"test attempted a connection to hostname {host}") from exc
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture
def settings(tmp_path: Path) -> RuntimeSettings:
    return RuntimeSettings(data_dir=str(tmp_path / "data"), lock_timeout_seconds=5)


@pytest.fixture
def repo(settings: RuntimeSettings) -> Iterator[StorageRepository]:
    repository = StorageRepository.open(settings)
    try:
        yield repository
    finally:
        repository.close()


@pytest.fixture
def client(settings: RuntimeSettings, repo: StorageRepository) -> Iterator[TestClient]:
    app = create_app(settings, repository=repo)
    with TestClient(app, base_url=LOCAL_BASE_URL, client=LOCAL_CLIENT) as test_client:
        yield test_client


def make_project(**overrides: Any) -> Project:
    now = datetime.now(UTC)
    data: dict[str, Any] = {
        "project_id": new_id("project"),
        "name": "Demo assessment",
        "client_name": "Acme Corp",
        "authorization": AuthorizationRecord(
            organization="Acme Corp",
            target_owner="Acme IT",
            authorized_by="CISO",
            reference="SOW-42",
            window_start=now - timedelta(days=1),
            window_end=now + timedelta(days=30),
        ),
    }
    data.update(overrides)
    return Project(**data)


def make_finding(project_id: str, **overrides: Any) -> Finding:
    data: dict[str, Any] = {
        "finding_id": new_id("finding"),
        "project_id": project_id,
        "title": "Missing Content-Security-Policy header",
        "severity": "medium",
        "confidence": "confirmed",
        "url": "https://app.example.com/login",
        "cwe_ids": [693],
    }
    data.update(overrides)
    return Finding(**data)


def make_asset(project_id: str, **overrides: Any) -> Asset:
    data: dict[str, Any] = {
        "asset_id": new_id("asset"),
        "project_id": project_id,
        "asset_type": "hostname",
        "locator": "app.example.com",
        "scope_status": "in_scope",
    }
    data.update(overrides)
    return Asset(**data)
