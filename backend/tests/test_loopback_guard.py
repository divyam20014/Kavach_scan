"""The ASGI app itself must refuse non-loopback peers, however it is launched."""

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.mark.parametrize("peer", ["127.0.0.1", "127.8.9.10", "::1"])
def test_loopback_peers_served(peer: str) -> None:
    client = TestClient(create_app(), client=(peer, 50000))
    assert client.get("/api/health").status_code == 200


@pytest.mark.parametrize(
    "peer", ["192.168.1.20", "10.0.0.5", "8.8.8.8", "2001:db8::1", "testclient", "localhost", ""]
)
def test_non_loopback_peers_rejected(peer: str) -> None:
    client = TestClient(create_app(), client=(peer, 50000))
    resp = client.get("/api/health")
    assert resp.status_code == 403
    assert "local machine" in resp.json()["detail"]


def test_rejection_applies_to_docs_and_unknown_routes() -> None:
    client = TestClient(create_app(), client=("192.168.1.20", 50000))
    assert client.get("/docs").status_code == 403
    assert client.get("/openapi.json").status_code == 403
    assert client.post("/api/scans").status_code == 403


def test_forwarded_headers_do_not_bypass_guard() -> None:
    client = TestClient(create_app(), client=("192.168.1.20", 50000))
    resp = client.get("/api/health", headers={"X-Forwarded-For": "127.0.0.1", "Host": "localhost"})
    assert resp.status_code == 403
