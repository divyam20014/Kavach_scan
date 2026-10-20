"""The ASGI app itself must refuse non-loopback peers and non-local Host headers."""

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import LOCAL_BASE_URL


def _client(peer: str, base_url: str = LOCAL_BASE_URL) -> TestClient:
    return TestClient(create_app(), base_url=base_url, client=(peer, 50000))


@pytest.mark.parametrize("peer", ["127.0.0.1", "127.8.9.10", "::1"])
def test_loopback_peers_served(peer: str) -> None:
    assert _client(peer).get("/api/health").status_code == 200


@pytest.mark.parametrize(
    "peer", ["192.168.1.20", "10.0.0.5", "8.8.8.8", "2001:db8::1", "testclient", "localhost", ""]
)
def test_non_loopback_peers_rejected(peer: str) -> None:
    resp = _client(peer).get("/api/health")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "non_local_client"


def test_rejection_applies_to_docs_and_unknown_routes() -> None:
    client = _client("192.168.1.20")
    assert client.get("/docs").status_code == 403
    assert client.get("/openapi.json").status_code == 403
    assert client.post("/api/scans").status_code == 403


def test_forwarded_headers_do_not_bypass_guard() -> None:
    resp = _client("192.168.1.20").get(
        "/api/health", headers={"X-Forwarded-For": "127.0.0.1", "Host": "localhost"}
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    "host", ["localhost", "localhost:8765", "127.0.0.1:8765", "[::1]:8765", "[::1]", "127.0.0.2"]
)
def test_local_host_headers_accepted(host: str) -> None:
    assert _client("127.0.0.1").get("/api/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",  # DNS rebinding: attacker domain resolving to 127.0.0.1
        "evil.example:8765",
        "localhost.evil.example",
        "127.0.0.1.nip.io",
        "testserver",
        "[::1",
        "localhost:abc",
        "0.0.0.0",  # noqa: S104 - Host header asserted to be rejected
    ],
)
def test_non_local_host_headers_rejected(host: str) -> None:
    resp = _client("127.0.0.1").get("/api/health", headers={"Host": host})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "invalid_host"
