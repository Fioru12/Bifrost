import importlib
import os

import pytest
from fastapi.testclient import TestClient

TEST_API_KEY = "test-api-key-for-pytest"


@pytest.fixture()
def client(monkeypatch):
    """Reload api.server with a known BIFROST_API_KEY set, so tests don't
    depend on (or leak) a randomly generated development key."""
    monkeypatch.setenv("BIFROST_API_KEY", TEST_API_KEY)
    from api import server as server_module
    importlib.reload(server_module)
    return TestClient(server_module.app)


def test_scan_without_api_key_is_unauthorized(client):
    response = client.post("/api/v1/scan", json={"host": "127.0.0.1", "ports": [80]})
    assert response.status_code == 401


def test_scan_with_too_many_ports_is_rejected(client):
    too_many_ports = list(range(1, 2000))  # exceeds MAX_PORTS_PER_REQUEST (1024)
    response = client.post(
        "/api/v1/scan",
        json={"host": "127.0.0.1", "ports": too_many_ports},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert response.status_code == 422


def test_scan_with_valid_key_succeeds(client):
    response = client.post(
        "/api/v1/scan",
        json={"host": "127.0.0.1", "ports": [80, 443]},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["host"] == "127.0.0.1"
    assert data["ports_scanned"] == 2


def test_scan_with_invalid_host_is_rejected(client):
    response = client.post(
        "/api/v1/scan",
        json={"host": "not a valid host!!", "ports": [80]},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert response.status_code == 422


def test_scan_with_empty_ports_is_rejected(client):
    response = client.post(
        "/api/v1/scan",
        json={"host": "127.0.0.1", "ports": []},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert response.status_code == 422
