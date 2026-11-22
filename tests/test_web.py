"""Web API hardening: token, headers, validation."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from dragoneye.web import app as web


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return TestClient(web.app)


def _token(client: TestClient) -> str:
    return client.get("/api/session").json()["token"]


def test_session_and_security_headers(client):
    response = client.get("/api/session")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "SAMEORIGIN"
    assert "frame-ancestors 'self'" in response.headers["content-security-policy"]


def test_mutations_require_header_token(client):
    payload = {"name": "acme", "in_scope": "acme.com"}
    assert client.post("/api/programs", json=payload).status_code == 403
    # A query token is not accepted: it leaks in logs and browser history.
    assert client.post("/api/programs?token=x", json=payload).status_code == 403

    ok = client.post(
        "/api/programs",
        json=payload,
        headers={"X-DragonEye-Token": _token(client)},
    )
    assert ok.status_code == 200
    assert ok.json()["program"]["name"] == "acme"


def test_program_validation(client):
    headers = {"X-DragonEye-Token": _token(client)}
    assert client.post("/api/programs", json={"name": "", "in_scope": "a.com"}, headers=headers).status_code == 422
    bad_port = {"name": "bad", "in_scope": "https://example.com:notaport"}
    response = client.post("/api/programs", json=bad_port, headers=headers)
    assert response.status_code == 400
    assert "invalid port" in response.json()["detail"]
