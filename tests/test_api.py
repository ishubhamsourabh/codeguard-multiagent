"""API contract tests using FastAPI's TestClient.

Only ``/health`` and ``/scan`` are exercised here: they are the endpoints with
no LLM dependency, so this file stays fast, free, and deterministic in CI.
``/validate-code`` is covered by the graph tests (with an injected fake coder).
"""

from __future__ import annotations

import pytest
from api import app
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Shared test client for the app."""
    return TestClient(app)


def test_health_reports_config(client: TestClient):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "model" in body
    assert isinstance(body["api_key_configured"], bool)


def test_scan_flags_hardcoded_secret(client: TestClient):
    resp = client.post("/scan", json={"code": 'API_KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c"\n'})
    assert resp.status_code == 200
    body = resp.json()
    assert body["passed"] is False
    assert any(i["code"] == "HARDCODED_SECRET" for i in body["blocking"])


def test_scan_passes_clean_code(client: TestClient):
    code = (
        "import os\n"
        "\n"
        "\n"
        "def token() -> str:\n"
        '    """Read the token from the environment."""\n'
        '    value = os.environ.get("APP_TOKEN")\n'
        "    if not value:\n"
        '        raise ValueError("APP_TOKEN is required")\n'
        "    return value\n"
    )
    resp = client.post("/scan", json={"code": code})
    assert resp.status_code == 200
    body = resp.json()
    assert body["passed"] is True
    assert body["blocking"] == []


def test_scan_flags_eval_and_bare_except(client: TestClient):
    code = (
        "def run(x: str) -> None:\n"
        '    """Run the payload."""\n'
        "    try:\n"
        "        eval(x)\n"
        "    except:\n"
        "        pass\n"
    )
    body = client.post("/scan", json={"code": code}).json()
    found = {i["code"] for i in body["issues"]}
    assert {"EVAL_EXEC", "BARE_EXCEPT"} <= found
    assert body["passed"] is False


def test_scan_rejects_empty_body(client: TestClient):
    assert client.post("/scan", json={"code": ""}).status_code == 422


def test_validate_code_shape_is_declared(client: TestClient):
    """The OpenAPI schema must expose /validate-code with the documented fields."""
    schema = client.get("/openapi.json").json()
    assert "/validate-code" in schema["paths"]
    props = schema["components"]["schemas"]["ValidateResponse"]["properties"]
    for field in ("verdict", "iterations", "generated_code", "security_issues"):
        assert field in props


def test_validate_code_requires_llm_key(client: TestClient, monkeypatch):
    """Without a key the endpoint must fail loudly, not silently fake a PASS."""
    from src.config import Settings

    monkeypatch.setattr(
        "api.get_settings", lambda: Settings(api_key="", base_url="http://x", model="m")
    )
    resp = client.post(
        "/validate-code",
        json={"intent_spec": {"title": "T", "description": "D", "function_name": "f"}},
    )
    assert resp.status_code == 503
