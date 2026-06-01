import pytest
from fastapi.testclient import TestClient

from app.api import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_query_denied_unknown_user(client):
    resp = client.post("/v1/query", json={"user_id": "nobody", "query": "hello"})
    body = resp.json()
    assert body.get("error_code") == "AUTH_FAILURE"
