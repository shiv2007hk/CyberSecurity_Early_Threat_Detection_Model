"""Shared pytest fixtures. A disposable SQLite database is seeded per test session."""
import os
from pathlib import Path

import pytest

TEST_DB = Path(__file__).resolve().parent / "test_aegis_sentinel.db"
for suffix in ("", "-wal", "-shm"):
    Path(str(TEST_DB) + suffix).unlink(missing_ok=True)

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["APP_ENV"] = "testing"
os.environ["SEED_INTELLIGENCE_CORPUS"] = "true"
os.environ["ENABLE_LIVE_THREAT_FEEDS"] = "false"
os.environ["JWT_SECRET_KEY"] = "test-only-secret-value-with-sufficient-length-123456"
os.environ["NVD_API_KEY"] = ""
os.environ["DEEPSEEK_API_KEY"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app.database import engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()
    for suffix in ("", "-wal", "-shm"):
        try:
            Path(str(TEST_DB) + suffix).unlink(missing_ok=True)
        except PermissionError:
            pass


@pytest.fixture(scope="session")
def tokens(client):
    credentials = {
        "admin": ("admin@aegissentinel.ai", "AegisAdmin#2026"),
        "analyst": ("analyst@aegissentinel.ai", "AegisAnalyst#2026"),
        "viewer": ("viewer@aegissentinel.ai", "AegisViewer#2026"),
    }
    result = {}
    for role, (email, password) in credentials.items():
        response = client.post("/api/auth/login", json={"email": email, "password": password})
        assert response.status_code == 200, response.text
        result[role] = {"Authorization": f"Bearer {response.json()['access_token']}"}
    return result


@pytest.fixture(scope="session")
def admin_headers(tokens):
    return tokens["admin"]


@pytest.fixture(scope="session")
def analyst_headers(tokens):
    return tokens["analyst"]


@pytest.fixture(scope="session")
def viewer_headers(tokens):
    return tokens["viewer"]
