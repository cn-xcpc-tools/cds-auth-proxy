from fastapi.testclient import TestClient

from cds_auth_proxy.app import app
from cds_auth_proxy.model import CDSConfig


def test_smoke():
    """Basic smoke test to verify the application starts and responds to requests."""
    client = TestClient(app)

    # Test root endpoint redirects to docs
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/docs"

    # Test config endpoint returns valid config
    response = client.get("/admin/config")
    assert response.status_code == 200
    config = CDSConfig(**response.json())
    assert isinstance(config, CDSConfig)

    # Test teams endpoint (should work even if empty)
    response = client.get("/teams")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
