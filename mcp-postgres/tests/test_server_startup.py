"""Integration tests for server startup.

Note: These tests require the server app to be importable but do not
require a running database. They validate configuration loading and route setup.
"""

import pytest
from starlette.testclient import TestClient


class TestServerStartup:
    """Validate the FastMCP 3 app builds and routes are accessible."""

    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch):
        """Ensure test config paths point to existing config files."""
        monkeypatch.setenv("FASTMCP_CONFIG_PATH", "config/instances.yaml")
        monkeypatch.setenv("FASTMCP_POLICY_PATH", "config/runtime-policy.yaml")
        monkeypatch.setenv("FASTMCP_RATE_LIMIT_PATH", "config/rate-limit.yaml")
        # Disable pool initialization for tests (no DB)
        monkeypatch.setenv("FASTMCP_STATELESS_HTTP", "true")

    @pytest.fixture
    def client(self):
        # Build fresh app for each test
        import importlib

        import src.server

        importlib.reload(src.server)
        # Patch pool init to avoid real DB connections
        from unittest.mock import patch

        with patch.object(
            src.server.ConnectionManager,
            "initialize_pools",
            new_callable=lambda: lambda self: None,
        ):
            app = src.server.build_app()
        return TestClient(app)

    def test_app_builds(self, client):
        """App builds without error."""
        assert client is not None

    def test_health_endpoint(self, client):
        """GET /health returns status with instances."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "instances" in data

    def test_readiness_endpoint(self, client):
        """GET /readiness returns ready status."""
        response = client.get("/readiness")
        assert response.status_code == 200
        data = response.json()
        assert "ready" in data
        assert "checks" in data

    def test_security_endpoint(self, client):
        """GET /security returns security posture."""
        response = client.get("/security")
        assert response.status_code == 200
        data = response.json()
        assert "write_mode" in data
        assert "enabled_instances" in data
        assert "registered_tools" in data

    def test_metrics_endpoint(self, client):
        """GET /metrics returns Prometheus text."""
        response = client.get("/metrics")
        assert response.status_code == 200
        # Prometheus content type or plain text
        assert "text/plain" in response.headers.get("content-type", "") or response.text

    def test_mcp_endpoint_responds(self, client):
        """MCP endpoint at /mcp responds."""
        response = client.get("/mcp")
        # MCP endpoint should not 404
        assert response.status_code != 404
