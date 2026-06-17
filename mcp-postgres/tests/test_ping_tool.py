"""Tests for the dual-instance db_pg96_ping tool."""

from unittest.mock import AsyncMock, MagicMock

import pytest


class TestPingTool:
    """Test db_pg96_ping tool behavior with mocked connection manager."""

    @pytest.fixture
    def mock_state(self):
        state = MagicMock()
        state.connection_manager = AsyncMock()
        state.connection_manager.list_enabled_instances = MagicMock(
            return_value=["primary", "secondary"]
        )
        state.session_manager = MagicMock()
        state.rate_limiter = MagicMock()
        state.rate_limiter.allow.return_value = True
        state.audit_logger = MagicMock()
        state.policy = MagicMock()
        state.auth = MagicMock()
        state.auth.azure_auth_enabled = False
        state.auth.auth_mode = "disabled"
        state.denied_requests = 0

        # Mock fetch_single_row to return EDBAS-style row
        async def mock_fetch(instance_id, db, sql):
            return {
                "instance_name": f"edb-cluster-{instance_id}",
                "database_version": "EnterpriseDB 9.6.24.10 on x86_64-pc-linux-gnu",
                "edb_compat_mode": "Oracle",
                "ip_address": f"10.0.0.{1 if instance_id == 'primary' else 2}",
                "current_utc_time": "2026-05-25T18:30:00.000000Z",
            }

        state.connection_manager.fetch_single_row = mock_fetch
        return state

    @pytest.fixture
    def mock_mcp(self):
        mcp = MagicMock()
        mcp.tool = MagicMock(return_value=lambda f: f)  # No-op decorator
        return mcp

    def test_full_name_generation(self):
        from src.tools.tool_registry import ToolSpec

        spec = ToolSpec(instance="primary", instance_number=1, toolname="ping")
        assert spec.full_name == "db_1_pg96_ping"
        spec2 = ToolSpec(instance="secondary", instance_number=2, toolname="ping")
        assert spec2.full_name == "db_2_pg96_ping"

    def test_registered_tools_list(self, mock_state, mock_mcp):
        from src.tools.pg_tools import register_pg_tools

        registered = register_pg_tools(mock_mcp, mock_state)
        assert "db_1_pg96_ping" in registered
        assert "db_2_pg96_ping" in registered
        assert len(registered) == 24

    def test_ping_sql_contains_edb_columns(self):
        from src.tools.pg_tools import _PING_SQL

        assert "instance_name" in _PING_SQL
        assert "database_version" in _PING_SQL
        assert "edb_compat_mode" in _PING_SQL
        assert "edb_redwood_date" in _PING_SQL
        assert "ip_address" in _PING_SQL
        assert "current_utc_time" in _PING_SQL
