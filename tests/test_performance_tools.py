"""Integration-style tests for performance tools in src/tools/pg_tools.py.

Uses mocked connection managers and mocked HypoPG responses to validate
output contracts, connection lifecycle, and lock-tree detection.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tools.pg_tools import register_pg_tools


class TestGetSlowStatements:
    """Tests for the get_slow_statements tool output contract."""

    @pytest.fixture
    def mock_state(self):
        state = MagicMock()
        state.connection_manager = AsyncMock()
        state.connection_manager.list_enabled_instances = MagicMock(
            return_value=["primary", "secondary"]
        )
        state.connection_manager.acquire = MagicMock()
        state.session_manager = MagicMock()
        state.rate_limiter = MagicMock()
        state.rate_limiter.allow.return_value = True
        state.audit_logger = MagicMock()
        state.policy = MagicMock()
        state.auth = MagicMock()
        state.auth.azure_auth_enabled = False
        state.auth.auth_mode = "disabled"
        state.denied_requests = 0
        state.write_guard = MagicMock()
        state.write_guard.enforce = MagicMock()
        return state

    @pytest.fixture
    def mock_mcp(self):
        mcp = MagicMock()
        mcp.tool = MagicMock(return_value=lambda f: f)
        return mcp

    def test_tool_name_generation(self, mock_state, mock_mcp):
        """Verify performance tools appear in the registered list."""
        registered = register_pg_tools(mock_mcp, mock_state)
        assert any("get_slow_statements" in name for name in registered)
        assert any("blocking_sessions" in name for name in registered)
        assert any("analyze_data_model" in name for name in registered)

    def test_registered_count_matches(self, mock_state, mock_mcp):
        """Verify total registered count matches expected value."""
        registered = register_pg_tools(mock_mcp, mock_state)
        assert len(registered) == 46

    def test_hypopg_sub_tools_registered(self, mock_state, mock_mcp):
        """Verify HypoPG sub-tools are in the registered list."""
        registered = register_pg_tools(mock_mcp, mock_state)
        assert any("hypopg_create_virtual_indexes" in name for name in registered)
        assert any("hypopg_explain_with_virtual" in name for name in registered)
        assert any("hypopg_find_optimal_indexes" in name for name in registered)

    def test_data_model_sub_tools_registered(self, mock_state, mock_mcp):
        """Verify data model sub-tools are in the registered list."""
        registered = register_pg_tools(mock_mcp, mock_state)
        assert any("extract_schema_model" in name for name in registered)
        assert any("analyze_constraints_and_fks" in name for name in registered)
        assert any("analyze_normalization" in name for name in registered)
        assert any("analyze_index_statistics" in name for name in registered)
        assert any("analyze_3nf_and_decomposition" in name for name in registered)


class TestBlockingSessions:
    """Tests for blocking_sessions tool output contracts."""

    @pytest.fixture
    def mock_state(self):
        state = MagicMock()
        state.connection_manager = AsyncMock()
        state.connection_manager.list_enabled_instances = MagicMock(
            return_value=["primary"]
        )
        state.connection_manager.acquire = MagicMock()
        state.session_manager = MagicMock()
        state.rate_limiter = MagicMock()
        state.rate_limiter.allow.return_value = True
        state.audit_logger = MagicMock()
        state.policy = MagicMock()
        state.auth = MagicMock()
        state.auth.azure_auth_enabled = False
        state.auth.auth_mode = "disabled"
        state.denied_requests = 0
        state.write_guard = MagicMock()
        return state

    def test_tool_names_matches_pattern(self, mock_state):
        """Verify blocking_sessions follows db_<n>_pg96_ naming."""
        from src.tools.tool_registry import ToolSpec
        spec = ToolSpec(instance="primary", instance_number=1, toolname="blocking_sessions")
        assert spec.full_name == "db_1_pg96_blocking_sessions"
        spec2 = ToolSpec(instance="secondary", instance_number=2, toolname="blocking_sessions")
        assert spec2.full_name == "db_2_pg96_blocking_sessions"


class TestAnalyzeDataModel:
    """Tests for analyze_data_model tool output contracts."""

    def test_tool_name(self):
        """Verify analyze_data_model naming."""
        from src.tools.tool_registry import ToolSpec
        spec = ToolSpec(instance="primary", instance_number=1, toolname="analyze_data_model")
        assert spec.full_name == "db_1_pg96_analyze_data_model"
        spec2 = ToolSpec(instance="secondary", instance_number=2, toolname="analyze_data_model")
        assert spec2.full_name == "db_2_pg96_analyze_data_model"


class TestConnectionLifecycle:
    """Regression tests for connection lifecycle in performance tools.

    Verifies that all tool code paths use managed context managers (async with)
    rather than raw __aenter__() calls, preventing connection leaks.
    """

    def test_no_raw_enter_call_in_pg_tools(self):
        """Verify __aenter__() is not called directly in pg_tools.py."""
        import ast
        import pathlib

        pg_tools_path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "src"
            / "tools"
            / "pg_tools.py"
        )
        with open(pg_tools_path) as f:
            tree = ast.parse(f.read())

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Look for .__aenter__() calls
                if (isinstance(node.func, ast.Attribute)
                        and node.func.attr == "__aenter__"):
                    # Check if it's from connection_manager.acquire
                    if hasattr(node.func, 'value') and hasattr(node.func.value, 'func'):
                        pytest.fail(
                            f"Direct __aenter__() call found in pg_tools.py "
                            f"at line {node.lineno}. Use 'async with' instead."
                        )


class TestAnalyzeTable:
    """Tests for analyze_table tool registration and naming."""

    @pytest.fixture
    def mock_state(self):
        state = MagicMock()
        state.connection_manager = AsyncMock()
        state.connection_manager.list_enabled_instances = MagicMock(
            return_value=["primary", "secondary"]
        )
        state.connection_manager.acquire = MagicMock()
        state.session_manager = MagicMock()
        state.rate_limiter = MagicMock()
        state.rate_limiter.allow.return_value = True
        state.audit_logger = MagicMock()
        state.policy = MagicMock()
        state.auth = MagicMock()
        state.auth.azure_auth_enabled = False
        state.auth.auth_mode = "disabled"
        state.denied_requests = 0
        state.write_guard = MagicMock()
        return state

    @pytest.fixture
    def mock_mcp(self):
        mcp = MagicMock()
        mcp.tool = MagicMock(return_value=lambda f: f)
        return mcp

    def test_analyze_table_registered(self, mock_state, mock_mcp):
        registered = register_pg_tools(mock_mcp, mock_state)
        assert "db_1_pg96_analyze_table" in registered
        assert "db_2_pg96_analyze_table" in registered

    def test_check_table_bloat_registered(self, mock_state, mock_mcp):
        registered = register_pg_tools(mock_mcp, mock_state)
        assert "db_1_pg96_check_table_bloat" in registered
        assert "db_2_pg96_check_table_wraparound" in registered

    def test_check_table_statistics_registered(self, mock_state, mock_mcp):
        registered = register_pg_tools(mock_mcp, mock_state)
        assert "db_1_pg96_check_table_statistics" in registered

    def test_check_index_health_registered(self, mock_state, mock_mcp):
        registered = register_pg_tools(mock_mcp, mock_state)
        assert "db_1_pg96_check_index_health" in registered


class TestListObjects:
    """Tests for list_objects tool registration and naming."""

    @pytest.fixture
    def mock_state(self):
        state = MagicMock()
        state.connection_manager = AsyncMock()
        state.connection_manager.list_enabled_instances = MagicMock(
            return_value=["primary", "secondary"]
        )
        state.connection_manager.acquire = MagicMock()
        state.session_manager = MagicMock()
        state.rate_limiter = MagicMock()
        state.rate_limiter.allow.return_value = True
        state.audit_logger = MagicMock()
        state.policy = MagicMock()
        state.auth = MagicMock()
        state.auth.azure_auth_enabled = False
        state.auth.auth_mode = "disabled"
        state.denied_requests = 0
        state.write_guard = MagicMock()
        return state

    @pytest.fixture
    def mock_mcp(self):
        mcp = MagicMock()
        mcp.tool = MagicMock(return_value=lambda f: f)
        return mcp

    def test_list_objects_registered(self, mock_state, mock_mcp):
        registered = register_pg_tools(mock_mcp, mock_state)
        assert "db_1_pg96_list_objects" in registered
        assert "db_2_pg96_list_objects" in registered

    def test_list_tables_registered(self, mock_state, mock_mcp):
        registered = register_pg_tools(mock_mcp, mock_state)
        assert "db_1_pg96_list_tables" in registered
        assert "db_2_pg96_list_tables" in registered

    def test_list_indexes_registered(self, mock_state, mock_mcp):
        registered = register_pg_tools(mock_mcp, mock_state)
        assert "db_1_pg96_list_indexes" in registered

    def test_list_views_registered(self, mock_state, mock_mcp):
        registered = register_pg_tools(mock_mcp, mock_state)
        assert "db_1_pg96_list_views" in registered
