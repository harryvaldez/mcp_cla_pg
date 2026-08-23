"""Regression tests for security-review findings.

Covers:
- M3: tool timeout rationalization (no over-inflated 120s timeouts).
- L2: session_counts included in cross-session restriction suffixes.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import yaml

from src.models import AuthConfig
from src.tools.pg_tools import register_pg_tools


def _mock_state() -> MagicMock:
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
    state.write_guard = MagicMock()
    return state


def _capture_tool_timeouts() -> tuple[MagicMock, dict[str, float | None]]:
    mcp = MagicMock()
    timeouts: dict[str, float | None] = {}

    def _decorator(**tool_kwargs):
        def _deco(fn):
            timeouts[tool_kwargs["name"]] = tool_kwargs.get("timeout")
            return fn

        return _deco

    mcp.tool = MagicMock(side_effect=_decorator)
    return mcp, timeouts


class TestToolTimeoutRationalization:
    def test_tool_timeouts_are_bounded_and_scoped(self):
        mcp, timeouts = _capture_tool_timeouts()
        register_pg_tools(mcp, _mock_state())

        # No tool may hold a connection longer than 120 seconds.
        assert all(t is not None and t <= 120.0 for t in timeouts.values())

        # Identity check is fast.
        assert timeouts["db_1_pg96_ping"] == 10.0

        # Heavy orchestrators retain the 120s ceiling.
        assert timeouts["db_1_pg96_get_slow_statements"] == 120.0
        assert timeouts["db_1_pg96_analyze_sett_sec"] == 120.0

        # Complex analysis is capped at 60s.
        assert timeouts["db_1_pg96_analyze_data_model"] == 60.0
        assert timeouts["db_1_pg96_hypopg_find_optimal_indexes"] == 60.0

        # User-supplied SELECT queries may run long; exec_query retains the 120s ceiling.
        assert timeouts["db_1_pg96_exec_query"] == 120.0

        # Simple read-only tools are capped at 30s.
        assert timeouts["db_1_pg96_blocking_sessions"] == 30.0
        assert timeouts["db_1_pg96_session_counts"] == 30.0


class TestCrossSessionRestriction:
    def test_auth_config_default_restricts_session_counts(self):
        assert "_pg96_session_counts" in AuthConfig().okta_cross_session_tool_suffixes

    def test_runtime_policy_restricts_session_counts(self):
        policy_path = (
            Path(__file__).resolve().parent.parent / "config" / "runtime-policy.yaml"
        )
        data = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        cross = data["auth"]["okta_cross_session_tool_suffixes"]
        assert "_pg96_blocking_sessions" in cross
        assert "_pg96_session_counts" in cross
