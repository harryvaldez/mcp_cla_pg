"""Regression tests for security-review findings.

Covers:
- M3: tool timeout rationalization (no over-inflated 120s timeouts).
- L2: session_counts included in cross-session restriction suffixes.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml
from fastmcp.exceptions import ToolError

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

        # No tool may hold a connection longer than 600 seconds.
        assert all(t is not None and t <= 600.0 for t in timeouts.values())

        # Identity check is fast.
        assert timeouts["db_1_pg96_ping"] == 10.0

        # Heavy orchestrators retain the 120s ceiling.
        assert timeouts["db_1_pg96_get_slow_statements"] == 120.0
        assert timeouts["db_1_pg96_analyze_sett_sec"] == 120.0

        # Complex analysis is capped at 60s.
        assert timeouts["db_1_pg96_analyze_data_model"] == 60.0
        assert timeouts["db_1_pg96_hypopg_find_optimal_indexes"] == 60.0

        # User-supplied SELECT queries may run long; exec_query retains the 600s ceiling.
        assert timeouts["db_1_pg96_exec_query"] == 600.0

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


class TestAuditedToolFailures:
    @pytest.mark.asyncio
    async def test_previously_unwrapped_validation_failure_is_audited_once(self):
        state = _mock_state()
        tools = {}
        mcp = MagicMock()

        def capture_tool(**kwargs):
            def decorator(fn):
                tools[kwargs["name"]] = fn
                return fn

            return decorator

        mcp.tool.side_effect = capture_tool
        register_pg_tools(mcp, state)

        with pytest.raises(ToolError, match="INVALID_INPUT: schema_name"):
            await tools["db_1_pg96_list_objects"](
                schema_name="invalid-schema", app_state=state
            )

        state.audit_logger.log_event.assert_called_once()
        assert (
            state.audit_logger.log_event.call_args.kwargs["error_code"]
            == "INVALID_INPUT: schema_name must be alphanumeric with underscores"
        )

    @pytest.mark.asyncio
    async def test_unexpected_database_error_is_masked_from_tool_response(self):
        state = _mock_state()
        state.connection_manager.acquire = MagicMock(
            side_effect=RuntimeError("db.internal.example password=super-secret")
        )
        tools = {}
        mcp = MagicMock()

        def capture_tool(**kwargs):
            def decorator(fn):
                tools[kwargs["name"]] = fn
                return fn

            return decorator

        mcp.tool.side_effect = capture_tool
        register_pg_tools(mcp, state)

        with pytest.raises(ToolError, match="TOOL_ERROR: Internal operation failed") as exc:
            await tools["db_1_pg96_list_objects"](app_state=state)

        assert "db.internal.example" not in str(exc.value)
        assert "super-secret" not in str(exc.value)
        state.audit_logger.log_event.assert_called_once()
        assert (
            state.audit_logger.log_event.call_args.kwargs["error_code"]
            == "TOOL_ERROR: Internal operation failed"
        )


class TestOktaAuthorizationFailsClosed:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "ctx",
        [
            None,
            SimpleNamespace(
                request_id="request-id",
                debug=AsyncMock(),
                warning=AsyncMock(),
                access_token=SimpleNamespace(
                    claims={"sub": "unprivileged-user", "groups": [], "scp": "openid"}
                ),
            ),
            SimpleNamespace(
                request_id="request-id", debug=AsyncMock(), warning=AsyncMock()
            ),
        ],
    )
    async def test_missing_or_unprivileged_okta_context_is_denied(self, ctx):
        state = _mock_state()
        state.auth = AuthConfig(auth_mode="okta")
        tools = {}
        mcp = MagicMock()

        def capture_tool(**kwargs):
            def decorator(fn):
                tools[kwargs["name"]] = fn
                return fn

            return decorator

        mcp.tool.side_effect = capture_tool
        register_pg_tools(mcp, state)

        with pytest.raises(PermissionError, match="AUTH_REQUIRED|AUTHZ_DENIED"):
            await tools["db_1_pg96_ping"](ctx=ctx, app_state=state)

        state.connection_manager.fetch_single_row.assert_not_called()
