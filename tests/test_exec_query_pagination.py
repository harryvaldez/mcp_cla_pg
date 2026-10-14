"""Tests for exec_query auto-pagination and pagination guardrails."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError
from fastmcp.utilities.pagination import CursorState


class TestExecQueryPagination:
    """Coverage for full-result auto-pagination in db_pg96_exec_query."""

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
        state.policy.max_result_rows = 5000
        state.auth = MagicMock()
        state.auth.azure_auth_enabled = False
        state.auth.auth_mode = "disabled"
        state.denied_requests = 0
        state.write_guard = MagicMock()

        # Default: return one full page and then empty page.
        async def mock_execute(instance_id, db, sql, max_rows=2000, offset=0):
            if offset >= max_rows:
                return []
            return [
                {"id": offset + i + 1, "name": f"row_{offset + i + 1}"}
                for i in range(max_rows)
            ]

        state.connection_manager.execute_query = mock_execute
        return state

    @pytest.fixture
    def mock_mcp(self):
        mcp = MagicMock()
        captured: dict[str, object] = {}

        def _capture_decorator(**tool_kwargs):
            def _decorator(fn):
                captured[tool_kwargs["name"]] = fn
                return fn

            return _decorator

        mcp.tool = MagicMock(side_effect=_capture_decorator)
        mcp.captured_tools = captured  # type: ignore[attr-defined]
        return mcp

    def _get_tool(self, mock_state, mock_mcp):
        """Register tools and return the exec_query tool function for instance 1."""
        from src.tools.pg_tools import register_pg_tools

        register_pg_tools(mock_mcp, mock_state)
        tool_fn = mock_mcp.captured_tools.get("db_1_pg96_exec_query")

        # Wrap to inject app_state (bypass FastMCP Depends)
        async def _call(**kwargs):
            return await tool_fn(app_state=mock_state, **kwargs)

        return _call

    @pytest.mark.asyncio
    async def test_cursorless_returns_complete_resultset(self, mock_state, mock_mcp):
        """Without cursor, exec_query auto-fetches all pages and returns one payload."""
        tool_fn = self._get_tool(mock_state, mock_mcp)
        assert tool_fn is not None

        result = await tool_fn(
            sql_statement="SELECT id FROM big_table ORDER BY id",
            database_name="lenexa",
            max_rows=500,
        )

        assert result["page"] == 2  # one full page + terminal empty page
        assert result["row_count"] == 500
        assert len(result["rows"]) == 500
        assert result["truncated"] is False
        assert result["nextCursor"] is None
        assert result["database"] == "lenexa"
        assert result["query"] == "SELECT id FROM big_table ORDER BY id"

    @pytest.mark.asyncio
    async def test_cursorless_small_result_single_page(self, mock_state, mock_mcp):
        """When result is smaller than max_rows, tool returns one page and stops."""
        async def mock_small(instance_id, db, sql, max_rows=2000, offset=0):
            return [{"id": i} for i in range(3)]

        mock_state.connection_manager.execute_query = mock_small

        tool_fn = self._get_tool(mock_state, mock_mcp)
        result = await tool_fn(
            sql_statement="SELECT id FROM small_table",
            max_rows=100,
        )

        assert result["row_count"] == 3
        assert result["nextCursor"] is None
        assert result["truncated"] is False
        assert result["page"] == 1

    @pytest.mark.asyncio
    async def test_cursorless_returns_standard_schema_keys(self, mock_state, mock_mcp):
        """Response includes all expected keys for backward compatibility."""
        tool_fn = self._get_tool(mock_state, mock_mcp)
        result = await tool_fn(
            sql_statement="SELECT 1",
            max_rows=10,
        )

        expected_keys = {
            "rows", "row_count", "page", "nextCursor",
            "truncated", "query", "database",
        }
        assert set(result.keys()) == expected_keys

    @pytest.mark.asyncio
    async def test_auto_pagination_aggregates_multiple_pages(self, mock_state, mock_mcp):
        """A 3-page dataset is aggregated into one final rows payload."""

        def page(start: int, size: int) -> list[dict[str, int]]:
            return [{"id": i} for i in range(start, start + size)]

        async def mock_multi(instance_id, db, sql, max_rows=2000, offset=0):
            if offset == 0:
                return page(0, max_rows)
            if offset == max_rows:
                return page(max_rows, max_rows)
            if offset == 2 * max_rows:
                return page(2 * max_rows, 3)
            return []

        mock_state.connection_manager.execute_query = mock_multi

        tool_fn = self._get_tool(mock_state, mock_mcp)
        result = await tool_fn(
            sql_statement="SELECT id FROM t ORDER BY id",
            max_rows=10,
        )

        assert result["row_count"] == 23
        assert len(result["rows"]) == 23
        assert result["rows"][0]["id"] == 0
        assert result["rows"][-1]["id"] == 22
        assert result["nextCursor"] is None
        assert result["truncated"] is False
        assert result["page"] == 3

    @pytest.mark.asyncio
    async def test_full_page_followed_by_partial_page_stops(self, mock_state, mock_mcp):
        """Tool continues after full page and stops after partial page."""

        async def mock_partial(instance_id, db, sql, max_rows=2000, offset=0):
            if offset == 0:
                return [{"id": i} for i in range(max_rows)]
            if offset == max_rows:
                return [{"id": 100}, {"id": 101}]
            return []

        mock_state.connection_manager.execute_query = mock_partial

        tool_fn = self._get_tool(mock_state, mock_mcp)
        result = await tool_fn(
            sql_statement="SELECT id FROM small_table",
            max_rows=10,
        )

        assert result["row_count"] == 12
        assert len(result["rows"]) == 12
        assert result["nextCursor"] is None
        assert result["truncated"] is False
        assert result["page"] == 2

    @pytest.mark.asyncio
    async def test_cursor_start_offset_is_respected(self, mock_state, mock_mcp):
        """When cursor is provided, aggregation starts from decoded offset."""

        async def mock_paginated(instance_id, db, sql, max_rows=2000, offset=0):
            if offset == 10:
                return [{"id": 10 + i} for i in range(max_rows)]
            if offset == 15:
                return [{"id": 15}, {"id": 16}]
            return []

        mock_state.connection_manager.execute_query = mock_paginated
        tool_fn = self._get_tool(mock_state, mock_mcp)

        start_cursor = CursorState(offset=10).encode()
        result = await tool_fn(sql_statement="SELECT id FROM t", max_rows=5, cursor=start_cursor)

        assert result["row_count"] == 7
        assert result["rows"][0]["id"] == 10
        assert result["rows"][-1]["id"] == 16
        assert result["nextCursor"] is None
        assert result["truncated"] is False
        assert result["page"] == 2

    @pytest.mark.asyncio
    async def test_exact_boundary_uses_terminal_empty_page(self, mock_state, mock_mcp):
        """Exact divisible totals trigger one terminal empty-page fetch and stop."""

        async def mock_exact(instance_id, db, sql, max_rows=2000, offset=0):
            if offset == 0:
                return [{"id": i} for i in range(max_rows)]
            if offset == max_rows:
                return []
            return []

        mock_state.connection_manager.execute_query = mock_exact

        tool_fn = self._get_tool(mock_state, mock_mcp)
        result = await tool_fn(sql_statement="SELECT id FROM t", max_rows=5)
        assert result["row_count"] == 5
        assert len(result["rows"]) == 5
        assert result["nextCursor"] is None
        assert result["page"] == 2

    @pytest.mark.asyncio
    async def test_invalid_cursor_raises_tool_error(self, mock_state, mock_mcp):
        """Malformed cursor string raises ToolError with clear message."""
        tool_fn = self._get_tool(mock_state, mock_mcp)

        with pytest.raises(ToolError, match="INVALID_INPUT: cursor is malformed or expired"):
            await tool_fn(
                sql_statement="SELECT 1",
                cursor="this-is-not-a-valid-cursor!!!",
            )

    @pytest.mark.asyncio
    async def test_non_advancing_cursor_raises_tool_error(self, mock_state, mock_mcp):
        """If pagination offset does not advance, tool raises guardrail ToolError."""

        async def stuck_pages(instance_id, db, sql, max_rows=2000, offset=0):
            return [{"id": i} for i in range(max_rows)]

        mock_state.connection_manager.execute_query = stuck_pages

        tool_fn = self._get_tool(mock_state, mock_mcp)

        with pytest.raises(ToolError, match="TOOL_ERROR: pagination exceeded max_auto_pages"):
            await tool_fn(sql_statement="SELECT id FROM t", max_rows=5)

    @pytest.mark.asyncio
    async def test_empty_cursor_treated_as_none(self, mock_state, mock_mcp):
        """Empty string cursor is treated as no cursor."""

        async def two_pages(instance_id, db, sql, max_rows=2000, offset=0):
            if offset == 0:
                return [{"id": i} for i in range(max_rows)]
            return []

        mock_state.connection_manager.execute_query = two_pages

        tool_fn = self._get_tool(mock_state, mock_mcp)

        result = await tool_fn(
            sql_statement="SELECT 1",
            cursor="",
            max_rows=5,
        )

        assert result["page"] == 2
        assert result["row_count"] == 5

    @pytest.mark.asyncio
    async def test_total_row_cap_truncates_and_returns_next_cursor(self, mock_state, mock_mcp):
        """Hitting the 10,000-row cap returns truncated=True and a resumable cursor."""

        async def infinite(instance_id, db, sql, max_rows=2000, offset=0):
            return [{"id": offset + i} for i in range(max_rows)]

        mock_state.connection_manager.execute_query = infinite
        tool_fn = self._get_tool(mock_state, mock_mcp)

        result = await tool_fn(sql_statement="SELECT id FROM big", max_rows=5000)

        assert result["truncated"] is True
        assert result["row_count"] == 10000
        assert len(result["rows"]) == 10000
        assert result["nextCursor"] is not None
        assert CursorState.decode(result["nextCursor"]).offset == 10000

    @pytest.mark.asyncio
    async def test_cursor_offset_out_of_bounds_raises(self, mock_state, mock_mcp):
        """Negative or oversized cursor offsets are rejected as invalid input."""
        tool_fn = self._get_tool(mock_state, mock_mcp)

        negative = CursorState(offset=-1).encode()
        with pytest.raises(ToolError, match="INVALID_INPUT: cursor offset out of bounds"):
            await tool_fn(sql_statement="SELECT 1", cursor=negative)

        oversized = CursorState(offset=2_000_000).encode()
        with pytest.raises(ToolError, match="INVALID_INPUT: cursor offset out of bounds"):
            await tool_fn(sql_statement="SELECT 1", cursor=oversized)

    @pytest.mark.asyncio
    async def test_guardrail_tool_error_is_audited(self, mock_state, mock_mcp):
        """Pagination guardrail errors record their error_code in the audit event."""

        async def stuck(instance_id, db, sql, max_rows=2000, offset=0):
            return [{"id": i} for i in range(max_rows)]

        mock_state.connection_manager.execute_query = stuck
        tool_fn = self._get_tool(mock_state, mock_mcp)

        with pytest.raises(ToolError, match="pagination exceeded max_auto_pages"):
            await tool_fn(sql_statement="SELECT 1", max_rows=5)

        assert mock_state.audit_logger.log_event.called
        error_code = mock_state.audit_logger.log_event.call_args.kwargs.get("error_code")
        assert error_code == "TOOL_ERROR: pagination exceeded max_auto_pages"

    @pytest.mark.asyncio
    async def test_invalid_sql_is_authorized_rate_limited_and_audited(self, mock_state, mock_mcp):
        tool_fn = self._get_tool(mock_state, mock_mcp)

        with pytest.raises(ToolError, match="INVALID_INPUT: only SELECT queries are allowed"):
            await tool_fn(sql_statement="UPDATE users SET name = 'x'")

        mock_state.rate_limiter.allow.assert_called()
        assert mock_state.session_manager.touch.called
        assert mock_state.audit_logger.log_event.called
        assert (
            mock_state.audit_logger.log_event.call_args.kwargs["error_code"]
            == "INVALID_INPUT: only SELECT queries are allowed"
        )

    @pytest.mark.asyncio
    async def test_malformed_cursor_is_audited(self, mock_state, mock_mcp):
        tool_fn = self._get_tool(mock_state, mock_mcp)

        with pytest.raises(ToolError, match="INVALID_INPUT: cursor is malformed or expired"):
            await tool_fn(sql_statement="SELECT 1", cursor="not-a-valid-cursor")

        assert mock_state.audit_logger.log_event.called
        assert (
            mock_state.audit_logger.log_event.call_args.kwargs["error_code"]
            == "INVALID_INPUT: cursor is malformed or expired"
        )

    def test_offset_wraps_sql_as_subquery(self):
        """ConnectionManager.execute_query wraps SQL with OFFSET subquery."""
        from src.db.connection_manager import ConnectionManager

        manager = ConnectionManager.__new__(ConnectionManager)
        manager._instances = {"test": MagicMock()}
        manager._pools = {}
        manager._health = {}
        manager._lock = MagicMock()

        # We need to verify the SQL wrapping. Use acquire mock.

        async def _run():
            with patch.object(manager, "acquire") as mock_acquire:
                mock_conn = AsyncMock()
                mock_conn.fetch = AsyncMock(return_value=[])
                mock_acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
                mock_acquire.return_value.__aexit__ = AsyncMock(return_value=None)

                _result = await manager.execute_query(
                    "test", "mydb", "SELECT id FROM users ORDER BY id",
                    max_rows=100, offset=50,
                )
                # Verify the SQL passed to fetch was wrapped
                call_sql = mock_conn.fetch.call_args[0][0]
                assert "OFFSET 50" in call_sql
                assert "_mcp_page" in call_sql
                assert "SELECT id FROM users ORDER BY id" in call_sql

        asyncio.run(_run())

    def test_offset_zero_still_pushes_limit_to_server(self):
        """LIMIT is pushed to the server even for the first page."""
        from src.db.connection_manager import ConnectionManager

        manager = ConnectionManager.__new__(ConnectionManager)
        manager._instances = {"test": MagicMock()}
        manager._pools = {}
        manager._health = {}
        manager._lock = MagicMock()


        async def _run():
            with patch.object(manager, "acquire") as mock_acquire:
                mock_conn = AsyncMock()
                mock_conn.fetch = AsyncMock(return_value=[])
                mock_acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
                mock_acquire.return_value.__aexit__ = AsyncMock(return_value=None)

                await manager.execute_query(
                    "test", "mydb", "SELECT id FROM users",
                    max_rows=100, offset=0,
                )
                call_sql = mock_conn.fetch.call_args[0][0]
                # Always wrapped so LIMIT is pushed to the server
                assert "_mcp_page" in call_sql
                assert call_sql.endswith("OFFSET 0 LIMIT 100")

        asyncio.run(_run())

    def test_offset_negative_raises_value_error(self):
        """Negative offset raises ValueError."""
        from src.db.connection_manager import ConnectionManager

        manager = ConnectionManager.__new__(ConnectionManager)
        manager._instances = {"test": MagicMock()}
        manager._pools = {}
        manager._health = {}
        manager._lock = MagicMock()


        async def _run():
            with pytest.raises(ValueError, match="offset must be >= 0"):
                await manager.execute_query(
                    "test", "mydb", "SELECT 1",
                    offset=-5,
                )

        asyncio.run(_run())


class TestCursorStateRoundtrip:
    """Verify CursorState encode/decode behaves as expected."""

    def test_encode_decode_roundtrip(self):
        state = CursorState(offset=42)
        encoded = state.encode()
        decoded = CursorState.decode(encoded)
        assert decoded.offset == 42

    def test_encode_is_string(self):
        state = CursorState(offset=100)
        assert isinstance(state.encode(), str)

    def test_large_offset_roundtrip(self):
        state = CursorState(offset=999999)
        decoded = CursorState.decode(state.encode())
        assert decoded.offset == 999999
