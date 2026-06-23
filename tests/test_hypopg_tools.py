"""Unit tests for HypoPG core functions in src/tools/hypopg_tools.py.

Tests use a mocked asyncpg connection to simulate hypopg_create_index(),
hypopg_reset(), EXPLAIN (FORMAT JSON), and information_schema responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.tools import hypopg_tools


class TestParseTablesAndColumns:
    """Tests for parse_tables_and_columns() — SQL text parser."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        # Default: information_schema returns a column for every query
        async def fetch_side_effect(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "INFORMATION_SCHEMA.COLUMNS" in sql_upper:
                return [
                    {"column_name": "id", "data_type": "integer"},
                    {"column_name": "name", "data_type": "text"},
                    {"column_name": "email", "data_type": "text"},
                    {"column_name": "amount", "data_type": "numeric"},
                ]
            return []

        conn.fetch = AsyncMock(side_effect=fetch_side_effect)
        return conn

    @pytest.mark.asyncio
    async def test_simple_select_extracts_table(self, mock_conn):
        result = await hypopg_tools.parse_tables_and_columns(
            mock_conn, "SELECT * FROM users"
        )
        assert "users" in result["tables"]

    @pytest.mark.asyncio
    async def test_join_extracts_both_tables(self, mock_conn):
        result = await hypopg_tools.parse_tables_and_columns(
            mock_conn,
            "SELECT * FROM orders JOIN users ON orders.user_id = users.id",
        )
        assert "orders" in result["tables"]
        assert "users" in result["tables"]

    @pytest.mark.asyncio
    async def test_where_clause_extracts_referenced_columns(self, mock_conn):
        result = await hypopg_tools.parse_tables_and_columns(
            mock_conn,
            "SELECT * FROM users WHERE users.email = 'test@example.com'",
        )
        assert "users" in result["tables"]
        # email should be in the referenced columns
        ref_cols = result["tables"]["users"].get("referenced_columns", [])
        assert "email" in ref_cols

    @pytest.mark.asyncio
    async def test_order_by_extracts_columns(self, mock_conn):
        result = await hypopg_tools.parse_tables_and_columns(
            mock_conn,
            "SELECT * FROM users ORDER BY users.name ASC",
        )
        assert "users" in result["tables"]
        ref_cols = result["tables"]["users"].get("referenced_columns", [])
        assert "name" in ref_cols

    @pytest.mark.asyncio
    async def test_empty_query_returns_no_tables(self, mock_conn):
        result = await hypopg_tools.parse_tables_and_columns(
            mock_conn, "SELECT 1"
        )
        assert result["tables"] == {}


class TestHypopgCreateVirtualIndexes:
    """Tests for hypopg_create_virtual_indexes()."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=(12345,))
        conn.execute = AsyncMock()
        return conn

    @pytest.mark.asyncio
    async def test_creates_index_for_where_column(self, mock_conn):
        query_analysis = {
            "tables": {
                "users": {
                    "referenced_columns": ["email"],
                    "all_columns": ["id", "name", "email"],
                }
            },
            "column_refs": [],
        }
        indexes = await hypopg_tools.hypopg_create_virtual_indexes(mock_conn, query_analysis)
        assert len(indexes) >= 1
        # Verify hypopg_reset was called
        mock_conn.execute.assert_any_call("SELECT hypopg_reset()")
        # Verify hypopg_create_index was called
        mock_conn.fetchrow.assert_any_call(
            "SELECT * FROM hypopg_create_index($1)",
            "CREATE INDEX ON users (email)",
        )

    @pytest.mark.asyncio
    async def test_empty_analysis_returns_empty_list(self, mock_conn):
        query_analysis = {"tables": {}, "column_refs": []}
        indexes = await hypopg_tools.hypopg_create_virtual_indexes(mock_conn, query_analysis)
        assert indexes == []

    @pytest.mark.asyncio
    async def test_hypopg_not_installed_raises(self, mock_conn):
        mock_conn.execute = AsyncMock(
            side_effect=Exception('function hypopg_reset() does not exist')
        )
        with pytest.raises(RuntimeError, match="HypoPG extension is not available"):
            await hypopg_tools.hypopg_create_virtual_indexes(
                mock_conn,
                {
                    "tables": {
                        "t": {
                            "referenced_columns": ["c"],
                            "all_columns": ["c"],
                        }
                    },
                    "column_refs": [],
                },
            )


class TestHypopgExplainWithVirtual:
    """Tests for hypopg_explain_with_virtual()."""

    @pytest.mark.asyncio
    async def test_returns_plan_and_cost(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value=(
                [
                    {
                        "Plan": {
                            "Node Type": "Seq Scan",
                            "Relation Name": "users",
                            "Total Cost": 42.5,
                        }
                    }
                ],
            )
        )
        result = await hypopg_tools.hypopg_explain_with_virtual(
            conn, "SELECT * FROM users WHERE email = 'test'"
        )
        assert "plan" in result
        assert "total_cost" in result
        assert result["total_cost"] == 42.5

    @pytest.mark.asyncio
    async def test_explain_failure_raises(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            side_effect=Exception("syntax error")
        )
        with pytest.raises(RuntimeError, match="EXPLAIN failed"):
            await hypopg_tools.hypopg_explain_with_virtual(
                conn, "SELECT invalid"
            )


class TestHypopgFindOptimalIndexes:
    """Tests for hypopg_find_optimal_indexes()."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        # information_schema response
        conn.fetch = AsyncMock(
            return_value=[
                {"column_name": "id", "data_type": "integer"},
                {"column_name": "email", "data_type": "text"},
            ]
        )
        conn.execute = AsyncMock()

        # EXPLAIN baseline returns higher cost
        baseline_plan = [{"Plan": {"Node Type": "Seq Scan", "Total Cost": 100.0}}]

        # EXPLAIN with virtual index returns lower cost
        indexed_plan = [{"Plan": {"Node Type": "Index Scan", "Total Cost": 30.0}}]

        # First call EXPLAIN returns baseline, subsequent calls return indexed
        explain_call_count = 0

        async def fetchrow_side_effect(sql, *args, **kwargs):
            nonlocal explain_call_count
            explain_call_count += 1
            if explain_call_count == 1:
                return (baseline_plan,)
            return (indexed_plan,)

        conn.fetchrow = AsyncMock(side_effect=fetchrow_side_effect)
        return conn

    @pytest.mark.asyncio
    async def test_returns_baseline_and_ranked_plans(self, mock_conn):
        result = await hypopg_tools.hypopg_find_optimal_indexes(
            mock_conn, "SELECT * FROM users WHERE email = 'test'", max_combinations=5
        )
        assert "baseline_cost" in result
        assert result["baseline_cost"] == 100.0
        assert "ranked_plans" in result
        assert len(result["ranked_plans"]) >= 1
        assert "best_recommendation" in result

    @pytest.mark.asyncio
    async def test_ranks_by_ascending_cost_plan(self, mock_conn):
        result = await hypopg_tools.hypopg_find_optimal_indexes(
            mock_conn, "SELECT * FROM users WHERE email = 'test'", max_combinations=5
        )
        costs = [p["total_cost"] for p in result["ranked_plans"]]
        assert costs == sorted(costs), "Plans must be ordered by ascending cost"

    @pytest.mark.asyncio
    async def test_baseline_included_when_no_candidates(self, mock_conn):
        # Query with no table references — no candidates generated
        result = await hypopg_tools.hypopg_find_optimal_indexes(
            mock_conn, "SELECT 1", max_combinations=5
        )
        assert "baseline_cost" in result
        assert "ranked_plans" in result
        # Should always contain at least the baseline plan
        assert len(result["ranked_plans"]) >= 1

    @pytest.mark.asyncio
    async def test_always_calls_hypopg_reset_in_finally(self, mock_conn):
        await hypopg_tools.hypopg_find_optimal_indexes(
            mock_conn, "SELECT * FROM users WHERE email = 'test'", max_combinations=3
        )
        # hypopg_reset must be called at least at start and once for cleanup
        reset_calls = [
            c for c in mock_conn.execute.call_args_list
            if c[0][0] == "SELECT hypopg_reset()"
        ]
        assert len(reset_calls) >= 2
