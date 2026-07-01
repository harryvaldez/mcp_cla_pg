"""Unit tests for table_analysis.py — maintenance and discovery functions.

Tests the pure async analysis functions with mocked asyncpg connections to
validate output schemas, edge cases, and error handling.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.tools import table_analysis

# ===========================================================================
# Maintenance Analysis Functions (used by _register_sub_tool)
# ===========================================================================


class TestCheckTableBloat:
    """Tests for check_table_bloat()."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "n_live_tup": 100000,
                "n_dead_tup": 5000,
                "dead_pct": 4.76,
                "n_tup_hot_upd": 500,
                "hot_update_pct": 15.2,
                "n_tup_ins": 20000,
                "n_tup_upd": 3289,
                "n_tup_del": 1500,
                "last_vacuum": None,
                "last_autovacuum": None,
            }
        )
        return conn

    @pytest.mark.asyncio
    async def test_bloat_output_schema(self, mock_conn):
        """Verify output contains expected keys."""
        result = await table_analysis.check_table_bloat(
            mock_conn, "public", "orders"
        )
        assert "dead_tuple_pct" in result
        assert "live_tuples" in result
        assert "dead_tuples" in result
        assert "bloat_severity" in result

    @pytest.mark.asyncio
    async def test_bloat_low_severity(self, mock_conn):
        """Under 10% dead tuples → LOW severity."""
        result = await table_analysis.check_table_bloat(
            mock_conn, "public", "orders"
        )
        assert result["bloat_severity"] == "LOW"

    @pytest.mark.asyncio
    async def test_bloat_high_severity(self, mock_conn):
        """Over 30% dead tuples → HIGH severity."""
        mock_conn.fetchrow = AsyncMock(
            return_value={
                "n_live_tup": 50000,
                "n_dead_tup": 25000,
                "dead_pct": 33.33,
                "n_tup_hot_upd": 100,
                "hot_update_pct": 5.0,
                "n_tup_ins": 10000,
                "n_tup_upd": 2000,
                "n_tup_del": 500,
                "last_vacuum": None,
                "last_autovacuum": None,
            }
        )
        result = await table_analysis.check_table_bloat(
            mock_conn, "public", "orders"
        )
        assert result["bloat_severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_bloat_table_not_found(self, mock_conn):
        """Missing table returns error dict."""
        mock_conn.fetchrow = AsyncMock(return_value=None)
        result = await table_analysis.check_table_bloat(
            mock_conn, "public", "nonexistent"
        )
        assert "error" in result
        assert "not found" in result["error"]


class TestCheckTableWraparound:
    """Tests for check_table_wraparound()."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "relname": "orders",
                "xid_age": 400000000,
                "risk_level": "LOW",
            }
        )
        return conn

    @pytest.mark.asyncio
    async def test_wraparound_output_schema(self, mock_conn):
        """Verify output contains expected keys."""
        result = await table_analysis.check_table_wraparound(
            mock_conn, "public", "orders"
        )
        assert "xid_age" in result
        assert "risk_level" in result
        assert "recommended_action" in result

    @pytest.mark.asyncio
    async def test_wraparound_low_risk(self, mock_conn):
        """Under 500M → LOW risk."""
        result = await table_analysis.check_table_wraparound(
            mock_conn, "public", "orders"
        )
        assert result["risk_level"] == "LOW"

    @pytest.mark.asyncio
    async def test_wraparound_critical_risk(self, mock_conn):
        """Over 1.5B → CRITICAL risk."""
        mock_conn.fetchrow = AsyncMock(
            return_value={
                "relname": "orders",
                "xid_age": 1700000000,
                "risk_level": "CRITICAL",
            }
        )
        result = await table_analysis.check_table_wraparound(
            mock_conn, "public", "orders"
        )
        assert result["risk_level"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_wraparound_table_not_found(self, mock_conn):
        """Missing table returns error dict."""
        mock_conn.fetchrow = AsyncMock(return_value=None)
        result = await table_analysis.check_table_wraparound(
            mock_conn, "public", "nonexistent"
        )
        assert "error" in result


class TestCheckTableStatistics:
    """Tests for check_table_statistics()."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "relname": "orders",
                "last_analyze": None,
                "last_autoanalyze": None,
                "n_mod_since_analyze": 50000,
                "n_live_tup": 100000,
                "days_since_analyze": 99999,
            }
        )
        return conn

    @pytest.mark.asyncio
    async def test_statistics_output_schema(self, mock_conn):
        """Verify output contains expected keys."""
        result = await table_analysis.check_table_statistics(
            mock_conn, "public", "orders"
        )
        assert "last_analyze" in result
        assert "is_stale" in result
        assert "recommendation" in result

    @pytest.mark.asyncio
    async def test_statistics_stale_when_never_analyzed(self, mock_conn):
        """Never analyzed with live tuples → stale."""
        result = await table_analysis.check_table_statistics(
            mock_conn, "public", "orders"
        )
        assert result["is_stale"] is True

    @pytest.mark.asyncio
    async def test_statistics_fresh(self, mock_conn):
        """Recently analyzed → not stale."""
        from datetime import UTC, datetime, timedelta
        mock_conn.fetchrow = AsyncMock(
            return_value={
                "relname": "orders",
                "last_analyze": datetime.now(UTC) - timedelta(hours=1),
                "last_autoanalyze": datetime.now(UTC) - timedelta(minutes=30),
                "n_mod_since_analyze": 100,
                "n_live_tup": 100000,
                "days_since_analyze": 0.04,
            }
        )
        result = await table_analysis.check_table_statistics(
            mock_conn, "public", "orders"
        )
        assert result["is_stale"] is False

    @pytest.mark.asyncio
    async def test_statistics_table_not_found(self, mock_conn):
        """Missing table returns error dict."""
        mock_conn.fetchrow = AsyncMock(return_value=None)
        result = await table_analysis.check_table_statistics(
            mock_conn, "public", "nonexistent"
        )
        assert "error" in result


class TestCheckIndexHealth:
    """Tests for check_index_health()."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        # fetchrow is called twice: for OID and for total size
        conn.fetchrow = AsyncMock(side_effect=[
            {"oid": 12345},              # OID query
            {"total_bytes": 6291456},     # total size query
        ])
        # fetch is called 3 times: invalid, unused, duplicate
        conn.fetch = AsyncMock(side_effect=[
            # Invalid indexes
            [],
            # Unused indexes
            [
                {
                    "indexrelname": "orders_unused_idx",
                    "size_bytes": 2097152,
                },
            ],
            # Duplicate indexes
            [],
        ])
        return conn

    @pytest.mark.asyncio
    async def test_index_health_output_schema(self, mock_conn):
        """Verify output contains expected keys."""
        result = await table_analysis.check_index_health(
            mock_conn, "public", "orders"
        )
        assert "invalid_indexes" in result
        assert "unused_indexes" in result
        assert "duplicate_indexes" in result
        assert "total_index_bytes" in result

    @pytest.mark.asyncio
    async def test_index_health_detects_unused(self, mock_conn):
        """Index with zero scans is flagged as unused."""
        result = await table_analysis.check_index_health(
            mock_conn, "public", "orders"
        )
        assert len(result["unused_indexes"]) == 1
        assert result["unused_indexes"][0]["name"] == "orders_unused_idx"

    @pytest.mark.asyncio
    async def test_index_health_no_indexes(self, mock_conn):
        """No indexes found."""
        mock_conn.fetchrow = AsyncMock(side_effect=[
            {"oid": 12345},
            {"total_bytes": 0},
        ])
        mock_conn.fetch = AsyncMock(side_effect=[
            [],   # invalid
            [],   # unused
            [],   # duplicate
        ])
        result = await table_analysis.check_index_health(
            mock_conn, "public", "orders"
        )
        assert result["invalid_indexes"] == []
        assert result["unused_indexes"] == []
        assert result["duplicate_indexes"] == []


# ===========================================================================
# Discovery Functions (used by _register_discovery_tool)
# ===========================================================================


class TestListTablesBySchema:
    """Tests for list_tables_by_schema()."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=[
                {
                    "name": "orders",
                    "owner": "app_user",
                    "row_count": 50000,
                    "size_bytes": 10485760,
                    "description": "Customer orders",
                },
                {
                    "name": "users",
                    "owner": "app_user",
                    "row_count": 10000,
                    "size_bytes": 2097152,
                    "description": None,
                },
            ]
        )
        return conn

    @pytest.mark.asyncio
    async def test_list_tables_output_schema(self, mock_conn):
        """Verify output contains expected keys per object."""
        result = await table_analysis.list_tables_by_schema(
            mock_conn, "public"
        )
        assert len(result) == 2
        assert result[0]["name"] == "orders"
        assert result[0]["owner"] == "app_user"
        assert "row_count" in result[0]
        assert "size_bytes" in result[0]

    @pytest.mark.asyncio
    async def test_list_tables_empty_schema(self, mock_conn):
        """Empty schema returns empty list."""
        mock_conn.fetch = AsyncMock(return_value=[])
        result = await table_analysis.list_tables_by_schema(
            mock_conn, "public"
        )
        assert result == []


class TestListIndexesBySchema:
    """Tests for list_indexes_by_schema()."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=[
                {
                    "name": "orders_pkey",
                    "table_name": "orders",
                    "index_type": "btree",
                    "size_bytes": 4194304,
                    "idx_scan": 50000,
                },
            ]
        )
        return conn

    @pytest.mark.asyncio
    async def test_list_indexes_output_schema(self, mock_conn):
        """Verify output contains expected keys."""
        result = await table_analysis.list_indexes_by_schema(
            mock_conn, "public"
        )
        assert len(result) == 1
        assert result[0]["name"] == "orders_pkey"
        assert result[0]["index_type"] == "btree"
        assert "idx_scan" in result[0]

    @pytest.mark.asyncio
    async def test_list_indexes_empty(self, mock_conn):
        """No indexes returns empty list."""
        mock_conn.fetch = AsyncMock(return_value=[])
        result = await table_analysis.list_indexes_by_schema(
            mock_conn, "public"
        )
        assert result == []


class TestListViewsBySchema:
    """Tests for list_views_by_schema()."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=[
                {
                    "name": "active_orders",
                    "owner": "app_user",
                    "definition": "SELECT * FROM orders WHERE status = 'active'",
                    "size_bytes": 0,
                },
            ]
        )
        return conn

    @pytest.mark.asyncio
    async def test_list_views_output_schema(self, mock_conn):
        """Verify output contains expected keys."""
        result = await table_analysis.list_views_by_schema(
            mock_conn, "public"
        )
        assert len(result) == 1
        assert result[0]["name"] == "active_orders"
        assert "definition" in result[0]

    @pytest.mark.asyncio
    async def test_list_views_empty(self, mock_conn):
        """No views returns empty list."""
        mock_conn.fetch = AsyncMock(return_value=[])
        result = await table_analysis.list_views_by_schema(
            mock_conn, "public"
        )
        assert result == []


class TestListObjectsByType:
    """Tests for list_objects_by_type() — generic relkind fallback."""

    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=[
                {
                    "name": "order_id_seq",
                    "owner": "app_user",
                    "size_bytes": 8192,
                    "description": "Sequence for order IDs",
                },
            ]
        )
        return conn

    @pytest.mark.asyncio
    async def test_list_objects_by_type_output_schema(self, mock_conn):
        """Verify output contains expected keys."""
        result = await table_analysis.list_objects_by_type(
            mock_conn, "public", "S"
        )
        assert len(result) == 1
        assert result[0]["name"] == "order_id_seq"
        assert "owner" in result[0]
        assert "size_bytes" in result[0]
        assert "description" in result[0]

    @pytest.mark.asyncio
    async def test_list_objects_by_type_empty(self, mock_conn):
        """No matching objects returns empty list."""
        mock_conn.fetch = AsyncMock(return_value=[])
        result = await table_analysis.list_objects_by_type(
            mock_conn, "public", "m"
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_list_objects_by_type_invalid_relkind(self, mock_conn):
        """Invalid relkind returns empty list (graceful)."""
        mock_conn.fetch = AsyncMock(return_value=[])
        result = await table_analysis.list_objects_by_type(
            mock_conn, "public", "x"
        )
        assert result == []
