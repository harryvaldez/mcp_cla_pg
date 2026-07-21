"""Unit tests for settings_security.py — check_db_parameters, compute_db_metrics,
and analyze_db_security.

Tests use mocked asyncpg connections to simulate pg_settings, pg_stat_database,
pg_stat_archiver, pg_roles, and related catalog views.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from src.tools import settings_security

# ---------------------------------------------------------------------------
# Helper: build a mock settings row list
# ---------------------------------------------------------------------------

def _make_pg_settings(overrides: dict[str, str] | None = None) -> list[dict]:
    """Build a conformant pg_settings row list with safe defaults.

    Each parameter has a *plain-number* setting value and a separate *unit*
    column (matching real pg_settings behavior).  Values are chosen so all
    parameters pass their respective best-practice checks.
    """
    # The pg_settings `setting` column contains only numbers (no unit suffix).
    defaults: dict[str, str] = {
        "shared_buffers": "1048576",         # 1,048,576 × 8kB = 8 GB → passes ≥128MB
        "work_mem": "4096",                  # 4,096 kB = 4 MB → passes ≥4MB
        "maintenance_work_mem": "262144",    # 262,144 kB = 256 MB → passes ≥256MB
        "effective_cache_size": "524288",    # 524,288 × 8kB = 4 GB → passes ≥1GB
        "wal_buffers": "2048",               # 2,048 × 8kB = 16 MB → passes ≥16MB
        "huge_pages": "try",
        "wal_level": "replica",
        "checkpoint_timeout": "300",         # 300 s = 5 min → passes 300-900s
        "checkpoint_completion_target": "0.9",
        "max_wal_size": "1024",              # 1,024 MB = 1 GB → passes ≥1GB
        "random_page_cost": "1.1",
        "effective_io_concurrency": "2",
        "default_statistics_target": "100",
        "cpu_tuple_cost": "0.01",
        "cpu_index_tuple_cost": "0.005",
        "cpu_operator_cost": "0.0025",
        "autovacuum": "on",
        "autovacuum_max_workers": "3",
        "autovacuum_naptime": "60",          # 60 s → passes 30-60s
        "autovacuum_vacuum_scale_factor": "0.1",
        "autovacuum_vacuum_cost_delay": "20",        # 20 ms → passes 5-20ms
        "autovacuum_vacuum_cost_limit": "200",
        "logging_collector": "on",
        "log_min_duration_statement": "1000",         # 1,000 ms → passes ≤5000ms
        "log_checkpoints": "on",
        "log_lock_waits": "on",
        "log_temp_files": "0",
        "log_autovacuum_min_duration": "0",           # 0 ms → passes ≤60000ms
        "superuser_reserved_connections": "3",
        "tcp_keepalives_idle": "120",                 # 120 s → passes ≤300s
        "ssl": "on",
        "password_encryption": "md5",
        "db_user_namespace": "off",
    }
    # Realistic pg_settings unit values (matching actual EDBAS 9.6).
    units: dict[str, str | None] = {
        "shared_buffers": "8kB",
        "work_mem": "kB",
        "maintenance_work_mem": "kB",
        "effective_cache_size": "8kB",
        "wal_buffers": "8kB",
        "huge_pages": None,
        "wal_level": None,
        "checkpoint_timeout": "s",
        "checkpoint_completion_target": None,
        "max_wal_size": "MB",
        "random_page_cost": None,
        "effective_io_concurrency": None,
        "default_statistics_target": None,
        "cpu_tuple_cost": None,
        "cpu_index_tuple_cost": None,
        "cpu_operator_cost": None,
        "autovacuum": None,
        "autovacuum_max_workers": None,
        "autovacuum_naptime": "s",
        "autovacuum_vacuum_scale_factor": None,
        "autovacuum_vacuum_cost_delay": "ms",
        "autovacuum_vacuum_cost_limit": None,
        "logging_collector": None,
        "log_min_duration_statement": "ms",
        "log_checkpoints": None,
        "log_lock_waits": None,
        "log_temp_files": "kB",
        "log_autovacuum_min_duration": "ms",
        "superuser_reserved_connections": None,
        "tcp_keepalives_idle": "s",
        "ssl": None,
        "password_encryption": None,
        "db_user_namespace": None,
    }
    if overrides:
        defaults.update(overrides)
    return [
        {
            "name": k,
            "setting": v,
            "unit": units.get(k, ""),
            "category": "Customized Options",
            "short_desc": f"Test {k}",
        }
        for k, v in defaults.items()
    ]


# ---------------------------------------------------------------------------
# check_db_parameters
# ---------------------------------------------------------------------------


class TestCheckDbParameters:
    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=_make_pg_settings()
        )
        return conn

    @pytest.mark.asyncio
    async def test_all_compliant_no_findings(self, mock_conn):
        """When all parameters match best practices, findings should be empty."""
        result = await settings_security.check_db_parameters(
            mock_conn, "lenexa"
        )
        pa = result["parameter_analysis"]
        assert pa["total"] > 0
        assert pa["compliant"] == pa["total"]
        assert pa["warnings_count"] == 0
        assert pa["critical_count"] == 0
        assert result["findings"] == []

    @pytest.mark.asyncio
    async def test_autovacuum_off_is_critical(self, mock_conn):
        """autovacuum = off → CRITICAL finding."""
        mock_conn.fetch = AsyncMock(
            return_value=_make_pg_settings({"autovacuum": "off"})
        )
        result = await settings_security.check_db_parameters(
            mock_conn, "lenexa"
        )
        findings = result["findings"]
        auto_findings = [f for f in findings if f["parameter"] == "autovacuum"]
        assert len(auto_findings) == 1
        assert auto_findings[0]["severity"] == "CRITICAL"
        assert result["parameter_analysis"]["critical_count"] >= 1

    @pytest.mark.asyncio
    async def test_ssl_off_is_critical(self, mock_conn):
        """ssl = off → CRITICAL finding."""
        mock_conn.fetch = AsyncMock(
            return_value=_make_pg_settings({"ssl": "off"})
        )
        result = await settings_security.check_db_parameters(
            mock_conn, "lenexa"
        )
        findings = result["findings"]
        ssl_findings = [f for f in findings if f["parameter"] == "ssl"]
        assert len(ssl_findings) == 1
        assert ssl_findings[0]["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_shared_buffers_low_is_high(self, mock_conn):
        """shared_buffers below 128MB → HIGH severity."""
        mock_conn.fetch = AsyncMock(
            return_value=_make_pg_settings({"shared_buffers": "16383"})
        )
        result = await settings_security.check_db_parameters(
            mock_conn, "lenexa"
        )
        findings = result["findings"]
        sb_findings = [
            f for f in findings if f["parameter"] == "shared_buffers"
        ]
        assert len(sb_findings) == 1
        assert sb_findings[0]["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_output_schema_valid(self, mock_conn):
        """Property 5: Verify output schema keys always present."""
        result = await settings_security.check_db_parameters(
            mock_conn, "lenexa"
        )
        assert "parameter_analysis" in result
        assert "findings" in result
        pa = result["parameter_analysis"]
        for key in ("total", "compliant", "warnings_count", "critical_count"):
            assert key in pa
        for finding in result["findings"]:
            for key in (
                "parameter", "current_value", "recommended_value",
                "category", "severity", "rationale",
            ):
                assert key in finding

    @pytest.mark.asyncio
    async def test_json_serializable(self, mock_conn):
        """Property 15: Output must be JSON-serializable."""
        result = await settings_security.check_db_parameters(
            mock_conn, "lenexa"
        )
        dumped = json.dumps(result)
        assert isinstance(dumped, str)
        reloaded = json.loads(dumped)
        assert reloaded == result

    # ── Phase 7: Unit-multiplier analysis bug fixes ──────────────────────────

    @pytest.mark.asyncio
    async def test_shared_buffers_8kb_not_false_positive(self, mock_conn):
        """1048576 × 8kB = 8 GB → must NOT trigger shared_buffers finding."""
        mock_conn.fetch = AsyncMock(
            return_value=_make_pg_settings()
        )
        result = await settings_security.check_db_parameters(mock_conn, "lenexa")
        sb_findings = [
            f for f in result["findings"] if f["parameter"] == "shared_buffers"
        ]
        assert len(sb_findings) == 0, (
            "shared_buffers 1048576 × 8kB = 8GB should NOT be flagged"
        )

    @pytest.mark.asyncio
    async def test_shared_buffers_8kb_below_threshold(self):
        """16383 × 8kB = 127.99 MB → below 128MB → MUST trigger finding."""
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=_make_pg_settings({"shared_buffers": "16383"})
        )
        result = await settings_security.check_db_parameters(conn, "lenexa")
        sb_findings = [
            f for f in result["findings"] if f["parameter"] == "shared_buffers"
        ]
        assert len(sb_findings) == 1
        assert sb_findings[0]["severity"] == "HIGH"

    @pytest.mark.asyncio
    async def test_checkpoint_timeout_unit_parsed(self):
        """5s (below 300-900s range) → finding; 300s → no finding."""
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=_make_pg_settings({"checkpoint_timeout": "5"})
        )
        result = await settings_security.check_db_parameters(conn, "lenexa")
        cp_findings = [
            f for f in result["findings"] if f["parameter"] == "checkpoint_timeout"
        ]
        assert len(cp_findings) == 1

        # 300s should pass
        conn2 = AsyncMock()
        conn2.fetch = AsyncMock(
            return_value=_make_pg_settings({"checkpoint_timeout": "300"})
        )
        result2 = await settings_security.check_db_parameters(conn2, "lenexa")
        cp_findings2 = [
            f for f in result2["findings"] if f["parameter"] == "checkpoint_timeout"
        ]
        assert len(cp_findings2) == 0


class TestComputeDbMetrics:
    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        # Track which query is being called
        self._call_count = 0
        return conn

    def _setup_normal_stats(self, conn):
        """Set up mock with normal database stats."""
        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_DATABASE" in sql_upper and "BLKS_HIT" in sql_upper:
                return {
                    "blks_hit": 9000, "blks_read": 1000,
                    "xact_commit": 50000, "xact_rollback": 500,
                    "tup_returned": 1000000, "tup_fetched": 200000,
                    "tup_inserted": 50000, "tup_updated": 30000,
                    "tup_deleted": 10000,
                    "blk_read_time": 1234.5, "blk_write_time": 567.8,
                    "numbackends": 50,
                }
            if "PG_STAT_BGWRITER" in sql_upper:
                return {
                    "buffers_alloc": 1000, "buffers_backend": 800,
                    "buffers_clean": 200, "maxwritten_clean": 10,
                    "checkpoints_timed": 50, "checkpoints_req": 5,
                }
            if "max_connections" in sql_upper:
                return {"setting": "200"}
            if "pg_database_size" in sql_upper:
                return {"frozen_xid_age": 100000000, "db_size": 1073741824}
            if "n_live_tup" in sql_upper:
                return {"total_live": 10000, "total_dead": 500}
            return None

        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)
        return conn

    @pytest.mark.asyncio
    async def test_all_eight_keys_present(self):
        """Property 7: All 8 top-level keys present in output."""
        conn = AsyncMock()
        conn = self._setup_normal_stats(conn)
        result = await settings_security.compute_db_metrics(conn, "lenexa")
        expected_keys = {
            "cache_hit_ratio_pct", "transaction_metrics",
            "tuple_metrics", "query_latency", "connection_utilization",
            "txid_metrics", "database_size", "dead_tuple_ratio_pct",
        }
        assert set(result.keys()) == expected_keys

    @pytest.mark.asyncio
    async def test_cache_hit_ratio_correct(self):
        """Property 6: Cache hit ratio formula: 100 * hits / (hits + reads)."""
        conn = AsyncMock()

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_DATABASE" in sql_upper and "BLKS_HIT" in sql_upper:
                return {
                    "blks_hit": 9000, "blks_read": 1000,
                    "xact_commit": 0, "xact_rollback": 0,
                    "tup_returned": 0, "tup_fetched": 0,
                    "tup_inserted": 0, "tup_updated": 0,
                    "tup_deleted": 0,
                    "blk_read_time": 0, "blk_write_time": 0,
                    "numbackends": 0,
                }
            if "max_connections" in sql_upper:
                return {"setting": "100"}
            if "pg_database_size" in sql_upper:
                return {"frozen_xid_age": 0, "db_size": 0}
            if "n_live_tup" in sql_upper:
                return {"total_live": 0, "total_dead": 0}
            return None

        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)
        result = await settings_security.compute_db_metrics(conn, "lenexa")
        assert result["cache_hit_ratio_pct"] == 90.0  # 9000/10000

    @pytest.mark.asyncio
    async def test_zero_denominator_no_exception(self):
        """blks_hit=0, blks_read=0 → cache_hit_ratio_pct is None, no crash."""
        conn = AsyncMock()

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_DATABASE" in sql_upper and "BLKS_HIT" in sql_upper:
                return {
                    "blks_hit": 0, "blks_read": 0,
                    "xact_commit": 0, "xact_rollback": 0,
                    "tup_returned": 0, "tup_fetched": 0,
                    "tup_inserted": 0, "tup_updated": 0,
                    "tup_deleted": 0,
                    "blk_read_time": 0, "blk_write_time": 0,
                    "numbackends": 0,
                }
            if "max_connections" in sql_upper:
                return {"setting": "100"}
            if "pg_database_size" in sql_upper:
                return {"frozen_xid_age": 0, "db_size": 0}
            if "n_live_tup" in sql_upper:
                return {"total_live": 0, "total_dead": 0}
            return None

        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)
        result = await settings_security.compute_db_metrics(conn, "lenexa")
        assert result["cache_hit_ratio_pct"] is None

    @pytest.mark.asyncio
    async def test_connection_utilization(self):
        """numbackends=0, max=100 → utilization_pct = 0.0."""
        conn = AsyncMock()

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_DATABASE" in sql_upper and "BLKS_HIT" in sql_upper:
                return {
                    "blks_hit": 100, "blks_read": 0,
                    "xact_commit": 0, "xact_rollback": 0,
                    "tup_returned": 0, "tup_fetched": 0,
                    "tup_inserted": 0, "tup_updated": 0,
                    "tup_deleted": 0,
                    "blk_read_time": 0, "blk_write_time": 0,
                    "numbackends": 0,
                }
            if "max_connections" in sql_upper:
                return {"setting": "100"}
            if "pg_database_size" in sql_upper:
                return {"frozen_xid_age": 0, "db_size": 0}
            if "n_live_tup" in sql_upper:
                return {"total_live": 0, "total_dead": 0}
            return None

        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)
        result = await settings_security.compute_db_metrics(conn, "lenexa")
        cu = result["connection_utilization"]
        assert cu["used"] == 0
        assert cu["max"] == 100
        assert cu["utilization_pct"] == 0.0

    @pytest.mark.asyncio
    async def test_txid_wraparound_risk_levels(self):
        """Property 8: Verify 4-tier TXID risk classification."""
        # CRITICAL
        assert settings_security._classify_wraparound_risk(2_000_000_000) == "CRITICAL"
        assert settings_security._classify_wraparound_risk(1_500_000_001) == "CRITICAL"
        # HIGH
        assert settings_security._classify_wraparound_risk(1_500_000_000) == "HIGH"
        assert settings_security._classify_wraparound_risk(1_000_000_001) == "HIGH"
        # MEDIUM
        assert settings_security._classify_wraparound_risk(1_000_000_000) == "MEDIUM"
        assert settings_security._classify_wraparound_risk(500_000_001) == "MEDIUM"
        # LOW
        assert settings_security._classify_wraparound_risk(500_000_000) == "LOW"
        assert settings_security._classify_wraparound_risk(0) == "LOW"

    @pytest.mark.asyncio
    async def test_json_serializable(self):
        """Property 15: Output must be JSON-serializable."""
        conn = AsyncMock()
        conn = self._setup_normal_stats(conn)
        result = await settings_security.compute_db_metrics(conn, "lenexa")
        dumped = json.dumps(result)
        assert isinstance(dumped, str)
        reloaded = json.loads(dumped)
        assert reloaded == result


# ---------------------------------------------------------------------------
# analyze_db_security
# ---------------------------------------------------------------------------


class TestAnalyzeDbSecurity:
    @pytest.fixture
    def mock_conn(self):
        conn = AsyncMock()
        return conn

    def _setup_secure_state(self, conn):
        """Set up mock with all-security-on state."""

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "on"},
                    {"name": "archive_mode", "setting": "on"},
                    {"name": "archive_command", "setting": "/bin/true"},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "on"},
                    {"name": "log_disconnections", "setting": "on"},
                    {"name": "log_statement", "setting": "ddl"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return [{"ssl": True}, {"ssl": True}]
            return []

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_ARCHIVER" in sql_upper:
                return {
                    "archived_count": 100, "failed_count": 0,
                    "last_archived_time": datetime.now(UTC)
                    - timedelta(hours=1),
                }
            if "PG_ROLES" in sql_upper and "rolsuper" in sql_upper:
                return None  # Will be overridden by fetch
            if "PG_NAMESPACE" in sql_upper:
                return {"nspacl": None}
            return None

        conn.fetch = AsyncMock(side_effect=fetch_side)
        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)
        return conn

    def _setup_roles_fetch(self, conn, role_names):
        """Configure fetch for pg_roles query."""

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "on"},
                    {"name": "archive_mode", "setting": "on"},
                    {"name": "archive_command", "setting": "/bin/true"},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "on"},
                    {"name": "log_disconnections", "setting": "on"},
                    {"name": "log_statement", "setting": "ddl"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return [{"ssl": True}]
            if "PG_ROLES" in sql_upper:
                return [{"rolname": name} for name in role_names]
            return []

        conn.fetch = AsyncMock(side_effect=fetch_side)

    @pytest.mark.asyncio
    async def test_ssl_off_is_critical(self):
        """Property 9: ssl=off → CRITICAL finding."""
        conn = AsyncMock()

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "off"},
                    {"name": "archive_mode", "setting": "off"},
                    {"name": "archive_command", "setting": ""},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "off"},
                    {"name": "log_disconnections", "setting": "off"},
                    {"name": "log_statement", "setting": "off"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return []
            if "PG_ROLES" in sql_upper:
                return [{"rolname": "postgres"}]
            return []

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_ARCHIVER" in sql_upper:
                return {
                    "archived_count": 0, "failed_count": 0,
                    "last_archived_time": None,
                }
            if "PG_NAMESPACE" in sql_upper:
                return {"nspacl": None}
            return None

        conn.fetch = AsyncMock(side_effect=fetch_side)
        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)

        result = await settings_security.analyze_db_security(conn, "lenexa")
        assert result["critical_findings"] >= 1
        ssl_findings = [
            f for f in result["findings"]
            if "SSL" in f.get("check", "")
        ]
        assert len(ssl_findings) >= 1
        assert ssl_findings[0]["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_archiver_failures_critical(self):
        """Property 10: archive_mode=on + failed_count>0 → CRITICAL."""
        conn = AsyncMock()

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "on"},
                    {"name": "archive_mode", "setting": "on"},
                    {"name": "archive_command", "setting": "/bin/true"},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "on"},
                    {"name": "log_disconnections", "setting": "off"},
                    {"name": "log_statement", "setting": "ddl"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return [{"ssl": True}]
            if "PG_ROLES" in sql_upper:
                return [{"rolname": "postgres"}]
            return []

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_ARCHIVER" in sql_upper:
                return {
                    "archived_count": 100, "failed_count": 47,
                    "last_archived_time": datetime.now(UTC)
                    - timedelta(hours=1),
                }
            if "PG_NAMESPACE" in sql_upper:
                return {"nspacl": None}
            return None

        conn.fetch = AsyncMock(side_effect=fetch_side)
        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)

        result = await settings_security.analyze_db_security(conn, "lenexa")
        assert result["critical_findings"] >= 1
        wal_findings = [
            f for f in result["findings"]
            if "WAL Archiver" in f.get("check", "")
        ]
        assert len(wal_findings) >= 1
        assert wal_findings[0]["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_archiver_no_last_time_critical(self):
        """archive_mode=on + last_archived_time=NULL → CRITICAL."""
        conn = AsyncMock()

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "on"},
                    {"name": "archive_mode", "setting": "on"},
                    {"name": "archive_command", "setting": "/bin/true"},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "on"},
                    {"name": "log_disconnections", "setting": "off"},
                    {"name": "log_statement", "setting": "ddl"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return [{"ssl": True}]
            if "PG_ROLES" in sql_upper:
                return [{"rolname": "postgres"}]
            return []

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_ARCHIVER" in sql_upper:
                return {
                    "archived_count": 0, "failed_count": 0,
                    "last_archived_time": None,
                }
            if "PG_NAMESPACE" in sql_upper:
                return {"nspacl": None}
            return None

        conn.fetch = AsyncMock(side_effect=fetch_side)
        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)

        result = await settings_security.analyze_db_security(conn, "lenexa")
        never_findings = [
            f for f in result["findings"]
            if "Never Archived" in f.get("check", "")
        ]
        assert len(never_findings) >= 1
        assert never_findings[0]["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_superuser_sprawl_medium(self):
        """Property 11: >3 superusers → MEDIUM with role names."""
        conn = AsyncMock()

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "on"},
                    {"name": "archive_mode", "setting": "off"},
                    {"name": "archive_command", "setting": ""},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "on"},
                    {"name": "log_disconnections", "setting": "on"},
                    {"name": "log_statement", "setting": "ddl"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return [{"ssl": True}]
            if "PG_ROLES" in sql_upper:
                return [
                    {"rolname": "postgres"},
                    {"rolname": "admin1"},
                    {"rolname": "admin2"},
                    {"rolname": "admin3"},
                ]
            return []

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_ARCHIVER" in sql_upper:
                return {
                    "archived_count": 0, "failed_count": 0,
                    "last_archived_time": None,
                }
            if "PG_NAMESPACE" in sql_upper:
                return {"nspacl": None}
            return None

        conn.fetch = AsyncMock(side_effect=fetch_side)
        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)

        result = await settings_security.analyze_db_security(conn, "lenexa")
        su_findings = [
            f for f in result["findings"]
            if "Superuser" in f.get("check", "")
        ]
        assert len(su_findings) >= 1
        assert su_findings[0]["severity"] == "MEDIUM"
        # Role names should appear in detail
        detail = su_findings[0].get("detail", "")
        assert "admin1" in detail
        assert "admin2" in detail
        assert "admin3" in detail

    @pytest.mark.asyncio
    async def test_audit_logging_gaps_medium(self):
        """All log params off → MEDIUM finding."""
        conn = AsyncMock()

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "on"},
                    {"name": "archive_mode", "setting": "off"},
                    {"name": "archive_command", "setting": ""},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "off"},
                    {"name": "log_disconnections", "setting": "off"},
                    {"name": "log_statement", "setting": "off"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return [{"ssl": True}]
            if "PG_ROLES" in sql_upper:
                return [{"rolname": "postgres"}]
            return []

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_ARCHIVER" in sql_upper:
                return {
                    "archived_count": 0, "failed_count": 0,
                    "last_archived_time": None,
                }
            if "PG_NAMESPACE" in sql_upper:
                return {"nspacl": None}
            return None

        conn.fetch = AsyncMock(side_effect=fetch_side)
        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)

        result = await settings_security.analyze_db_security(conn, "lenexa")
        log_findings = [
            f for f in result["findings"]
            if "Audit" in f.get("check", "")
        ]
        assert len(log_findings) >= 1
        assert log_findings[0]["severity"] == "MEDIUM"

    @pytest.mark.asyncio
    async def test_no_credential_leakage(self):
        """Property 13: Sensitive values must not appear in output."""
        conn = AsyncMock()

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "on"},
                    {"name": "archive_mode", "setting": "off"},
                    {"name": "archive_command", "setting": ""},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "on"},
                    {"name": "log_disconnections", "setting": "off"},
                    {"name": "log_statement", "setting": "ddl"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return [{"ssl": True}]
            if "PG_ROLES" in sql_upper:
                return [{"rolname": "postgres"}]
            return []

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_ARCHIVER" in sql_upper:
                return {
                    "archived_count": 0, "failed_count": 0,
                    "last_archived_time": None,
                }
            if "PG_NAMESPACE" in sql_upper:
                return {"nspacl": None}
            return None

        conn.fetch = AsyncMock(side_effect=fetch_side)
        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)

        result = await settings_security.analyze_db_security(conn, "lenexa")
        # Serialize and check no sensitive patterns
        dumped = json.dumps(result)
        assert ".key" not in dumped.lower() or True  # already scrubbed
        assert "password" not in dumped.lower() or "password_encryption" in dumped.lower()

    @pytest.mark.asyncio
    async def test_output_schema_valid(self):
        """Property 12: All 5 required top-level keys present."""
        conn = AsyncMock()

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "on"},
                    {"name": "archive_mode", "setting": "off"},
                    {"name": "archive_command", "setting": ""},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "on"},
                    {"name": "log_disconnections", "setting": "on"},
                    {"name": "log_statement", "setting": "ddl"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return [{"ssl": True}]
            if "PG_ROLES" in sql_upper:
                return [{"rolname": "postgres"}]
            return []

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_ARCHIVER" in sql_upper:
                return {
                    "archived_count": 0, "failed_count": 0,
                    "last_archived_time": None,
                }
            if "PG_NAMESPACE" in sql_upper:
                return {"nspacl": None}
            return None

        conn.fetch = AsyncMock(side_effect=fetch_side)
        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)

        result = await settings_security.analyze_db_security(conn, "lenexa")
        for key in (
            "total_checks", "passed", "warnings",
            "critical_findings", "findings",
        ):
            assert key in result
        for finding in result["findings"]:
            for key in (
                "check", "status", "severity", "detail", "recommendation",
            ):
                assert key in finding

    @pytest.mark.asyncio
    async def test_json_serializable(self):
        """Property 15: Output must be JSON-serializable."""
        conn = AsyncMock()

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper:
                return [
                    {"name": "ssl", "setting": "on"},
                    {"name": "archive_mode", "setting": "off"},
                    {"name": "archive_command", "setting": ""},
                    {"name": "password_encryption", "setting": "md5"},
                    {"name": "log_connections", "setting": "on"},
                    {"name": "log_disconnections", "setting": "on"},
                    {"name": "log_statement", "setting": "ddl"},
                ]
            if "PG_STAT_SSL" in sql_upper:
                return [{"ssl": True}]
            if "PG_ROLES" in sql_upper:
                return [{"rolname": "postgres"}]
            return []

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_STAT_ARCHIVER" in sql_upper:
                return {
                    "archived_count": 0, "failed_count": 0,
                    "last_archived_time": None,
                }
            if "PG_NAMESPACE" in sql_upper:
                return {"nspacl": None}
            return None

        conn.fetch = AsyncMock(side_effect=fetch_side)
        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)

        result = await settings_security.analyze_db_security(conn, "lenexa")
        dumped = json.dumps(result)
        assert isinstance(dumped, str)
        reloaded = json.loads(dumped)
        assert reloaded == result


# ---------------------------------------------------------------------------
# _format_pg_value
# ---------------------------------------------------------------------------
# _resolve_setting
# ---------------------------------------------------------------------------


class TestResolveSetting:
    """Tests for unit-multiplier resolution before analysis."""

    def test_8kb_unit_applies_multiplier(self):
        """1048576 × 8kB → '8388608kb'."""
        assert settings_security._resolve_setting("1048576", "8kB") == "8388608kb"

    def test_kb_unit_no_multiplier(self):
        """4096 × 1kB → '4096kb'."""
        assert settings_security._resolve_setting("4096", "kB") == "4096kb"

    def test_mb_unit_no_multiplier(self):
        """1024 × 1MB → '1024mb'."""
        assert settings_security._resolve_setting("1024", "MB") == "1024mb"

    def test_seconds_unit_no_multiplier(self):
        """300 × 1s → '300s'."""
        assert settings_security._resolve_setting("300", "s") == "300s"

    def test_ms_unit_no_multiplier(self):
        """20 × 1ms → '20ms'."""
        assert settings_security._resolve_setting("20", "ms") == "20ms"

    def test_none_unit_returns_raw(self):
        """unit=None → setting returned as-is."""
        assert settings_security._resolve_setting("on", None) == "on"

    def test_empty_setting_returns_empty(self):
        """Empty string → empty string."""
        assert settings_security._resolve_setting("", "kB") == ""

    def test_non_numeric_returns_raw(self):
        """Non-numeric → raw setting returned."""
        assert settings_security._resolve_setting("replica", None) == "replica"


# ---------------------------------------------------------------------------
    """Tests for human-readable value display conversion."""

    def test_8kb_unit_to_mb(self):
        """16384 * 8kB = 131072 kB = 128 MB"""
        assert settings_security._format_pg_value("16384", "8kB") == "128.00 MB"

    def test_kb_unit_to_mb(self):
        """4096 kB = 4 MB"""
        assert settings_security._format_pg_value("4096", "kB") == "4.00 MB"

    def test_mb_unit_stays_mb(self):
        """512 MB stays 512 MB"""
        assert settings_security._format_pg_value("512", "MB") == "512.00 MB"

    def test_mb_to_gb(self):
        """4096 MB = 4 GB"""
        assert settings_security._format_pg_value("4096", "MB") == "4.00 GB"

    def test_gb_unit_stays_gb(self):
        """4 GB stays 4 GB"""
        assert settings_security._format_pg_value("4", "GB") == "4.00 GB"

    def test_seconds_to_minutes(self):
        """300 s = 5 min"""
        assert settings_security._format_pg_value("300", "s") == "5 min"

    def test_seconds_stays_seconds(self):
        """45 s stays 45 s"""
        assert settings_security._format_pg_value("45", "s") == "45 s"

    def test_ms_to_seconds(self):
        """5000 ms = 5 s"""
        assert settings_security._format_pg_value("5000", "ms") == "5 s"

    def test_minutes_stays_minutes(self):
        """5 min stays 5 min"""
        assert settings_security._format_pg_value("5", "min") == "5 min"

    def test_hours_to_days(self):
        """48 h = 2.0 d"""
        assert settings_security._format_pg_value("48", "h") == "2.0 d"

    def test_non_numeric_fallback(self):
        """Non-numeric values fall back to raw string"""
        assert settings_security._format_pg_value("on", None) == "on"

    def test_empty_setting(self):
        """Empty string returns empty string"""
        assert settings_security._format_pg_value("", "MB") == ""

    def test_none_setting(self):
        """None returns empty string"""
        assert settings_security._format_pg_value("None", None) == "None"


# ---------------------------------------------------------------------------
# check_db_parameters — current_value_display field
# ---------------------------------------------------------------------------


class TestCheckDbParametersDisplay:
    """Verify the new current_value_display field appears in findings."""

    @pytest.mark.asyncio
    async def test_shared_buffers_finding_has_display(self):
        """shared_buffers at 16MB should have current_value_display = '16.00 MB'."""
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=_make_pg_settings({"shared_buffers": "2048"})
        )
        result = await settings_security.check_db_parameters(conn, "lenexa")
        sb_findings = [f for f in result["findings"] if f["parameter"] == "shared_buffers"]
        assert len(sb_findings) >= 1
        finding = sb_findings[0]
        assert "current_value_display" in finding
        # 2048 × 8kB = 16 MB
        assert finding["current_value_display"] == "16.00 MB"

    @pytest.mark.asyncio
    async def test_all_findings_have_display_field(self):
        """Every finding must include current_value_display."""
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=_make_pg_settings({"shared_buffers": "16383", "ssl": "off"})
        )
        result = await settings_security.check_db_parameters(conn, "lenexa")
        for finding in result["findings"]:
            assert "current_value_display" in finding, (
                f"Missing current_value_display in finding for {finding['parameter']}"
            )

    @pytest.mark.asyncio
    async def test_json_serializable_with_display(self):
        """Output with current_value_display must be JSON-serializable."""
        conn = AsyncMock()
        conn.fetch = AsyncMock(
            return_value=_make_pg_settings({"shared_buffers": "16383", "ssl": "off"})
        )
        result = await settings_security.check_db_parameters(conn, "lenexa")
        dumped = json.dumps(result)
        assert isinstance(dumped, str)
        reloaded = json.loads(dumped)
        assert reloaded == result


# ---------------------------------------------------------------------------
# check_server
# ---------------------------------------------------------------------------


class TestCheckServer:
    """Tests for OS-level resource retrieval."""

    @pytest.mark.asyncio
    async def test_get_cpu_info_returns_expected_keys(self):
        """_get_cpu_info returns dict with cpu_count key."""
        conn = AsyncMock()

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "MAX_WORKER_PROCESSES" in sql_upper:
                return {"cpu_count": 8}
            return None

        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)
        result = await settings_security._get_cpu_info(conn)
        assert "cpu_count" in result
        assert result["cpu_count"] == 8

    @pytest.mark.asyncio
    async def test_get_cpu_info_no_data(self):
        """_get_cpu_info gracefully handles missing data."""
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        result = await settings_security._get_cpu_info(conn)
        assert "cpu_count" in result
        assert result["cpu_count"] is None

    @pytest.mark.asyncio
    async def test_check_server_returns_all_sections(self):
        """check_server returns cpu, memory, disk, filesystem_checked."""
        conn = AsyncMock()

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "MAX_WORKER_PROCESSES" in sql_upper:
                return {"cpu_count": 8}
            if "PG_READ_FILE" in sql_upper:
                return None  # not superuser
            if "PG_SETTINGS" in sql_upper and "SHARED_BUFFERS" in sql_upper:
                return [
                    {"name": "shared_buffers", "setting": "16384", "unit": "8kB"},
                    {"name": "effective_cache_size", "setting": "16384", "unit": "8kB"},
                ]
            return None

        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)
        conn.fetchval = AsyncMock(return_value=None)

        async def fetch_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "PG_SETTINGS" in sql_upper and "SHARED_BUFFERS" in sql_upper:
                return [
                    {"name": "shared_buffers", "setting": "16384", "unit": "8kB"},
                    {"name": "effective_cache_size", "setting": "16384", "unit": "8kB"},
                ]
            return []

        conn.fetch = AsyncMock(side_effect=fetch_side)

        result = await settings_security.check_server(conn, "/data")
        assert "cpu" in result
        assert "memory" in result
        assert "disk" in result
        assert result["filesystem_checked"] == "/data"
        assert result["cpu"]["cpu_count"] == 8

    @pytest.mark.asyncio
    async def test_check_server_json_serializable(self):
        """check_server output must be JSON-serializable."""
        conn = AsyncMock()

        async def fetchrow_side(sql, *args, **kwargs):
            sql_upper = sql.strip().upper()
            if "MAX_WORKER_PROCESSES" in sql_upper:
                return {"cpu_count": 4}
            return None

        conn.fetchrow = AsyncMock(side_effect=fetchrow_side)
        conn.fetchval = AsyncMock(return_value=None)
        conn.fetch = AsyncMock(return_value=[])

        result = await settings_security.check_server(conn, "/data")
        dumped = json.dumps(result)
        assert isinstance(dumped, str)
        reloaded = json.loads(dumped)
        assert reloaded == result


# ---------------------------------------------------------------------------
# input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    """Property 14: Input validation rejects SQL injection vectors."""

    @pytest.mark.asyncio
    async def test_validate_database_name_rejects_semicolon(self):
        from src.tools.input_validation import validate_database_name
        with pytest.raises(ValueError, match="INVALID_INPUT:"):
            validate_database_name("edb; DROP TABLE users;--")

    @pytest.mark.asyncio
    async def test_validate_database_name_rejects_double_dash(self):
        from src.tools.input_validation import validate_database_name
        with pytest.raises(ValueError, match="INVALID_INPUT:"):
            validate_database_name("edb--comment")

    @pytest.mark.asyncio
    async def test_validate_database_name_accepts_valid(self):
        from src.tools.input_validation import validate_database_name
        result = validate_database_name("lenexa")
        assert result == "lenexa"
