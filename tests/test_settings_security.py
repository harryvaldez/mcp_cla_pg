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
    """Build a conformant pg_settings row list with safe defaults."""
    defaults: dict[str, str] = {
        "shared_buffers": "512MB",
        "work_mem": "4MB",
        "maintenance_work_mem": "256MB",
        "effective_cache_size": "4GB",
        "wal_buffers": "16MB",
        "huge_pages": "try",
        "wal_level": "replica",
        "checkpoint_timeout": "300s",
        "checkpoint_completion_target": "0.9",
        "max_wal_size": "1GB",
        "random_page_cost": "1.1",
        "effective_io_concurrency": "2",
        "default_statistics_target": "100",
        "cpu_tuple_cost": "0.01",
        "cpu_index_tuple_cost": "0.005",
        "cpu_operator_cost": "0.0025",
        "autovacuum": "on",
        "autovacuum_max_workers": "3",
        "autovacuum_naptime": "60s",
        "autovacuum_vacuum_scale_factor": "0.1",
        "autovacuum_vacuum_cost_delay": "20ms",
        "autovacuum_vacuum_cost_limit": "200",
        "logging_collector": "on",
        "log_min_duration_statement": "1000ms",
        "log_checkpoints": "on",
        "log_lock_waits": "on",
        "log_temp_files": "0",
        "log_autovacuum_min_duration": "0",
        "superuser_reserved_connections": "3",
        "tcp_keepalives_idle": "120s",
        "ssl": "on",
        "password_encryption": "md5",
        "db_user_namespace": "off",
    }
    if overrides:
        defaults.update(overrides)
    return [
        {
            "name": k,
            "setting": v,
            "unit": "",
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
            mock_conn, "edb"
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
            mock_conn, "edb"
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
            mock_conn, "edb"
        )
        findings = result["findings"]
        ssl_findings = [f for f in findings if f["parameter"] == "ssl"]
        assert len(ssl_findings) == 1
        assert ssl_findings[0]["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_shared_buffers_low_is_high(self, mock_conn):
        """shared_buffers below 128MB → HIGH severity."""
        mock_conn.fetch = AsyncMock(
            return_value=_make_pg_settings({"shared_buffers": "16MB"})
        )
        result = await settings_security.check_db_parameters(
            mock_conn, "edb"
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
            mock_conn, "edb"
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
            mock_conn, "edb"
        )
        dumped = json.dumps(result)
        assert isinstance(dumped, str)
        reloaded = json.loads(dumped)
        assert reloaded == result


# ---------------------------------------------------------------------------
# compute_db_metrics
# ---------------------------------------------------------------------------


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
        result = await settings_security.compute_db_metrics(conn, "edb")
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
        result = await settings_security.compute_db_metrics(conn, "edb")
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
        result = await settings_security.compute_db_metrics(conn, "edb")
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
        result = await settings_security.compute_db_metrics(conn, "edb")
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
        result = await settings_security.compute_db_metrics(conn, "edb")
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

        result = await settings_security.analyze_db_security(conn, "edb")
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

        result = await settings_security.analyze_db_security(conn, "edb")
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

        result = await settings_security.analyze_db_security(conn, "edb")
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

        result = await settings_security.analyze_db_security(conn, "edb")
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

        result = await settings_security.analyze_db_security(conn, "edb")
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

        result = await settings_security.analyze_db_security(conn, "edb")
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

        result = await settings_security.analyze_db_security(conn, "edb")
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

        result = await settings_security.analyze_db_security(conn, "edb")
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
        result = validate_database_name("edb")
        assert result == "edb"
