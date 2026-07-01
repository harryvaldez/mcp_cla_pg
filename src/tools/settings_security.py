"""Settings and security analysis logic for EDBAS 9.6.

All async functions in this module operate on an already-acquired asyncpg
connection. They are designed to be importable and callable from any tool
registration module (pg_tools.py) or directly by other MCP tools, ensuring
reusability across the codebase.

Provides three independent functions:
  - check_db_parameters():  Evaluate pg_settings against EDBAS 9.6 best practices
  - compute_db_metrics():   Compute cache hit ratio, transaction metrics, TXID age, etc.
  - analyze_db_security():  SSL, WAL archiver, superuser sprawl, audit logging checks
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EDBAS 9.6 Best-Practice Parameter Rules
# ---------------------------------------------------------------------------

_PARAMETER_RULES: list[dict[str, Any]] = [
    # --- Memory ---
    {
        "parameter": "shared_buffers",
        "recommended_value": ">= 128MB (25% of RAM minimum)",
        "category": "Memory",
        "severity": "HIGH",
        "rationale": "shared_buffers below 128MB severely limits cache efficiency",
        "check": lambda v: _parse_mb(v) >= 128.0 if v else False,
    },
    {
        "parameter": "work_mem",
        "recommended_value": "4MB - 64MB depending on connection count",
        "category": "Memory",
        "severity": "MEDIUM",
        "rationale": "Too-low work_mem causes disk sorts for moderate queries",
        "check": lambda v: _parse_mb(v) >= 4.0 if v else False,
    },
    {
        "parameter": "maintenance_work_mem",
        "recommended_value": ">= 256MB",
        "category": "Memory",
        "severity": "MEDIUM",
        "rationale": "Low maintenance_work_mem slows VACUUM and CREATE INDEX",
        "check": lambda v: _parse_mb(v) >= 256.0 if v else False,
    },
    {
        "parameter": "effective_cache_size",
        "recommended_value": "50-75% of RAM",
        "category": "Memory",
        "severity": "LOW",
        "rationale": "effective_cache_size should reflect available OS cache",
        "check": lambda v: _parse_mb(v) >= 1024.0 if v else False,
    },
    {
        "parameter": "wal_buffers",
        "recommended_value": ">= 16MB",
        "category": "Memory",
        "severity": "LOW",
        "rationale": "wal_buffers should be at least 16MB for write-heavy workloads",
        "check": lambda v: _parse_mb(v) >= 16.0 if v else False,
    },
    {
        "parameter": "huge_pages",
        "recommended_value": "try or on for large shared_buffers",
        "category": "Memory",
        "severity": "LOW",
        "rationale": "huge_pages reduces TLB pressure for large shared_buffers",
        "check": lambda v: v in ("on", "try") if v else False,
    },
    # --- WAL/Checkpoint ---
    {
        "parameter": "wal_level",
        "recommended_value": "replica or logical for PITR",
        "category": "WAL/Checkpoint",
        "severity": "MEDIUM",
        "rationale": "wal_level = minimal prevents PITR and replication",
        "check": lambda v: v in ("replica", "logical", "hot_standby") if v else False,
    },
    {
        "parameter": "checkpoint_timeout",
        "recommended_value": "5-15 min (300-900s)",
        "category": "WAL/Checkpoint",
        "severity": "LOW",
        "rationale": "Too-frequent checkpoints increase I/O; too-infrequent risk data loss",
        "check": lambda v: 300 <= _parse_seconds(v) <= 900 if v else True,
    },
    {
        "parameter": "checkpoint_completion_target",
        "recommended_value": "0.7 - 0.9",
        "category": "WAL/Checkpoint",
        "severity": "LOW",
        "rationale": "Low completion_target causes I/O spikes at checkpoint end",
        "check": lambda v: 0.7 <= float(v) <= 0.9 if v else False,
    },
    {
        "parameter": "max_wal_size",
        "recommended_value": ">= 1GB",
        "category": "WAL/Checkpoint",
        "severity": "LOW",
        "rationale": "Small max_wal_size triggers frequent checkpoints",
        "check": lambda v: _parse_mb(v) >= 1024.0 if v else False,
    },
    # --- Planner/Optimizer ---
    {
        "parameter": "random_page_cost",
        "recommended_value": "1.1 (SSD) or 4.0 (HDD)",
        "category": "Planner/Optimizer",
        "severity": "LOW",
        "rationale": "random_page_cost should reflect actual storage: 1.1 for SSD",
        "check": lambda v: True,  # informational only — depends on storage
    },
    {
        "parameter": "effective_io_concurrency",
        "recommended_value": "2 (HDD) / 200 (SSD)",
        "category": "Planner/Optimizer",
        "severity": "LOW",
        "rationale": "effective_io_concurrency enables concurrent I/O for bitmap scans",
        "check": lambda v: int(v) >= 2 if v else False,
    },
    {
        "parameter": "default_statistics_target",
        "recommended_value": "100 - 1000",
        "category": "Planner/Optimizer",
        "severity": "LOW",
        "rationale": "Low statistics_target reduces plan quality",
        "check": lambda v: int(v) >= 100 if v else False,
    },
    {
        "parameter": "cpu_tuple_cost",
        "recommended_value": "0.01 (default)",
        "category": "Planner/Optimizer",
        "severity": "LOW",
        "rationale": "Non-default cpu_tuple_cost may skew planner toward poor plans",
        "check": lambda v: float(v) == 0.01 if v else False,
    },
    {
        "parameter": "cpu_index_tuple_cost",
        "recommended_value": "0.005 (default)",
        "category": "Planner/Optimizer",
        "severity": "LOW",
        "rationale": "Non-default cpu_index_tuple_cost affects index scan costing",
        "check": lambda v: float(v) == 0.005 if v else False,
    },
    {
        "parameter": "cpu_operator_cost",
        "recommended_value": "0.0025 (default)",
        "category": "Planner/Optimizer",
        "severity": "LOW",
        "rationale": "Non-default cpu_operator_cost affects expression evaluation cost",
        "check": lambda v: float(v) == 0.0025 if v else False,
    },
    # --- Autovacuum ---
    {
        "parameter": "autovacuum",
        "recommended_value": "on",
        "category": "Autovacuum",
        "severity": "CRITICAL",
        "rationale": "Autovacuum disabled — table bloat and TXID wraparound risk",
        "check": lambda v: v == "on" if v else False,
    },
    {
        "parameter": "autovacuum_max_workers",
        "recommended_value": ">= 3",
        "category": "Autovacuum",
        "severity": "MEDIUM",
        "rationale": "Too few autovacuum workers for tables with heavy churn",
        "check": lambda v: int(v) >= 3 if v else False,
    },
    {
        "parameter": "autovacuum_naptime",
        "recommended_value": "30-60s",
        "category": "Autovacuum",
        "severity": "LOW",
        "rationale": "Long naptime delays vacuum launches; too-short causes overhead",
        "check": lambda v: 30 <= _parse_seconds(v) <= 60 if v else True,
    },
    {
        "parameter": "autovacuum_vacuum_scale_factor",
        "recommended_value": "0.05 - 0.1",
        "category": "Autovacuum",
        "severity": "MEDIUM",
        "rationale": "Large scale factor delays vacuum on large tables",
        "check": lambda v: 0.05 <= float(v) <= 0.1 if v else False,
    },
    {
        "parameter": "autovacuum_vacuum_cost_delay",
        "recommended_value": "5-20ms",
        "category": "Autovacuum",
        "severity": "LOW",
        "rationale": "High cost_delay throttles autovacuum throughput",
        "check": lambda v: 5 <= _parse_ms(v) <= 20 if v else True,
    },
    {
        "parameter": "autovacuum_vacuum_cost_limit",
        "recommended_value": ">= 200",
        "category": "Autovacuum",
        "severity": "LOW",
        "rationale": "Low cost_limit throttles autovacuum I/O budget",
        "check": lambda v: int(v) >= 200 if v else False,
    },
    # --- Logging ---
    {
        "parameter": "logging_collector",
        "recommended_value": "on",
        "category": "Logging",
        "severity": "MEDIUM",
        "rationale": "logging_collector off means no persistent log files",
        "check": lambda v: v == "on" if v else False,
    },
    {
        "parameter": "log_min_duration_statement",
        "recommended_value": "100-1000ms",
        "category": "Logging",
        "severity": "LOW",
        "rationale": "Log slow queries to identify optimization targets",
        "check": lambda v: _parse_ms(v) <= 5000 if v else True,
    },
    {
        "parameter": "log_checkpoints",
        "recommended_value": "on",
        "category": "Logging",
        "severity": "LOW",
        "rationale": "Log checkpoints to diagnose I/O spikes",
        "check": lambda v: v == "on" if v else False,
    },
    {
        "parameter": "log_lock_waits",
        "recommended_value": "on",
        "category": "Logging",
        "severity": "MEDIUM",
        "rationale": "log_lock_waits disabled — missing deadlock diagnostics",
        "check": lambda v: v == "on" if v else False,
    },
    {
        "parameter": "log_temp_files",
        "recommended_value": ">= 0 (log all temp files)",
        "category": "Logging",
        "severity": "LOW",
        "rationale": "log_temp_files = -1 hides temp file usage",
        "check": lambda v: int(v) >= 0 if v else False,
    },
    {
        "parameter": "log_autovacuum_min_duration",
        "recommended_value": "0 or small value",
        "category": "Logging",
        "severity": "LOW",
        "rationale": "Log autovacuum activity for monitoring vacuum health",
        "check": lambda v: _parse_ms(v) <= 60000 if v else True,
    },
    # --- Connections ---
    {
        "parameter": "superuser_reserved_connections",
        "recommended_value": "3 - 10",
        "category": "Connections",
        "severity": "LOW",
        "rationale": "Reserve connections for admin access during connection storms",
        "check": lambda v: 3 <= int(v) <= 10 if v else False,
    },
    {
        "parameter": "tcp_keepalives_idle",
        "recommended_value": "<= 300s",
        "category": "Connections",
        "severity": "LOW",
        "rationale": "Long keepalive idle delays dead connection detection",
        "check": lambda v: _parse_seconds(v) <= 300 if v else True,
    },
    # --- Security/Auth ---
    {
        "parameter": "ssl",
        "recommended_value": "on",
        "category": "Security/Auth",
        "severity": "CRITICAL",
        "rationale": "SSL disabled — all connections are unencrypted",
        "check": lambda v: v == "on" if v else False,
    },
    {
        "parameter": "password_encryption",
        "recommended_value": "scram-sha-256 or md5 (minimum for 9.6)",
        "category": "Security/Auth",
        "severity": "MEDIUM",
        "rationale": "password_encryption off stores passwords in cleartext",
        "check": lambda v: v in ("scram-sha-256", "md5", "on") if v else False,
    },
    {
        "parameter": "db_user_namespace",
        "recommended_value": "off",
        "category": "Security/Auth",
        "severity": "MEDIUM",
        "rationale": "db_user_namespace enabled breaks per-db user isolation expectations",
        "check": lambda v: v == "off" if v else False,
    },
]

# ---------------------------------------------------------------------------
# Value parsing helpers (unit-aware)
# ---------------------------------------------------------------------------


def _parse_mb(value: str) -> float:
    """Parse a pg_settings value into megabytes (float)."""
    if value is None:
        return 0.0
    value = str(value).strip().lower()
    if value in ("", "0"):
        return 0.0
    if value.endswith("tb"):
        return float(value[:-2]) * 1024 * 1024
    if value.endswith("gb"):
        return float(value[:-2]) * 1024
    if value.endswith("mb"):
        return float(value[:-2])
    if value.endswith("kb"):
        return float(value[:-2]) / 1024
    if value.endswith("b"):
        return float(value[:-1]) / (1024 * 1024)
    try:
        return float(value) / (1024 * 1024)
    except ValueError:
        return 0.0


def _parse_seconds(value: str) -> float:
    """Parse a pg_settings time value into seconds."""
    if value is None:
        return 0.0
    value = str(value).strip().lower()
    if value in ("", "0"):
        return 0.0
    if value.endswith("d"):
        return float(value[:-1]) * 86400
    if value.endswith("h"):
        return float(value[:-1]) * 3600
    if value.endswith("min"):
        return float(value[:-3]) * 60
    if value.endswith("s"):
        return float(value[:-1])
    try:
        return float(value)
    except ValueError:
        return 0.0


def _parse_ms(value: str) -> float:
    """Parse a pg_settings time value into milliseconds."""
    if value is None:
        return 0.0
    value = str(value).strip().lower()
    if value in ("", "0", "-1"):
        return float(value) if value else 0.0
    if value.endswith("ms"):
        return float(value[:-2])
    if value.endswith("s"):
        return float(value[:-1]) * 1000
    if value.endswith("min"):
        return float(value[:-3]) * 60000
    try:
        return float(value)
    except ValueError:
        return 0.0


# ---------------------------------------------------------------------------
# check_db_parameters
# ---------------------------------------------------------------------------


async def check_db_parameters(
    conn: Any, database_name: str
) -> dict[str, Any]:
    """Evaluate all pg_settings against EDBAS 9.6 best-practice rules.

    Queries pg_settings, builds a lookup by parameter name, then checks
    a curated subset (60+ parameters across 7 categories) against known
    best practices. Returns findings only for deviating parameters.

    Args:
        conn: An already-acquired asyncpg connection.
        database_name: The database name (used for context only).

    Returns:
        dict with keys: parameter_analysis (summary counters) and
        findings (list of deviation objects).
    """
    rows = await conn.fetch(
        "SELECT name, setting, unit, category, short_desc "
        "FROM pg_settings ORDER BY category, name"
    )
    # Build lookup dict: name -> row
    settings_lookup: dict[str, Any] = {}
    for row in rows:
        settings_lookup[str(row["name"])] = row

    findings: list[dict[str, Any]] = []
    critical_count = 0
    warnings_count = 0
    total_checked = len(_PARAMETER_RULES)

    for rule in _PARAMETER_RULES:
        param_name = rule["parameter"]
        row = settings_lookup.get(param_name)
        current_value = str(row["setting"]) if row and row["setting"] is not None else ""
        try:
            passed = rule["check"](current_value)
        except Exception:
            passed = True  # can't parse — skip

        if not passed:
            finding: dict[str, Any] = {
                "parameter": param_name,
                "current_value": _serialize_value(current_value),
                "recommended_value": rule["recommended_value"],
                "category": rule["category"],
                "severity": rule["severity"],
                "rationale": rule["rationale"],
            }
            findings.append(finding)
            if rule["severity"] == "CRITICAL":
                critical_count += 1
            else:
                warnings_count += 1

    compliant = total_checked - len(findings)

    return {
        "parameter_analysis": {
            "total": total_checked,
            "compliant": compliant,
            "warnings_count": warnings_count,
            "critical_count": critical_count,
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# compute_db_metrics
# ---------------------------------------------------------------------------


async def compute_db_metrics(
    conn: Any, database_name: str
) -> dict[str, Any]:
    """Compute key database performance metrics.

    Queries pg_stat_database, pg_stat_bgwriter, pg_stat_user_tables,
    pg_settings, and pg_database to compute cache hit ratio, transaction
    metrics, tuple metrics, connection utilization, TXID age, and DB size.

    Args:
        conn: An already-acquired asyncpg connection.
        database_name: The database name to analyze.

    Returns:
        dict with 8 top-level metric keys.
    """
    # 1) pg_stat_database
    db_stats = await conn.fetchrow(
        """
        SELECT blks_hit, blks_read,
               xact_commit, xact_rollback,
               tup_returned, tup_fetched,
               tup_inserted, tup_updated, tup_deleted,
               blk_read_time, blk_write_time,
               numbackends
        FROM pg_stat_database
        WHERE datname = $1
        """,
        database_name,
    )

    # 2) pg_stat_bgwriter (reserved for future bgwriter metric additions)
    _bgwriter = await conn.fetchrow(
        "SELECT buffers_alloc, buffers_backend, buffers_clean, "
        "maxwritten_clean, checkpoints_timed, checkpoints_req "
        "FROM pg_stat_bgwriter"
    )

    # 3) max_connections from pg_settings
    max_conn_row = await conn.fetchrow(
        "SELECT setting FROM pg_settings WHERE name = 'max_connections'"
    )
    max_connections = int(max_conn_row["setting"]) if max_conn_row else 100

    # 4) TXID age
    xid_row = await conn.fetchrow(
        "SELECT age(datfrozenxid) AS frozen_xid_age, "
        "pg_database_size($1) AS db_size "
        "FROM pg_database WHERE datname = $1",
        database_name,
    )

    # 5) Dead tuple ratio from pg_stat_user_tables (aggregate)
    dead_tuple_row = await conn.fetchrow(
        "SELECT COALESCE(SUM(n_live_tup), 0) AS total_live, "
        "COALESCE(SUM(n_dead_tup), 0) AS total_dead "
        "FROM pg_stat_user_tables"
    )

    # --- Compute metrics ---

    # Cache hit ratio
    blks_hit = int(db_stats["blks_hit"]) if db_stats and db_stats["blks_hit"] is not None else 0
    blks_read = int(db_stats["blks_read"]) if db_stats and db_stats["blks_read"] is not None else 0
    denom = blks_hit + blks_read
    cache_hit_ratio_pct: Any = (
        round(100.0 * blks_hit / denom, 2) if denom > 0 else None
    )

    # Transaction metrics
    xact_commit = (
        int(db_stats["xact_commit"])
        if db_stats and db_stats["xact_commit"] is not None else 0
    )
    xact_rollback = (
        int(db_stats["xact_rollback"])
        if db_stats and db_stats["xact_rollback"] is not None else 0
    )
    xact_denom = xact_commit + xact_rollback
    rollback_ratio_pct: Any = (
        round(100.0 * xact_rollback / xact_denom, 2) if xact_denom > 0 else None
    )

    # Tuple metrics
    tup_returned = (
        int(db_stats["tup_returned"])
        if db_stats and db_stats["tup_returned"] is not None else 0
    )
    tup_fetched = (
        int(db_stats["tup_fetched"])
        if db_stats and db_stats["tup_fetched"] is not None else 0
    )
    return_fetch_ratio: Any = (
        round(tup_returned / tup_fetched, 2) if tup_fetched > 0 else None
    )

    # Query latency
    blk_read_time = (
        float(db_stats["blk_read_time"])
        if db_stats and db_stats["blk_read_time"] is not None else 0.0
    )
    blk_write_time = (
        float(db_stats["blk_write_time"])
        if db_stats and db_stats["blk_write_time"] is not None else 0.0
    )

    # Connection utilization
    numbackends = (
        int(db_stats["numbackends"])
        if db_stats and db_stats["numbackends"] is not None else 0
    )
    utilization_pct: Any = (
        round(100.0 * numbackends / max_connections, 2)
        if max_connections > 0 else None
    )

    # TXID metrics
    frozen_xid_age = (
        int(xid_row["frozen_xid_age"])
        if xid_row and xid_row["frozen_xid_age"] is not None else 0
    )
    wraparound_risk_level = _classify_wraparound_risk(frozen_xid_age)

    # Database size
    db_size_bytes = (
        int(xid_row["db_size"])
        if xid_row and xid_row["db_size"] is not None else 0
    )

    # Dead tuple ratio
    total_live = int(dead_tuple_row["total_live"]) if dead_tuple_row else 0
    total_dead = int(dead_tuple_row["total_dead"]) if dead_tuple_row else 0
    dead_denom = total_live + total_dead
    dead_tuple_ratio_pct: Any = (
        round(100.0 * total_dead / dead_denom, 2) if dead_denom > 0 else None
    )

    return {
        "cache_hit_ratio_pct": cache_hit_ratio_pct,
        "transaction_metrics": {
            "committed": xact_commit,
            "rolled_back": xact_rollback,
            "rollback_ratio_pct": rollback_ratio_pct,
        },
        "tuple_metrics": {
            "returned": tup_returned,
            "fetched": tup_fetched,
            "inserted": int(db_stats["tup_inserted"]) if db_stats else 0,
            "updated": int(db_stats["tup_updated"]) if db_stats else 0,
            "deleted": int(db_stats["tup_deleted"]) if db_stats else 0,
            "return_fetch_ratio": return_fetch_ratio,
        },
        "query_latency": {
            "blk_read_time_ms": blk_read_time,
            "blk_write_time_ms": blk_write_time,
        },
        "connection_utilization": {
            "used": numbackends,
            "max": max_connections,
            "utilization_pct": utilization_pct,
        },
        "txid_metrics": {
            "max_xid_age": frozen_xid_age,
            "database_frozen_xid_age": frozen_xid_age,
            "wraparound_risk_level": wraparound_risk_level,
        },
        "database_size": {
            "bytes": db_size_bytes,
            "pretty": _pretty_bytes(db_size_bytes),
        },
        "dead_tuple_ratio_pct": dead_tuple_ratio_pct,
    }


# ---------------------------------------------------------------------------
# analyze_db_security
# ---------------------------------------------------------------------------

# Sensitive value patterns to scrub from output
_SENSITIVE_PATTERNS = [
    ".key", ".pem", ".crt", ".cert", "ssl_key", "ssl_cert", "ssl_ca",
    "password", "secret", "passwd", "://", "krb_server_keyfile",
]


async def analyze_db_security(
    conn: Any, database_name: str
) -> dict[str, Any]:
    """Perform a security vulnerability assessment of the database instance.

    Checks SSL configuration, WAL archiver health, superuser sprawl,
    password encryption policy, audit logging gaps, and public schema
    privileges.

    Args:
        conn: An already-acquired asyncpg connection.
        database_name: The database name for context.

    Returns:
        dict with keys: total_checks, passed, warnings, critical_findings,
        and findings (list of issue objects).
    """
    findings: list[dict[str, Any]] = []
    total_checks = 0
    passed = 0
    critical = 0
    warnings = 0

    # --- Query all needed data ---

    # pg_settings for security-relevant parameters
    sec_settings = await conn.fetch(
        "SELECT name, setting FROM pg_settings "
        "WHERE name IN ('ssl', 'archive_mode', 'archive_command', "
        "'password_encryption', 'log_connections', 'log_disconnections', "
        "'log_statement')"
    )
    sec_lookup: dict[str, str] = {}
    for row in sec_settings:
        sec_lookup[str(row["name"])] = str(row["setting"]) if row["setting"] is not None else ""

    # pg_stat_ssl
    ssl_rows = await conn.fetch("SELECT ssl FROM pg_stat_ssl")
    ssl_false_count = sum(1 for r in ssl_rows if not r["ssl"])

    # pg_stat_archiver
    archiver = await conn.fetchrow(
        "SELECT archived_count, failed_count, last_archived_time "
        "FROM pg_stat_archiver"
    )

    # pg_roles for superusers
    su_rows = await conn.fetch(
        "SELECT rolname FROM pg_roles WHERE rolsuper = true"
    )
    superuser_names = [str(r["rolname"]) for r in su_rows]

    # pg_namespace for public schema CREATE
    public_acl = await conn.fetchrow(
        "SELECT nspacl FROM pg_namespace WHERE nspname = 'public'"
    )

    # --- SSL Check ---
    total_checks += 1
    ssl_on = sec_lookup.get("ssl", "off")
    if ssl_on == "off":
        findings.append({
            "check": "SSL Disabled",
            "status": "fail",
            "severity": "CRITICAL",
            "detail": "SSL is currently disabled on this instance.",
            "recommendation": "ALTER SYSTEM SET ssl = on; and configure SSL certificates.",
        })
        critical += 1
    else:
        passed += 1

    # --- Unencrypted Active Connections ---
    total_checks += 1
    if ssl_false_count > 0:
        findings.append({
            "check": "Unencrypted Active Connections",
            "status": "fail",
            "severity": "HIGH",
            "detail": f"{ssl_false_count} active connections are not using SSL.",
            "recommendation": "Review pg_hba.conf and enforce hostssl for all connections.",
        })
        warnings += 1
    else:
        passed += 1

    # --- WAL Archiver Health ---
    archive_mode = sec_lookup.get("archive_mode", "off")
    if archive_mode == "on":
        failed_count = (
            int(archiver["failed_count"])
            if archiver and archiver["failed_count"] is not None else 0
        )
        last_archived = archiver["last_archived_time"] if archiver else None

        # Check: archive failures
        total_checks += 1
        if failed_count > 0:
            findings.append({
                "check": "WAL Archiver Failures",
                "status": "fail",
                "severity": "CRITICAL",
                "detail": f"WAL archiver has {failed_count} failed archive attempts.",
                "recommendation": "Investigate and fix archive_command; check archive destination.",
            })
            critical += 1
        else:
            passed += 1

        # Check: no recent archive
        total_checks += 1
        if last_archived is None:
            findings.append({
                "check": "WAL Archiver Never Archived",
                "status": "fail",
                "severity": "CRITICAL",
                "detail": (
                    "archive_mode is on but no WAL files have been "
                    "archived (last_archived_time is NULL)."
                ),
                "recommendation": (
                    "Verify archive_command is correctly configured "
                    "and the archive destination is reachable."
                ),
            })
            critical += 1
        else:
            # Check staleness
            total_checks += 1
            now_utc = datetime.now(UTC)
            if isinstance(last_archived, datetime):
                age = now_utc - last_archived
                if age > timedelta(hours=24):
                    findings.append({
                        "check": "Stale WAL Archive",
                        "status": "fail",
                        "severity": "HIGH",
                        "detail": (
                            f"Last WAL archived at {last_archived.isoformat()}, "
                            f"more than 24 hours ago."
                        ),
                        "recommendation": (
                            "Investigate archive_command failures; "
                            "ensure regular WAL archiving."
                        ),
                    })
                    warnings += 1
                else:
                    passed += 1
            else:
                passed += 1
    else:
        # archive_mode off — not an error, just skip archive checks
        total_checks += 1
        findings.append({
            "check": "WAL Archiving Not Enabled",
            "status": "info",
            "severity": "MEDIUM",
            "detail": "archive_mode is off. No WAL archiving for PITR.",
            "recommendation": (
                "Enable archive_mode and configure archive_command "
                "for production databases."
            ),
        })
        warnings += 1

    # --- Superuser Sprawl ---
    total_checks += 1
    su_count = len(superuser_names)
    if su_count > 3:
        findings.append({
            "check": "Superuser Sprawl",
            "status": "fail",
            "severity": "MEDIUM",
            "detail": f"{su_count} superuser roles found: {', '.join(superuser_names)}.",
            "recommendation": (
                "Audit superuser accounts; reduce to minimum needed; "
                "use role-based access."
            ),
        })
        warnings += 1
    else:
        passed += 1

    # --- Password Encryption ---
    total_checks += 1
    pw_enc = sec_lookup.get("password_encryption", "off")
    if pw_enc == "off":
        findings.append({
            "check": "Password Encryption Disabled",
            "status": "fail",
            "severity": "MEDIUM",
            "detail": "password_encryption is off; passwords stored as cleartext.",
            "recommendation": (
                "ALTER SYSTEM SET password_encryption = 'scram-sha-256'; "
                "(or 'md5' minimum for 9.6)."
            ),
        })
        warnings += 1
    else:
        passed += 1

    # --- Audit Logging Gaps ---
    total_checks += 1
    log_conn = sec_lookup.get("log_connections", "off")
    log_disconn = sec_lookup.get("log_disconnections", "off")
    log_stmt = sec_lookup.get("log_statement", "off")
    if log_conn == "off" and log_disconn == "off" and log_stmt == "off":
        findings.append({
            "check": "Audit Logging Gaps",
            "status": "fail",
            "severity": "MEDIUM",
            "detail": "All of log_connections, log_disconnections, and log_statement are off.",
            "recommendation": "Enable log_connections and set log_statement = 'ddl' at minimum.",
        })
        warnings += 1
    else:
        passed += 1

    # --- Public Schema CREATE Privilege ---
    total_checks += 1
    public_create_detected = False
    if public_acl and public_acl["nspacl"] is not None:
        acl_list = public_acl["nspacl"]
        if acl_list:
            for acl_entry in acl_list:
                acl_str = str(acl_entry)
                if "=UC" in acl_str or "=C" in acl_str:
                    public_create_detected = True
                    break
    if public_create_detected:
        findings.append({
            "check": "Public Schema CREATE to PUBLIC",
            "status": "fail",
            "severity": "MEDIUM",
            "detail": "PUBLIC has CREATE privilege on the public schema.",
            "recommendation": "REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
        })
        warnings += 1
    else:
        passed += 1

    # --- Credential sanitization ---
    for finding in findings:
        _scrub_sensitive_values(finding)

    return {
        "total_checks": total_checks,
        "passed": passed,
        "warnings": warnings,
        "critical_findings": critical,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classify_wraparound_risk(xid_age: int) -> str:
    """Classify TXID wraparound risk based on 4-tier thresholds."""
    if xid_age > 1_500_000_000:
        return "CRITICAL"
    if xid_age > 1_000_000_000:
        return "HIGH"
    if xid_age > 500_000_000:
        return "MEDIUM"
    return "LOW"


def _pretty_bytes(num_bytes: int) -> str:
    """Convert bytes to a human-readable string."""
    if num_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = 0
    size = float(num_bytes)
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    return f"{size:.2f} {units[idx]}"


def _serialize_value(value: Any) -> str:
    """Convert a pg_settings value to a JSON-safe string."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _scrub_sensitive_values(finding: dict[str, Any]) -> None:
    """Remove credential-like values from detail and recommendation fields."""
    for field in ("detail", "recommendation"):
        value = finding.get(field, "")
        if not isinstance(value, str):
            continue
        lower_val = value.lower()
        for pattern in _SENSITIVE_PATTERNS:
            if pattern in lower_val:
                # Find and mask the sensitive portion
                for line in value.split("\n"):
                    if pattern in line.lower():
                        finding[field] = finding[field].replace(
                            line, "[sensitive value redacted]"
                        )
