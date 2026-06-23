"""Core table analysis and object discovery logic for EDBAS 9.6.

All async functions in this module operate on an already-acquired asyncpg
connection. They are designed to be importable and callable from any tool
registration module (pg_tools.py) or directly by other MCP tools, ensuring
reusability across the codebase.

Maintenance functions (check_table_*) analyze a single table for issues.
Discovery functions (list_*_by_schema) enumerate database objects by type.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Maintenance Analysis Functions
# ---------------------------------------------------------------------------


async def check_table_bloat(
    conn: Any, schema: str, table: str
) -> dict[str, Any]:
    """Analyze dead tuple ratio and vacuum staleness for a table.

    Returns dead tuple percentage, HOT update efficiency, and last vacuum
    timestamps. High dead tuple % suggests a VACUUM FULL is needed.
    """
    row = await conn.fetchrow(
        """
        SELECT n_live_tup, n_dead_tup,
               ROUND(100.0 * n_dead_tup / NULLIF(n_live_tup + n_dead_tup, 0), 2) AS dead_pct,
               n_tup_hot_upd,
               ROUND(100.0 * n_tup_hot_upd / NULLIF(n_tup_upd, 0), 2) AS hot_update_pct,
               n_tup_ins, n_tup_upd, n_tup_del,
               last_vacuum, last_autovacuum
        FROM pg_stat_user_tables
        WHERE schemaname = $1 AND relname = $2
        """,
        schema, table,
    )
    if row is None:
        return {"error": f"Table {schema}.{table} not found in pg_stat_user_tables"}

    dead_pct = float(row["dead_pct"] or 0)
    if dead_pct > 30:
        bloat_severity = "HIGH"
    elif dead_pct > 10:
        bloat_severity = "MEDIUM"
    else:
        bloat_severity = "LOW"

    return {
        "dead_tuple_pct": dead_pct,
        "live_tuples": row["n_live_tup"],
        "dead_tuples": row["n_dead_tup"],
        "hot_update_pct": float(row["hot_update_pct"] or 0),
        "inserts": row["n_tup_ins"],
        "updates": row["n_tup_upd"],
        "deletes": row["n_tup_del"],
        "last_vacuum": str(row["last_vacuum"]) if row["last_vacuum"] else None,
        "last_autovacuum": str(row["last_autovacuum"]) if row["last_autovacuum"] else None,
        "bloat_severity": bloat_severity,
    }


async def check_table_wraparound(
    conn: Any, schema: str, table: str
) -> dict[str, Any]:
    """Check transaction ID wraparound risk for a table.

    Returns XID age and risk level. Tables approaching 2 billion transactions
    since last freeze risk database shutdown.
    """
    row = await conn.fetchrow(
        """
        SELECT c.relname,
               age(c.relfrozenxid) AS xid_age,
               CASE WHEN age(c.relfrozenxid) > 1500000000 THEN 'CRITICAL'
                    WHEN age(c.relfrozenxid) > 1000000000 THEN 'HIGH'
                    WHEN age(c.relfrozenxid) >  500000000 THEN 'MEDIUM'
                    ELSE 'LOW' END AS risk_level
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind = 'r'
        """,
        schema, table,
    )
    if row is None:
        return {"error": f"Table {schema}.{table} not found in pg_class (relkind=r)"}

    xid_age = int(row["xid_age"])
    risk = row["risk_level"]
    if risk == "CRITICAL":
        action = f"VACUUM FREEZE {schema}.{table}; -- IMMEDIATE action required, XID age {xid_age}"
    elif risk == "HIGH":
        action = f"VACUUM FREEZE {schema}.{table}; -- Schedule within 24h, XID age {xid_age}"
    elif risk == "MEDIUM":
        action = f"Monitor {schema}.{table} wraparound; autovacuum should handle this. XID age {xid_age}"  # noqa: E501
    else:
        action = f"No action needed. XID age {xid_age} is within safe range."

    return {
        "xid_age": xid_age,
        "risk_level": risk,
        "recommended_action": action,
    }


async def check_table_statistics(
    conn: Any, schema: str, table: str
) -> dict[str, Any]:
    """Check staleness of table statistics for query planner.

    Flags tables where ANALYZE hasn't run in > 7 days or never ran
    despite having live tuples.
    """
    row = await conn.fetchrow(
        """
        SELECT relname, last_analyze, last_autoanalyze,
               n_mod_since_analyze, n_live_tup,
               EXTRACT(DAY FROM NOW() - COALESCE(last_analyze, '1970-01-01'::timestamp))
                   AS days_since_analyze
        FROM pg_stat_user_tables
        WHERE schemaname = $1 AND relname = $2
        """,
        schema, table,
    )
    if row is None:
        return {"error": f"Table {schema}.{table} not found in pg_stat_user_tables"}

    days = float(row["days_since_analyze"] or 0)
    live = int(row["n_live_tup"] or 0)
    is_stale = days > 7 or (row["last_analyze"] is None and live > 0)

    if row["last_analyze"] is None and live > 0:
        recommendation = f"ANALYZE {schema}.{table}; -- Never analyzed, {live} live tuples"
    elif days > 30:
        recommendation = f"ANALYZE {schema}.{table}; -- Last analyzed {int(days)} days ago, {row['n_mod_since_analyze'] or 0} modifications since"  # noqa: E501
    elif days > 7:
        recommendation = f"Consider ANALYZE {schema}.{table}; -- Last analyzed {int(days)} days ago"
    else:
        recommendation = f"Statistics are current (last analyzed {int(days)} days ago)"

    return {
        "last_analyze": str(row["last_analyze"]) if row["last_analyze"] else None,
        "last_autoanalyze": str(row["last_autoanalyze"]) if row["last_autoanalyze"] else None,
        "days_since_analyze": int(days),
        "n_mod_since_analyze": row["n_mod_since_analyze"],
        "live_tuples": live,
        "is_stale": is_stale,
        "recommendation": recommendation,
    }


async def check_index_health(
    conn: Any, schema: str, table: str
) -> dict[str, Any]:
    """Assess index health: invalid, unused, duplicate indexes and total bloat.

    Returns lists of problem indexes with sizes and recommended actions.
    """
    qualified = f"{schema}.{table}"
    relid_row = await conn.fetchrow("SELECT $1::regclass::oid AS oid", qualified)
    if relid_row is None or relid_row["oid"] is None:
        return {"error": f"Table {qualified} not found"}

    table_oid = relid_row["oid"]

    # Invalid indexes
    invalid_rows = await conn.fetch(
        "SELECT indexrelid::regclass AS index_name FROM pg_index WHERE indrelid = $1 AND NOT indisvalid",  # noqa: E501
        table_oid,
    )
    invalid = [r["index_name"] for r in invalid_rows]

    # Unused indexes
    unused_rows = await conn.fetch(
        """
        SELECT indexrelname, pg_relation_size(indexrelid) AS size_bytes
        FROM pg_stat_user_indexes
        WHERE schemaname = $1 AND relname = $2 AND idx_scan = 0
        """,
        schema, table,
    )
    unused = [{"name": r["indexrelname"], "size_bytes": r["size_bytes"]} for r in unused_rows]

    # Duplicate indexes
    dup_rows = await conn.fetch(
        """
        SELECT array_agg(indexrelname) AS duplicates, indkey::text AS columns, count(*) AS cnt
        FROM pg_index i JOIN pg_stat_user_indexes s ON s.indexrelid = i.indexrelid
        WHERE s.schemaname = $1 AND s.relname = $2
        GROUP BY indkey::text HAVING count(*) > 1
        """,
        schema, table,
    )
    duplicates = [{"indexes": r["duplicates"], "columns": r["columns"], "count": r["cnt"]} for r in dup_rows]  # noqa: E501

    # Total index size
    size_row = await conn.fetchrow(
        "SELECT SUM(pg_relation_size(indexrelid)) AS total_bytes FROM pg_index WHERE indrelid = $1",
        table_oid,
    )
    total_index_bytes = int(size_row["total_bytes"] or 0)

    # Build actions
    actions = []
    for idx in invalid:
        actions.append(f"DROP INDEX IF EXISTS {idx}; -- Invalid index")
    for u in unused:
        actions.append(f"DROP INDEX IF EXISTS {u['name']}; -- 0 scans, {u['size_bytes']} bytes wasted")  # noqa: E501
    for d in duplicates:
        indexes = ", ".join(d["indexes"])
        actions.append(f"Review duplicate indexes: {indexes} -- Same column set, keep one")

    return {
        "invalid_indexes": invalid,
        "unused_indexes": unused,
        "duplicate_indexes": duplicates,
        "total_index_bytes": total_index_bytes,
        "recommended_actions": actions,
        "issue_count": len(invalid) + len(unused) + len(duplicates),
    }


# ---------------------------------------------------------------------------
# Object Discovery Functions
# ---------------------------------------------------------------------------

async def list_tables_by_schema(
    conn: Any, schema: str
) -> list[dict[str, Any]]:
    """List all tables in a schema with row counts, sizes, and descriptions."""
    rows = await conn.fetch(
        """
        SELECT c.relname AS name,
               pg_get_userbyid(c.relowner) AS owner,
               pg_relation_size(c.oid) AS size_bytes,
               COALESCE(s.n_live_tup, 0) AS row_count,
               obj_description(c.oid, 'pg_class') AS description
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
        WHERE n.nspname = $1 AND c.relkind = 'r'
        ORDER BY c.relname
        """,
        schema,
    )
    return [dict(r) for r in rows]


async def list_indexes_by_schema(
    conn: Any, schema: str
) -> list[dict[str, Any]]:
    """List all indexes in a schema with type, size, and scan stats."""
    rows = await conn.fetch(
        """
        SELECT c.relname AS name,
               t.relname AS table_name,
               am.amname AS index_type,
               pg_relation_size(c.oid) AS size_bytes,
               COALESCE(s.idx_scan, 0) AS idx_scan,
               COALESCE(s.idx_tup_read, 0) AS idx_tup_read
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_index i ON i.indexrelid = c.oid
        JOIN pg_class t ON t.oid = i.indrelid
        JOIN pg_am am ON am.oid = c.relam
        LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = c.oid
        WHERE n.nspname = $1 AND c.relkind = 'i'
        ORDER BY c.relname
        """,
        schema,
    )
    return [dict(r) for r in rows]


async def list_views_by_schema(
    conn: Any, schema: str
) -> list[dict[str, Any]]:
    """List all views in a schema with definition and owner."""
    rows = await conn.fetch(
        """
        SELECT c.relname AS name,
               pg_get_userbyid(c.relowner) AS owner,
               LEFT(pg_get_viewdef(c.oid), 500) AS definition,
               obj_description(c.oid, 'pg_class') AS description
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relkind = 'v'
        ORDER BY c.relname
        """,
        schema,
    )
    return [dict(r) for r in rows]


async def list_objects_by_type(
    conn: Any, schema: str, relkind: str
) -> list[dict[str, Any]]:
    """Generic object lister for any pg_class.relkind value.

    Args:
        conn: Active asyncpg connection.
        schema: Schema name to filter by.
        relkind: pg_class.relkind value (e.g., 'S' for sequences, 'm' for matviews).
    """
    rows = await conn.fetch(
        """
        SELECT c.relname AS name,
               pg_get_userbyid(c.relowner) AS owner,
               pg_relation_size(c.oid) AS size_bytes,
               obj_description(c.oid, 'pg_class') AS description
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relkind = $2
        ORDER BY c.relname
        """,
        schema, relkind,
    )
    return [dict(r) for r in rows]
