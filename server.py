import json
import os
import re
from typing import Any

from fastmcp import FastMCP
from psycopg.errors import UndefinedTable
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row
from starlette.requests import Request
from starlette.responses import PlainTextResponse

mcp = FastMCP(
    name=os.environ.get("MCP_SERVER_NAME", "PostgreSQL MCP Server"),
    auth=os.environ.get("FASTMCP_AUTH_TYPE") if os.environ.get("FASTMCP_AUTH_TYPE") else None
)


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return int(value)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _build_database_url_from_pg_env() -> str | None:
    host = os.environ.get("PGHOST")
    port = os.environ.get("PGPORT", "5432")
    user = os.environ.get("PGUSER")
    password = os.environ.get("PGPASSWORD")
    database = os.environ.get("PGDATABASE")
    if not host or not user or not database:
        return None
    password_part = f":{password}" if password else ""
    return f"postgresql://{user}{password_part}@{host}:{port}/{database}"


DATABASE_URL = os.environ.get("DATABASE_URL") or _build_database_url_from_pg_env()
if not DATABASE_URL:
    raise RuntimeError(
        "Missing DATABASE_URL or PGHOST/PGUSER/PGDATABASE environment variables"
    )

ALLOW_WRITE = _env_bool("MCP_ALLOW_WRITE", False)
DEFAULT_MAX_ROWS = _env_int("MCP_MAX_ROWS", 500)
POOL_MIN_SIZE = _env_int("MCP_POOL_MIN_SIZE", 1)
POOL_MAX_SIZE = _env_int("MCP_POOL_MAX_SIZE", 5)

pool = ConnectionPool(
    conninfo=DATABASE_URL,
    min_size=POOL_MIN_SIZE,
    max_size=POOL_MAX_SIZE,
    kwargs={"row_factory": dict_row},
)


_SINGLE_QUOTED = re.compile(r"'(?:''|[^'])*'")
_DOUBLE_QUOTED = re.compile(r'"(?:[^"]|"")*"')
_LINE_COMMENT = re.compile(r"--[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*[\s\S]*?\*/")
_DOLLAR_QUOTED = re.compile(r"\$[A-Za-z0-9_]*\$[\s\S]*?\$[A-Za-z0-9_]*\$")


def _strip_sql_noise(sql: str) -> str:
    s = _BLOCK_COMMENT.sub(" ", sql)
    s = _LINE_COMMENT.sub(" ", s)
    s = _DOLLAR_QUOTED.sub(" ", s)
    s = _SINGLE_QUOTED.sub(" ", s)
    s = _DOUBLE_QUOTED.sub(" ", s)
    return s


_WRITE_KEYWORDS = {
    "insert",
    "update",
    "delete",
    "merge",
    "create",
    "alter",
    "drop",
    "truncate",
    "grant",
    "revoke",
    "comment",
    "vacuum",
    "analyze",
    "reindex",
    "cluster",
    "refresh",
    "copy",
    "call",
    "do",
    "execute",
    "set",
    "reset",
    "lock",
}

_READONLY_START = {"select", "with", "show", "explain"}


def _is_sql_readonly(sql: str) -> bool:
    cleaned = _strip_sql_noise(sql).strip().lower()
    if not cleaned:
        return False
    first = cleaned.split(None, 1)[0]
    if first not in _READONLY_START:
        return False
    tokens = re.findall(r"[a-zA-Z_]+", cleaned)
    return not any(t in _WRITE_KEYWORDS for t in tokens)


def _require_readonly(sql: str) -> None:
    if ALLOW_WRITE:
        return
    if not _is_sql_readonly(sql):
        raise ValueError(
            "Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable."
        )


def _fetch_limited(cur, max_rows: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    remaining = max_rows
    while remaining > 0:
        batch = cur.fetchmany(min(remaining, 200))
        if not batch:
            break
        rows.extend(batch)
        remaining -= len(batch)
    return rows


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


@mcp.tool
def ping() -> dict[str, Any]:
    return {"ok": True}


@mcp.tool
def server_info() -> dict[str, Any]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  current_database() as database,
                  current_user as user,
                  inet_server_addr()::text as server_addr,
                  inet_server_port() as server_port,
                  version() as version
                """
            )
            row = cur.fetchone()
            assert row is not None
            return {
                "database": row["database"],
                "user": row["user"],
                "server_addr": row["server_addr"],
                "server_port": row["server_port"],
                "version": row["version"],
                "allow_write": ALLOW_WRITE,
                "default_max_rows": DEFAULT_MAX_ROWS,
            }


@mcp.tool
def list_databases() -> list[dict[str, Any]]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  datname as name,
                  pg_database_size(datname) as size_bytes,
                  datallowconn as allow_connections,
                  datistemplate as is_template
                from pg_database
                order by pg_database_size(datname) desc
                """
            )
            return cur.fetchall()


@mcp.tool
def list_schemas(include_system: bool = False) -> list[str]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if include_system:
                cur.execute(
                    """
                    select nspname
                    from pg_namespace
                    order by nspname
                    """
                )
            else:
                cur.execute(
                    """
                    select nspname
                    from pg_namespace
                    where nspname not like 'pg_%%'
                      and nspname <> 'information_schema'
                    order by nspname
                    """
                )
            return [r["nspname"] for r in cur.fetchall()]


@mcp.tool
def list_tables(schema: str = "public") -> list[dict[str, Any]]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  table_schema,
                  table_name,
                  table_type
                from information_schema.tables
                where table_schema = %(schema)s
                order by table_name
                """,
                {"schema": schema},
            )
            return cur.fetchall()


@mcp.tool
def describe_table(schema: str, table: str) -> dict[str, Any]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  c.ordinal_position,
                  c.column_name,
                  c.data_type,
                  c.is_nullable,
                  c.column_default
                from information_schema.columns c
                where c.table_schema = %(schema)s
                  and c.table_name = %(table)s
                order by c.ordinal_position
                """,
                {"schema": schema, "table": table},
            )
            columns = cur.fetchall()

            cur.execute(
                """
                select
                  i.indexname as index_name,
                  i.indexdef as index_def
                from pg_indexes i
                where i.schemaname = %(schema)s
                  and i.tablename = %(table)s
                order by i.indexname
                """,
                {"schema": schema, "table": table},
            )
            indexes = cur.fetchall()

            cur.execute(
                """
                select
                  pg_total_relation_size(format('%%I.%%I', %(schema)s::text, %(table)s::text)) as total_size_bytes,
                  pg_relation_size(format('%%I.%%I', %(schema)s::text, %(table)s::text)) as heap_size_bytes
                """,
                {"schema": schema, "table": table},
            )
            size_row = cur.fetchone()

            cur.execute(
                """
                select
                  reltuples::bigint as approx_rows
                from pg_class
                where oid = format('%%I.%%I', %(schema)s::text, %(table)s::text)::regclass
                """,
                {"schema": schema, "table": table},
            )
            approx = cur.fetchone()

            return {
                "schema": schema,
                "table": table,
                "columns": columns,
                "indexes": indexes,
                "total_size_bytes": size_row["total_size_bytes"] if size_row else None,
                "heap_size_bytes": size_row["heap_size_bytes"] if size_row else None,
                "approx_rows": approx["approx_rows"] if approx else None,
            }


@mcp.tool
def run_query(sql: str, params_json: str | None = None, max_rows: int | None = None) -> dict[str, Any]:
    _require_readonly(sql)
    limit = max_rows if max_rows is not None else DEFAULT_MAX_ROWS
    if limit < 0:
        raise ValueError("max_rows must be >= 0")
    params: dict[str, Any] | None = None
    if params_json:
        params = json.loads(params_json)
        if not isinstance(params, dict):
            raise ValueError("params_json must decode to a JSON object")

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows_plus_one = _fetch_limited(cur, limit + 1 if limit >= 0 else 1)
            truncated = len(rows_plus_one) > limit
            rows = rows_plus_one[:limit]
            columns = [d.name for d in cur.description] if cur.description else []
            return {
                "columns": columns,
                "rows": rows,
                "returned_rows": len(rows),
                "truncated": truncated,
            }


@mcp.tool
def explain_query(
    sql: str,
    analyze: bool = False,
    buffers: bool = False,
    verbose: bool = False,
    settings: bool = False,
    format: str = "json",
) -> dict[str, Any]:
    _require_readonly(sql)
    fmt = format.strip().lower()
    if fmt not in {"json", "text"}:
        raise ValueError("format must be 'json' or 'text'")

    opts: list[str] = []
    if analyze:
        opts.append("ANALYZE")
    if buffers:
        opts.append("BUFFERS")
    if verbose:
        opts.append("VERBOSE")
    if settings:
        opts.append("SETTINGS")
    opts.append(f"FORMAT {fmt.upper()}")
    stmt = f"EXPLAIN ({', '.join(opts)}) {sql}"

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(stmt)
            rows = cur.fetchall()
            if fmt == "json":
                plan = rows[0]["QUERY PLAN"] if rows else None
                return {"format": "json", "plan": plan}
            text = "\n".join(r["QUERY PLAN"] for r in rows)
            return {"format": "text", "plan": text}


@mcp.tool
def active_sessions(min_duration_seconds: int = 60) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  pid,
                  usename as user,
                  datname as database,
                  application_name,
                  client_addr::text as client_addr,
                  state,
                  now() - xact_start as xact_age,
                  now() - query_start as query_age,
                  wait_event_type,
                  wait_event,
                  left(query, 5000) as query
                from pg_stat_activity
                where pid <> pg_backend_pid()
                  and (
                    (query_start is not null and now() - query_start > make_interval(secs => %(min_secs)s))
                    or (xact_start is not null and now() - xact_start > make_interval(secs => %(min_secs)s))
                  )
                order by greatest(coalesce(now() - query_start, interval '0'), coalesce(now() - xact_start, interval '0')) desc
                """,
                {"min_secs": min_duration_seconds},
            )
            return cur.fetchall()


@mcp.tool
def db_locks(min_wait_seconds: int = 0, limit: int = 100) -> list[dict[str, Any]]:
    return _db_locks(min_wait_seconds=min_wait_seconds, limit=limit)


def _db_locks(min_wait_seconds: int, limit: int) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                with blocked as (
                  select
                    bl.pid as blocked_pid,
                    a.usename as blocked_user,
                    a.datname as blocked_database,
                    a.application_name as blocked_application_name,
                    a.client_addr::text as blocked_client_addr,
                    a.state as blocked_state,
                    a.wait_event_type as blocked_wait_event_type,
                    a.wait_event as blocked_wait_event,
                    now() - a.query_start as blocked_execution_time,
                    now() - a.xact_start as blocked_xact_age,
                    now() - coalesce(a.state_change, a.query_start, now()) as blocked_state_age,
                    left(a.query, 5000) as blocked_query,
                    bl.locktype,
                    bl.mode as blocked_lock_mode,
                    bl.database,
                    bl.relation,
                    bl.page,
                    bl.tuple,
                    bl.virtualxid,
                    bl.transactionid,
                    bl.classid,
                    bl.objid,
                    bl.objsubid
                  from pg_catalog.pg_locks bl
                  join pg_catalog.pg_stat_activity a on a.pid = bl.pid
                  where not bl.granted
                    and bl.pid <> pg_backend_pid()
                )
                select
                  b.blocked_pid,
                  b.blocked_user,
                  b.blocked_database,
                  b.blocked_application_name,
                  b.blocked_client_addr,
                  b.blocked_state,
                  b.blocked_wait_event_type,
                  b.blocked_wait_event,
                  b.blocked_query,
                  b.blocked_execution_time,
                  b.blocked_state_age as blocked_lock_wait_time,
                  b.blocked_xact_age,
                  b.locktype,
                  b.blocked_lock_mode,
                  b.relation::regclass::text as locked_relation,
                  kl.pid as blocking_pid,
                  ka.usename as blocking_user,
                  ka.application_name as blocking_application_name,
                  ka.client_addr::text as blocking_client_addr,
                  ka.state as blocking_state,
                  now() - ka.query_start as blocking_execution_time,
                  now() - ka.xact_start as blocking_xact_age,
                  left(ka.query, 5000) as blocking_query,
                  kl.mode as blocking_lock_mode
                from blocked b
                join pg_catalog.pg_locks kl
                  on kl.locktype = b.locktype
                  and kl.database is not distinct from b.database
                  and kl.relation is not distinct from b.relation
                  and kl.page is not distinct from b.page
                  and kl.tuple is not distinct from b.tuple
                  and kl.virtualxid is not distinct from b.virtualxid
                  and kl.transactionid is not distinct from b.transactionid
                  and kl.classid is not distinct from b.classid
                  and kl.objid is not distinct from b.objid
                  and kl.objsubid is not distinct from b.objsubid
                  and kl.granted
                  and kl.pid <> b.blocked_pid
                join pg_catalog.pg_stat_activity ka on ka.pid = kl.pid
                where ka.pid <> pg_backend_pid()
                  and b.blocked_state_age >= make_interval(secs => %(min_wait_secs)s)
                order by b.blocked_state_age desc
                limit %(limit)s
                """,
                {"min_wait_secs": min_wait_seconds, "limit": limit},
            )
            return cur.fetchall()


@mcp.tool
def table_sizes(schema: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if schema:
                cur.execute(
                    """
                    select
                      n.nspname as schema,
                      c.relname as table,
                      pg_total_relation_size(c.oid) as total_size_bytes,
                      pg_relation_size(c.oid) as heap_size_bytes,
                      pg_indexes_size(c.oid) as index_size_bytes
                    from pg_class c
                    join pg_namespace n on n.oid = c.relnamespace
                    where c.relkind = 'r'
                      and n.nspname = %(schema)s
                    order by pg_total_relation_size(c.oid) desc
                    limit %(limit)s
                    """,
                    {"schema": schema, "limit": limit},
                )
            else:
                cur.execute(
                    """
                    select
                      n.nspname as schema,
                      c.relname as table,
                      pg_total_relation_size(c.oid) as total_size_bytes,
                      pg_relation_size(c.oid) as heap_size_bytes,
                      pg_indexes_size(c.oid) as index_size_bytes
                    from pg_class c
                    join pg_namespace n on n.oid = c.relnamespace
                    where c.relkind = 'r'
                      and n.nspname not like 'pg_%%'
                      and n.nspname <> 'information_schema'
                    order by pg_total_relation_size(c.oid) desc
                    limit %(limit)s
                    """,
                    {"limit": limit},
                )
            return cur.fetchall()


@mcp.tool
def index_usage(schema: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if schema:
                cur.execute(
                    """
                    select
                      schemaname as schema,
                      relname as table,
                      indexrelname as index,
                      idx_scan,
                      idx_tup_read,
                      idx_tup_fetch,
                      pg_relation_size(indexrelid) as index_size_bytes
                    from pg_stat_user_indexes
                    where schemaname = %(schema)s
                    order by pg_relation_size(indexrelid) desc
                    limit %(limit)s
                    """,
                    {"schema": schema, "limit": limit},
                )
            else:
                cur.execute(
                    """
                    select
                      schemaname as schema,
                      relname as table,
                      indexrelname as index,
                      idx_scan,
                      idx_tup_read,
                      idx_tup_fetch,
                      pg_relation_size(indexrelid) as index_size_bytes
                    from pg_stat_user_indexes
                    order by pg_relation_size(indexrelid) desc
                    limit %(limit)s
                    """,
                    {"limit": limit},
                )
            return cur.fetchall()


@mcp.tool
def top_queries(limit: int = 10, order_by: str = "total_time") -> list[dict[str, Any]]:
    order = order_by.strip().lower()
    allowed = {"total_time", "mean_time", "calls"}
    if order not in allowed:
        raise ValueError(f"order_by must be one of: {sorted(allowed)}")
    with pool.connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    f"""
                    select
                      left(query, 5000) as query,
                      calls,
                      total_exec_time as total_time,
                      mean_exec_time as mean_time,
                      rows
                    from pg_stat_statements
                    order by {order} desc
                    limit %(limit)s
                    """,
                    {"limit": limit},
                )
                return cur.fetchall()
            except UndefinedTable:
                return [
                    {
                        "error": "pg_stat_statements is not available",
                        "hint": "Enable the extension and shared_preload_libraries, then create extension pg_stat_statements.",
                    }
                ]


def main() -> None:
    transport = os.environ.get("MCP_TRANSPORT", "http").strip().lower()
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = _env_int("MCP_PORT", 8000)
    if transport in {"http", "sse"}:
        mcp.run(transport=transport, host=host, port=port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()

