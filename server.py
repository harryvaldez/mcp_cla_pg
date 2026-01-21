import json
import hashlib
import logging
import os
import re
from typing import Any

from fastmcp import FastMCP
from psycopg import Error as PsycopgError
from psycopg import sql
from psycopg.errors import UndefinedTable
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row
from starlette.requests import Request
from starlette.responses import PlainTextResponse, JSONResponse

# Configure structured logging
log_level_str = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_str, logging.INFO)
log_file = os.environ.get("MCP_LOG_FILE")

logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=log_file,
    filemode='a' if log_file else None
)
logger = logging.getLogger("mcp-postgres")

def _get_auth() -> Any:
    auth_type = os.environ.get("FASTMCP_AUTH_TYPE")
    if not auth_type:
        return None

    auth_type_lower = auth_type.lower()
    allowed_auth_types = {"oidc", "jwt", "azure-ad", "none"}
    
    if auth_type_lower not in allowed_auth_types:
        raise ValueError(
            f"Invalid FASTMCP_AUTH_TYPE: '{auth_type}'. "
            f"Accepted values are: {', '.join(sorted(allowed_auth_types))}"
        )

    if auth_type_lower == "none":
        return None

    # Full OIDC Proxy (handles login flow)
    if auth_type_lower == "oidc":
        from fastmcp.server.auth.providers.oidc import OIDCProxy

        config_url = os.environ.get("FASTMCP_OIDC_CONFIG_URL")
        client_id = os.environ.get("FASTMCP_OIDC_CLIENT_ID")
        client_secret = os.environ.get("FASTMCP_OIDC_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_OIDC_BASE_URL")

        if not all([config_url, client_id, client_secret, base_url]):
            raise RuntimeError(
                "OIDC authentication requires FASTMCP_OIDC_CONFIG_URL, FASTMCP_OIDC_CLIENT_ID, "
                "FASTMCP_OIDC_CLIENT_SECRET, and FASTMCP_OIDC_BASE_URL"
            )

        return OIDCProxy(
            config_url=config_url,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            audience=os.environ.get("FASTMCP_OIDC_AUDIENCE"),
        )

    # Pure JWT Verification (resource server mode)
    if auth_type_lower == "jwt":
        from fastmcp.server.auth.providers.jwt import JWTVerifier

        jwks_uri = os.environ.get("FASTMCP_JWT_JWKS_URI")
        issuer = os.environ.get("FASTMCP_JWT_ISSUER")

        if not all([jwks_uri, issuer]):
            raise RuntimeError(
                "JWT verification requires FASTMCP_JWT_JWKS_URI and FASTMCP_JWT_ISSUER"
            )

        return JWTVerifier(
            jwks_uri=jwks_uri,
            issuer=issuer,
            audience=os.environ.get("FASTMCP_JWT_AUDIENCE"),
        )

    # Azure AD (Microsoft Entra ID) simplified configuration
    if auth_type_lower == "azure-ad":
        tenant_id = os.environ.get("FASTMCP_AZURE_AD_TENANT_ID")
        client_id = os.environ.get("FASTMCP_AZURE_AD_CLIENT_ID")
        
        if not all([tenant_id, client_id]):
            raise RuntimeError(
                "Azure AD authentication requires FASTMCP_AZURE_AD_TENANT_ID and FASTMCP_AZURE_AD_CLIENT_ID"
            )
            
        # Determine if we should use full OIDC flow or just JWT verification
        # If client_secret and base_url are provided, we use OIDC Proxy
        client_secret = os.environ.get("FASTMCP_AZURE_AD_CLIENT_SECRET")
        base_url = os.environ.get("FASTMCP_AZURE_AD_BASE_URL")
        
        config_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
        
        if client_secret and base_url:
            from fastmcp.server.auth.providers.oidc import OIDCProxy
            return OIDCProxy(
                config_url=config_url,
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
                audience=os.environ.get("FASTMCP_AZURE_AD_AUDIENCE", client_id),
            )
        else:
            from fastmcp.server.auth.providers.jwt import JWTVerifier
            jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
            issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
            return JWTVerifier(
                jwks_uri=jwks_uri,
                issuer=issuer,
                audience=os.environ.get("FASTMCP_AZURE_AD_AUDIENCE", client_id),
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


mcp = FastMCP(
    name=os.environ.get("MCP_SERVER_NAME", "PostgreSQL MCP Server"),
    auth=_get_auth()
)


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

if os.environ.get("MCP_ALLOW_WRITE") is None:
    raise RuntimeError("MCP_ALLOW_WRITE environment variable is required (e.g. 'true' or 'false')")

ALLOW_WRITE = _env_bool("MCP_ALLOW_WRITE", False)
DEFAULT_MAX_ROWS = _env_int("MCP_MAX_ROWS", 500)
POOL_MIN_SIZE = _env_int("MCP_POOL_MIN_SIZE", 1)
POOL_MAX_SIZE = _env_int("MCP_POOL_MAX_SIZE", 5)
POOL_TIMEOUT = float(os.environ.get("MCP_POOL_TIMEOUT", "30.0"))
POOL_MAX_WAITING = _env_int("MCP_POOL_MAX_WAITING", 10)
STATEMENT_TIMEOUT_MS = _env_int("MCP_STATEMENT_TIMEOUT_MS", 120000) # 120s default

pool = ConnectionPool(
    conninfo=DATABASE_URL,
    min_size=POOL_MIN_SIZE,
    max_size=POOL_MAX_SIZE,
    timeout=POOL_TIMEOUT,
    max_waiting=POOL_MAX_WAITING,
    open=True,
    kwargs={"row_factory": dict_row, "options": "-c DateStyle=ISO,MDY"},
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
    "reset",
    "lock",
    "commit",
    "rollback",
    "begin",
    "savepoint",
    "release",
}

_READONLY_START = {"select", "with", "show", "explain", "set"}


def _is_sql_readonly(sql: str) -> bool:
    cleaned = _strip_sql_noise(sql).strip().lower()
    if not cleaned:
        return False
    # Check if first word is a known read-only starting keyword
    first = cleaned.split(None, 1)[0]
    if first not in _READONLY_START:
        return False
    # Ensure no write keywords exist anywhere in the tokens
    tokens = re.findall(r"[a-zA-Z_]+", cleaned)
    return not any(t in _WRITE_KEYWORDS for t in tokens)


def _require_readonly(sql: str) -> None:
    if ALLOW_WRITE:
        return
    if not _is_sql_readonly(sql):
        logger.warning(f"BLOCKED write attempt in read-only mode: {sql[:200]}...")
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


def _execute_safe(cur, sql: Any, params: Any = None) -> None:
    """Executes a query with session-level timeouts and sanitized error handling."""
    try:
        if logger.isEnabledFor(logging.DEBUG):
            # Log query (truncated if too long for sanity)
            query_str = str(sql)
            if len(query_str) > 1000:
                query_str = query_str[:1000] + "..."
            logger.debug(f"Executing SQL: {query_str} | Params: {params}")

        # Set session-level timeout for this specific query execution
        cur.execute(f"SET statement_timeout = {STATEMENT_TIMEOUT_MS}")
        cur.execute(sql, params)
    except PsycopgError as e:
        logger.error(f"Database error: {str(e)}")
        # Sanitize error message to prevent leaking schema details
        # We only return the main error message if it's safe or a generic one
        if "timeout" in str(e).lower():
            raise RuntimeError("Query execution timed out.") from e
        raise RuntimeError(f"Database operation failed: {e.diag.message_primary if hasattr(e, 'diag') and e.diag else 'Internal error'}") from e
    except Exception as e:
        logger.exception("Unexpected error during query execution")
        raise RuntimeError("An unexpected error occurred while processing the query.") from e


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


@mcp.custom_route("/", methods=["GET"])
async def root(_request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "online",
        "message": "PostgreSQL MCP Server is running",
        "endpoints": {
            "mcp": "/mcp (MCP/SSE protocol endpoint)",
            "health": "/health",
            "info": "use 'server_info' tool via MCP"
        }
    })


@mcp.tool
def create_db_user(
    username: str,
    password: str,
    privileges: str = "read",
    database: str = "lenexa"
) -> str:
    """
    Creates a new database user and assigns privileges.

    Args:
        username: The name of the user to create.
        password: The password for the new user.
        privileges: 'read' for SELECT only, 'read-write' for full DML access.
        database: The database to grant access to (default: 'lenexa').
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable user creation.")

    if privileges not in ["read", "read-write"]:
        raise ValueError("privileges must be either 'read' or 'read-write'")

    # Basic input validation for username to prevent SQL injection in identifiers
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", username):
        raise ValueError("Invalid username format. Use only alphanumeric characters and underscores, starting with a letter.")

    # We use a separate connection if the target database is different from the current one
    # to ensure GRANT commands on tables work correctly (they are database-local).
    # However, for simplicity and protocol consistency, we use the existing pool
    # and warn if the grants might be schema-specific to the current DB.
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # 1. Create the user (Global operation)
            logger.info(f"Creating database user: {username}")
            _execute_safe(
                cur,
                sql.SQL("CREATE ROLE {} WITH LOGIN PASSWORD {}").format(
                    sql.Identifier(username),
                    sql.Literal(password),
                ),
            )

            # 2. Grant connection to database
            _execute_safe(
                cur,
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(database),
                    sql.Identifier(username),
                ),
            )

            # 3. Grant schema/table permissions
            # Note: These typically apply to the database the session is currently connected to.
            if privileges == "read":
                _execute_safe(
                    cur,
                    sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(username)),
                )
                _execute_safe(
                    cur,
                    sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(username)),
                )
                # Optionally grant ro_role if it exists
                cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'ro_role'")
                if cur.fetchone():
                    _execute_safe(
                        cur,
                        sql.SQL("GRANT ro_role to {}").format(sql.Identifier(username)),
                    )
                _execute_safe(
                    cur,
                    sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {}").format(
                        sql.Identifier(username)
                    ),
                )
            else:
                _execute_safe(
                    cur,
                    sql.SQL("GRANT ALL PRIVILEGES ON DATABASE {} TO {}").format(
                        sql.Identifier(database),
                        sql.Identifier(username),
                    ),
                )
                _execute_safe(
                    cur,
                    sql.SQL("GRANT ALL PRIVILEGES ON SCHEMA public TO {}").format(sql.Identifier(username)),
                )
                _execute_safe(
                    cur,
                    sql.SQL("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(username)),
                )
                _execute_safe(
                    cur,
                    sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO {}").format(
                        sql.Identifier(username)
                    ),
                )

            return f"User '{username}' created successfully with {privileges} privileges. Access granted to database '{database}'."


@mcp.tool
def drop_db_user(username: str) -> str:
    """
    Drops a database user (role).

    Args:
        username: The name of the user to drop.
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable user deletion.")

    # Basic input validation for username
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", username):
        raise ValueError("Invalid username format.")

    with pool.connection() as conn:
        with conn.cursor() as cur:
            logger.info(f"Dropping database user: {username}")
            _execute_safe(
                cur,
                sql.SQL("DROP OWNED BY {}").format(sql.Identifier(username)),
            )
            _execute_safe(
                cur,
                sql.SQL("DROP ROLE {}").format(sql.Identifier(username)),
            )
            return f"User '{username}' dropped successfully."


@mcp.tool
def check_bloat(limit: int = 50) -> list[dict[str, Any]]:
    """
    Identifies the top bloated tables and indexes and provides maintenance commands.

    Args:
        limit: Maximum number of objects to return (default: 50).
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Combined query for Table and Index bloat estimation
            # Using a simplified version of the PostgreSQL Experts/Check_postgres bloat query
            _execute_safe(
                cur,
                """
                with bloat as (
                  -- Table Bloat
                  select
                    'table' as type,
                    schemaname,
                    tblname as object_name,
                    bs::bigint * tblpages::bigint as real_size,
                    (tblpages::bigint - est_tblpages::bigint) * bs::bigint as extra_size,
                    case when tblpages > 0 then (tblpages - est_tblpages)::float / tblpages else 0 end as bloat_ratio,
                    case
                      when (tblpages - est_tblpages) > 0
                      then 'VACUUM FULL ' || quote_ident(schemaname) || '.' || quote_ident(tblname)
                      else 'VACUUM ' || quote_ident(schemaname) || '.' || quote_ident(tblname)
                    end as maintenance_cmd
                  from (
                    select
                      (ceil( reltuples / ( (bs-page_hdr)/fillfactor ) ) + ceil( toasttuples / 4 ))::bigint as est_tblpages,
                      tblpages, fillfactor, bs, tblname, schemaname, page_hdr
                    from (
                      select
                        (select current_setting('block_size')::int) as bs,
                        24 as page_hdr,
                        schemaname, tblname, reltuples, tblpages, toasttuples,
                        coalesce(substring(
                          array_to_string(reloptions, ' ') from 'fillfactor=([0-9]+)'
                        )::int, 100) as fillfactor
                      from (
                        select
                          n.nspname as schemaname,
                          c.relname as tblname,
                          c.reltuples,
                          c.relpages as tblpages,
                          c.reloptions,
                          coalesce( (select sum(t.reltuples) from pg_class t where t.oid = c.reltoastrelid), 0) as toasttuples
                        from pg_class c
                        join pg_namespace n on n.oid = c.relnamespace
                        where c.relkind = 'r'
                          and n.nspname not in ('pg_catalog', 'information_schema')
                          and c.relpages > 128
                      ) as foo
                    ) as first_el_idx
                  ) as second_el_idx

                  union all

                  -- Index Bloat (B-tree only)
                  select
                    'index' as type,
                    schemaname,
                    idxname as object_name,
                    bs::bigint * relpages::bigint as real_size,
                    (relpages::bigint - est_pages::bigint) * bs::bigint as extra_size,
                    case when relpages > 0 then (relpages - est_pages)::float / relpages else 0 end as bloat_ratio,
                    'REINDEX INDEX ' || quote_ident(schemaname) || '.' || quote_ident(idxname) as maintenance_cmd
                  from (
                    select
                      bs, schemaname, idxname, relpages,
                      ceil(reltuples * (avgwidth + 12.0) / (bs - 20.0) / 0.9)::bigint as est_pages
                    from (
                      select
                        (select current_setting('block_size')::int) as bs,
                        n.nspname as schemaname,
                        c.relname as idxname,
                        c.reltuples,
                        c.relpages,
                        (select avg(avg_width) from pg_stats where schemaname = n.nspname and tablename = t.relname) as avgwidth
                      from pg_class c
                      join pg_namespace n on n.oid = c.relnamespace
                      join pg_index i on i.indexrelid = c.oid
                      join pg_class t on t.oid = i.indrelid
                      where c.relkind = 'i'
                        and i.indisprimary = false
                        and n.nspname not in ('pg_catalog', 'information_schema')
                        and c.relpages > 128
                    ) as foo
                  ) as third_el_idx
                )
                select
                  type,
                  schemaname as schema,
                  object_name,
                  real_size as size_bytes,
                  extra_size as bloat_bytes,
                  round(bloat_ratio::numeric * 100, 2) as bloat_percentage,
                  maintenance_cmd
                from bloat
                where extra_size > 0
                order by extra_size desc
                limit %(limit)s
                """,
                {"limit": limit}
            )
            return cur.fetchall()


@mcp.tool
def db_stats(database: str | None = None, include_performance: bool = False) -> list[dict[str, Any]] | dict[str, Any]:
    """
    Get database-level statistics including commits, rollbacks, temp files, and deadlocks.
    
    Args:
        database: Optional database name to filter results. If None, returns all databases.
        include_performance: If True, includes additional performance metrics like cache hit ratio.
    
    Returns:
        List of database statistics or single database stats if database specified.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(cur, "select current_setting('server_version_num')::int as server_version_num")
            version_row = cur.fetchone()
            server_version_num = int(version_row["server_version_num"]) if version_row else 0
            checksum_expr = "checksum_failures" if server_version_num >= 120000 else "null::bigint as checksum_failures"

            if database:
                _execute_safe(
                    cur,
                    f"""
                    select
                      datname as database,
                      numbackends as active_connections,
                      xact_commit as commits,
                      xact_rollback as rollbacks,
                      blks_read as blocks_read,
                      blks_hit as blocks_hit,
                      tup_returned as tuples_returned,
                      tup_fetched as tuples_fetched,
                      tup_inserted as tuples_inserted,
                      tup_updated as tuples_updated,
                      tup_deleted as tuples_deleted,
                      conflicts,
                      temp_files,
                      temp_bytes,
                      deadlocks,
                      {checksum_expr}
                    from pg_stat_database
                    where datname = %(database)s
                    """,
                    {"database": database}
                )
                result = cur.fetchone()
                if not result:
                    return {"error": f"Database '{database}' not found"}
                
                if include_performance:
                    # Add cache hit ratio calculation
                    total_blocks = result["blocks_read"] + result["blocks_hit"]
                    result["cache_hit_ratio"] = round((result["blocks_hit"] / total_blocks * 100), 2) if total_blocks > 0 else 0
                    
                    # Add transaction success rate
                    total_xacts = result["commits"] + result["rollbacks"]
                    result["transaction_success_rate"] = round((result["commits"] / total_xacts * 100), 2) if total_xacts > 0 else 0
                
                return result
            else:
                _execute_safe(
                    cur,
                    f"""
                    select
                      datname as database,
                      numbackends as active_connections,
                      xact_commit as commits,
                      xact_rollback as rollbacks,
                      blks_read as blocks_read,
                      blks_hit as blocks_hit,
                      tup_returned as tuples_returned,
                      tup_fetched as tuples_fetched,
                      tup_inserted as tuples_inserted,
                      tup_updated as tuples_updated,
                      tup_deleted as tuples_deleted,
                      conflicts,
                      temp_files,
                      temp_bytes,
                      deadlocks,
                      {checksum_expr},
                      blk_read_time as block_read_time_ms,
                      blk_write_time as block_write_time_ms,
                      stats_reset
                    from pg_stat_database
                    where datname not like 'template%%'
                    order by datname
                    """
                )
                results = cur.fetchall()
                
                if include_performance:
                    # Enhance each result with performance metrics
                    for result in results:
                        total_blocks = result["blocks_read"] + result["blocks_hit"]
                        result["cache_hit_ratio"] = round((result["blocks_hit"] / total_blocks * 100), 2) if total_blocks > 0 else 0
                        
                        total_xacts = result["commits"] + result["rollbacks"]
                        result["transaction_success_rate"] = round((result["commits"] / total_xacts * 100), 2) if total_xacts > 0 else 0
                
                return results


@mcp.tool
def analyze_table_health(
    schema: str | None = None,
    min_size_mb: int = 50,
    include_bloat: bool = True,
    include_maintenance: bool = True,
    include_autovacuum: bool = True,
    limit: int = 30,
    profile: str = "oltp"
) -> dict[str, Any]:
    """
    Comprehensive table health analysis combining bloat detection, maintenance needs, and autovacuum recommendations.
    
    Args:
        schema: Optional schema name to filter analysis.
        min_size_mb: Minimum table size in MB to consider.
        include_bloat: Include bloat analysis (default: True).
        include_maintenance: Include maintenance statistics (default: True).
        include_autovacuum: Include autovacuum recommendations (default: True).
        limit: Maximum number of tables to analyze (default: 30).
        profile: Workload profile to tune thresholds, e.g. "oltp" or "olap".
    
    Returns:
        Dictionary containing table health summary, detailed analysis, and recommendations.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            results = {
                "summary": {
                    "total_tables_analyzed": 0,
                    "tables_with_issues": 0,
                    "critical_issues": 0,
                    "materialized_view_candidates": 0,
                    "recommendations": []
                },
                "tables": [],
                "overall_health_score": 100
            }

            profile_value = (profile or "oltp").lower()
            if profile_value == "olap":
                autovac_high_mod_threshold = 5000
                autovac_low_mod_threshold = 500
                mv_min_size_mb = max(min_size_mb, 50)
                mv_max_mods_per_day = 1000
                mv_min_reads = 100
                mv_min_ratio = 3.0
            else:
                autovac_high_mod_threshold = 1000
                autovac_low_mod_threshold = 100
                mv_min_size_mb = max(min_size_mb, 100)
                mv_max_mods_per_day = 100
                mv_min_reads = 1000
                mv_min_ratio = 10.0

            # Get candidate tables
            _execute_safe(
                cur,
                """
                select
                  c.oid
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where c.relkind = 'r'
                  and n.nspname not in ('pg_catalog', 'information_schema')
                  and (%(schema)s::text is null or n.nspname = %(schema)s::text)
                  and pg_relation_size(c.oid) > %(min_size)s::bigint * 1024 * 1024
                order by pg_relation_size(c.oid) desc
                limit %(limit)s
                """,
                {"schema": schema, "min_size": min_size_mb, "limit": limit}
            )
            candidate_oids = [row['oid'] for row in cur.fetchall()]
            
            candidate_tables = []
            for oid in candidate_oids:
                _execute_safe(
                    cur,
                    """
                    select
                      n.nspname as schema,
                      c.relname as table,
                      pg_total_relation_size(c.oid) as size_bytes,
                      c.reltuples::bigint as approx_rows,
                      s.n_live_tup as live_tuples,
                      s.n_dead_tup as dead_tuples,
                      s.n_tup_ins as inserts,
                      s.n_tup_upd as updates,
                      s.n_tup_del as deletes,
                      s.seq_scan,
                      s.idx_scan,
                      s.last_vacuum,
                      s.last_autovacuum,
                      s.last_analyze,
                      s.last_autoanalyze,
                      case
                        when coalesce(s.last_autovacuum, s.last_vacuum) is null then null
                        else extract(epoch from (now() - coalesce(s.last_autovacuum, s.last_vacuum)))
                      end as seconds_since_vacuum,
                      case
                        when coalesce(s.last_autoanalyze, s.last_analyze) is null then null
                        else extract(epoch from (now() - coalesce(s.last_autoanalyze, s.last_analyze)))
                      end as seconds_since_analyze,
                      age(c.relfrozenxid) as frozenxid_age
                    from pg_class c
                    join pg_namespace n on n.oid = c.relnamespace
                    left join pg_stat_user_tables s on s.relid = c.oid
                    where c.oid = %(oid)s
                    """,
                    {"oid": oid}
                )
                candidate_tables.append(cur.fetchone())
            
            results["summary"]["total_tables_analyzed"] = len(candidate_tables)

            for table in candidate_tables:
                table_analysis = {
                    "schema": table["schema"],
                    "table": table["table"],
                    "size_mb": round(table["size_bytes"] / (1024 * 1024), 1),
                    "approx_rows": table["approx_rows"],
                    "health_score": 100,
                    "issues": [],
                    "recommendations": []
                }

                # Calculate modification rate
                total_mods = (table["inserts"] or 0) + (table["updates"] or 0) + (table["deletes"] or 0)
                age_seconds_candidates = [table.get("seconds_since_vacuum"), table.get("seconds_since_analyze")]
                age_seconds = min([s for s in age_seconds_candidates if s is not None], default=86400)
                age_days = max(float(age_seconds) / 86400.0, 1.0)
                mod_rate_per_day = total_mods / age_days

                # 1. Bloat Analysis
                if include_bloat:
                    _execute_safe(
                        cur,
                        """
                        with bloat_estimate as (
                          select
                            case
                              when (s.n_live_tup + s.n_dead_tup) > 0
                              then round((s.n_dead_tup::float / (s.n_live_tup + s.n_dead_tup) * 100)::numeric, 2)
                              else 0
                            end as dead_tuple_percent,
                            case
                              when pg_total_relation_size(c.oid) > 0
                              then round((s.n_dead_tup * 100.0 / greatest(s.n_live_tup, 1))::numeric, 2)
                              else 0
                            end as estimated_bloat_percent
                          from pg_class c
                          join pg_namespace n on n.oid = c.relnamespace
                          left join pg_stat_user_tables s on s.relid = c.oid
                          where n.nspname = %(schema)s and c.relname = %(table)s
                        )
                        select dead_tuple_percent, estimated_bloat_percent
                        from bloat_estimate
                        """,
                        {"schema": table["schema"], "table": table["table"]}
                    )
                    bloat_info = cur.fetchone()
                    
                    if bloat_info:
                        dead_tuple_percent = bloat_info["dead_tuple_percent"]
                        estimated_bloat_percent = bloat_info["estimated_bloat_percent"]
                        
                        if dead_tuple_percent > 20:
                            table_analysis["issues"].append(f"High dead tuple ratio: {dead_tuple_percent}%")
                            table_analysis["recommendations"].append("Run VACUUM to clean up dead tuples")
                            table_analysis["health_score"] -= 20
                        elif dead_tuple_percent > 10:
                            table_analysis["issues"].append(f"Moderate dead tuple ratio: {dead_tuple_percent}%")
                            table_analysis["health_score"] -= 10

                # 2. Maintenance Analysis
                if include_maintenance:
                    # Check freeze risk
                    _execute_safe(
                        cur,
                        """
                        select current_setting('autovacuum_freeze_max_age')::bigint as freeze_max_age
                        """
                    )
                    freeze_settings = cur.fetchone()
                    freeze_max_age = freeze_settings["freeze_max_age"]
                    
                    age_percent = (table["frozenxid_age"] / freeze_max_age * 100) if freeze_max_age > 0 else 0
                    
                    if age_percent > 50:
                        table_analysis["issues"].append(f"High transaction ID age: {round(age_percent, 1)}% of freeze_max_age")
                        table_analysis["recommendations"].append("Prioritize freeze operations - table at risk of wraparound")
                        table_analysis["health_score"] -= 30
                        results["summary"]["critical_issues"] += 1
                    elif age_percent > 25:
                        table_analysis["issues"].append(f"Moderate transaction ID age: {round(age_percent, 1)}% of freeze_max_age")
                        table_analysis["health_score"] -= 15

                    # Check vacuum/analyze recency
                    days_since_vacuum = float(table["seconds_since_vacuum"]) / 86400.0 if table.get("seconds_since_vacuum") is not None else 999.0
                    days_since_analyze = float(table["seconds_since_analyze"]) / 86400.0 if table.get("seconds_since_analyze") is not None else 999.0
                    
                    if days_since_vacuum > 7:
                        table_analysis["issues"].append(f"No vacuum in {int(days_since_vacuum)} days")
                        table_analysis["health_score"] -= 10
                    
                    if days_since_analyze > 7:
                        table_analysis["issues"].append(f"No analyze in {int(days_since_analyze)} days")
                        table_analysis["health_score"] -= 5

                # 3. Autovacuum Recommendations
                if include_autovacuum:
                    if mod_rate_per_day > autovac_high_mod_threshold:
                        table_analysis["recommendations"].append("High modification rate - consider aggressive autovacuum settings")
                        table_analysis["autovacuum_suggestions"] = {
                            "autovacuum_vacuum_scale_factor": 0.1,
                            "autovacuum_vacuum_threshold": 50,
                            "autovacuum_vacuum_cost_delay": 0
                        }
                    elif mod_rate_per_day < autovac_low_mod_threshold:
                        table_analysis["recommendations"].append("Low modification rate - standard autovacuum settings sufficient")
                        table_analysis["autovacuum_suggestions"] = {
                            "autovacuum_vacuum_scale_factor": 0.2,
                            "autovacuum_vacuum_threshold": 100
                        }

                # 4. Materialized view candidate analysis
                read_ops = (table["seq_scan"] or 0) + (table["idx_scan"] or 0)
                write_ops = total_mods
                if write_ops > 0:
                    read_to_write_ratio = read_ops / write_ops
                else:
                    read_to_write_ratio = float("inf") if read_ops > 0 else 0.0

                mv_candidate = (
                    table_analysis["size_mb"] >= mv_min_size_mb
                    and mod_rate_per_day < mv_max_mods_per_day
                    and read_ops >= mv_min_reads
                    and read_to_write_ratio >= mv_min_ratio
                )

                if mv_candidate:
                    table_analysis["materialized_view_candidate"] = True
                    table_analysis["recommendations"].append(
                        "High read, low write workload - consider materialized views for common reporting queries"
                    )
                    results["summary"]["materialized_view_candidates"] += 1
                else:
                    table_analysis["materialized_view_candidate"] = False

                # Final health score adjustments
                if table_analysis["health_score"] < 70:
                    results["summary"]["tables_with_issues"] += 1
                
                table_analysis["health_score"] = max(0, min(100, table_analysis["health_score"]))
                results["tables"].append(table_analysis)

            # Calculate overall health score
            if results["tables"]:
                avg_health = sum(t["health_score"] for t in results["tables"]) / len(results["tables"])
                critical_ratio = results["summary"]["critical_issues"] / len(results["tables"])
                
                results["overall_health_score"] = max(0, avg_health - (critical_ratio * 20))

            # Generate summary recommendations
            if results["summary"]["critical_issues"] > 0:
                results["summary"]["recommendations"].append(f"URGENT: {results['summary']['critical_issues']} tables have critical issues requiring immediate attention")
            
            if results["summary"]["tables_with_issues"] > len(results["tables"]) * 0.5:
                results["summary"]["recommendations"].append("More than 50% of analyzed tables have health issues - consider database-wide maintenance")
            
            if results["overall_health_score"] < 70:
                results["summary"]["recommendations"].append("Overall database health is concerning - prioritize maintenance operations")

            return results


@mcp.tool
def database_security_performance_metrics(
    cache_hit_threshold: int | None = None,
    connection_usage_threshold: float | None = None,
    profile: str = "oltp"
) -> dict[str, Any]:
    """
    Analyzes database security and performance metrics, identifying issues and providing optimization commands.
    
    Args:
        cache_hit_threshold: Minimum acceptable cache hit ratio percentage. If None, tuned by profile.
        connection_usage_threshold: Maximum acceptable connection usage ratio. If None, tuned by profile.
        profile: Workload profile to tune thresholds, e.g. "oltp" or "olap".
    
    Returns:
        Dictionary containing security metrics, performance metrics, issues found, and recommended fixes.
    """
    # Profile-based threshold logic
    profile_value = (profile or "oltp").lower()
    if profile_value == "olap":
        default_cache_threshold = 80
        default_conn_threshold = 0.9
        checkpoint_req_threshold = 50
        temp_file_threshold = 500
    else:  # Default to oltp
        default_cache_threshold = 95
        default_conn_threshold = 0.7
        checkpoint_req_threshold = 20
        temp_file_threshold = 50

    cache_hit_limit = cache_hit_threshold if cache_hit_threshold is not None else default_cache_threshold
    conn_usage_limit = connection_usage_threshold if connection_usage_threshold is not None else default_conn_threshold

    with pool.connection() as conn:
        with conn.cursor() as cur:
            results = {
                "security_metrics": {},
                "performance_metrics": {},
                "issues_found": [],
                "recommended_fixes": [],
                "profile_applied": profile_value
            }

            # 1. SSL/TLS Configuration
            _execute_safe(
                cur,
                """
                select
                  name,
                  setting,
                  context,
                  pending_restart
                from pg_settings
                where name in ('ssl', 'ssl_ciphers', 'ssl_cert_file', 'ssl_key_file', 'ssl_ca_file')
                order by name
                """
            )
            ssl_settings = cur.fetchall()
            results["security_metrics"]["ssl_settings"] = ssl_settings

            # Check if SSL is enabled
            ssl_enabled = any(s["name"] == "ssl" and s["setting"] == "on" for s in ssl_settings)
            if not ssl_enabled:
                results["issues_found"].append("SSL is not enabled - connections are not encrypted")
                results["recommended_fixes"].append("Enable SSL by setting ssl = on in postgresql.conf and configure certificates")

            # 2. Authentication and Connection Security
            try:
                _execute_safe(
                    cur,
                    """
                    select
                      r.rolname as user,
                      r.oid as usesysid,
                      r.rolcreatedb as usecreatedb,
                      r.rolsuper as usesuper,
                      r.rolreplication as userepl,
                      r.rolbypassrls as usebypassrls,
                      s.passwd is not null as has_password,
                      s.valuntil as password_expiry,
                      s.valuntil - now() as time_until_expiry
                    from pg_roles r
                    left join pg_shadow s on s.usename = r.rolname
                    where r.rolname not like 'pg_%'
                    order by r.rolname
                    """
                )
                user_security = cur.fetchall()
            except RuntimeError:
                _execute_safe(
                    cur,
                    """
                    select
                      r.rolname as user,
                      r.oid as usesysid,
                      r.rolcreatedb as usecreatedb,
                      r.rolsuper as usesuper,
                      r.rolreplication as userepl,
                      r.rolbypassrls as usebypassrls,
                      null::boolean as has_password,
                      null::timestamptz as password_expiry,
                      null::interval as time_until_expiry
                    from pg_roles r
                    where r.rolname not like 'pg_%'
                    order by r.rolname
                    """
                )
                user_security = cur.fetchall()
            
            # Summarize users to avoid truncation
            superusers = [u for u in user_security if u["usesuper"]]
            users_without_passwords = [u for u in user_security if not u["has_password"]]
            
            results["security_metrics"]["user_accounts_summary"] = {
                "total_users": len(user_security),
                "superuser_count": len(superusers),
                "no_password_count": len(users_without_passwords),
                "superusers": [u["user"] for u in superusers],
                "users_without_passwords": [u["user"] for u in users_without_passwords][:10] # Show first 10
            }

            # Check for superusers and password issues
            if len(superusers) > 1:
                results["issues_found"].append(f"Multiple superusers found: {[u['user'] for u in superusers]}")
                results["recommended_fixes"].append("Review superuser privileges and limit to minimum required")

            if users_without_passwords:
                results["issues_found"].append(f"Users without passwords: {len(users_without_passwords)} users detected")
                results["recommended_fixes"].append("Set strong passwords for all user accounts")

            # 3. Cache Hit Ratio Analysis
            _execute_safe(
                cur,
                """
                select
                  datname as database,
                  blks_hit,
                  blks_read,
                  case
                    when (blks_hit + blks_read) > 0
                    then round((blks_hit::float / (blks_hit + blks_read) * 100)::numeric, 2)
                    else 0
                  end as cache_hit_ratio
                from pg_stat_database
                where datname not like 'template%%'
                order by cache_hit_ratio asc
                """
            )
            cache_metrics = cur.fetchall()
            results["performance_metrics"]["cache_hit_ratios"] = cache_metrics

            # Identify databases with poor cache hit ratios
            poor_cache_databases = [db for db in cache_metrics if db["cache_hit_ratio"] < cache_hit_limit]
            if poor_cache_databases:
                results["issues_found"].append(f"Low cache hit ratios: {[f'{db['database']} ({db['cache_hit_ratio']}%)' for db in poor_cache_databases]}")
                results["recommended_fixes"].append(f"Consider increasing shared_buffers for better cache performance (threshold: {cache_hit_limit}% for {profile_value})")

            # 4. Connection Pool and Limits
            _execute_safe(
                cur,
                """
                select
                  current_setting('max_connections')::int as max_connections,
                  current_setting('superuser_reserved_connections')::int as reserved_connections,
                  count(*) as active_connections,
                  current_setting('max_connections')::int - count(*) as available_connections
                from pg_stat_activity
                where state != 'idle'
                """
            )
            connection_metrics = cur.fetchone()
            results["performance_metrics"]["connection_usage"] = connection_metrics

            if connection_metrics["active_connections"] > connection_metrics["max_connections"] * conn_usage_limit:
                results["issues_found"].append(f"High connection usage: {connection_metrics['active_connections']}/{connection_metrics['max_connections']} connections active")
                results["recommended_fixes"].append(f"Consider increasing max_connections or implementing connection pooling (threshold: {int(conn_usage_limit*100)}% for {profile_value})")

            # 5. WAL and Checkpoint Performance
            _execute_safe(
                cur,
                """
                select
                  checkpoints_timed,
                  checkpoints_req,
                  checkpoint_write_time,
                  checkpoint_sync_time,
                  buffers_checkpoint,
                  buffers_clean,
                  buffers_backend,
                  case
                    when checkpoints_timed + checkpoints_req > 0
                    then round((checkpoints_req::float / (checkpoints_timed + checkpoints_req) * 100)::numeric, 2)
                    else 0
                  end as checkpoint_request_ratio
                from pg_stat_bgwriter
                """
            )
            checkpoint_metrics = cur.fetchone()
            results["performance_metrics"]["checkpoint_stats"] = checkpoint_metrics

            if checkpoint_metrics["checkpoint_request_ratio"] > checkpoint_req_threshold:
                results["issues_found"].append(f"High checkpoint request ratio: {checkpoint_metrics['checkpoint_request_ratio']}%")
                results["recommended_fixes"].append(f"Consider increasing max_wal_size or checkpoint_timeout to reduce frequency (threshold: {checkpoint_req_threshold}% for {profile_value})")

            # 6. Lock and Deadlock Analysis
            _execute_safe(
                cur,
                """
                select
                  deadlocks,
                  conflicts,
                  temp_files,
                  temp_bytes
                from pg_stat_database
                where datname = current_database()
                """
            )
            lock_metrics = cur.fetchone()
            results["performance_metrics"]["lock_stats"] = lock_metrics

            if lock_metrics["deadlocks"] > 0:
                results["issues_found"].append(f"Deadlocks detected: {lock_metrics['deadlocks']}")
                results["recommended_fixes"].append("Review application locking patterns and transaction isolation levels")

            if lock_metrics["temp_files"] > temp_file_threshold:
                results["issues_found"].append(f"High temp file usage: {lock_metrics['temp_files']} files, {lock_metrics['temp_bytes']} bytes")
                results["recommended_fixes"].append(f"Consider increasing work_mem to reduce temporary file creation (threshold: {temp_file_threshold} for {profile_value})")

            # 7. Extension Security
            _execute_safe(
                cur,
                """
                select
                  extname as extension,
                  extversion as version,
                  n.nspname as schema
                from pg_extension e
                join pg_namespace n on n.oid = e.extnamespace
                where extname not in ('plpgsql')
                order by extname
                """
            )
            extensions = cur.fetchall()
            results["security_metrics"]["installed_extensions"] = extensions

            # Check for potentially risky extensions
            risky_extensions = ["dblink", "postgres_fdw", "file_fdw", "plpython3u", "plperlu"]
            installed_risky = [ext for ext in extensions if ext["extension"] in risky_extensions]
            if installed_risky:
                results["issues_found"].append(f"Potentially risky extensions installed: {[ext['extension'] for ext in installed_risky]}")
                results["recommended_fixes"].append("Review and restrict access to extensions that enable external connections or code execution")

            # 8. Generate specific configuration commands
            if not ssl_enabled:
                results["recommended_fixes"].append("# Generate SSL certificates and update postgresql.conf:")
                results["recommended_fixes"].append("# ssl = on")
                results["recommended_fixes"].append("# ssl_cert_file = 'server.crt'")
                results["recommended_fixes"].append("# ssl_key_file = 'server.key'")
                results["recommended_fixes"].append("# ssl_ca_file = 'root.crt'")

            if poor_cache_databases:
                results["recommended_fixes"].append("# Increase shared_buffers:")
                results["recommended_fixes"].append("# shared_buffers = 256MB  # Adjust based on available RAM")

            if connection_metrics["active_connections"] > connection_metrics["max_connections"] * conn_usage_limit:
                results["recommended_fixes"].append(f"# Increase max_connections (currently {connection_metrics['max_connections']}):")
                results["recommended_fixes"].append("# max_connections = 200  # Adjust based on workload")

            if checkpoint_metrics["checkpoint_request_ratio"] > checkpoint_req_threshold:
                results["recommended_fixes"].append("# Optimize checkpoint settings:")
                results["recommended_fixes"].append("# checkpoint_timeout = 15min")
                results["recommended_fixes"].append("# max_wal_size = 4GB")
                results["recommended_fixes"].append("# min_wal_size = 1GB")

            if lock_metrics["temp_files"] > temp_file_threshold:
                results["recommended_fixes"].append("# Increase work_mem (use caution, affects per-operation memory):")
                results["recommended_fixes"].append("# work_mem = 64MB  # Adjust based on concurrent connections")

            return results


@mcp.tool
def recommend_partitioning(
    min_size_gb: float = 1.0,
    schema: str | None = None,
    limit: int = 50
) -> dict[str, Any]:
    """
    Suggests tables for partitioning based primarily on size and basic access patterns.
    
    Args:
        min_size_gb: Minimum total table size in gigabytes to consider as a candidate.
        schema: Optional schema name to filter tables. If None, all user schemas are considered.
        limit: Maximum number of candidate tables to return.
    
    Returns:
        Dictionary containing a summary and a list of candidate tables with size and access metrics.
    """
    if min_size_gb <= 0:
        raise ValueError("min_size_gb must be positive")
    if limit <= 0:
        raise ValueError("limit must be positive")

    size_bytes_threshold = int(min_size_gb * 1024 * 1024 * 1024)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                with params as (
                  select current_setting('block_size')::int as bs
                )
                select
                  c.oid,
                  n.nspname as schema,
                  c.relname as table,
                  (c.relpages::bigint * p.bs::bigint) as approx_size_bytes
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                cross join params p
                where c.relkind = 'r'
                  and n.nspname not in ('pg_catalog', 'information_schema')
                  and (%(schema)s::text is null or n.nspname = %(schema)s::text)
                order by (c.relpages::bigint * p.bs::bigint) desc
                limit %(limit)s
                """,
                {
                    "schema": schema,
                    "limit": limit,
                },
            )
            base_rows = cur.fetchall()

            results: dict[str, Any] = {
                "summary": {
                    "min_size_gb": float(min_size_gb),
                    "schema_filter": schema,
                    "total_candidates": 0,
                },
                "candidates": [],
            }

            if not base_rows:
                return results

            filtered_rows = [
                row for row in base_rows
                if row["approx_size_bytes"] >= size_bytes_threshold
            ]
            results["summary"]["total_candidates"] = len(filtered_rows)

            for row in filtered_rows:
                oid = row["oid"]

                _execute_safe(
                    cur,
                    """
                    select
                      s.n_live_tup as live_rows,
                      s.n_dead_tup as dead_rows,
                      s.seq_scan,
                      s.idx_scan,
                      s.n_tup_ins as inserts,
                      s.n_tup_upd as updates,
                      s.n_tup_del as deletes
                    from pg_stat_user_tables s
                    where s.relid = %(oid)s
                    """,
                    {"oid": oid},
                )
                stats = cur.fetchone() or {}

                approx_size_gb = row["approx_size_bytes"] / float(1024 * 1024 * 1024)
                live_rows = stats.get("live_rows") or 0
                dead_rows = stats.get("dead_rows") or 0
                seq_scan = stats.get("seq_scan") or 0
                idx_scan = stats.get("idx_scan") or 0
                inserts = stats.get("inserts") or 0
                updates = stats.get("updates") or 0
                deletes = stats.get("deletes") or 0

                total_reads = seq_scan + idx_scan
                total_writes = inserts + updates + deletes

                if total_reads > 0 or total_writes > 0:
                    if total_reads >= 10 * max(total_writes, 1):
                        workload_pattern = "read_heavy"
                    elif total_writes >= 5 * max(total_reads, 1):
                        workload_pattern = "write_heavy"
                    else:
                        workload_pattern = "mixed"
                else:
                    workload_pattern = "unknown"

                if approx_size_gb >= 10.0 or live_rows >= 100_000_000:
                    benefit = "high"
                elif approx_size_gb >= 1.0 or live_rows >= 10_000_000:
                    benefit = "medium"
                else:
                    benefit = "low"

                notes_parts = []
                if benefit == "high":
                    notes_parts.append("Very large table; partitioning likely to improve maintenance and query performance")
                elif benefit == "medium":
                    notes_parts.append("Large table; partitioning may help for time-based or tenant-based queries")
                else:
                    notes_parts.append("Borderline size for partitioning; consider only if query patterns benefit")

                if workload_pattern == "read_heavy":
                    notes_parts.append("Read-heavy workload")
                elif workload_pattern == "write_heavy":
                    notes_parts.append("Write-heavy workload")
                elif workload_pattern == "mixed":
                    notes_parts.append("Balanced read/write workload")

                candidate = {
                    "schema": row["schema"],
                    "table": row["table"],
                    "approx_size_gb": round(approx_size_gb, 3),
                    "live_rows": live_rows,
                    "dead_rows": dead_rows,
                    "seq_scan": seq_scan,
                    "idx_scan": idx_scan,
                    "total_reads": total_reads,
                    "total_writes": total_writes,
                    "workload_pattern": workload_pattern,
                    "estimated_partitioning_benefit": benefit,
                    "notes": "; ".join(notes_parts),
                }

                results["candidates"].append(candidate)

            return results


@mcp.tool
def analyze_sessions(
    include_idle: bool = True,
    include_active: bool = True,
    include_locked: bool = True,
    min_duration_seconds: int = 60,
    min_idle_seconds: int = 60
) -> dict[str, Any]:
    """
    Comprehensive session analysis combining active queries, idle sessions, and locks.
    
    Args:
        include_idle: Include idle and idle-in-transaction sessions.
        include_active: Include active query sessions.
        include_locked: Include sessions involved in locks.
        min_duration_seconds: Minimum query/transaction duration to include.
        min_idle_seconds: Minimum idle time for idle sessions.
    
    Returns:
        Dictionary containing session summary, detailed sessions, and recommendations.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            results = {
                "summary": {},
                "active_sessions": [],
                "idle_sessions": [],
                "locked_sessions": [],
                "recommendations": []
            }

            # Get overall session statistics
            _execute_safe(
                cur,
                """
                select
                  count(*) as total_sessions,
                  count(*) filter (where state = 'active') as active_count,
                  count(*) filter (where state like 'idle%') as idle_count,
                  count(*) filter (where wait_event is not null) as waiting_count
                from pg_stat_activity
                where pid <> pg_backend_pid()
                """
            )
            results["summary"] = cur.fetchone()

            # Active sessions with long-running queries/transactions
            if include_active:
                _execute_safe(
                    cur,
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
                        (query_start is not null and now() - query_start > make_interval(secs => %(min_duration)s))
                        or (xact_start is not null and now() - xact_start > make_interval(secs => %(min_duration)s))
                      )
                    order by greatest(coalesce(now() - query_start, interval '0'), coalesce(now() - xact_start, interval '0')) desc
                    """,
                    {"min_duration": min_duration_seconds}
                )
                results["active_sessions"] = cur.fetchall()

            # Idle sessions
            if include_idle:
                _execute_safe(
                    cur,
                    """
                    select
                      pid,
                      usename as user,
                      datname as database,
                      application_name,
                      state,
                      now() - backend_start as connection_duration,
                      now() - state_change as idle_duration,
                      left(query, 1000) as last_query
                    from pg_stat_activity
                    where state in ('idle', 'idle in transaction', 'idle in transaction (aborted)')
                      and pid <> pg_backend_pid()
                      and now() - state_change > make_interval(secs => %(min_idle)s)
                    order by state_change asc
                    """,
                    {"min_idle": min_idle_seconds}
                )
                results["idle_sessions"] = cur.fetchall()

            # Locked sessions (blocked and blocking)
            if include_locked:
                _execute_safe(
                    cur,
                    """
                    with lock_chains as (
                      select
                        bl.pid as blocked_pid,
                        a.usename as blocked_user,
                        a.datname as blocked_database,
                        a.application_name as blocked_application_name,
                        a.client_addr::text as blocked_client_addr,
                        a.state as blocked_state,
                        now() - a.query_start as blocked_execution_time,
                        left(a.query, 500) as blocked_query,
                        bl.locktype,
                        bl.mode as blocked_lock_mode,
                        -- Find the blocking session
                        (select pid from pg_locks where granted and pg_locks.locktype = bl.locktype 
                         and pg_locks.database = bl.database and pg_locks.relation = bl.relation 
                         and pg_locks.page = bl.page and pg_locks.tuple = bl.tuple 
                         and pg_locks.virtualxid = bl.virtualxid and pg_locks.transactionid = bl.transactionid 
                         and pg_locks.classid = bl.classid and pg_locks.objid = bl.objid 
                         and pg_locks.objsubid = bl.objsubid limit 1) as blocking_pid
                      from pg_catalog.pg_locks bl
                      join pg_catalog.pg_stat_activity a on a.pid = bl.pid
                      where not bl.granted
                        and bl.pid <> pg_backend_pid()
                    )
                    select
                      blocked_pid,
                      blocked_user,
                      blocked_database,
                      blocked_application_name,
                      blocked_client_addr,
                      blocked_state,
                      blocked_execution_time,
                      blocked_query,
                      blocked_lock_mode,
                      blocking_pid,
                      (select usename from pg_stat_activity where pid = blocking_pid) as blocking_user,
                      (select left(query, 200) from pg_stat_activity where pid = blocking_pid) as blocking_query
                    from lock_chains
                    where blocking_pid is not null
                    order by blocked_execution_time desc
                    """
                )
                results["locked_sessions"] = cur.fetchall()

            # Generate recommendations based on findings
            if results["active_sessions"]:
                longest_active = max(results["active_sessions"], key=lambda x: x["query_age"] or x["xact_age"])
                results["recommendations"].append(
                    f"Longest active session: PID {longest_active['pid']} ({longest_active['user']}) running for {longest_active['query_age']}"
                )

            if results["idle_sessions"]:
                longest_idle = max(results["idle_sessions"], key=lambda x: x["idle_duration"])
                results["recommendations"].append(
                    f"Longest idle session: PID {longest_idle['pid']} ({longest_idle['user']}) idle for {longest_idle['idle_duration']}"
                )

            if results["locked_sessions"]:
                results["recommendations"].append(
                    f"Found {len(results['locked_sessions'])} sessions waiting on locks. Consider reviewing blocking sessions."
                )

            return results


@mcp.tool
def kill_session(pid: int) -> dict[str, Any]:
    """
    Terminates a database session by its process ID (PID).
    Requires MCP_ALLOW_WRITE=true.

    Args:
        pid: The process ID of the session to terminate.
    """
    if not ALLOW_WRITE:
        raise ValueError("Write operations are disabled. Set MCP_ALLOW_WRITE=true to enable killing sessions.")

    with pool.connection() as conn:
        with conn.cursor() as cur:
            logger.info(f"Terminating session with PID: {pid}")
            _execute_safe(
                cur,
                "select pg_terminate_backend(%(pid)s) as terminated",
                {"pid": pid}
            )
            row = cur.fetchone()
            terminated = row["terminated"] if row else False
            return {
                "pid": pid,
                "terminated": terminated,
                "message": f"Session {pid} terminated." if terminated else f"Failed to terminate session {pid} or session not found."
            }




@mcp.tool
def server_info() -> dict[str, Any]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
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
                "statement_timeout_ms": STATEMENT_TIMEOUT_MS,
            }


@mcp.tool
def get_db_parameters(pattern: str | None = None) -> list[dict[str, Any]]:
    """
    Retrieves database configuration parameters (GUCs).

    Args:
        pattern: Optional regex pattern to filter parameter names (e.g., 'max_connections' or 'shared_.*').
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if pattern:
                _execute_safe(
                    cur,
                    """
                    select
                      name,
                      setting,
                      unit,
                      category,
                      short_desc,
                      context,
                      vartype,
                      min_val,
                      max_val,
                      enumvals,
                      boot_val,
                      reset_val,
                      pending_restart
                    from pg_settings
                    where name ~* %(pattern)s
                    order by name
                    """,
                    {"pattern": pattern},
                )
            else:
                _execute_safe(
                    cur,
                    """
                    select
                      name,
                      setting,
                      unit,
                      category,
                      short_desc,
                      context,
                      vartype,
                      min_val,
                      max_val,
                      enumvals,
                      boot_val,
                      reset_val,
                      pending_restart
                    from pg_settings
                    order by name
                    """
                )
            return cur.fetchall()


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
def list_largest_schemas(limit: int = 30) -> list[dict[str, Any]]:
    """
    Lists the largest schemas in the current database ordered by total size.

    Args:
        limit: Maximum number of schemas to return (default: 30).
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select
                  n.nspname as schema,
                  sum(pg_total_relation_size(c.oid)) as size_bytes
                from pg_catalog.pg_namespace n
                join pg_catalog.pg_class c on n.oid = c.relnamespace
                where n.nspname not like 'pg_%%'
                  and n.nspname <> 'information_schema'
                  and c.relkind in ('r', 'm', 'p') -- tables, matviews, partitioned tables
                group by n.nspname
                order by size_bytes desc
                limit %(limit)s
                """,
                {"limit": limit},
            )
            return cur.fetchall()


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
def analyze_indexes(schema: str | None = None, limit: int = 50) -> dict[str, Any]:
    """
    Identify unused and duplicate indexes.
    
    Args:
        schema: Optional schema name to filter.
        limit: Maximum number of rows to return for each category.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            results = {
                "unused_indexes": [],
                "duplicate_indexes": [],
                "missing_indexes": [],
                "redundant_indexes": []
            }

            # 1. Unused Indexes
            _execute_safe(
                cur,
                """
                select
                  schemaname as schema,
                  relname as table,
                  indexrelname as index,
                  pg_size_pretty(pg_relation_size(i.indexrelid)) as size,
                  idx_scan as scans
                from pg_stat_user_indexes i
                join pg_index using (indexrelid)
                where schemaname not in ('pg_catalog', 'information_schema')
                  and (%(schema)s::text is null or schemaname = %(schema)s::text)
                  and indisunique = false
                  and idx_scan = 0
                order by pg_relation_size(i.indexrelid) desc
                limit %(limit)s
                """,
                {"schema": schema, "limit": limit}
            )
            results["unused_indexes"] = cur.fetchall()

            # 2. Duplicate Indexes
            _execute_safe(
                cur,
                """
                select
                  n.nspname as schema,
                  t.relname as table,
                  (select array_agg(a.attname) from pg_attribute a where a.attrelid = t.oid and a.attnum = any(idx.indkey)) as columns,
                  array_agg(i.relname) as indexes,
                  count(*) as dup_count
                from pg_index idx
                join pg_class t on t.oid = idx.indrelid
                join pg_class i on i.oid = idx.indexrelid
                join pg_namespace n on n.oid = t.relnamespace
                where n.nspname not in ('pg_catalog', 'information_schema')
                  and (%(schema)s::text is null or n.nspname = %(schema)s::text)
                group by n.nspname, t.relname, t.oid, idx.indkey
                having count(*) > 1
                limit %(limit)s
                """,
                {"schema": schema, "limit": limit}
            )
            results["duplicate_indexes"] = cur.fetchall()
            results["missing_indexes"] = []
            results["redundant_indexes"] = []

            return results


@mcp.tool
def list_largest_tables(schema: str = "public", limit: int = 30) -> list[dict[str, Any]]:
    """
    List the largest tables in a specific schema ranked by total size (including indexes and TOAST).
    
    Args:
        schema: Schema name (default: 'public').
        limit: Maximum number of tables to return (default: 30).
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select
                  n.nspname as schema,
                  c.relname as table,
                  pg_total_relation_size(c.oid) as total_size_bytes,
                  pg_relation_size(c.oid) as table_size_bytes,
                  pg_total_relation_size(c.oid) - pg_relation_size(c.oid) as index_size_bytes,
                  reltuples::bigint as approx_rows
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = %(schema)s
                  and c.relkind = 'r'
                order by pg_total_relation_size(c.oid) desc
                limit %(limit)s
                """,
                {"schema": schema, "limit": limit}
            )
            return cur.fetchall()


@mcp.tool
def list_temp_objects() -> dict[str, Any]:
    """
    List temporary schemas with object counts and total size.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select
                  n.nspname as schema,
                  count(*) as object_count,
                  pg_size_pretty(sum(pg_total_relation_size(c.oid))) as total_size
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname like 'pg_temp%%'
                group by n.nspname
                order by sum(pg_total_relation_size(c.oid)) desc
                """
            )
            rows = cur.fetchall()
            return {
                "temp_schemas": rows,
                "total_temp_objects": sum(r["object_count"] for r in rows) if rows else 0
            }


@mcp.tool
def table_sizes(schema: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """
    List tables by size including indexes and TOAST.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select
                  n.nspname as schema,
                  c.relname as table,
                  pg_size_pretty(pg_total_relation_size(c.oid)) as total_size,
                  pg_size_pretty(pg_relation_size(c.oid)) as table_size,
                  pg_size_pretty(pg_total_relation_size(c.oid) - pg_relation_size(c.oid)) as index_size,
                  reltuples::bigint as approx_rows
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where c.relkind = 'r'
                  and n.nspname not in ('pg_catalog', 'information_schema')
                  and (%(schema)s::text is null or n.nspname = %(schema)s::text)
                order by pg_total_relation_size(c.oid) desc
                limit %(limit)s
                """,
                {"schema": schema, "limit": limit}
            )
            return cur.fetchall()


@mcp.tool
def index_usage(schema: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """
    Show index usage statistics.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select
                  schemaname as schema,
                  relname as table,
                  indexrelname as index,
                  idx_scan as scans,
                  idx_tup_read as tuples_read,
                  idx_tup_fetch as tuples_fetched
                from pg_stat_user_indexes
                where (%(schema)s::text is null or schemaname = %(schema)s::text)
                order by idx_scan desc
                limit %(limit)s
                """,
                {"schema": schema, "limit": limit}
            )
            return cur.fetchall()


@mcp.tool
def maintenance_stats(schema: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """
    Show vacuum and analyze statistics.
    """
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select
                  schemaname as schema,
                  relname as table,
                  n_live_tup as live_rows,
                  n_dead_tup as dead_rows,
                  round((n_dead_tup::numeric / greatest(n_live_tup + n_dead_tup, 1)::numeric) * 100, 2) as dead_ratio,
                  last_vacuum,
                  last_autovacuum,
                  last_analyze,
                  last_autoanalyze,
                  vacuum_count + autovacuum_count as total_vacuums,
                  analyze_count + autoanalyze_count as total_analyzes
                from pg_stat_user_tables
                where (%(schema)s::text is null or schemaname = %(schema)s::text)
                order by n_dead_tup desc
                limit %(limit)s
                """,
                {"schema": schema, "limit": limit}
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
    sql_fingerprint = hashlib.sha256(sql.encode("utf-8")).hexdigest()
    params_fingerprint = (
        hashlib.sha256(params_json.encode("utf-8")).hexdigest() if params_json is not None else None
    )
    logger.info(f"run_query called. sql_len={len(sql)} max_rows={limit} sql_sha256={sql_fingerprint}")
    logger.debug(f"run_query params_sha256={params_fingerprint}")
    params: dict[str, Any] | None = None
    if params_json:
        params = json.loads(params_json)
        if not isinstance(params, dict):
            raise ValueError("params_json must decode to a JSON object")

    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(cur, sql, params)
            rows_plus_one = _fetch_limited(cur, limit + 1 if limit >= 0 else 1)
            truncated = len(rows_plus_one) > limit
            rows = rows_plus_one[:limit]
            if cur.description:
                first = cur.description[0]
                columns = (
                    [d.name for d in cur.description]
                    if hasattr(first, "name")
                    else [d[0] for d in cur.description]
                )
            else:
                columns = []
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
    sql_fingerprint = hashlib.sha256(sql.encode("utf-8")).hexdigest()
    logger.info(
        f"explain_query called. format={format.strip().lower()} analyze={analyze} buffers={buffers} "
        f"verbose={verbose} settings={settings} sql_len={len(sql)} sql_sha256={sql_fingerprint}"
    )
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
            _execute_safe(cur, stmt)
            rows = cur.fetchall()
            if fmt == "json":
                plan = rows[0]["QUERY PLAN"] if rows else None
                return {"format": "json", "plan": plan}
            text = "\n".join(r["QUERY PLAN"] for r in rows)
            return {"format": "text", "plan": text}


@mcp.tool
def ping() -> dict[str, Any]:
    return {"ok": True}


@mcp.tool
def server_info_mcp() -> dict[str, Any]:
    """Get information about the MCP server."""
    with pool.connection() as conn:
        with conn.cursor() as cur:
            _execute_safe(
                cur,
                """
                select current_database() as database
                """
            )
            row = cur.fetchone()
            database_name = row["database"] if row and "database" in row else "unknown"
    return {
        "name": mcp.name,
        "version": "1.0.0",
        "status": "healthy",
        "transport": os.environ.get("MCP_TRANSPORT", "http"),
        "database": database_name
    }


def _configure_fastmcp_runtime() -> None:
    cert_file = os.environ.get("SSL_CERT_FILE")
    if cert_file and not os.path.exists(cert_file):
        os.environ.pop("SSL_CERT_FILE", None)
    try:
        import fastmcp

        fastmcp.settings.check_for_updates = "off"
    except Exception:
        pass


def main() -> None:
    _configure_fastmcp_runtime()

    transport = os.environ.get("MCP_TRANSPORT", "http").strip().lower()
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = _env_int("MCP_PORT", 8000)
    
    stateless = _env_bool("MCP_STATELESS", False)
    json_resp = _env_bool("MCP_JSON_RESPONSE", False)
    
    # SSL Configuration for HTTPS
    ssl_cert = os.environ.get("MCP_SSL_CERT")
    ssl_key = os.environ.get("MCP_SSL_KEY")
    
    if transport in {"http", "sse"}:
        run_kwargs = {
            "transport": transport,
            "host": host,
            "port": port,
            "stateless_http": stateless,
            "json_response": json_resp
        }
        
        if ssl_cert and ssl_key:
            run_kwargs["ssl_certfile"] = ssl_cert
            run_kwargs["ssl_keyfile"] = ssl_key
            logger.info(f"Starting MCP server with HTTPS enabled using cert: {ssl_cert}")
        
        mcp.run(**run_kwargs)
    elif transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
