from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any

from fastmcp import Context, FastMCP
from fastmcp.dependencies import Depends
from fastmcp.utilities.logging import get_logger
from mcp.types import ToolAnnotations

from src.middleware.rate_limiter import RateLimitExceededError
from src.tools import hypopg_tools
from src.tools.input_validation import (
    validate_database_name,
    validate_query_text,
    validate_schema_name,
)
from src.tools.tool_flags import is_tool_enabled

logger = get_logger(__name__)

# Ping query for EDBAS 9.6 identity
_PING_SQL = (
    "SELECT "
    "current_setting('cluster_name') AS instance_name, "
    "version() AS database_version, "
    "CASE WHEN current_setting('edb_redwood_date') = 'on' "
    "THEN 'Oracle' ELSE 'PostgreSQL' END AS edb_compat_mode, "
    "host(inet_server_addr()) AS ip_address, "
    "now() AT TIME ZONE 'UTC' AS current_utc_time"
)


def register_pg_tools(mcp: FastMCP, state: Any) -> list[str]:
    """Register dual-instance MCP tools for all enabled EDBAS instances.

    Every tool definition is automatically mirrored across all enabled instances.
    Tool naming follows: db_{instance_number}_pg96_{toolname}
    """
    registered: list[str] = []

    instance_ids = state.connection_manager.list_enabled_instances()
    number_by_instance = {instance_id: idx for idx, instance_id in enumerate(instance_ids, start=1)}

    def _auth_enforced() -> bool:
        auth_cfg = getattr(state, "auth", None)
        if auth_cfg is None:
            return False
        return bool(auth_cfg.azure_auth_enabled or auth_cfg.auth_mode == "azure_token_verifier")

    async def _resolve_actor_and_authorize(
        *,
        actor: str,
        tool: str,
        required_privilege: str,
        ctx: Context | None,
    ) -> tuple[str, dict[str, Any]]:
        # Currently auth is disabled; return pass-through
        return actor, {
            "auth_mode": "disabled",
            "auth_subject": None,
            "privilege_level": "none",
            "group_match_result": {"group_authorization_enabled": False},
        }

    def _log_audit_event(
        *,
        request_id: str,
        actor: str,
        tool: str,
        instance: str,
        sql: str,
        decision: str,
        latency_ms: int,
        rows: int,
        error_code: str | None,
        auth_ctx: dict[str, Any] | None,
    ) -> None:
        state.audit_logger.log_event(
            request_id=request_id,
            actor=actor,
            tool=tool,
            instance=instance,
            sql=sql,
            decision=decision,
            latency_ms=latency_ms,
            rows=rows,
            error_code=error_code,
            auth_mode=(auth_ctx or {}).get("auth_mode"),
            auth_subject=(auth_ctx or {}).get("auth_subject"),
            privilege_level=(auth_ctx or {}).get("privilege_level"),
            group_match_result=(auth_ctx or {}).get("group_match_result"),
        )

    # -----------------------------------------------------------------------
    # Register ping tool for each enabled instance (auto-mirrored)
    # -----------------------------------------------------------------------
    for instance_id in instance_ids:
        instance_number = number_by_instance[instance_id]
        ping_tool_name = f"db_{instance_number}_pg96_ping"

        # Check if tool is enabled for this instance
        if not is_tool_enabled(state.policy, instance_id, "ping"):
            logger.info(f"Skipping disabled tool '{ping_tool_name}' for instance '{instance_id}'")
            continue

        @mcp.tool(
            name=ping_tool_name,
            annotations=ToolAnnotations(
                readOnlyHint=True,
                idempotentHint=True,
                openWorldHint=False,
            ),
            tags={"read-only", "diagnostics", f"instance-{instance_number}"},
            timeout=10.0,
        )
        async def _ping(
            actor: str = "system",
            ctx: Context | None = None,
            _tool: str = ping_tool_name,
            _instance: str = instance_id,
            _instance_number: int = instance_number,
        ) -> dict[str, str]:
            """Check accessibility and identity of an EDBAS 9.6 instance.

            Outputs instance_name, database_version (EDBAS-branded),
            edb_compat_mode (Oracle/PostgreSQL), ip_address, and current UTC time.
            """
            request_id = str(uuid.uuid4())
            started = time.time()
            decision = "allow"
            error_code = None
            row_count = 0
            _auth_ctx: dict[str, Any] | None = None
            try:
                if ctx is not None:
                    await ctx.debug(
                        f"[{request_id}] Pinging instance {_instance_number} "
                        f"({_instance}) for actor={actor}",
                        extra={
                            "request_id": request_id,
                            "tool": _tool,
                            "instance": _instance,
                        },
                    )

                actor, _auth_ctx = await _resolve_actor_and_authorize(
                    actor=actor,
                    tool=_tool,
                    required_privilege="read",
                    ctx=ctx,
                )
                state.session_manager.touch(actor, request_id)
                state.rate_limiter.allow(actor)

                # Execute identity query against the bound instance
                payload = await state.connection_manager.fetch_single_row(
                    _instance, "edb", _PING_SQL
                )
                row_count = 1 if payload else 0

                # Apply fallbacks for EDBAS 9.6 edge cases
                if not payload.get("ip_address"):
                    payload["ip_address"] = "unknown"
                    if ctx is not None:
                        await ctx.warning(
                            f"[{request_id}] inet_server_addr() returned NULL "
                            f"for instance {_instance_number}; using fallback",
                            extra={"instance": _instance, "instance_number": _instance_number},
                        )

                if not payload.get("edb_compat_mode"):
                    payload["edb_compat_mode"] = "PostgreSQL (default)"

                if ctx is not None:
                    await ctx.info(
                        f"[{request_id}] Instance {_instance_number} is accessible",
                        extra={
                            "request_id": request_id,
                            "tool": _tool,
                            "instance": _instance,
                            "instance_name": payload.get("instance_name"),
                            "version": payload.get("database_version"),
                        },
                    )

                return dict(payload)

            except PermissionError as exc:
                decision = "deny"
                error_code = str(exc)
                state.denied_requests += 1
                if ctx is not None:
                    await ctx.warning(
                        f"[{request_id}] Ping denied: {error_code}",
                        extra={"tool": _tool, "instance": _instance, "error": error_code},
                    )
                raise
            except RateLimitExceededError as exc:
                decision = "deny"
                error_code = str(exc)
                state.denied_requests += 1
                if ctx is not None:
                    await ctx.warning(
                        f"[{request_id}] Rate limit exceeded: {error_code}",
                        extra={"tool": _tool, "instance": _instance, "error": error_code},
                    )
                raise
            except Exception as exc:
                decision = "deny"
                error_code = f"PING_ERROR: {exc}"
                state.denied_requests += 1
                if ctx is not None:
                    await ctx.error(
                        f"[{request_id}] Ping failed: {error_code}",
                        extra={"tool": _tool, "instance": _instance, "error": error_code},
                    )
                raise RuntimeError(error_code) from exc
            finally:
                latency_ms = int((time.time() - started) * 1000)
                _log_audit_event(
                    request_id=request_id,
                    actor=actor,
                    tool=_tool,
                    instance=_instance,
                    sql=_PING_SQL,
                    decision=decision,
                    latency_ms=latency_ms,
                    rows=row_count,
                    error_code=error_code,
                    auth_ctx=_auth_ctx,
                )

        registered.append(ping_tool_name)

        # -----------------------------------------------------------------------
        # Register db_{instance_number}_pg96_get_slow_statements
        # -----------------------------------------------------------------------
        slow_statements_tool_name = f"db_{instance_number}_pg96_get_slow_statements"

        if is_tool_enabled(state.policy, instance_id, "get_slow_statements"):

            @mcp.tool(
                name=slow_statements_tool_name,
                annotations=ToolAnnotations(
                    readOnlyHint=True, idempotentHint=False, openWorldHint=False
                ),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=60.0,
            )
            async def _get_slow_statements(
                database_name: str,
                max_combinations: int = 10,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = slow_statements_tool_name,
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Retrieves long-running SQL statements, execution stats, and generates execution plans.

                For each slow query, captures the baseline EXPLAIN plan, then uses HypoPG to create and test
                virtual index combinations, ranking at least 5 improved plans by cost (ascending).
                The best combination of virtual + existing indexes is presented as the recommendation.

                Args:
                    database_name: Name of the database to query.
                    max_combinations: Maximum HypoPG index combinations to test per statement (default 10).
                """
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None

                database_name = validate_database_name(database_name)

                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)

                    sql = """
                        SELECT pd.datname, p.query, p.total_time, p.calls, p.rows,
                               (p.total_time / GREATEST(p.calls, 1)) AS mean_time
                        FROM pg_stat_statements p
                        JOIN pg_database pd ON p.dbid = pd.oid
                        WHERE pd.datname = $1
                        ORDER BY mean_time DESC
                        LIMIT 5
                    """
                    app_state.write_guard.enforce(_tool, sql)

                    rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql, database_name
                    )

                    fixes = []
                    for row in rows:
                        query_text = row.get("query", "")[:1000]
                        if not query_text.strip().upper().startswith("SELECT"):
                            fixes.append(
                                {
                                    "Long Running Statement": query_text[:200],
                                    "Calls": row.get("calls"),
                                    "Mean Time": row.get("mean_time"),
                                    "Total Time": row.get("total_time"),
                                    "Recommendations/Fixes": [
                                        "Non-SELECT query — HypoPG index analysis not applicable"
                                    ],
                                }
                            )
                            continue

                        # Run HypoPG analysis via raw connection
                        try:
                            async with app_state.connection_manager.acquire(_instance) as conn:
                                optimal = await hypopg_tools.hypopg_find_optimal_indexes(
                                    conn, query_text, max_combinations=max_combinations
                                )
                        except RuntimeError as hypopg_err:
                            fixes.append(
                                {
                                    "Long Running Statement": query_text[:200],
                                    "Calls": row.get("calls"),
                                    "Mean Time": row.get("mean_time"),
                                    "Total Time": row.get("total_time"),
                                    "Recommendations/Fixes": [
                                        f"HypoPG analysis unavailable: {hypopg_err}"
                                    ],
                                }
                            )
                            continue

                        # Format ranked plans
                        ranked = []
                        for plan in optimal.get("ranked_plans", []):
                            ranked.append(
                                {
                                    "rank": plan.get("rank"),
                                    "virtual_indexes_tested": plan.get("virtual_indexes_used", []),
                                    "total_cost": plan.get("total_cost"),
                                    "cost_improvement_pct": plan.get("cost_improvement_pct"),
                                    "description": plan.get("description", ""),
                                }
                            )

                        # Check for stale statistics on relevant tables
                        stats_recs = []
                        query_analysis = await hypopg_tools.parse_tables_and_columns(
                            await app_state.connection_manager.acquire(_instance).__aenter__(),
                            query_text,
                        )
                        for table_name in query_analysis.get("tables", {}):
                            schema_part = "public"
                            table_part = table_name
                            if "." in table_name:
                                schema_part, table_part = table_name.split(".", 1)
                            try:
                                async with app_state.connection_manager.acquire(_instance) as conn:
                                    stats_row = await conn.fetchrow(
                                        """
                                        SELECT relname, last_analyze, last_autoanalyze
                                        FROM pg_stat_user_tables
                                        WHERE schemaname = $1 AND relname = $2
                                        """,
                                        schema_part,
                                        table_part,
                                    )
                                    if stats_row:
                                        last_analyze = stats_row.get("last_analyze")
                                        if last_analyze is None:
                                            stats_recs.append(
                                                f"ANALYZE {table_name};  -- Never analyzed"
                                            )
                            except Exception:
                                pass

                        entry = {
                            "Long Running Statement": query_text[:200],
                            "Calls": row.get("calls"),
                            "Mean Time": row.get("mean_time"),
                            "Total Time": row.get("total_time"),
                            "Baseline Explain Plan": optimal.get("baseline_plan"),
                            "Baseline Total Cost": optimal.get("baseline_cost"),
                            "Ranked Improved Plans": ranked,
                            "Best Recommendation": optimal.get("best_recommendation", {}),
                        }
                        if stats_recs:
                            entry["Statistics Recommendations"] = stats_recs

                        fixes.append(entry)

                    result = {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": f"Found {len(rows)} slow queries in database {database_name}. HypoPG analysis generated index recommendations for {sum(1 for f in fixes if 'Best Recommendation' in f)} queries.",
                        "Impacted Metrics": "CPU usage and Disk I/O during slow query execution",
                        "Issue Priority": "High" if len(rows) > 0 else "Low",
                        "Recommendations/Fixes": fixes,
                    }
                    row_count = len(rows)
                    return result
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="slow_statements_query",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(slow_statements_tool_name)

        # -----------------------------------------------------------------------
        # Register db_{instance_number}_pg96_blocking_sessions
        # -----------------------------------------------------------------------
        blocking_sessions_tool_name = f"db_{instance_number}_pg96_blocking_sessions"

        if is_tool_enabled(state.policy, instance_id, "blocking_sessions"):

            @mcp.tool(
                name=blocking_sessions_tool_name,
                annotations=ToolAnnotations(
                    readOnlyHint=True, idempotentHint=False, openWorldHint=False
                ),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _blocking_sessions(
                database_name: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = blocking_sessions_tool_name,
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Analyzes active, idle, and idle-in-transaction sessions.

                Evaluates locking, deadlocks, blocking trees, connection pooling,
                sequence scan abuse, and wait events.
                """
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None

                database_name = validate_database_name(database_name)

                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)

                    # Step 1: Active sessions (non-idle)
                    sql_activity = """
                        SELECT pid, usename, datname, state, wait_event_type, wait_event,
                               query_start, query, backend_start, application_name
                        FROM pg_stat_activity
                        WHERE datname = $1 AND state != 'idle'
                        ORDER BY query_start ASC
                        LIMIT 20
                    """
                    app_state.write_guard.enforce(_tool, sql_activity)
                    active_rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql_activity, database_name
                    )

                    # Step 2: Lock tree - blocking sessions
                    sql_locks = """
                        SELECT
                            blocked.pid AS blocked_pid,
                            blocked.query AS blocked_query,
                            blocked.wait_event_type AS blocked_wait_type,
                            blocked.wait_event AS blocked_wait_event,
                            blocked.state AS blocked_state,
                            blocking.pid AS blocking_pid,
                            blocking.query AS blocking_query,
                            blocking.state AS blocking_state,
                            blocked_l.relation
                        FROM pg_locks blocked_l
                        JOIN pg_stat_activity blocked ON blocked.pid = blocked_l.pid
                        JOIN pg_locks blocking_l
                            ON blocking_l.relation = blocked_l.relation
                            AND blocking_l.locktype = blocked_l.locktype
                            AND blocking_l.granted = true
                            AND blocking_l.pid != blocked_l.pid
                        JOIN pg_stat_activity blocking ON blocking.pid = blocking_l.pid
                        WHERE NOT blocked_l.granted
                          AND blocked.datname = $1
                        ORDER BY blocked.query_start
                        LIMIT 20
                    """
                    app_state.write_guard.enforce(_tool, sql_locks)
                    lock_rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql_locks, database_name
                    )

                    # Step 3: Seq scan abuse detection
                    sql_seq = """
                        SELECT relname, seq_scan, idx_scan,
                               (seq_scan - COALESCE(idx_scan, 0)) AS scan_gap
                        FROM pg_stat_user_tables
                        WHERE seq_scan > COALESCE(idx_scan, 0) * 10
                          AND seq_scan > 1000
                        ORDER BY scan_gap DESC
                        LIMIT 10
                    """
                    app_state.write_guard.enforce(_tool, sql_seq)
                    seq_rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql_seq
                    )

                    # Build fixes output
                    fixes = []

                    # Lock tree entries
                    for lock_row in lock_rows:
                        fixes.append(
                            {
                                "type": "blocking_chain",
                                "blocked_pid": lock_row.get("blocked_pid"),
                                "blocked_state": lock_row.get("blocked_state"),
                                "blocked_wait_event": lock_row.get("blocked_wait_event"),
                                "blocked_query": (lock_row.get("blocked_query") or "")[:200],
                                "blocking_pid": lock_row.get("blocking_pid"),
                                "blocking_query": (lock_row.get("blocking_query") or "")[:200],
                                "recommendation": (
                                    f"Blocking chain detected: PID {lock_row.get('blocking_pid')} "
                                    f"blocks PID {lock_row.get('blocked_pid')}. "
                                    f"Consider terminating PID {lock_row.get('blocking_pid')} "
                                    f"if it is a runaway transaction."
                                ),
                            }
                        )

                    # Active session entries with wait events
                    for act_row in active_rows:
                        wait_type = act_row.get("wait_event_type")
                        if wait_type and wait_type not in (None, ""):
                            fixes.append(
                                {
                                    "type": "active_session",
                                    "pid": act_row.get("pid"),
                                    "user": act_row.get("usename"),
                                    "state": act_row.get("state"),
                                    "wait_event_type": wait_type,
                                    "wait_event": act_row.get("wait_event"),
                                    "query": (act_row.get("query") or "")[:200],
                                    "application_name": act_row.get("application_name"),
                                    "recommendation": (
                                        f"Session PID {act_row.get('pid')} is in state "
                                        f"'{act_row.get('state')}' with wait event "
                                        f"'{act_row.get('wait_event')}'. "
                                        f"{'Investigate long-running transaction.' if act_row.get('state') == 'idle in transaction' else 'Monitor for completion.'}"
                                    ),
                                }
                            )

                    # Seq scan abuse entries
                    for seq_row in seq_rows:
                        fixes.append(
                            {
                                "type": "seq_scan_abuse",
                                "table": seq_row.get("relname"),
                                "seq_scan": seq_row.get("seq_scan"),
                                "idx_scan": seq_row.get("idx_scan"),
                                "scan_gap": seq_row.get("scan_gap"),
                                "recommendation": (
                                    f"Table '{seq_row.get('relname')}' has {seq_row.get('seq_scan')} "
                                    f"sequential scans vs {seq_row.get('idx_scan')} index scans. "
                                    f"Consider adding indexes on heavily filtered columns."
                                ),
                            }
                        )

                    # Detect potential deadlocks by checking for cyclical patterns
                    deadlock_count = 0
                    blocked_pids = {l.get("blocked_pid") for l in lock_rows}
                    blocking_pids = {l.get("blocking_pid") for l in lock_rows}
                    if blocked_pids & blocking_pids:
                        deadlock_count = len(blocked_pids & blocking_pids)

                    result = {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": (
                            f"Detected {len(active_rows)} active sessions, "
                            f"{len(lock_rows)} blocking chains, "
                            f"{deadlock_count} potential deadlocks, "
                            f"{len(seq_rows)} tables with seq_scan abuse."
                        ),
                        "Impacted Metrics": "Wait times, lock contention, sequence scan overhead",
                        "Issue Priority": "High"
                        if deadlock_count > 0
                        else ("Medium" if len(lock_rows) > 0 else "Low"),
                        "Recommendations/Fixes": fixes,
                    }
                    row_count = len(active_rows)
                    return result
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="blocking_sessions_query",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(blocking_sessions_tool_name)

        # -----------------------------------------------------------------------
        # Register db_{instance_number}_pg96_analyze_data_model
        # -----------------------------------------------------------------------
        analyze_data_model_tool_name = f"db_{instance_number}_pg96_analyze_data_model"

        if is_tool_enabled(state.policy, instance_id, "analyze_data_model"):

            @mcp.tool(
                name=analyze_data_model_tool_name,
                annotations=ToolAnnotations(
                    readOnlyHint=True, idempotentHint=False, openWorldHint=False
                ),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=60.0,
            )
            async def _analyze_data_model(
                database_name: str,
                schema_name: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = analyze_data_model_tool_name,
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Orchestrates comprehensive data model analysis.

                Delegates to sub-tools (extract_schema_model, analyze_constraints_and_fks,
                analyze_normalization, analyze_index_statistics, analyze_3nf_and_decomposition)
                internally and aggregates findings into a unified report. Also includes
                HypoPG index recommendations for tables with sequential scan abuse.
                """
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None

                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)

                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)

                    aggregated = {
                        "schema_model": None,
                        "constraints": None,
                        "normalization": None,
                        "index_statistics": None,
                        "decomposition_3nf": None,
                        "hypopg_recommendations": [],
                    }

                    # 1) Extract schema model
                    sql_extract = """
                        SELECT c.relname AS table_name, a.attname AS column_name,
                               pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
                               a.attnotnull AS not_null,
                               COALESCE(i.indisprimary, false) AS is_pk
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                        LEFT JOIN pg_index i ON i.indrelid = c.oid AND i.indisprimary AND a.attnum = ANY(i.indkey)
                        WHERE n.nspname = $1 AND c.relkind = 'r'
                        ORDER BY c.relname, a.attnum
                    """
                    app_state.write_guard.enforce(_tool, sql_extract)
                    schema_rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql_extract, schema_name
                    )
                    aggregated["schema_model"] = schema_rows

                    # 2) Constraints & FKs
                    sql_constraints = """
                        SELECT
                            conname, contype,
                            conrelid::regclass AS table_name,
                            confrelid::regclass AS referenced_table
                        FROM pg_constraint c
                        JOIN pg_namespace n ON n.oid = c.connamespace
                        WHERE n.nspname = $1
                    """
                    app_state.write_guard.enforce(_tool, sql_constraints)
                    constraint_rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql_constraints, schema_name
                    )
                    aggregated["constraints"] = constraint_rows

                    # 3) Normalization - type mismatch detection
                    sql_norm = """
                        SELECT
                            a1.attrelid::regclass AS table1,
                            a1.attname AS col1,
                            pg_catalog.format_type(a1.atttypid, a1.atttypmod) AS type1,
                            a2.attrelid::regclass AS table2,
                            a2.attname AS col2,
                            pg_catalog.format_type(a2.atttypid, a2.atttypmod) AS type2
                        FROM pg_attribute a1
                        JOIN pg_attribute a2
                            ON a1.attname = a2.attname
                            AND a1.attrelid != a2.attrelid
                            AND a1.atttypid != a2.atttypid
                            AND a1.attnum > 0 AND a2.attnum > 0
                            AND NOT a1.attisdropped AND NOT a2.attisdropped
                        JOIN pg_class c1 ON c1.oid = a1.attrelid AND c1.relkind = 'r'
                        JOIN pg_class c2 ON c2.oid = a2.attrelid AND c2.relkind = 'r'
                        JOIN pg_namespace n1 ON n1.oid = c1.relnamespace
                        JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                        WHERE n1.nspname = $1 AND n2.nspname = $1
                        ORDER BY a1.attname
                        LIMIT 20
                    """
                    app_state.write_guard.enforce(_tool, sql_norm)
                    norm_rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql_norm, schema_name
                    )
                    aggregated["normalization"] = norm_rows

                    # 4) Index statistics
                    sql_stats = """
                        SELECT relname, n_live_tup, n_dead_tup,
                               last_analyze, last_autoanalyze,
                               last_vacuum, last_autovacuum
                        FROM pg_stat_user_tables
                        WHERE schemaname = $1
                        ORDER BY GREATEST(n_dead_tup, 0) DESC
                    """
                    app_state.write_guard.enforce(_tool, sql_stats)
                    stats_rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql_stats, schema_name
                    )
                    aggregated["index_statistics"] = stats_rows

                    # 5) 3NF decomposition
                    sql_3nf = """
                        SELECT c.relname AS table_name,
                               t.seq_scan, t.idx_scan,
                               (t.seq_scan - COALESCE(t.idx_scan, 0)) AS scan_gap
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        LEFT JOIN pg_stat_user_tables t ON t.relid = c.oid
                        WHERE n.nspname = $1 AND c.relkind = 'r'
                          AND (t.seq_scan - COALESCE(t.idx_scan, 0)) > 1000
                        ORDER BY scan_gap DESC
                        LIMIT 10
                    """
                    app_state.write_guard.enforce(_tool, sql_3nf)
                    decomposition_rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql_3nf, schema_name
                    )
                    aggregated["decomposition_3nf"] = decomposition_rows

                    # 6) HypoPG recommendations for seq_scan abuse tables
                    for decomp_row in decomposition_rows:
                        table_name = decomp_row.get("table_name")
                        if table_name:
                            try:
                                async with app_state.connection_manager.acquire(_instance) as conn:
                                    sample_query = (
                                        f"SELECT * FROM {schema_name}.{table_name} LIMIT 0"
                                    )
                                    optimal = await hypopg_tools.hypopg_find_optimal_indexes(
                                        conn, sample_query, max_combinations=5
                                    )
                                    if (
                                        optimal.get("best_recommendation", {}).get(
                                            "improvement_pct", 0
                                        )
                                        > 0
                                    ):
                                        aggregated["hypopg_recommendations"].append(
                                            {
                                                "table": f"{schema_name}.{table_name}",
                                                "best_recommendation": optimal[
                                                    "best_recommendation"
                                                ],
                                            }
                                        )
                            except Exception:
                                pass

                    # Build fixes combining constraint, normalization, stats, and 3NF issues
                    fixes = []

                    # Add constraint findings
                    if constraint_rows:
                        pkeys = [r for r in constraint_rows if r.get("contype") == "p"]
                        fkeys = [r for r in constraint_rows if r.get("contype") == "f"]
                        fixes.append(
                            {
                                "section": "Constraints & Foreign Keys",
                                "detail": f"Found {len(pkeys)} primary keys and {len(fkeys)} foreign keys in schema",
                                "tables": [
                                    r.get("table_name")
                                    for r in constraint_rows
                                    if r.get("table_name")
                                ],
                            }
                        )

                    # Add normalization mismatches
                    if norm_rows:
                        fixes.append(
                            {
                                "section": "Normalization - Type Mismatches",
                                "detail": f"Found {len(norm_rows)} column type mismatches across tables",
                                "mismatches": [
                                    {
                                        "columns": f"{r.get('table1')}.{r.get('col1')} ({r.get('type1')}) vs {r.get('table2')}.{r.get('col2')} ({r.get('type2')})",
                                    }
                                    for r in norm_rows
                                ],
                            }
                        )

                    # Add stale statistics
                    stale_count = 0
                    stats_fixes = []
                    for r in stats_rows:
                        if r.get("last_analyze") is None:
                            stale_count += 1
                            stats_fixes.append(f"ANALYZE {r.get('relname')};  -- Never analyzed")
                    if stale_count > 0:
                        fixes.append(
                            {
                                "section": "Index Statistics",
                                "detail": f"Found {stale_count} tables with stale/missing statistics",
                                "recommendations": stats_fixes,
                            }
                        )

                    # Add 3NF decomposition findings
                    if decomposition_rows:
                        fixes.append(
                            {
                                "section": "3NF Decomposition Analysis",
                                "detail": f"Found {len(decomposition_rows)} tables with excessive sequential scans suggesting poor normalization",
                                "tables": [
                                    {
                                        "table": r.get("table_name"),
                                        "seq_scan": r.get("seq_scan"),
                                        "idx_scan": r.get("idx_scan"),
                                    }
                                    for r in decomposition_rows
                                ],
                            }
                        )

                    # Add HypoPG recommendations
                    if aggregated["hypopg_recommendations"]:
                        fixes.append(
                            {
                                "section": "HypoPG Index Recommendations",
                                "detail": "Virtual index recommendations for tables with sequential scan abuse",
                                "recommendations": aggregated["hypopg_recommendations"],
                            }
                        )

                    total_issues = (
                        len(constraint_rows)
                        + len(norm_rows)
                        + stale_count
                        + len(decomposition_rows)
                    )

                    result = {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": (
                            f"Analyzed schema '{schema_name}': {len(schema_rows)} columns mapped, "
                            f"{len(constraint_rows)} constraints, "
                            f"{len(norm_rows)} type mismatches, "
                            f"{stale_count} stale statistics, "
                            f"{len(decomposition_rows)} tables needing 3NF review."
                        ),
                        "Impacted Metrics": "Data integrity, storage efficiency, query performance",
                        "Issue Priority": "High"
                        if total_issues > 10
                        else ("Medium" if total_issues > 0 else "Low"),
                        "Recommendations/Fixes": fixes,
                    }
                    row_count = len(schema_rows)
                    return result
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="analyze_data_model_aggregator",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(analyze_data_model_tool_name)

            # --- Sub-tool: extract_schema_model ---
            @mcp.tool(
                name=f"db_{instance_number}_pg96_extract_schema_model",
                annotations=ToolAnnotations(
                    readOnlyHint=True, idempotentHint=False, openWorldHint=False
                ),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _extract_schema_model(
                database_name: str,
                schema_name: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_extract_schema_model",
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Generates the raw physical data model of a schema (tables, columns, types)."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = """
                        SELECT c.relname AS table_name, a.attname AS column_name,
                               pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
                               a.attnotnull AS not_null,
                               COALESCE(i.indisprimary, false) AS is_pk
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                        LEFT JOIN pg_index i ON i.indrelid = c.oid AND i.indisprimary AND a.attnum = ANY(i.indkey)
                        WHERE n.nspname = $1 AND c.relkind = 'r'
                        ORDER BY c.relname, a.attnum
                    """
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql, schema_name
                    )
                    row_count = len(rows)
                    return {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": "N/A - Model Extraction",
                        "Impacted Metrics": "None",
                        "Issue Priority": "Low",
                        "Recommendations/Fixes": rows,
                    }
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="extract_schema_query",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(f"db_{instance_number}_pg96_extract_schema_model")

            # --- Sub-tool: analyze_constraints_and_fks ---
            @mcp.tool(
                name=f"db_{instance_number}_pg96_analyze_constraints_and_fks",
                annotations=ToolAnnotations(
                    readOnlyHint=True, idempotentHint=False, openWorldHint=False
                ),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _analyze_constraints_and_fks(
                database_name: str,
                schema_name: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_analyze_constraints_and_fks",
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Scans relationships to find missing foreign keys and missing required constraints."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = """
                        SELECT
                            conname, contype,
                            conrelid::regclass AS table_name,
                            confrelid::regclass AS referenced_table,
                            CASE contype
                                WHEN 'p' THEN 'Primary Key'
                                WHEN 'f' THEN 'Foreign Key'
                                WHEN 'u' THEN 'Unique'
                                WHEN 'c' THEN 'Check'
                                WHEN 't' THEN 'Trigger'
                                ELSE 'Other'
                            END AS constraint_type
                        FROM pg_constraint c
                        JOIN pg_namespace n ON n.oid = c.connamespace
                        WHERE n.nspname = $1
                        ORDER BY contype, table_name
                    """
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql, schema_name
                    )
                    row_count = len(rows)

                    # Detect tables missing primary keys
                    tables_with_pk = {r.get("table_name") for r in rows if r.get("contype") == "p"}
                    sql_all_tables = """
                        SELECT relname AS table_name
                        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = $1 AND c.relkind = 'r'
                    """
                    all_tables = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql_all_tables, schema_name
                    )
                    missing_pk = [
                        t.get("table_name")
                        for t in all_tables
                        if t.get("table_name") not in tables_with_pk
                    ]

                    findings = {
                        "total_constraints": len(rows),
                        "by_type": {
                            t: len([r for r in rows if r.get("constraint_type") == t])
                            for t in set(r.get("constraint_type") for r in rows)
                        },
                        "tables_missing_primary_key": missing_pk,
                        "constraints": rows,
                    }
                    return {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": f"Scanned {len(all_tables)} tables, {len(rows)} constraints. {len(missing_pk)} tables missing primary keys.",
                        "Impacted Metrics": "Data Integrity, Index Performance",
                        "Issue Priority": "High" if missing_pk else "Low",
                        "Recommendations/Fixes": findings,
                    }
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="analyze_fks_query",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(f"db_{instance_number}_pg96_analyze_constraints_and_fks")

            # --- Sub-tool: analyze_normalization ---
            @mcp.tool(
                name=f"db_{instance_number}_pg96_analyze_normalization",
                annotations=ToolAnnotations(
                    readOnlyHint=True, idempotentHint=False, openWorldHint=False
                ),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _analyze_normalization(
                database_name: str,
                schema_name: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_analyze_normalization",
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Identifies column data type mismatches across tables and structural anomalies."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = """
                        SELECT
                            a1.attrelid::regclass AS table1,
                            a1.attname AS column1,
                            pg_catalog.format_type(a1.atttypid, a1.atttypmod) AS type1,
                            a2.attrelid::regclass AS table2,
                            a2.attname AS column2,
                            pg_catalog.format_type(a2.atttypid, a2.atttypmod) AS type2
                        FROM pg_attribute a1
                        JOIN pg_attribute a2
                            ON a1.attname = a2.attname
                            AND a1.attrelid != a2.attrelid
                            AND a1.atttypid != a2.atttypid
                            AND a1.attnum > 0 AND a2.attnum > 0
                            AND NOT a1.attisdropped AND NOT a2.attisdropped
                        JOIN pg_class c1 ON c1.oid = a1.attrelid AND c1.relkind = 'r'
                        JOIN pg_class c2 ON c2.oid = a2.attrelid AND c2.relkind = 'r'
                        JOIN pg_namespace n1 ON n1.oid = c1.relnamespace
                        JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                        WHERE n1.nspname = $1 AND n2.nspname = $1
                        ORDER BY a1.attname
                        LIMIT 50
                    """
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql, schema_name
                    )
                    row_count = len(rows)
                    return {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": f"{len(rows)} column type mismatches found across tables",
                        "Impacted Metrics": "Data Integrity, Join Performance",
                        "Issue Priority": "Medium" if len(rows) > 0 else "Low",
                        "Recommendations/Fixes": rows,
                    }
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="analyze_normalization_query",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(f"db_{instance_number}_pg96_analyze_normalization")

            # --- Sub-tool: analyze_index_statistics ---
            @mcp.tool(
                name=f"db_{instance_number}_pg96_analyze_index_statistics",
                annotations=ToolAnnotations(
                    readOnlyHint=True, idempotentHint=False, openWorldHint=False
                ),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _analyze_index_statistics(
                database_name: str,
                schema_name: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_analyze_index_statistics",
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Evaluates pg_stats to flag missing, stale, or severely outdated statistics."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = """
                        SELECT relname, n_live_tup, n_dead_tup,
                               last_analyze, last_autoanalyze,
                               last_vacuum, last_autovacuum
                        FROM pg_stat_user_tables
                        WHERE schemaname = $1
                        ORDER BY GREATEST(n_dead_tup, 0) DESC
                    """
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql, schema_name
                    )
                    row_count = len(rows)

                    stale_tables = []
                    for r in rows:
                        if r.get("last_analyze") is None and r.get("n_live_tup", 0) > 0:
                            stale_tables.append(
                                {
                                    "table": r.get("relname"),
                                    "live_tuples": r.get("n_live_tup"),
                                    "dead_tuples": r.get("n_dead_tup"),
                                    "recommendation": f"ANALYZE {r.get('relname')}; -- Never analyzed, {r.get('n_dead_tup', 0)} dead tuples",
                                }
                            )

                    return {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": f"Checked {len(rows)} tables for statistics staleness. {len(stale_tables)} tables need ANALYZE.",
                        "Impacted Metrics": "Query Plan Quality",
                        "Issue Priority": "High"
                        if len(stale_tables) > 5
                        else ("Medium" if stale_tables else "Low"),
                        "Recommendations/Fixes": stale_tables
                        if stale_tables
                        else "All tables have current statistics",
                    }
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="analyze_index_stats_query",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(f"db_{instance_number}_pg96_analyze_index_statistics")

            # --- Sub-tool: analyze_3nf_and_decomposition ---
            @mcp.tool(
                name=f"db_{instance_number}_pg96_analyze_3nf_and_decomposition",
                annotations=ToolAnnotations(
                    readOnlyHint=True, idempotentHint=False, openWorldHint=False
                ),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _analyze_3nf_and_decomposition(
                database_name: str,
                schema_name: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_analyze_3nf_and_decomposition",
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Analyzes data row repetition to detect M:N relationships requiring decomposition to 3NF."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = """
                        SELECT c.relname AS table_name,
                               t.seq_scan, t.idx_scan,
                               (t.seq_scan - COALESCE(t.idx_scan, 0)) AS scan_gap,
                               t.n_live_tup
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        LEFT JOIN pg_stat_user_tables t ON t.relid = c.oid
                        WHERE n.nspname = $1 AND c.relkind = 'r'
                          AND (t.seq_scan - COALESCE(t.idx_scan, 0)) > 500
                        ORDER BY scan_gap DESC
                        LIMIT 20
                    """
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(
                        _instance, database_name, sql, schema_name
                    )
                    row_count = len(rows)
                    fixes = []
                    for row in rows:
                        table = row.get("table_name")
                        seq = row.get("seq_scan") or 0
                        idx = row.get("idx_scan") or 0
                        fixes.append(
                            {
                                "table": table,
                                "seq_scan": seq,
                                "idx_scan": idx,
                                "anomaly_type": "Insertion/Deletion/Update anomaly risk"
                                if seq > idx * 20
                                else "Inefficient scanning pattern",
                                "recommendation": (
                                    f"Table '{table}' has {seq} seq scans vs {idx} index scans. "
                                    f"Consider reviewing for M:N relationship decomposition or missing indexes."
                                ),
                            }
                        )
                    return {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": f"Found {len(rows)} tables with inefficient scanning patterns suggesting normalization issues",
                        "Impacted Metrics": "Data Redundancy, Query Performance",
                        "Issue Priority": "High"
                        if len(fixes) > 5
                        else ("Medium" if fixes else "Low"),
                        "Recommendations/Fixes": fixes,
                    }
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="analyze_3nf_query",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(f"db_{instance_number}_pg96_analyze_3nf_and_decomposition")

        # -----------------------------------------------------------------------
        # Register db_{instance_number}_pg96_hypopg_create_virtual_indexes
        # -----------------------------------------------------------------------
        hypopg_create_tool_name = f"db_{instance_number}_pg96_hypopg_create_virtual_indexes"
        if is_tool_enabled(state.policy, instance_id, "hypopg_create_virtual_indexes"):

            @mcp.tool(
                name=hypopg_create_tool_name,
                annotations=ToolAnnotations(
                    readOnlyHint=False, idempotentHint=False, openWorldHint=False
                ),
                tags={"hypopg", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _hypopg_create_virtual_indexes(
                database_name: str,
                query_text: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = hypopg_create_tool_name,
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Parses a SELECT query and creates candidate virtual indexes via HypoPG.

                Extracts referenced tables/columns from the query, generates B-tree
                virtual index definitions, and creates them in the session using hypopg_create_index().

                Args:
                    database_name: Database to connect to.
                    query_text: The SELECT query to analyze for index candidates.
                """
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                query_text = validate_query_text(query_text)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    async with app_state.connection_manager.acquire(_instance) as conn:
                        query_analysis = await hypopg_tools.parse_tables_and_columns(
                            conn, query_text
                        )
                        virtual_indexes = await hypopg_tools.hypopg_create_virtual_indexes(
                            conn, query_analysis
                        )
                    row_count = len(virtual_indexes)
                    return {
                        "virtual_indexes_created": virtual_indexes,
                        "query_analysis": query_analysis,
                        "count": len(virtual_indexes),
                    }
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="hypopg_create",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(hypopg_create_tool_name)

        # -----------------------------------------------------------------------
        # Register db_{instance_number}_pg96_hypopg_explain_with_virtual
        # -----------------------------------------------------------------------
        hypopg_explain_tool_name = f"db_{instance_number}_pg96_hypopg_explain_with_virtual"
        if is_tool_enabled(state.policy, instance_id, "hypopg_explain_with_virtual"):

            @mcp.tool(
                name=hypopg_explain_tool_name,
                annotations=ToolAnnotations(
                    readOnlyHint=True, idempotentHint=False, openWorldHint=False
                ),
                tags={"hypopg", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _hypopg_explain_with_virtual(
                database_name: str,
                query_text: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = hypopg_explain_tool_name,
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Runs EXPLAIN (FORMAT JSON) for a query using the current session's virtual indexes.

                Args:
                    database_name: Database to connect to.
                    query_text: The SELECT query to explain.
                """
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                query_text = validate_query_text(query_text)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    async with app_state.connection_manager.acquire(_instance) as conn:
                        result = await hypopg_tools.hypopg_explain_with_virtual(conn, query_text)
                    row_count = 1
                    return result
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="hypopg_explain",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(hypopg_explain_tool_name)

        # -----------------------------------------------------------------------
        # Register db_{instance_number}_pg96_hypopg_find_optimal_indexes
        # -----------------------------------------------------------------------
        hypopg_optimal_tool_name = f"db_{instance_number}_pg96_hypopg_find_optimal_indexes"
        if is_tool_enabled(state.policy, instance_id, "hypopg_find_optimal_indexes"):

            @mcp.tool(
                name=hypopg_optimal_tool_name,
                annotations=ToolAnnotations(
                    readOnlyHint=False, idempotentHint=False, openWorldHint=False
                ),
                tags={"hypopg", "performance", f"instance-{instance_number}"},
                timeout=60.0,
            )
            async def _hypopg_find_optimal_indexes(
                database_name: str,
                query_text: str,
                max_combinations: int = 10,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = hypopg_optimal_tool_name,
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Finds the optimal HypoPG virtual index combination for a query.

                Captures baseline EXPLAIN cost, creates candidate virtual indexes,
                tests combinations (singletons, pairwise, triplets), ranks by cost,
                and returns the best recommendation.

                Args:
                    database_name: Database to connect to.
                    query_text: The SELECT query to optimize.
                    max_combinations: Maximum index combinations to test (default 10, minimum 5).
                """
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                query_text = validate_query_text(query_text)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(
                        actor=actor, tool=_tool, required_privilege="read", ctx=ctx
                    )
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    async with app_state.connection_manager.acquire(_instance) as conn:
                        result = await hypopg_tools.hypopg_find_optimal_indexes(
                            conn, query_text, max_combinations=max(max_combinations, 5)
                        )
                    row_count = len(result.get("ranked_plans", []))
                    return result
                except PermissionError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except RateLimitExceededError as exc:
                    decision, error_code = "deny", str(exc)
                    app_state.denied_requests += 1
                    raise
                except Exception as exc:
                    decision, error_code = f"TOOL_ERROR: {exc}"
                    app_state.denied_requests += 1
                    raise RuntimeError(error_code) from exc
                finally:
                    _log_audit_event(
                        request_id=request_id,
                        actor=actor,
                        tool=_tool,
                        instance=_instance,
                        sql="hypopg_optimal",
                        decision=decision,
                        latency_ms=int((time.time() - started) * 1000),
                        rows=row_count,
                        error_code=error_code,
                        auth_ctx=_auth_ctx,
                    )

            registered.append(hypopg_optimal_tool_name)

    return registered
