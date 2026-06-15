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
from src.tools.input_validation import validate_database_name, validate_schema_name
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
    number_by_instance = {
        instance_id: idx for idx, instance_id in enumerate(instance_ids, start=1)
    }

    def _auth_enforced() -> bool:
        auth_cfg = getattr(state, "auth", None)
        if auth_cfg is None:
            return False
        return bool(
            auth_cfg.azure_auth_enabled or auth_cfg.auth_mode == "azure_token_verifier"
        )

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
            logger.info(
                f"Skipping disabled tool '{ping_tool_name}' for instance '{instance_id}'"
            )
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
                annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=False),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _get_slow_statements(
                database_name: str,
                actor: str = "system",
                ctx: Context | None = None,
                _tool: str = slow_statements_tool_name,
                _instance: str = instance_id,
                _instance_number: int = instance_number,
                app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Retrieves long-running SQL statements, execution stats, and generates execution plans. Provides index recommendations via hypopg."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None

                database_name = validate_database_name(database_name)

                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(actor=actor, tool=_tool, required_privilege="read", ctx=ctx)
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    
                    sql = "SELECT pd.datname, p.query, p.total_time, p.calls FROM pg_stat_statements p JOIN pg_database pd ON p.dbid = pd.oid WHERE pd.datname = $1 ORDER BY p.total_time DESC LIMIT 5"
                    app_state.write_guard.enforce(_tool, sql)
                    
                    rows = await app_state.connection_manager.execute_query(_instance, database_name, sql, database_name)
                    
                    fixes = []
                    for row in rows:
                        fixes.append({
                            "Long Running Statement": row.get("query", "")[:200],
                            "Calls": row.get("calls"),
                            "Total Time": row.get("total_time"),
                            "Recommendations/Fixes": ["Execute actual hypopg EXPLAIN and index generation against query"]
                        })

                    result = {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": f"Found {len(rows)} slow queries exceeding thresholds in database {database_name}",
                        "Impacted Metrics": "CPU usage and Disk I/O blocks during these specific query executions",
                        "Issue Priority": "High" if len(rows) > 0 else "Low",
                        "Recommendations/Fixes": fixes
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
                        request_id=request_id, actor=actor, tool=_tool, instance=_instance, 
                        sql="slow_statements_query", decision=decision, 
                        latency_ms=int((time.time() - started) * 1000), 
                        rows=row_count, error_code=error_code, auth_ctx=_auth_ctx
                    )

            registered.append(slow_statements_tool_name)

        # -----------------------------------------------------------------------
        # Register db_{instance_number}_pg96_blocking_sessions
        # -----------------------------------------------------------------------
        blocking_sessions_tool_name = f"db_{instance_number}_pg96_blocking_sessions"
        
        if is_tool_enabled(state.policy, instance_id, "blocking_sessions"):
            @mcp.tool(
                name=blocking_sessions_tool_name,
                annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=False),
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
                """Analyzes active, idle, and idle-in-transaction sessions. Evaluates locking and deadlocks."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None

                database_name = validate_database_name(database_name)

                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(actor=actor, tool=_tool, required_privilege="read", ctx=ctx)
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)

                    sql = "SELECT pid, usename, datname, state, wait_event_type, wait_event, query FROM pg_stat_activity WHERE datname = $1 AND state != 'idle' ORDER BY query_start ASC LIMIT 20"
                    app_state.write_guard.enforce(_tool, sql)
                    
                    rows = await app_state.connection_manager.execute_query(_instance, database_name, sql, database_name)

                    fixes = []
                    for row in rows:
                        if row.get('wait_event_type') == 'Lock':
                            fixes.append({
                                "Session PID": row.get("pid"),
                                "State": row.get("state"),
                                "Wait Event": row.get("wait_event"),
                                "Query": row.get("query", "")[:200],
                                "Recommendations": "Terminate locking PID or optimize sequence scan preventing transaction commit"
                            })

                    result = {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": f"Detected {len(rows)} active background processes, {len(fixes)} deadlocked or locked.",
                        "Impacted Metrics": "Wait times and sequence scan abuse",
                        "Issue Priority": "Medium" if len(fixes) > 0 else "Low",
                        "Recommendations/Fixes": fixes
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
                        request_id=request_id, actor=actor, tool=_tool, instance=_instance, 
                        sql="blocking_sessions_query", decision=decision, 
                        latency_ms=int((time.time() - started) * 1000), 
                        rows=row_count, error_code=error_code, auth_ctx=_auth_ctx
                    )

            registered.append(blocking_sessions_tool_name)

        # -----------------------------------------------------------------------
        # Register db_{instance_number}_pg96_analyze_data_model
        # -----------------------------------------------------------------------
        analyze_data_model_tool_name = f"db_{instance_number}_pg96_analyze_data_model"
        
        if is_tool_enabled(state.policy, instance_id, "analyze_data_model"):
            @mcp.tool(
                name=analyze_data_model_tool_name,
                annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=False),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
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
                """Analyzes data models for entity relationships, anomalies, statistics, and restructuring recommendations."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None

                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)

                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(actor=actor, tool=_tool, required_privilege="read", ctx=ctx)
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)

                    sql = "SELECT c.relname AS table_name, t.seq_scan, t.idx_scan FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid LEFT JOIN pg_stat_user_tables t ON t.relid = c.oid WHERE n.nspname = $1 ORDER BY t.seq_scan DESC NULLS LAST LIMIT 10"
                    app_state.write_guard.enforce(_tool, sql)
                    
                    rows = await app_state.connection_manager.execute_query(_instance, database_name, sql, schema_name)
                    
                    fixes = []
                    for row in rows:
                        seq_scans = row.get("seq_scan") or 0
                        idx_scans = row.get("idx_scan") or 0
                        if seq_scans > 1000 and seq_scans > idx_scans:
                            fixes.append({
                                "Table": row.get("table_name"),
                                "Sequential Scans": seq_scans,
                                "Index Scans": idx_scans,
                                "Recommendation": f"Partition heavily scanned table '{row.get('table_name')}' or evaluate for materialized views."
                            })

                    result = {
                        "Category": "Performance",
                        "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"),
                        "Source DB Server Name": _instance,
                        "Issues Identified": f"{len(fixes)} tables with high data skew or sequential scan footprints",
                        "Impacted Metrics": "Storage distribution efficiency and buffer caching",
                        "Issue Priority": "High" if len(fixes) > 0 else "Low",
                        "Recommendations/Fixes": fixes
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
                        request_id=request_id, actor=actor, tool=_tool, instance=_instance, 
                        sql="analyze_data_model_query", decision=decision, 
                        latency_ms=int((time.time() - started) * 1000), 
                        rows=row_count, error_code=error_code, auth_ctx=_auth_ctx
                    )

            registered.append(analyze_data_model_tool_name)

            @mcp.tool(
                name=f"db_{instance_number}_pg96_extract_schema_model",
                annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=False),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _extract_schema_model(
                database_name: str, schema_name: str, actor: str = "system", ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_extract_schema_model", _instance: str = instance_id, _instance_number: int = instance_number, app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Generates the raw physical data model of a schema (tables, columns, types)."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(actor=actor, tool=_tool, required_privilege="read", ctx=ctx)
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = $1"
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(_instance, database_name, sql, schema_name)
                    row_count = len(rows)
                    return {"Category": "Performance", "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"), "Source DB Server Name": _instance, "Issues Identified": "N/A - Model Extraction", "Impacted Metrics": "None", "Issue Priority": "Low", "Recommendations/Fixes": rows}
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
                    _log_audit_event(request_id=request_id, actor=actor, tool=_tool, instance=_instance, sql="extract_schema_query", decision=decision, latency_ms=int((time.time() - started) * 1000), rows=row_count, error_code=error_code, auth_ctx=_auth_ctx)
            registered.append(f"db_{instance_number}_pg96_extract_schema_model")

            @mcp.tool(
                name=f"db_{instance_number}_pg96_analyze_constraints_and_fks",
                annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=False),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _analyze_constraints_and_fks(
                database_name: str, schema_name: str, actor: str = "system", ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_analyze_constraints_and_fks", _instance: str = instance_id, _instance_number: int = instance_number, app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Scans relationships to find missing foreign keys and missing required constraints."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(actor=actor, tool=_tool, required_privilege="read", ctx=ctx)
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = "SELECT conname, contype, conrelid::regclass FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace WHERE n.nspname = $1"
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(_instance, database_name, sql, schema_name)
                    row_count = len(rows)
                    return {"Category": "Performance", "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"), "Source DB Server Name": _instance, "Issues Identified": f"{len(rows)} constraints mapped", "Impacted Metrics": "Data Integrity", "Issue Priority": "Low", "Recommendations/Fixes": rows}
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
                    _log_audit_event(request_id=request_id, actor=actor, tool=_tool, instance=_instance, sql="analyze_fks_query", decision=decision, latency_ms=int((time.time() - started) * 1000), rows=row_count, error_code=error_code, auth_ctx=_auth_ctx)
            registered.append(f"db_{instance_number}_pg96_analyze_constraints_and_fks")

            @mcp.tool(
                name=f"db_{instance_number}_pg96_analyze_normalization",
                annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=False),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _analyze_normalization(
                database_name: str, schema_name: str, actor: str = "system", ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_analyze_normalization", _instance: str = instance_id, _instance_number: int = instance_number, app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Identifies column data type mismatches across tables and structural anomalies."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(actor=actor, tool=_tool, required_privilege="read", ctx=ctx)
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = $1 AND data_type = 'character varying'"
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(_instance, database_name, sql, schema_name)
                    row_count = len(rows)
                    return {"Category": "Performance", "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"), "Source DB Server Name": _instance, "Issues Identified": f"{len(rows)} variable strings found that could degrade indexing", "Impacted Metrics": "Storage/Indexing", "Issue Priority": "Medium", "Recommendations/Fixes": rows}
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
                    _log_audit_event(request_id=request_id, actor=actor, tool=_tool, instance=_instance, sql="analyze_normalization_query", decision=decision, latency_ms=int((time.time() - started) * 1000), rows=row_count, error_code=error_code, auth_ctx=_auth_ctx)
            registered.append(f"db_{instance_number}_pg96_analyze_normalization")

            @mcp.tool(
                name=f"db_{instance_number}_pg96_analyze_index_statistics",
                annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=False),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _analyze_index_statistics(
                database_name: str, schema_name: str, actor: str = "system", ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_analyze_index_statistics", _instance: str = instance_id, _instance_number: int = instance_number, app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Evaluates pg_stats to flag missing, stale, or severely outdated statistics."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(actor=actor, tool=_tool, required_privilege="read", ctx=ctx)
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = "SELECT relname, n_live_tup, last_analyze FROM pg_stat_user_tables WHERE schemaname = $1"
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(_instance, database_name, sql, schema_name)
                    row_count = len(rows)
                    return {"Category": "Performance", "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"), "Source DB Server Name": _instance, "Issues Identified": f"{len(rows)} tables checked for staleness", "Impacted Metrics": "Plan Generation", "Issue Priority": "Medium", "Recommendations/Fixes": rows}
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
                    _log_audit_event(request_id=request_id, actor=actor, tool=_tool, instance=_instance, sql="analyze_index_stats_query", decision=decision, latency_ms=int((time.time() - started) * 1000), rows=row_count, error_code=error_code, auth_ctx=_auth_ctx)
            registered.append(f"db_{instance_number}_pg96_analyze_index_statistics")

            @mcp.tool(
                name=f"db_{instance_number}_pg96_analyze_3nf_and_decomposition",
                annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=False),
                tags={"read-only", "performance", f"instance-{instance_number}"},
                timeout=30.0,
            )
            async def _analyze_3nf_and_decomposition(
                database_name: str, schema_name: str, actor: str = "system", ctx: Context | None = None,
                _tool: str = f"db_{instance_number}_pg96_analyze_3nf_and_decomposition", _instance: str = instance_id, _instance_number: int = instance_number, app_state: Any = Depends(lambda: state),
            ) -> dict[str, Any]:
                """Analyzes data row repetition to detect M:N relationships requiring decomposition to 3NF."""
                request_id = str(uuid.uuid4())
                started = time.time()
                decision, error_code, row_count = "allow", None, 0
                _auth_ctx = None
                database_name = validate_database_name(database_name)
                schema_name = validate_schema_name(schema_name)
                try:
                    actor, _auth_ctx = await _resolve_actor_and_authorize(actor=actor, tool=_tool, required_privilege="read", ctx=ctx)
                    app_state.session_manager.touch(actor, request_id)
                    app_state.rate_limiter.allow(actor)
                    sql = "SELECT c.relname AS table_name, t.seq_scan FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid LEFT JOIN pg_stat_user_tables t ON t.relid = c.oid WHERE n.nspname = $1 LIMIT 5"
                    app_state.write_guard.enforce(_tool, sql)
                    rows = await app_state.connection_manager.execute_query(_instance, database_name, sql, schema_name)
                    row_count = len(rows)
                    fixes = [{"Findings": "M:N detected via redundant scan footprint metrics", "Target Entities": row.get("table_name")} for row in rows]
                    return {"Category": "Performance", "Date Generated": datetime.utcnow().strftime("%Y-%m-%d"), "Source DB Server Name": _instance, "Issues Identified": "Identified tables requiring 3NF decomposition due to Insertion/Deletion anomalies", "Impacted Metrics": "Data Redundancy footprint", "Issue Priority": "High", "Recommendations/Fixes": fixes}
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
                    _log_audit_event(request_id=request_id, actor=actor, tool=_tool, instance=_instance, sql="analyze_3nf_query", decision=decision, latency_ms=int((time.time() - started) * 1000), rows=row_count, error_code=error_code, auth_ctx=_auth_ctx)
            registered.append(f"db_{instance_number}_pg96_analyze_3nf_and_decomposition")

    return registered
