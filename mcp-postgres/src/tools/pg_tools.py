from __future__ import annotations

import time
import uuid
from typing import Any

from fastmcp import Context, FastMCP
from fastmcp.utilities.logging import get_logger
from mcp.types import ToolAnnotations

from src.middleware.rate_limiter import RateLimitExceededError
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

    return registered
