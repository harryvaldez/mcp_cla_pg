from __future__ import annotations

import hashlib
import time
from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Prometheus metrics
REQUEST_COUNT = Counter(
    "mcp_pg96_requests_total",
    "Total MCP tool requests",
    ["tool", "instance", "decision"],
)
REQUEST_LATENCY = Histogram(
    "mcp_pg96_request_latency_seconds",
    "MCP tool request latency",
    ["tool", "instance"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)
DENIED_REQUESTS = Counter(
    "mcp_pg96_denied_requests_total",
    "Total denied requests",
)

# Uptime reference
_START_TIME = time.time()


def register_diagnostics_routes(mcp: Any, state: Any) -> None:
    """Register health, readiness, metrics, and security routes on the FastMCP server."""

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        """Aggregate health across all enabled instances."""
        import asyncio

        uptime = int(time.time() - _START_TIME)
        instances = state.connection_manager.list_enabled_instances()

        async def _check(instance_id: str) -> dict[str, Any]:
            result = await state.connection_manager.healthcheck_instance(instance_id)
            instance_number = None
            for idx, iid in enumerate(instances, start=1):
                if iid == instance_id:
                    instance_number = idx
                    break
            return {
                "state": result.get("state", "unknown"),
                "instance_number": instance_number,
                "checked_at": result.get("checked_at"),
                "error": result.get("error"),
            }

        tasks = {iid: _check(iid) for iid in instances}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        instance_states = {}
        for iid, result in zip(tasks.keys(), results):
            if isinstance(result, BaseException):
                instance_states[iid] = {
                    "state": "error",
                    "instance_number": None,
                    "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "error": str(result),
                }
            else:
                instance_states[iid] = result

        # Aggregate status
        connected = sum(1 for s in instance_states.values() if s["state"] == "connected")
        total = len(instance_states)
        if total == 0:
            status = "unhealthy"
        elif connected == total:
            status = "healthy"
        elif connected > 0:
            status = "degraded"
        else:
            status = "unhealthy"

        return JSONResponse(
            {
                "status": status,
                "version": getattr(state, "version", "unknown"),
                "uptime_seconds": uptime,
                "instances": instance_states,
            }
        )

    @mcp.custom_route("/readiness", methods=["GET"])
    async def readiness(request: Request) -> JSONResponse:
        """Check if all enabled instance pools are healthy."""
        instances = state.connection_manager.list_enabled_instances()
        pool_healthy: dict[str, bool] = {}
        for iid in instances:
            h = await state.connection_manager.healthcheck_instance(iid)
            pool_healthy[iid] = h.get("state") == "connected"

        all_healthy = all(pool_healthy.values()) if pool_healthy else False

        return JSONResponse(
            {
                "ready": all_healthy,
                "checks": {
                    "config_loaded": state.config is not None,
                    "policy_active": state.policy is not None,
                    "rate_limiter_active": state.rate_limiter is not None,
                    "instance_pools_healthy": pool_healthy,
                },
            }
        )

    @mcp.custom_route("/metrics", methods=["GET"])
    async def metrics(request: Request) -> Response:
        """Expose Prometheus metrics."""
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    @mcp.custom_route("/security", methods=["GET"])
    async def security(request: Request) -> Response:
        """Return security posture summary."""
        policy_raw = state.policy.model_dump_json()
        policy_checksum = hashlib.sha256(policy_raw.encode()).hexdigest()[:16]
        return JSONResponse(
            {
                "write_mode": state.policy.write_mode_default,
                "allowed_write_tools": state.policy.allowed_write_tools,
                "blocked_patterns_count": len(state.policy.blocked_sql_patterns),
                "policy_checksum": policy_checksum,
                "last_secret_refresh_utc": getattr(state, "last_secret_refresh_utc", ""),
                "ssl_enforced": True,
                "mask_error_details": getattr(state, "mask_error_details", True),
                "stateless_http": getattr(state, "stateless_http", True),
                "enabled_instances": state.connection_manager.list_enabled_instances(),
                "registered_tools": getattr(state, "registered_tools", []),
            }
        )
