"""EnterpriseDB Advanced Server 9.6 FastMCP 3 Server.

Dual-instance MCP server exposing database tools over HTTP.
Entry point: python -m src.server
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from fastmcp import FastMCP

from src.config_loader import AppConfig, load_config
from src.db.connection_manager import ConnectionManager
from src.diagnostics.routes import register_diagnostics_routes
from src.middleware.audit_logger import AuditLogger
from src.middleware.rate_limiter import RateLimiter, build_rate_limiter
from src.middleware.write_guard import WriteGuard
from src.models import RuntimePolicy
from src.security.session_manager import SessionManager
from src.tools.pg_tools import register_pg_tools


def secret_resolver(secret_ref: str) -> dict[str, str]:
    """Resolve database credentials from environment variables.

    Maps auth_secret_ref values like 'secret/pg/primary' to env vars:
      SECRET_PG_PRIMARY_USERNAME
      SECRET_PG_PRIMARY_PASSWORD
    """
    env_name = secret_ref.upper().replace("/", "_")
    username = os.getenv(f"{env_name}_USERNAME", "edb_readonly_user")
    password = os.getenv(f"{env_name}_PASSWORD", "change-me")
    return {"username": username, "password": password}


@dataclass
class AppState:
    """Runtime application state shared across tools, middleware, and diagnostics."""

    version: str
    config: AppConfig
    policy: RuntimePolicy
    auth: Any
    connection_manager: ConnectionManager
    write_guard: WriteGuard
    rate_limiter: RateLimiter
    audit_logger: AuditLogger
    session_manager: SessionManager
    registered_tools: list[str] = field(default_factory=list)
    denied_requests: int = 0
    last_secret_refresh_utc: str = ""
    mask_error_details: bool = True
    stateless_http: bool = True


def build_app() -> Any:
    """Build and return the FastMCP 3 ASGI application.

    Returns:
        ASGI app from mcp.http_app() with dual-instance tools, diagnostics,
        and server lifespan for pool lifecycle management.
    """
    config_path = os.getenv("FASTMCP_CONFIG_PATH", "config/instances.yaml")
    policy_path = os.getenv("FASTMCP_POLICY_PATH", "config/runtime-policy.yaml")
    rate_limit_path = os.getenv("FASTMCP_RATE_LIMIT_PATH", "config/rate-limit.yaml")
    audit_path = os.getenv("FASTMCP_AUDIT_PATH", "/var/log/mcp/audit.log")
    rate_limit_backend = os.getenv("FASTMCP_RATE_LIMIT_BACKEND", "local")
    redis_url = os.getenv("FASTMCP_REDIS_URL")
    redis_namespace = os.getenv("FASTMCP_REDIS_NAMESPACE", "mcp:ratelimit")
    mask_errors = os.getenv("FASTMCP_MASK_ERROR_DETAILS", "true").lower() == "true"
    stateless = os.getenv("FASTMCP_STATELESS_HTTP", "true").lower() == "true"

    cfg = load_config(config_path, policy_path, rate_limit_path)

    conn_mgr = ConnectionManager(cfg.instances, secret_resolver=secret_resolver)
    limiter = build_rate_limiter(
        backend=rate_limit_backend,
        actor_rpm=cfg.rate_limit.actor.requests_per_minute,
        actor_burst=cfg.rate_limit.actor.burst,
        global_rpm=cfg.rate_limit.global_.requests_per_minute,
        global_burst=cfg.rate_limit.global_.burst,
        redis_url=redis_url,
        redis_namespace=redis_namespace,
    )

    state = AppState(
        version="1.0.0",
        config=cfg,
        policy=cfg.policy,
        auth=cfg.auth,
        connection_manager=conn_mgr,
        write_guard=WriteGuard(cfg.policy),
        rate_limiter=limiter,
        audit_logger=AuditLogger(file_path=audit_path),
        session_manager=SessionManager(
            session_ttl_minutes=cfg.rate_limit.session.session_ttl_minutes,
            inactivity_timeout_minutes=cfg.rate_limit.session.inactivity_timeout_minutes,
            concurrent_sessions_limit=cfg.rate_limit.session.concurrent_sessions_limit,
        ),
        registered_tools=[],
        last_secret_refresh_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        mask_error_details=mask_errors,
        stateless_http=stateless,
    )

    # Define server lifespan for connection pool lifecycle
    @asynccontextmanager
    async def app_lifespan(server: FastMCP):
        """Initialize pools on startup, close on shutdown."""
        await state.connection_manager.initialize_pools()
        try:
            yield
        finally:
            await state.connection_manager.close_all_pools()

    # Initialize FastMCP 3 server with lifespan
    mcp = FastMCP(
        "pg96-edb-dual-instance",
        version="1.0.0",
        mask_error_details=mask_errors,
        lifespan=app_lifespan,
    )

    # Attach session-tracking middleware (auto-touches on every tool call)
    mcp.add_middleware(state.session_manager.as_middleware())

    # Register dual-instance tools
    registered_tools = register_pg_tools(mcp, state)
    state.registered_tools = registered_tools

    # Register diagnostics custom routes
    register_diagnostics_routes(mcp, state)

    # Build ASGI app — lifespan is managed by FastMCP
    app = mcp.http_app(path="/mcp", stateless_http=stateless)

    # Store state reference for debugging
    app.state.runtime = state
    return app


# Build the ASGI application instance at module level for uvicorn
app = build_app()

if __name__ == "__main__":
    host = os.getenv("FASTMCP_HOST", "0.0.0.0")
    port = int(os.getenv("FASTMCP_PORT", "8080"))
    log_level = os.getenv("FASTMCP_LOG_LEVEL", "info")

    import uvicorn

    uvicorn.run("src.server:app", host=host, port=port, log_level=log_level)
