---
goal: Remote Dual-Instance EnterpriseDB Advanced Server 9.6 MCP Server with FastMCP 3 Framework in Docker
version: 1.2
date_created: 2026-05-25
last_updated: 2026-05-25
owner: Cloud Solutions Architecture
status: Planned
tags: [feature, architecture, security, docker, enterprisedb, edbas, mcp, fastmcp3, multi-instance]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This implementation plan defines a deterministic, security-first deployment for a FastMCP 3-based MCP server that connects to two independently configured remote EnterpriseDB Advanced Server 9.6 (EDBAS 9.6) database instances. EDBAS 9.6 is an Oracle-compatible fork of PostgreSQL 9.6, providing Oracle PL/SQL compatibility, EDB-specific system functions, and enhanced security features on top of the PostgreSQL foundation. The design follows the proven dual-instance architecture of the sibling `mcp-sql-server` project while adapting for the PostgreSQL/EDBAS driver ecosystem (`asyncpg`), connection semantics, and catalog queries.

The server is containerized with Docker, enforces runtime safety controls, and uses the tool naming convention `db_<instance_number>_pg96_<toolname>` where `<instance_number>` is `1` or `2` corresponding to the instance index in `config/instances.yaml`. Every tool registered for instance 1 is automatically mirrored for instance 2 with its own independently configured connection pool, audit trail, and rate limiting scope. The first deliverable tools are `db_1_pg96_ping` and `db_2_pg96_ping`, each outputting instance-specific identity details including instance_name, database version string (EDBAS-specific), host/IP address, and current UTC time.

This plan leverages the latest FastMCP 3 framework features as documented at [gofastmcp.com](https://gofastmcp.com/getting-started/welcome), including `mcp.http_app()` for ASGI deployment, `@mcp.custom_route()` for diagnostics endpoints, `@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))` for MCP protocol annotations, `Context`-based logging and progress reporting, server-level `lifespan` for lifecycle management, and `mask_error_details` for production security hardening.

## 1. Requirements & Constraints

- **REQ-001**: Deploy one FastMCP 3 service as a Docker container connecting to two independently configured remote EnterpriseDB Advanced Server 9.6 (EDBAS 9.6) database instances (instance 1 and instance 2).
- **REQ-002**: Support independently configurable EDBAS endpoints per instance (host, port, database, credentials, SSL mode, timeout, pool settings) via YAML configuration. Each instance can be independently enabled/disabled.
- **REQ-003**: Enforce tool naming convention `db_<instance_number>_pg96_<toolname>` for all exposed MCP tools, where `<instance_number>` is `1` or `2`, auto-assigned from the instance's zero-based index in `config/instances.yaml` plus one.
- **REQ-004**: Every tool registered for instance 1 must be automatically available for instance 2 with identical functionality but independent connection routing. First tools `db_1_pg96_ping` and `db_2_pg96_ping` must output: `instance_name`, `database_version`, `edb_compat_mode`, `ip_address`, `current_utc_time` — each for its respective instance.
- **REQ-005**: Expose diagnostic endpoints for health, readiness, metrics, and security posture summary using FastMCP 3 `@mcp.custom_route()` decorator. Diagnostics must report per-instance connectivity state independently.
- **REQ-006**: Support connection pooling with configurable min/max pool sizes, acquire timeouts, and idle connection management via `asyncpg`.
- **REQ-007**: Include startup and deployment scripts for local development and Docker-based production rollout.
- **REQ-008**: Use FastMCP 3 `@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))` for all read-only tools to enable client-side optimization (skipped confirmation prompts in ChatGPT/Claude).
- **REQ-009**: Use FastMCP 3 `mcp.http_app(stateless_http=True)` for horizontally scalable stateless deployments.
- **REQ-010**: Use FastMCP 3 server-level `lifespan` for pool initialization and graceful shutdown.
- **SEC-001**: Enforce least privilege by using a dedicated EDBAS role with read-only or scoped access.
- **SEC-002**: Enforce runtime write restriction policy with default `deny` and explicit allowlist per tool.
- **SEC-003**: Enforce request rate limiting by caller identity and global quotas with burst control.
- **SEC-004**: Implement immutable audit logging for tool invocation, SQL text hash, instance target, actor identity, and decision outcome.
- **SEC-005**: Use SSL/TLS-encrypted EDBAS transport (`sslmode=require` or `sslmode=verify-full`) unless explicit exception is documented for trusted networks.
- **SEC-006**: Store secrets outside image layers using environment variables, Docker secrets, or external secret manager.
- **SEC-007**: Run container as non-root, with read-only filesystem, dropped Linux capabilities, and explicit writable volume allowlist.
- **SEC-008**: Enable FastMCP 3 `mask_error_details=True` in production to avoid leaking internal error details to clients.
- **OPS-001**: Integrate with existing DBA workflows through scriptable CLI tasks and scheduled report generation.
- **OPS-002**: Enable automated rotation of logs and auditable archival retention.
- **CON-001**: Do not embed production credentials in source code, Dockerfile, or committed configuration files.
- **CON-002**: Do not allow unrestricted ad-hoc DDL execution through MCP tools. Block EDBAS-specific DDL (Oracle-compatible `CREATE OR REPLACE PACKAGE`, `CREATE TYPE BODY`, etc.).
- **CON-003**: Plan must remain executable for Windows-hosted operations with Docker Desktop or Linux Docker host.
- **CON-004**: Target EDBAS 9.6 compatibility — use standard PostgreSQL 9.6-compatible catalog views and system functions; avoid EDBAS 10+ features. EDBAS 9.6 includes Oracle compatibility features (`edb_redwood_date`, `edb_redwood_strings`, `edb_redwood_raw`, SPL procedures, packages) that must be handled correctly.
- **CON-005**: Use `asyncpg` as the database driver — it is compatible with EDBAS 9.6 since EDBAS maintains wire-protocol compatibility with PostgreSQL. If compatibility issues arise, fall back to `psycopg2` with `asyncio.to_thread()`.
- **GUD-001**: Keep configuration declarative (YAML/ENV) and avoid hardcoded instance-specific logic.
- **GUD-002**: Prefer standardized observability formats (JSON logs, Prometheus metrics, UTC timestamps).
- **GUD-003**: Mirror the proven project structure from `mcp-sql-server` while adopting FastMCP 3 idiomatic patterns (`http_app()`, `custom_route()`, `lifespan`).
- **PAT-001**: Follow the `mcp-sql-server` project structure: `src/`, `config/`, `docker/`, `tests/`, `scripts/`, `policy/`, `docs/`, `plan/`.
- **PAT-002**: Use FastMCP 3 native patterns rather than legacy FastAPI mounting where possible: `mcp.http_app()` for ASGI, `@mcp.custom_route()` for diagnostics, server `lifespan` for lifecycle.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Establish secure project structure, dependency manifest with FastMCP 3, dual-instance naming conventions (`db_<n>_pg96_<toolname>`), and deterministic configuration model for two EDBAS 9.6 instances.
- EXIT-001: All required configuration files exist with schema-validated fields; project installs cleanly with `pip install -e .[dev]`; `generate_tool_specs(["primary", "secondary"])` emits `db_1_pg96_ping` and `db_2_pg96_ping`.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Create folder structure mirroring `mcp-sql-server`: `src/`, `src/db/`, `src/tools/`, `src/middleware/`, `src/security/`, `src/diagnostics/`, `config/`, `docker/`, `tests/`, `scripts/`, `policy/`, `docs/`, `plan/`. Include `__init__.py` files in all Python packages. |  |  |
| TASK-002 | Create `pyproject.toml` with project name `mcp-pg96-server`, Python `>=3.11`, dependencies: `fastmcp>=3.2.0` (latest FastMCP 3 framework), `pydantic>=2.8.0`, `PyYAML>=6.0.1`, `prometheus-client>=0.20.0`, `asyncpg>=0.29.0`, `starlette>=0.38.0` (for middleware/custom routes). Dev dependencies: `pytest>=8.2.0`, `ruff>=0.5.0`, `pytest-asyncio>=0.24.0`. Set `[tool.pytest.ini_options]` with `testpaths = ["tests"]` and `pythonpath = ["src"]`. Note: FastAPI and uvicorn are NOT required as direct dependencies — FastMCP 3's `mcp.http_app()` produces a standard ASGI app runnable with `uvicorn` (installed as a dev/ops dependency). |  |  |
| TASK-003 | Create `.env.example` with placeholders: `SECRET_PG_PRIMARY_USERNAME=edb_readonly_user`, `SECRET_PG_PRIMARY_PASSWORD=ChangeMe!`, `SECRET_PG_SECONDARY_USERNAME=edb_readonly_user`, `SECRET_PG_SECONDARY_PASSWORD=ChangeMeToo!`, `FASTMCP_RATE_LIMIT_BACKEND=local`, `FASTMCP_REDIS_URL=`, `FASTMCP_REDIS_NAMESPACE=mcp:ratelimit`, `FASTMCP_STATELESS_HTTP=true`, `FASTMCP_MASK_ERROR_DETAILS=true`, optional `FASTMCP_TOOL_ENABLE_FLAGS_JSON` and `FASTMCP_INSTANCE_TOOL_ENABLE_FLAGS_JSON`. |  |  |
| TASK-004 | Create `.gitignore` excluding `.env`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, `.venv/`, `*.egg-info/`, `dist/`, `build/`, `docker-compose.override.yml`. |  |  |
| TASK-005 | Define `src/models.py` with Pydantic models: `EdbInstanceConfig` (fields: `id` with pattern `^(primary|secondary)$`, `host`, `port=5444` — EDBAS default port, `database="edb"`, `auth_secret_ref`, `sslmode` with default `require` and pattern `^(disable|allow|prefer|require|verify-ca|verify-full)$`, `connect_timeout_sec=5`, `command_timeout_sec=30`, `pool_min=2`, `pool_max=10`, `pool_enabled=true`, `pool_idle_timeout_sec=300`, `pool_acquire_timeout_sec=5`, `enabled=true`, `edb_oracle_compat_mode=false`); `RuntimePolicy`; `AuthConfig`; `RateLimitConfig`; `RateLimitSection`; `SessionLimits`. |  |  |
| TASK-006 | Define `src/tools/tool_registry.py` with `ToolSpec` dataclass (fields: `instance`, `instance_number: int`, `toolname`) and `generate_tool_specs(enabled_instances: list[str])` that: (1) assigns instance numbers starting from 1 based on list index, (2) generates a `ToolSpec` for each combination of instance × toolname, (3) `full_name` property emits `db_{instance_number}_pg96_{toolname}` (e.g., `db_1_pg96_ping`, `db_2_pg96_ping`). Add `metadata` dict to `ToolSpec` with `annotations`, `tags`, and `timeout` fields. Initial tool list: `["ping"]`. |  |  |
| TASK-007 | Define `config/instances.yaml` with two entries: `id: primary` (host, port 5444, database edb, auth_secret_ref secret/pg/primary) and `id: secondary` (host, port 5444, database edb, auth_secret_ref secret/pg/secondary). Both with: `sslmode: require`, `connect_timeout_sec: 5`, `command_timeout_sec: 30`, `pool_min: 2`, `pool_max: 10`, `pool_enabled: true`, `pool_idle_timeout_sec: 300`, `pool_acquire_timeout_sec: 5`, `enabled: true`, `edb_oracle_compat_mode: false`. |  |  |
| TASK-008 | Define `config/runtime-policy.yaml` with `write_mode_default: deny`, `allowed_write_tools: []`, `blocked_sql_patterns` (same EDBAS DDL patterns), `max_result_rows: 5000`, `max_query_duration_ms: 15000`, `instance_enable_flags: {primary: true, secondary: true}`, `tool_enable_flags: {}`, `instance_tool_enable_flags: {}`, `allowed_tools: {}`. |  |  |
| TASK-009 | Define `config/rate-limit.yaml` with `global: {requests_per_minute: 1200, burst: 200}`, `actor: {requests_per_minute: 180, burst: 30}`, `session: {concurrent_sessions_limit: 10, session_ttl_minutes: 60, inactivity_timeout_minutes: 15}`. |  |  |

### Implementation Phase 2

- GOAL-002: Implement core server bootstrap using FastMCP 3 native patterns (`http_app()`, `lifespan`, `custom_route()`), configuration loading, and asyncpg connection pooling for EDBAS 9.6.
- EXIT-002: `python -m src.server` starts the service; `mcp.http_app()` produces valid ASGI app; connection pool initializes on lifespan startup; MCP tools are registered.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-010 | Implement `src/config_loader.py` with `AppConfig` Pydantic model (fields: `instances: list[EdbInstanceConfig]`, `policy: RuntimePolicy`, `rate_limit: RateLimitConfig`, `auth: AuthConfig`), `load_config()` function reading YAML from `FASTMCP_CONFIG_PATH`, `FASTMCP_POLICY_PATH`, `FASTMCP_RATE_LIMIT_PATH` env vars with defaults. Include `apply_policy_env_overrides()` for `FASTMCP_TOOL_ENABLE_FLAGS_JSON` and `FASTMCP_INSTANCE_TOOL_ENABLE_FLAGS_JSON` parsing (mirror `mcp-sql-server` pattern). |  |  |
| TASK-011 | Implement `src/db/__init__.py` (package init) and `src/db/connection_manager.py` with `ConnectionManager` class. Constructor accepts `list[EdbInstanceConfig]` and `secret_resolver` callable. Implement `_build_dsn()` constructing asyncpg DSN: `postgresql://{user}:{password}@{host}:{port}/{database}?sslmode={sslmode}`. Implement `_secret_resolver` adapter for env-var-based secrets (reads `SECRET_PG_PRIMARY_USERNAME`/`PASSWORD` and `SECRET_PG_SECONDARY_USERNAME`/`PASSWORD` based on `auth_secret_ref`). Implement `list_enabled_instances()` returning list of enabled instance IDs (e.g., `["primary", "secondary"]`). Implement `healthcheck_instance(instance_id)` executing `SELECT 1` on the target instance. Implement `get_pool_diagnostics()` returning per-instance pool stats keyed by instance_id. Implement `close_all_pools()` for graceful shutdown of all instance pools. |  |  |
| TASK-012 | Implement async connection pool management in `ConnectionManager`: `_pools` dict keyed by instance_id holding `asyncpg.Pool` objects. Implement async `initialize_pools()` called at startup that iterates over all enabled instances and creates an `asyncpg.create_pool()` per instance with `min_size=pool_min`, `max_size=pool_max`, `command_timeout=command_timeout_sec`, `ssl` context derived from `sslmode`. Implement async `acquire(instance_id)` context manager yielding a connection from the specified instance's pool. Implement `fetch_single_row(instance_id, database_name, sql)` and `execute_query(instance_id, database_name, sql)` async methods that acquire from the correct instance pool. Each instance maintains its own independent connection pool — they do not share connections. |  |  |
| TASK-013 | Implement `src/server.py` as the FastMCP 3 bootstrap entry point. Define `AppState` dataclass. Implement `secret_resolver()` reading both `SECRET_PG_PRIMARY_*` and `SECRET_PG_SECONDARY_*` from environment. Implement `build_app()` factory that: (1) loads config, (2) creates `ConnectionManager`, (3) builds rate limiter, (4) creates `AppState`, (5) initializes `FastMCP("pg96-edb-dual-instance", version="1.0.0", mask_error_details=...)`, (6) calls `register_pg_tools(mcp, state)` which iterates over all enabled instances and registers mirrored tools for each, (7) adds custom routes via `@mcp.custom_route()` for `/health`, `/readiness`, `/metrics`, `/security` diagnostics (health reports per-instance state), (8) returns `mcp.http_app(path="/mcp", stateless_http=True)`. Use server `lifespan` for pool initialization (both instance pools) and shutdown. |  |  |
| TASK-014 | Add `if __name__ == "__main__"` block to `src/server.py` using FastMCP 3's `mcp.run(transport="http", host=FASTMCP_HOST, port=FASTMCP_PORT, stateless_http=True)` for development. For production, document `uvicorn src.server:app --host 0.0.0.0 --port 8080 --workers 4` where `app` is the ASGI app from `build_app()`. Use env vars `FASTMCP_HOST=0.0.0.0`, `FASTMCP_PORT=8080`, `FASTMCP_LOG_LEVEL=INFO` with defaults. |  |  |

### Implementation Phase 3

- GOAL-003: Implement middleware stack: write guard, rate limiter, audit logger, and session manager — mirroring `mcp-sql-server` patterns adapted for EDBAS and FastMCP 3.
- EXIT-003: Every MCP tool invocation passes through write guard validation, rate limit check, and produces a structured audit log entry.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-015 | Implement `src/middleware/__init__.py` (package init) and `src/middleware/write_guard.py` with `WriteGuard` class. Constructor accepts `RuntimePolicy`. Implement `enforce(tool_name, sql_text)` method: normalize SQL text, extract leading verb, check against `blocked_sql_patterns`. **EDBAS-specific**: recognize Oracle-compatible statements (`EXEC`, `EXECUTE`, `CALL`, `MERGE`) as potentially write-capable; treat `CREATE OR REPLACE PACKAGE`, `CREATE TYPE BODY`, `CREATE SYNONYM`, `CREATE DIRECTORY` as DDL (blocked by default). PostgreSQL standard: recognize `COPY`, `EXPLAIN`, `SHOW`, `SET` as non-write statements. Raise `PermissionError` if write is not allowed. |  |  |
| TASK-016 | Implement `src/middleware/rate_limiter.py` with `RateLimiter` class and `build_rate_limiter()` factory. Support `local` backend using in-memory token bucket (thread-safe with `threading.RLock`). Support optional `redis` backend. Implement `allow(actor_id)` method: check per-actor RPM/burst, check global RPM/burst, return `True` if allowed, raise `RateLimitExceededError` with deterministic message `RATE_LIMIT_EXCEEDED` otherwise. Include `get_diagnostics()` for current bucket states. |  |  |
| TASK-017 | Implement `src/middleware/audit_logger.py` with `AuditLogger` class. Constructor accepts `file_path` (default `/var/log/mcp/audit.log`). Implement `log_event()` writing structured JSON lines with fields: `ts_utc` (ISO 8601), `request_id` (UUID), `actor`, `tool`, `instance`, `sql_hash` (SHA-256 truncated to 12 chars), `decision` (allow/deny), `latency_ms`, `rows`, `error_code`, `auth_mode`, `auth_subject`, `privilege_level`. Use append-only writes. Implement `rotate()` for log archival. |  |  |
| TASK-018 | Implement `src/security/__init__.py` (package init) and `src/security/session_manager.py` with `SessionManager` class. Constructor accepts `session_ttl_minutes`, `inactivity_timeout_minutes`, `concurrent_sessions_limit`. Implement `touch(actor_id, request_id)` updating last activity timestamp and enforcing concurrent session cap. Implement `expire_stale()` for periodic cleanup. Implement `get_active_count()` for diagnostics. Note: With `stateless_http=True` (FastMCP 3), sessions are transport-level only; this manager tracks actor-level session metadata for rate limiting and audit correlation. |  |  |

### Implementation Phase 4

- GOAL-004: Implement the dual-instance tool registration infrastructure that auto-mirrors every tool across both instances, starting with `db_1_pg96_ping` and `db_2_pg96_ping`.
- EXIT-004: Invoking `db_1_pg96_ping` returns instance 1 details; `db_2_pg96_ping` returns instance 2 details. Both tools share identical logic but route to independent connection pools.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-019 | Implement `src/tools/__init__.py` and `src/tools/pg_tools.py` with `register_pg_tools(mcp: FastMCP, state: Any) -> list[str]`. Follow the dual-instance pattern from `mcp-sql-server/src/tools/sql_tools.py`. Key architecture: (1) call `state.connection_manager.list_enabled_instances()` to get all enabled instance IDs, (2) build a `number_by_instance` dict mapping instance IDs to 1-based numbers (e.g., `{"primary": 1, "secondary": 2}`), (3) for each tool definition, iterate over all instance IDs and register a per-instance version using `@mcp.tool(name=f"db_{instance_number}_pg96_{toolname}", ...)`. Every tool is automatically mirrored — adding a tool definition adds it for all enabled instances. Include helper closures: `_auth_enforced()`, `_resolve_actor_and_authorize()`, `_log_audit_event()`. |  |  |
| TASK-020 | Inside `register_pg_tools()`, for each enabled `instance_id`, register ping tool with name `f"db_{instance_number}_pg96_ping"`. Each registration uses: `@mcp.tool(name=tool_name, annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False), tags={"read-only", "diagnostics", f"instance-{instance_number}"}, timeout=10.0)`. The tool function signature: `async def _ping(actor: str = "system", ctx: Context | None = None, _tool=tool_name, _instance=instance_id, _instance_number=instance_number) -> dict[str, str]`. Instance binding is captured via closure default arguments (same pattern as `mcp-sql-server`). |  |  |
| TASK-021 | Implement `_ping` body with dual-instance awareness: Generate `request_id = str(uuid.uuid4())`. Resolve actor/authorize via `_resolve_actor_and_authorize()`. Touch session. Check rate limit. Execute **EDBAS identity query** against the bound `_instance`: `SELECT current_setting('cluster_name') AS instance_name, version() AS database_version, CASE WHEN current_setting('edb_redwood_date') = 'on' THEN 'Oracle' ELSE 'PostgreSQL' END AS edb_compat_mode, host(inet_server_addr()) AS ip_address, now() AT TIME ZONE 'UTC' AS current_utc_time;`. Route through `state.connection_manager.fetch_single_row(_instance, "edb", sql)` — each instance hits its own pool. Return result dict. Audit log includes `instance=_instance` so logs are separable by instance. |  |  |
| TASK-022 | Implement fallback handling per instance: (a) `inet_server_addr()` NULL → use `host(inet_server_addr())` fallback, (b) `edb_redwood_date` GUC failure → default to "PostgreSQL (default)", (c) Log warning via `ctx.warning()` tagged with instance number. Fallbacks are instance-independent. |  |  |
| TASK-023 | After the per-instance loop, append each `tool_name` to `registered` list (e.g., `["db_1_pg96_ping", "db_2_pg96_ping"]`). Return `registered` from `register_pg_tools()`. The loop architecture ensures adding a new tool definition auto-registers it for all enabled instances — zero per-instance code duplication. |  |  |
| TASK-023 | Add `registered.append("db_pg96_ping")` at end of tool registration. Return `registered` list from `register_pg_tools()`. |  |  |
| TASK-024 | Implement `src/tools/input_validation.py` with EDBAS-specific validators: `validate_database_name()`, `validate_identifier()`, `validate_positive_int()`, `validate_schema_name()` (alphanumeric + underscore, no semicolons, no double-dash, reject EDBAS-specific `sys` schema prefix for direct access). Mirror `mcp-sql-server/src/tools/input_validation.py` pattern. |  |  |
| TASK-025 | Implement `src/tools/tool_flags.py` with `is_tool_enabled(policy, instance, toolname)` function — exact mirror of `mcp-sql-server/src/tools/tool_flags.py`. |  |  |

### Implementation Phase 5

- GOAL-005: Implement diagnostics endpoints using FastMCP 3 `@mcp.custom_route()` decorator: health, readiness, metrics (Prometheus), and security posture.
- EXIT-005: All diagnostics endpoints return deterministic JSON payloads accessible at `/health`, `/readiness`, `/metrics`, `/security`; Prometheus metrics scrape successfully.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-026 | Implement `src/diagnostics/__init__.py` (package init) and `src/diagnostics/routes.py` with a `register_diagnostics_routes(mcp, state)` function that registers custom routes using FastMCP 3 `@mcp.custom_route(path, methods=["GET"])`. This replaces the previous FastAPI `APIRouter` approach. Define Prometheus counters: `REQUEST_COUNT` (labels: tool, instance, decision), `REQUEST_LATENCY` (Histogram, labels: tool, instance), `DENIED_REQUESTS` (Counter). |  |  |
| TASK-027 | Implement `GET /health` via `@mcp.custom_route("/health", methods=["GET"])` returning `{"status": "healthy"|"degraded"|"unhealthy", "version": state.version, "uptime_seconds": <calculated>, "instances": {"primary": {"state": "connected"|"disconnected", "instance_number": 1, ...}, "secondary": {"state": "connected"|"disconnected", "instance_number": 2, ...}}}`. Aggregate status: "healthy" if all enabled instances connected; "degraded" if some down; "unhealthy" if all down. |  |  |
| TASK-028 | Implement `GET /readiness` via `@mcp.custom_route("/readiness", methods=["GET"])` returning `{"ready": true|false, "checks": {"config_loaded": true, "policy_active": true, "rate_limiter_active": true, "instance_pools_healthy": {"primary": true|false, "secondary": true|false}, "details": {...}}}`. Ready is true only when all enabled instance pools are healthy. |  |  |
| TASK-029 | Implement `GET /metrics` via `@mcp.custom_route("/metrics", methods=["GET"])` returning Prometheus text format via `generate_latest()` from `prometheus_client`. Include `REQUEST_COUNT`, `REQUEST_LATENCY`, `DENIED_REQUESTS`, pool diagnostics gauges. Set response `Content-Type` header to `CONTENT_TYPE_LATEST`. |  |  |
| TASK-030 | Implement `GET /security` via `@mcp.custom_route("/security", methods=["GET"])` returning `{"write_mode": "deny"|"allow", "allowed_write_tools": [...], "blocked_patterns_count": <n>, "policy_checksum": <sha256>, "last_secret_refresh_utc": <ISO 8601>, "ssl_enforced": true|false, "mask_error_details": true|false, "stateless_http": true|false, "enabled_instances": ["primary", "secondary"], "registered_tools": ["db_1_pg96_ping", "db_2_pg96_ping"]}`. |  |  |

### Implementation Phase 6

- GOAL-006: Containerize the MCP server with Docker multi-stage build, Docker Compose, hardening, and operational scripts for EDBAS 9.6 + FastMCP 3.
- EXIT-006: `docker compose up` starts the service; healthcheck hits `/health`; container runs as non-root with read-only filesystem.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-031 | Create `docker/Dockerfile` with multi-stage build. **Builder stage**: `FROM python:3.11-slim`, install build deps (`gcc`, `curl`), copy `pyproject.toml` and `src/`, `pip install --prefix=/install .`. **Runtime stage**: `FROM python:3.11-slim`, install runtime deps (`ca-certificates`, `curl`), create non-root user `mcpuser` (UID 10001, no shell), copy from builder `/install` to `/usr/local`, copy `config/`, `policy/`, `src/` to `/app`. Create `/var/log/mcp` with `mcpuser` ownership. Set `USER mcpuser`, `EXPOSE 8080`, `ENTRYPOINT ["uvicorn", "src.server:app", "--host", "0.0.0.0", "--port", "8080"]` — FastMCP 3's `http_app()` produces a standard ASGI app runnable with uvicorn directly. No ODBC drivers needed (asyncpg connects natively to EDBAS). |  |  |
| TASK-032 | Create `docker/docker-compose.yml` with service `fastmcp-edb96`. Image: `ghcr.io/company/fastmcp-edb96:1.0.0` (placeholder). Set `container_name: fastmcp-edb96`, `restart: unless-stopped`, `ports: ["8080:8080"]`. Harden: `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `tmpfs: [/tmp:size=64m]`. Mounts: `../config:/app/config:ro`, `../policy:/app/policy:ro`, `mcp-audit-log:/var/log/mcp`. Environment vars: `FASTMCP_CONFIG_PATH=/app/config/instances.yaml`, `FASTMCP_POLICY_PATH=/app/config/runtime-policy.yaml`, `FASTMCP_RATE_LIMIT_PATH=/app/config/rate-limit.yaml`, `FASTMCP_HOST=0.0.0.0`, `FASTMCP_PORT=8080`, `FASTMCP_LOG_LEVEL=INFO`, `FASTMCP_STATELESS_HTTP=true`, `FASTMCP_MASK_ERROR_DETAILS=true`, `FASTMCP_RATE_LIMIT_BACKEND`, plus secret refs from `.env`. Healthcheck: `curl -fsS http://localhost:8080/health` (FastMCP 3 custom route — no `/diagnostics` prefix needed). Interval: 30s, timeout: 5s, retries: 3, start period: 20s. |  |  |
| TASK-033 | Create `docker/docker-compose.runtime.yml` for production deployment with `env_file: ../.env`, image reference to registry, and optional Redis profile for distributed rate limiting. Mirror `mcp-sql-server/docker/docker-compose.runtime.yml`. |  |  |
| TASK-034 | Create `scripts/start-fastmcp.ps1` (Windows) and `scripts/start-fastmcp.sh` (Linux/macOS) that validate `.env` exists, validate YAML config syntax, then run `docker compose -f docker/docker-compose.yml up -d`. |  |  |
| TASK-035 | Create `scripts/deploy-prod.ps1` for production deployment: pull image digest, inject secrets from environment, run `docker compose -f docker/docker-compose.runtime.yml up -d`, run smoke test (`curl http://localhost:8080/health`), persist deployment evidence. |  |  |

### Implementation Phase 7

- GOAL-007: Implement testing: unit tests for models, connection manager, middleware, tools; integration tests for server startup and FastMCP 3 custom route endpoints.
- EXIT-007: `pytest -q` passes all tests; coverage exceeds 80% for core modules.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-036 | Create `tests/conftest.py` with `ROOT` path injection matching `mcp-sql-server/tests/conftest.py`. Add `pytest-asyncio` fixture for async test support. Add fixtures: `sample_dual_edb_config()` returning two EDBAS instance configs (primary at port 5444, secondary at port 5445); `mock_policy()` returning a `RuntimePolicy` with both instances enabled; `mock_connection_manager()` using `unittest.mock.AsyncMock` with `list_enabled_instances()` returning `["primary", "secondary"]`. |  |  |
| TASK-037 | Create `tests/test_models.py` validating `EdbInstanceConfig` Pydantic model: reject invalid `sslmode` values, accept valid config, default port 5444, default database "edb", `edb_oracle_compat_mode` boolean field. Test that `id` pattern accepts both `primary` and `secondary`. |  |  |
| TASK-038 | Create `tests/test_tool_naming.py` validating dual-instance tool name conventions: `ToolSpec(instance="primary", instance_number=1, toolname="ping").full_name` equals `"db_1_pg96_ping"`, and `ToolSpec(instance="secondary", instance_number=2, toolname="ping").full_name` equals `"db_2_pg96_ping"`. Test that names match expected regex `^db_[12]_pg96_[a-z_]+$`. Test that `generate_tool_specs(["primary", "secondary"])` produces 2 `ToolSpec` entries per tool (one per instance). |  |  |
| TASK-039 | Create `tests/test_connection_manager.py` with async tests: dual pool initialization with two instance configs, DSN construction with independent SSL parameters per instance, `fetch_single_row("primary", ...)` routes to primary pool, `fetch_single_row("secondary", ...)` routes to secondary pool, healthcheck per instance returns independent states, `list_enabled_instances()` returns `["primary", "secondary"]`. Use `pytest-asyncio` and mock `asyncpg`. |  |  |
| TASK-040 | Create `tests/test_write_guard.py` testing `WriteGuard.enforce()`: SELECT passes, INSERT with `write_mode_default=deny` raises `PermissionError`, blocked SQL pattern `DROP TABLE` raises `PermissionError`, EDBAS-specific `CREATE OR REPLACE PACKAGE` raises `PermissionError`, `CREATE TYPE BODY` raises `PermissionError`, allowlisted tool with write passes, `COPY` and `EXPLAIN` classified as non-write, `MERGE` classified as potentially write-capable. |  |  |
| TASK-041 | Create `tests/test_rate_limiter.py` testing: within-limit requests pass, exceeding per-actor RPM raises `RateLimitExceededError`, burst allows short spike, global limit enforced, diagnostics return bucket state. |  |  |
| TASK-042 | Create `tests/test_ping_tool.py` with async tests for dual-instance ping: `db_1_pg96_ping` returns dict with keys `instance_name`, `database_version`, `edb_compat_mode`, `ip_address`, `current_utc_time`; `db_2_pg96_ping` returns same structure but from secondary instance pool; `database_version` contains "EnterpriseDB" string for both instances; both tools have FastMCP 3 `readOnlyHint=True` annotations; audit log includes correct `instance` field per tool; rate limiter called for each; session touched for each. Test that `db_1_pg96_ping` and `db_2_pg96_ping` route to different connection pools. Test fallbacks independently per instance. |  |  |
| TASK-043 | Create `tests/test_server_startup.py` testing: FastMCP 3 `build_app()` returns ASGI app with both instances configured, `GET /health` returns dual-instance status with both `primary` and `secondary` entries, `GET /readiness` checks both pools, `GET /security` lists both enabled instances and tools `["db_1_pg96_ping", "db_2_pg96_ping"]`, verify `stateless_http` mode active, verify both `db_1_pg96_ping` and `db_2_pg96_ping` appear in registered tools list. |  |  |
| TASK-044 | Create `tests/test_input_validation.py` testing EDBAS validators: valid database names pass, SQL injection patterns in database names rejected, schema names with special characters rejected, `sys` schema prefix flagged. |  |  |

### Implementation Phase 8

- GOAL-008: Finalize documentation, operational runbooks, and project metadata for production readiness.
- EXIT-008: All documentation files populated; README provides clear quick-start for EDBAS 9.6 + FastMCP 3; AGENTS.md guides AI coding agents.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-045 | Create `README.md` with: project description (EDBAS 9.6 MCP server with FastMCP 3), repository structure overview, prerequisites (Python 3.11+, Docker, EDBAS 9.6 remote instance), quick start (clone, venv, `pip install -e .[dev]`, `cp .env.example .env`, configure `config/instances.yaml` with EDBAS host/port 5444, `python -m src.server`), Docker quick start (`docker compose up`), links to FastMCP 3 docs at gofastmcp.com. |  |  |
| TASK-046 | Create `AGENTS.md` with: project snapshot (FastMCP 3 + EDBAS 9.6), fast start commands, architecture boundaries (service/bootstrap, EDBAS access/pooling, security/policy, tool contracts, diagnostics via `custom_route`), non-negotiable guardrails (read-only defaults, input validation including EDBAS DDL patterns, never expose secrets, deterministic error contracts with `mask_error_details`, preserve audit logging), change workflow, high-value references including FastMCP 3 docs. |  |  |
| TASK-047 | Create `docs/mcp-tool-catalog.md` documenting `db_pg96_ping` contract: description, parameters (`actor: str = "system"`), FastMCP 3 annotations (`readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`), output schema (`instance_name: string`, `database_version: string` — EDBAS version string, `edb_compat_mode: string` — "Oracle" or "PostgreSQL (default)", `ip_address: string`, `current_utc_time: string (ISO 8601)`), example response, error codes, timeout (10s). Document that `edb_compat_mode` detects Oracle compatibility via `current_setting('edb_redwood_date')`. |  |  |
| TASK-048 | Create `docs/run-mcp-server-with-docker.md` with: prerequisites, building image, configuring `.env` and `config/instances.yaml` for EDBAS (port 5444, database "edb"), running with `docker compose`, verifying health at `/health` (FastMCP 3 custom route), stopping, troubleshooting common issues (SSL errors with EDBAS certs, connection refused on port 5444, pool exhaustion, Oracle compatibility mode detection failures). |  |  |
| TASK-049 | Create `SECURITY.md` with: supported versions, reporting vulnerabilities, security model (least privilege, read-only default with EDBAS-specific DDL blocking, SSL enforcement, audit logging, non-root container, read-only filesystem, FastMCP 3 `mask_error_details`), configuration guidance. |  |  |
| TASK-050 | Create `CONTRIBUTING.md` with: branch strategy, PR process, testing requirements (`pytest -q` must pass), linting requirements (`ruff check .` must pass), code style guidelines (use FastMCP 3 idiomatic patterns), commit message conventions. |  |  |

## 3. Alternatives

- **ALT-001**: Use `psycopg2` (sync) instead of `asyncpg` — Rejected because FastMCP 3 is built on asyncio; `asyncpg` provides native async support and better performance for connection pooling under concurrent load. `asyncpg` is compatible with EDBAS 9.6 since EDBAS maintains PostgreSQL wire-protocol compatibility. Fallback to `psycopg2` with `asyncio.to_thread()` if compatibility issues discovered.
- **ALT-002**: Use SQLAlchemy async with `asyncpg` driver — Rejected for initial implementation to keep dependencies minimal. The `ConnectionManager` abstraction using raw `asyncpg` is simpler, more transparent for DBA users, and matches the `pyodbc`-direct pattern in `mcp-sql-server`.
- **ALT-003**: Single-instance support only — Rejected in favor of dual-instance architecture matching `mcp-sql-server`. Each tool definition is automatically mirrored across all enabled instances via the registration loop pattern (TASK-019). Adding a second instance is purely a configuration change in `config/instances.yaml` — no code changes needed. Instances can be independently enabled/disabled via `enabled` flag and `instance_enable_flags`.
- **ALT-004**: Use FastAPI + `APIRouter` for diagnostics (like `mcp-sql-server`) — Replaced with FastMCP 3 `@mcp.custom_route()` which is the idiomatic FastMCP 3 approach. This eliminates the FastAPI dependency, simplifies the codebase, and provides built-in unauthenticated access for health checks. Custom routes are served alongside MCP endpoints on the same ASGI app.
- **ALT-005**: Use `mcp.run(transport="http")` for production — Rejected in favor of `mcp.http_app()` + uvicorn for production. `http_app()` produces a standard ASGI app enabling multi-worker deployment, middleware integration, and standard uvicorn/gunicorn tooling. `mcp.run()` is kept for development convenience only.
- **ALT-006**: Use `current_setting('server_version')` instead of `version()` — Rejected because `version()` in EDBAS returns the full EnterpriseDB-branded version string (e.g., "EnterpriseDB 9.6.24.10 on x86_64-pc-linux-gnu...") while `current_setting('server_version')` returns only the numeric version. The branded string is more informative for instance identification.

## 4. Dependencies

- **DEP-001**: Python 3.11+ (runtime requirement for FastMCP 3)
- **DEP-002**: FastMCP >= 3.2.0 (latest FastMCP 3 framework with `@mcp.tool()`, `Context`, `mcp.http_app()`, `@mcp.custom_route()`, `lifespan`, `mask_error_details`, `stateless_http`, `ToolAnnotations`, tool `timeout`, tag-based visibility)
- **DEP-003**: Starlette >= 0.38.0 (transitive via FastMCP 3; used directly for `TestClient` in tests and `Request`/`Response` types in custom routes)
- **DEP-004**: Uvicorn >= 0.30.0 (ASGI server for production; installed as dev/ops dependency, not a direct project dependency)
- **DEP-005**: asyncpg >= 0.29.0 (async PostgreSQL driver with connection pooling; compatible with EDBAS 9.6 via PostgreSQL wire protocol)
- **DEP-006**: Pydantic >= 2.8.0 (configuration validation models)
- **DEP-007**: PyYAML >= 6.0.1 (YAML configuration parsing)
- **DEP-008**: prometheus-client >= 0.20.0 (metrics exposition for `/metrics` custom route)
- **DEP-009**: Docker Engine 24+ (container runtime)
- **DEP-010**: Two independently accessible remote EDBAS 9.6 instances (primary and secondary), each reachable via TCP/IP with SSL support on their configured ports
- **DEP-011**: Redis >= 7 (optional, for distributed rate limiting; local in-memory backend works without it)
- **DEP-012**: `mcp` Python SDK (transitive via FastMCP 3; provides `ToolAnnotations`, `TextContent`, and MCP protocol types)

## 5. Files

- **FILE-001**: `pyproject.toml` — Project manifest with FastMCP 3 dependencies, build system, and pytest configuration
- **FILE-002**: `.env.example` — Environment variable template for EDBAS credentials and FastMCP 3 runtime settings
- **FILE-003**: `.gitignore` — Git ignore rules
- **FILE-004**: `src/__init__.py` — Package init with docstring
- **FILE-005**: `src/models.py` — Pydantic models: `EdbInstanceConfig` (with `edb_oracle_compat_mode` field), `RuntimePolicy`, `AuthConfig`, `RateLimitConfig`, `RateLimitSection`, `SessionLimits`
- **FILE-006**: `src/server.py` — FastMCP 3 bootstrap with `build_app()` returning `mcp.http_app()`, server `lifespan` for pool management, `@mcp.custom_route()` diagnostics, `mask_error_details` and `stateless_http` configuration
- **FILE-007**: `src/config_loader.py` — `AppConfig`, `load_config()`, `apply_policy_env_overrides()`
- **FILE-008**: `src/db/__init__.py` — DB package init
- **FILE-009**: `src/db/connection_manager.py` — `ConnectionManager` with asyncpg pool management, DSN construction (port 5444 default), EDBAS-compatible queries
- **FILE-010**: `src/tools/__init__.py` — Tools package init
- **FILE-011**: `src/tools/pg_tools.py` — `register_pg_tools()` with `db_pg96_ping` using FastMCP 3 `@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True), timeout=10.0)`
- **FILE-012**: `src/tools/tool_registry.py` — `ToolSpec` dataclass with FastMCP 3 metadata fields
- **FILE-013**: `src/tools/tool_flags.py` — `is_tool_enabled()` function
- **FILE-014**: `src/tools/input_validation.py` — EDBAS input validators (including `sys` schema detection)
- **FILE-015**: `src/middleware/__init__.py` — Middleware package init
- **FILE-016**: `src/middleware/write_guard.py` — `WriteGuard` with EDBAS-specific DDL pattern blocking (`CREATE OR REPLACE PACKAGE`, `CREATE TYPE BODY`, `CREATE SYNONYM`, `CREATE DIRECTORY`, `MERGE` detection)
- **FILE-017**: `src/middleware/rate_limiter.py` — `RateLimiter` with token bucket algorithm
- **FILE-018**: `src/middleware/audit_logger.py` — `AuditLogger` with structured JSON logging
- **FILE-019**: `src/security/__init__.py` — Security package init
- **FILE-020**: `src/security/session_manager.py` — `SessionManager` with stateless-http awareness
- **FILE-021**: `src/diagnostics/__init__.py` — Diagnostics package init
- **FILE-022**: `src/diagnostics/routes.py` — `register_diagnostics_routes()` using `@mcp.custom_route()` for `/health`, `/readiness`, `/metrics`, `/security`
- **FILE-023**: `config/instances.yaml` — EDBAS instance connection configuration (port 5444, database "edb")
- **FILE-024**: `config/runtime-policy.yaml` — Write mode, blocked patterns (including EDBAS DDL), tool flags
- **FILE-025**: `config/rate-limit.yaml` — Global and per-actor rate limits
- **FILE-026**: `docker/Dockerfile` — Multi-stage Docker build with uvicorn entrypoint
- **FILE-027**: `docker/docker-compose.yml` — Development Docker Compose (healthcheck at `/health`)
- **FILE-028**: `docker/docker-compose.runtime.yml` — Production Docker Compose
- **FILE-029**: `scripts/start-fastmcp.ps1` — Windows startup script
- **FILE-030**: `scripts/start-fastmcp.sh` — Linux/macOS startup script
- **FILE-031**: `scripts/deploy-prod.ps1` — Production deployment script
- **FILE-032**: `tests/conftest.py` — Pytest fixtures with EDBAS config defaults
- **FILE-033**: `tests/test_models.py` — `EdbInstanceConfig` model validation tests
- **FILE-034**: `tests/test_tool_naming.py` — Tool naming convention tests
- **FILE-035**: `tests/test_connection_manager.py` — Connection manager tests with EDBAS DSN
- **FILE-036**: `tests/test_write_guard.py` — Write guard tests including EDBAS-specific DDL
- **FILE-037**: `tests/test_rate_limiter.py` — Rate limiter tests
- **FILE-038**: `tests/test_ping_tool.py` — `db_pg96_ping` tests with EDBAS version string and `edb_compat_mode` assertions
- **FILE-039**: `tests/test_server_startup.py` — Server integration tests with FastMCP 3 custom routes
- **FILE-040**: `tests/test_input_validation.py` — Input validation tests with EDBAS-specific checks
- **FILE-041**: `README.md` — Project readme with EDBAS + FastMCP 3 quick start
- **FILE-042**: `AGENTS.md` — AI coding agent guidance for FastMCP 3 patterns
- **FILE-043**: `SECURITY.md` — Security policy
- **FILE-044**: `CONTRIBUTING.md` — Contribution guidelines
- **FILE-045**: `docs/mcp-tool-catalog.md` — Tool contract documentation with FastMCP 3 annotations and EDBAS output schema
- **FILE-046**: `docs/run-mcp-server-with-docker.md` — Docker runtime documentation

## 6. Testing

- **TEST-001**: `test_models.py::test_edb_instance_config_valid` — Valid `EdbInstanceConfig` passes for both `primary` and `secondary` IDs
- **TEST-002**: `test_models.py::test_edb_instance_config_invalid_sslmode` — Invalid `sslmode` raises `ValidationError`
- **TEST-003**: `test_models.py::test_edb_instance_config_defaults` — Default port 5444, default database "edb", default pool settings
- **TEST-004**: `test_tool_naming.py::test_ping_tool_name_instance_1` — `ToolSpec("primary", 1, "ping").full_name` equals `"db_1_pg96_ping"`
- **TEST-005**: `test_tool_naming.py::test_ping_tool_name_instance_2` — `ToolSpec("secondary", 2, "ping").full_name` equals `"db_2_pg96_ping"`
- **TEST-006**: `test_tool_naming.py::test_tool_name_regex` — Generated names match `^db_[12]_pg96_[a-z_]+$`
- **TEST-007**: `test_tool_naming.py::test_dual_tool_specs_generated` — `generate_tool_specs(["primary", "secondary"])` produces 2 entries per tool
- **TEST-008**: `test_connection_manager.py::test_dsn_construction` — DSN includes host, port 5444, database "edb", sslmode per instance
- **TEST-009**: `test_connection_manager.py::test_dual_pool_initialization` — Separate pools created for primary and secondary
- **TEST-010**: `test_connection_manager.py::test_fetch_single_row_routes_correctly` — `fetch_single_row("primary", ...)` uses primary pool; `fetch_single_row("secondary", ...)` uses secondary pool
- **TEST-011**: `test_connection_manager.py::test_healthcheck_per_instance` — Each instance returns independent health state
- **TEST-012**: `test_connection_manager.py::test_list_enabled_instances` — Returns `["primary", "secondary"]` when both enabled
- **TEST-013**: `test_write_guard.py::test_select_passes` — SELECT passes write guard
- **TEST-014**: `test_write_guard.py::test_insert_denied` — INSERT raises `PermissionError` with `write_mode_default=deny`
- **TEST-015**: `test_write_guard.py::test_drop_table_blocked` — `DROP TABLE` matched and blocked
- **TEST-016**: `test_write_guard.py::test_edb_create_package_blocked` — `CREATE OR REPLACE PACKAGE` blocked (EDBAS-specific)
- **TEST-017**: `test_write_guard.py::test_edb_create_type_body_blocked` — `CREATE TYPE BODY` blocked (EDBAS-specific)
- **TEST-018**: `test_write_guard.py::test_merge_detected` — `MERGE` classified as write-capable
- **TEST-019**: `test_rate_limiter.py::test_within_limit` — Within RPM/burst passes
- **TEST-020**: `test_rate_limiter.py::test_exceeds_actor_rpm` — Exceeding per-actor RPM raises `RateLimitExceededError`
- **TEST-021**: `test_rate_limiter.py::test_burst_allows_spike` — Burst allows temporary spike
- **TEST-022**: `test_rate_limiter.py::test_global_limit` — Global limit enforced
- **TEST-023**: `test_ping_tool.py::test_ping_instance_1_keys` — `db_1_pg96_ping` returns `instance_name`, `database_version`, `edb_compat_mode`, `ip_address`, `current_utc_time`
- **TEST-024**: `test_ping_tool.py::test_ping_instance_2_keys` — `db_2_pg96_ping` returns same structure from secondary
- **TEST-025**: `test_ping_tool.py::test_ping_edb_version_string` — `database_version` contains "EnterpriseDB" for both instances
- **TEST-026**: `test_ping_tool.py::test_ping_oracle_compat` — `edb_compat_mode` is "Oracle" or "PostgreSQL (default)"
- **TEST-027**: `test_ping_tool.py::test_ping_different_pools` — `db_1_pg96_ping` and `db_2_pg96_ping` use different connection pools
- **TEST-028**: `test_ping_tool.py::test_ping_audit_logged` — Audit event includes correct `instance` field per tool
- **TEST-029**: `test_ping_tool.py::test_ping_fallback_per_instance` — Fallback triggered independently per instance
- **TEST-030**: `test_ping_tool.py::test_ping_annotations` — FastMCP 3 `readOnlyHint=True` set on both tools
- **TEST-031**: `test_server_startup.py::test_app_builds` — `build_app()` returns ASGI app
- **TEST-032**: `test_server_startup.py::test_health_dual_instance` — `GET /health` returns both primary and secondary with instance_numbers
- **TEST-033**: `test_server_startup.py::test_readiness_dual_pools` — `GET /readiness` checks both pools
- **TEST-034**: `test_server_startup.py::test_security_lists_both_instances` — `GET /security` lists both instances and tools
- **TEST-035**: `test_server_startup.py::test_registered_tools_dual` — Both `db_1_pg96_ping` and `db_2_pg96_ping` registered
- **TEST-036**: `test_server_startup.py::test_stateless_http` — Repeated requests use separate transport contexts
- **TEST-037**: `test_input_validation.py::test_valid_database_name` — Valid names pass
- **TEST-038**: `test_input_validation.py::test_sql_injection_rejected` — `;` and `--` rejected
- **TEST-039**: `test_input_validation.py::test_sys_schema_flagged` — `sys` schema detected

## 7. Risks & Assumptions

- **RISK-001**: EDBAS 9.6 End-of-Life — EDBAS 9.6 is based on PostgreSQL 9.6 which reached community EOL in November 2021. EnterpriseDB may provide extended support depending on the customer agreement. Mitigation: Document this risk; the server design is version-agnostic and can be pointed at newer EDBAS versions; isolate the EDBAS 9.6 instance on a secured network segment.
- **RISK-002**: `asyncpg` compatibility with EDBAS 9.6 — `asyncpg` supports standard PostgreSQL wire protocol; EDBAS maintains wire compatibility but Oracle compatibility features may introduce edge cases. Mitigation: Pin `asyncpg>=0.29.0,<0.30.0`; test against actual EDBAS 9.6 instance; verify `current_setting('edb_redwood_date')` and `version()` work correctly via asyncpg; fall back to `psycopg2` with `asyncio.to_thread()` if needed.
- **RISK-003**: SSL certificate validation with EDBAS — EDBAS 9.6 SSL setup may use different certificate paths or self-signed certificates. Mitigation: Support configurable `sslmode`; document `require` vs `verify-full` tradeoffs; EDBAS typically uses the same `ssl_cert_file`, `ssl_key_file`, `ssl_ca_file` settings as PostgreSQL.
- **RISK-004**: `inet_server_addr()` NULL with EDBAS — EDBAS inherits PostgreSQL networking behavior; `inet_server_addr()` returns NULL for Unix socket connections. Mitigation: Implemented fallback query in TASK-022; log warning when fallback is triggered.
- **RISK-005**: `edb_redwood_date` GUC detection failure — If Oracle compatibility mode is not enabled or the GUC is not accessible to the connecting role, `current_setting('edb_redwood_date')` will raise an exception. Mitigation: Catch exception and default to "PostgreSQL (default)" in TASK-022.
- **RISK-006**: FastMCP 3 API stability — FastMCP 3.x follows semantic versioning with adapted practices; breaking changes may occur in minor versions. Mitigation: Pin `fastmcp==3.2.x` in production; test upgrades in staging first; monitor [FastMCP release notes](https://gofastmcp.com/development/releases).
- **RISK-007**: `stateless_http=True` disables session-dependent features — Features like elicitation, sampling, and progress reporting across requests won't work in stateless mode. Mitigation: The initial `db_pg96_ping` tool does not require these features; document this limitation for future tool developers.
- **ASSUMPTION-001**: Two remote EDBAS 9.6 instances are already provisioned, each independently accessible via TCP/IP on their configured host:port, with SSL enabled.
- **ASSUMPTION-002**: Dedicated EDBAS roles with read-only or scoped access exist for each instance independently (e.g., `edb_readonly_user_1`, `edb_readonly_user_2`) and credentials are available via separate environment variables.
- **ASSUMPTION-006**: Both EDBAS instances may have different configurations (different hosts, ports, SSL certificates, Oracle compatibility modes) — the dual-instance architecture handles these independently.
- **ASSUMPTION-003**: Docker Engine 24+ is available on the deployment host with Docker Compose plugin.
- **ASSUMPTION-004**: The deployment host has network access to the remote EDBAS 9.6 instance on the configured port (default 5444).
- **ASSUMPTION-005**: FastMCP 3.2+ provides the API surface documented at gofastmcp.com: `@mcp.tool()`, `Context`, `mcp.http_app()`, `@mcp.custom_route()`, `lifespan`, `mask_error_details`, `stateless_http`, `ToolAnnotations`, tool `timeout`.

## 8. Related Specifications / Further Reading

- [FastMCP 3 Welcome & Getting Started](https://gofastmcp.com/getting-started/welcome) — Official FastMCP 3 documentation entry point
- [FastMCP 3 Server Documentation](https://gofastmcp.com/servers/server) — `FastMCP` class reference, `http_app()`, `custom_route()`, `lifespan`, configuration
- [FastMCP 3 Tools Documentation](https://gofastmcp.com/servers/tools) — `@mcp.tool()` decorator, `ToolAnnotations`, `Context`, timeouts, return values
- [FastMCP 3 HTTP Deployment](https://gofastmcp.com/deployment/http) — `http_app()`, `stateless_http`, FastAPI integration, production deployment
- [FastMCP 3 Installation](https://gofastmcp.com/getting-started/installation) — Package installation, optional dependencies, versioning policy
- [mcp-sql-server Reference Project](file:///c:/Users/HarryValdez/OneDrive/Documents/trae/mcp-sql-server/) — Sibling MCP server project that serves as the architectural template
- [mcp-sql-server Deployment Plan](file:///c:/Users/HarryValdez/OneDrive/Documents/trae/mcp-sql-server/plan/remote-sql2019-fastmcp3-deployment-plan.md) — Reference deployment plan
- [EnterpriseDB Advanced Server Documentation](https://www.enterprisedb.com/docs/) — Official EDBAS documentation
- [EDBAS 9.6 Oracle Compatibility Guide](https://www.enterprisedb.com/edb-docs/d/edb-postgres-advanced-server/user-guides/database-compatibility-for-oracle-developers-guide/9.6/) — EDBAS Oracle compatibility features reference
- [asyncpg Documentation](https://magicstack.github.io/asyncpg/current/) — asyncpg driver documentation and version compatibility
- [PostgreSQL 9.6 Documentation](https://www.postgresql.org/docs/9.6/) — PostgreSQL 9.6 base documentation (EDBAS 9.6 foundation)
- [PostgreSQL SSL Configuration](https://www.postgresql.org/docs/9.6/ssl-tcp.html) — SSL/TLS setup (applicable to EDBAS)
