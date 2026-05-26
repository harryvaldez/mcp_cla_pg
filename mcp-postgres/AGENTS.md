# AGENTS

Guidance for AI coding agents working in this repository.

## Project Snapshot

- Python 3.11+ FastMCP 3 service for dual-instance EnterpriseDB Advanced Server 9.6.
- Strong read-only posture with controlled-write guardrails, rate limiting, and diagnostics.
- Runtime entry point: [src/server.py](src/server.py). Module-level `app = build_app()` for uvicorn.
- Tool naming: `db_{n}_pg96_{toolname}` — auto-mirrored across all enabled instances via closure binding in a registration loop.

## Fast Start

```powershell
pip install -e ".[dev]"
ruff check .
pytest -q
python -m src.server
```

## Architecture Boundaries

| Boundary | Files | Responsibility |
|---|---|---|
| Service/bootstrap | [src/server.py](src/server.py), [src/config_loader.py](src/config_loader.py) | AppState, FastMCP init, ASGI app, lifespan |
| EDBAS access/pooling | [src/db/](src/db) | asyncpg pools, DSN construction, SSL, query execution |
| Security/policy | [src/middleware/](src/middleware), [src/security/](src/security) | WriteGuard, RateLimiter, AuditLogger, SessionManager |
| Tool contracts | [src/tools/](src/tools) | Tool registration loop, closure binding, input validation |
| Diagnostics | [src/diagnostics/](src/diagnostics) | /health, /readiness, /metrics, /security custom routes |
| Config | [config/](config/) | YAML: instances, runtime-policy, rate-limit |
| Docs | [docs/](docs/) | Tool catalog, Docker runtime guide |

When adding features, keep changes inside the relevant boundary.

## Non-Negotiable Guardrails

- **Read-only defaults**: `write_mode_default: deny` in [config/runtime-policy.yaml](config/runtime-policy.yaml). All writes must be explicitly allowlisted.
- **Input validation**: Every SQL-facing parameter must go through [src/tools/input_validation.py](src/tools/input_validation.py). Never concatenate user input into SQL.
- **Never expose secrets**: No connection strings, passwords, or host details in logs, diagnostics, or error messages.
- **Deterministic error contracts**: `RATE_LIMIT_EXCEEDED`, `INVALID_INPUT: <reason>`, `PermissionError`.
- **Audit logging**: Every tool invocation produces a structured JSON event via `state.audit_logger.log_event()`.
- **Dual-instance symmetry**: Every tool added must auto-register for all enabled instances via the registration loop pattern. Never hardcode instance names in tool logic.

## Change Workflow

1. Read nearby tests first in [tests/](tests).
2. Implement minimal, focused changes.
3. Add/update tests for behavior changes.
4. Run `ruff check .` and `pytest -q`.
5. Update [docs/mcp-tool-catalog.md](docs/mcp-tool-catalog.md) if adding/modifying tools.

## Tool Authoring Pattern

Every tool follows this lifecycle. Copy this pattern when creating new tools in [src/tools/pg_tools.py](src/tools/pg_tools.py):

```python
# --- Inside register_pg_tools(), within the instance loop ---
@mcp.tool(
    name=f"db_{instance_number}_pg96_{toolname}",
    annotations=ToolAnnotations(readOnlyHint=True, ...),
    tags={"read-only", f"instance-{instance_number}"},
    timeout=10.0,
)
async def _tool_impl(
    actor: str = "system",
    ctx: Context | None = None,
    _tool: str = tool_name,          # bounded via closure default
    _instance: str = instance_id,    # bounded via closure default
    _instance_number: int = instance_number,
) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    started = time.time()
    decision, error_code, row_count = "allow", None, 0
    _auth_ctx = None
    try:
        actor, _auth_ctx = await _resolve_actor_and_authorize(
            actor=actor, tool=_tool, required_privilege="read", ctx=ctx,
        )
        state.session_manager.touch(actor, request_id)
        state.rate_limiter.allow(actor)
        state.write_guard.enforce(_tool, sql)  # raises PermissionError

        result = await state.connection_manager.fetch_single_row(
            _instance, database_name, sql
        )
        row_count = 1 if result else 0
        return dict(result)
    except PermissionError as exc:
        decision, error_code = "deny", str(exc)
        state.denied_requests += 1
        raise
    except RateLimitExceededError as exc:
        decision, error_code = "deny", str(exc)
        state.denied_requests += 1
        raise
    except Exception as exc:
        decision, error_code = f"TOOL_ERROR: {exc}"
        state.denied_requests += 1
        raise RuntimeError(error_code) from exc
    finally:
        _log_audit_event(
            request_id=request_id, actor=actor, tool=_tool, instance=_instance,
            sql=sql, decision=decision, latency_ms=int((time.time()-started)*1000),
            rows=row_count, error_code=error_code, auth_ctx=_auth_ctx,
        )
    registered.append(tool_name)
```

### Key imports for tools
```python
from fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from src.middleware.rate_limiter import RateLimitExceededError
```

### Closure binding for dual-instance
The `_tool`, `_instance`, and `_instance_number` parameters use default argument capture. Python closures over loop variables would otherwise share the last iteration's value. This pattern (also used in [mcp-sql-server](file:///c:/Users/HarryValdez/OneDrive/Documents/trae/mcp-sql-server/)) ensures each registered tool instance is bound to the correct instance at registration time.

## Middleware Quick Reference

| Class | Method | Raises | File |
|---|---|---|---|
| `WriteGuard` | `enforce(tool_name, sql_text)` | `PermissionError` | [src/middleware/write_guard.py](src/middleware/write_guard.py) |
| `RateLimiter` | `allow(actor_id) -> bool` | `RateLimitExceededError` | [src/middleware/rate_limiter.py](src/middleware/rate_limiter.py) |
| `AuditLogger` | `log_event(**kwargs)` | (never crashes) | [src/middleware/audit_logger.py](src/middleware/audit_logger.py) |
| `SessionManager` | `touch(actor_id, request_id)` | — | [src/security/session_manager.py](src/security/session_manager.py) |

## Connection Manager Quick Reference

| Method | Async | Returns | Use |
|---|---|---|---|
| `fetch_single_row(instance_id, db, sql)` | yes | `dict[str, Any]` or `{}` | Single-row queries |
| `execute_query(instance_id, db, sql, max_rows)` | yes | `list[dict]` | Multi-row (capped) |
| `acquire(instance_id)` | context mgr | `asyncpg.Connection` | Raw SQL |
| `list_enabled_instances()` | no | `list[str]` | Get instance IDs |
| `healthcheck_instance(instance_id)` | yes | `dict` | Per-instance health |

## Common Pitfalls

- **`list_enabled_instances()` is sync**, not async. Do not `await` it.
- **`fetch_single_row()` returns `{}` (empty dict)** when no rows found — not `None`.
- **All SQL must use parameterized queries** — never f-string user input into SQL. Input validation functions in [src/tools/input_validation.py](src/tools/input_validation.py) block `;` and `--`.
- **The `app` module-level variable** in [src/server.py](src/server.py) is created at import time — tests must patch before import or use `reload()`.
- **Custom routes are unauthenticated** by design — do not place sensitive data in `/health`, `/readiness`, `/metrics`, or `/security`.
- **Rate limiter has both per-actor and global buckets** — if global blocks, the actor token is refunded. Both must pass.

## FastMCP 3 Patterns

- `@mcp.tool(name=..., annotations=ToolAnnotations(readOnlyHint=True), timeout=10.0)` for tools.
- `@mcp.custom_route("/path", methods=["GET"])` for diagnostics. Uses `starlette.requests.Request` and `starlette.responses.JSONResponse`.
- `mcp.http_app(path="/mcp", stateless_http=True)` for ASGI app creation.
- Server `lifespan` (`@asynccontextmanager`) for pool initialization and graceful shutdown.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `FASTMCP_CONFIG_PATH` | `config/instances.yaml` | Instance connection config |
| `FASTMCP_POLICY_PATH` | `config/runtime-policy.yaml` | Write guard & tool flags |
| `FASTMCP_RATE_LIMIT_PATH` | `config/rate-limit.yaml` | Rate limits |
| `FASTMCP_AUDIT_PATH` | `/var/log/mcp/audit.log` | Audit log file |
| `FASTMCP_RATE_LIMIT_BACKEND` | `local` | `local` or `redis` |
| `FASTMCP_STATELESS_HTTP` | `true` | Stateless mode for scaling |
| `FASTMCP_MASK_ERROR_DETAILS` | `true` | Mask internal errors |
| `SECRET_PG_PRIMARY_USERNAME` | `edb_readonly_user` | Instance 1 credential |
| `SECRET_PG_SECONDARY_USERNAME` | `edb_readonly_user` | Instance 2 credential |

## Further Reading

- [Tool catalog](docs/mcp-tool-catalog.md) — canonical tool contracts
- [Docker runtime guide](docs/run-mcp-server-with-docker.md)
- [Implementation plan](plan/feature-postgres96-fastmcp-deployment-plan-1.md)
- [FastMCP 3 docs](https://gofastmcp.com/)
- [Security policy](SECURITY.md)
