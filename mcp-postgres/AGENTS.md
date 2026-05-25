# AGENTS

Guidance for AI coding agents working in this repository.

## Project Snapshot

- Python 3.11+ FastMCP 3 service for dual-instance EnterpriseDB Advanced Server 9.6.
- Strong read-only posture with controlled-write guardrails, rate limiting, and diagnostics.
- Runtime entry point: [src/server.py](src/server.py).
- Tool naming: `db_<instance_number>_pg96_<toolname>` — auto-mirrored across all enabled instances.

## Fast Start

1. Create/activate a virtual environment.
2. Install dependencies:
   - `pip install -e ".[dev]"`
3. Run checks before proposing changes:
   - `ruff check .`
   - `pytest -q`

## Architecture Boundaries

- Service/bootstrap: [src/server.py](src/server.py), [src/config_loader.py](src/config_loader.py)
- EDBAS access and pooling: [src/db/](src/db)
- Security and policy enforcement: [src/middleware/](src/middleware), [src/security/](src/security)
- Tool contracts and registration: [src/tools/](src/tools)
- Diagnostics endpoints and summaries: [src/diagnostics/](src/diagnostics)

When adding features, keep changes inside the relevant boundary and avoid cross-cutting edits unless required.

## Non-Negotiable Guardrails

- Preserve read-only defaults and write controls:
  - Policy: [config/runtime-policy.yaml](config/runtime-policy.yaml)
- Keep strict input validation for all tools and SQL-facing parameters.
- Never expose secrets or connection details in logs, diagnostics, or errors.
- Preserve deterministic error contracts (RATE_LIMIT_EXCEEDED, INVALID_INPUT, PermissionError).
- Do not weaken audit logging or rate limiting paths.
- Maintain dual-instance symmetry: every tool added must auto-register for all enabled instances.

## Change Workflow

1. Read nearby tests first in [tests/](tests).
2. Implement minimal, focused changes.
3. Add/update tests for behavior changes.
4. Run `ruff check .` and `pytest -q`.
5. Update docs if behavior/config changes.

## FastMCP 3 Patterns

- Use `@mcp.tool(name=..., annotations=ToolAnnotations(readOnlyHint=True), timeout=10.0)` for tools.
- Use `@mcp.custom_route("/path", methods=["GET"])` for diagnostics endpoints.
- Use `mcp.http_app(path="/mcp", stateless_http=True)` for ASGI app creation.
- Use server `lifespan` for pool initialization and shutdown.
