# PostgreSQL MCP Server (Python + Docker)

Remote MCP server that exposes PostgreSQL DBA-oriented tools over Streamable HTTP, designed to be consumed by MCP-capable clients (including Codex – OpenAI’s coding agent in VS Code).

## Overview

This server runs as an HTTP service and provides:

- Read-only safe database inspection by default (writes disabled unless explicitly enabled)
- Common DBA discovery and monitoring tools (schemas, tables, sizes, sessions, query stats)
- Ad-hoc SQL execution with a configurable row limit
- EXPLAIN plan generation for query performance analysis

The MCP endpoint is served at:

- `http://<host>:<port>/mcp`

Health endpoint:

- `http://<host>:<port>/health`

## Tools Exposed

The MCP server exposes these tools:

- `ping`
- `server_info`
- `list_databases`
- `list_schemas`
- `list_tables`
- `describe_table`
- `run_query`
- `explain_query`
- `active_sessions`
- `db_locks`
- `table_sizes`
- `index_usage`
- `top_queries`

## How to Use

### Typical flow

1. Start the container (read-only recommended).
2. Add the MCP server URL to your VS Code MCP client.
3. In chat, verify connectivity with `ping` and `server_info`.
4. Explore schema with `list_schemas` → `list_tables` → `describe_table`.
5. Use `run_query` for ad-hoc SELECTs (row-limited).
6. Use `explain_query` to inspect query plans before changing indexes/SQL.

### Example prompts (VS Code / Codex)

Basic connectivity:

- “Using `postgres_readonly`, call `ping` and show the result.”
- “Using `postgres_readonly`, call `server_info` and summarize database/user/version.”

Schema discovery:

- “Using `postgres_readonly`, call `list_schemas` (include_system=false).”
- “Using `postgres_readonly`, call `list_tables` for schema `public`.”
- “Using `postgres_readonly`, call `describe_table` for `public.orders` and summarize indexes and size.”

Ad-hoc query (read-only):

- “Using `postgres_readonly`, run this query with `run_query` and return the first 50 rows:
  `select * from public.orders order by created_at desc`”

Parameterized query (with `params_json`):

- “Using `postgres_readonly`, call `run_query` with:
  - sql: `select * from public.orders where id = %(id)s`
  - params_json: `{ \"id\": 123 }`”

Explain plan:

- “Using `postgres_readonly`, call `explain_query` (format=json, analyze=false) for:
  `select * from public.orders where customer_id = 42 order by created_at desc limit 50`
  Then interpret the plan and suggest indexes.”

Active session triage:

- “Using `postgres_readonly`, call `active_sessions(min_duration_seconds=300)` and summarize what looks stuck.”

Lock triage:

- “Using `postgres_readonly`, call `db_locks(min_wait_seconds=30, limit=50)` and summarize blockers vs blocked.”

Capacity review:

- “Using `postgres_readonly`, call `table_sizes(limit=20)` and `index_usage(limit=20)`, then highlight the biggest objects.”

## Requirements

### Runtime (recommended)

- Docker
- Network access from the container to PostgreSQL

### Development (optional)

- Python 3.12+

Note: local `pip install` can fail on some Windows setups due to a broken TLS CA bundle path. Docker builds are not affected.

## Configuration

### Database Connection

Provide one of the following:

- `DATABASE_URL` (recommended)
- or: `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`

Example:

- `DATABASE_URL=postgresql://mcp_readonly:password@db-host:5432/app_db`

### Safety / Limits

- `MCP_ALLOW_WRITE` (default: `false`)
  - `false`: only read-only queries are allowed (SELECT/WITH/SHOW/EXPLAIN)
  - `true`: write and DDL statements are allowed
- `MCP_MAX_ROWS` (default: `500`): default max rows returned by `run_query`

### Connection Pool

- `MCP_POOL_MIN_SIZE` (default: `1`)
- `MCP_POOL_MAX_SIZE` (default: `5`)

### Server Transport

- `MCP_TRANSPORT` (default: `http`): `http`, `sse`, or `stdio`
- `MCP_HOST` (default: `0.0.0.0`)
- `MCP_PORT` (default: `8000`)
- `MCP_SERVER_NAME` (default: `PostgreSQL MCP Server`)

### Auth0 Authentication

To secure the remote endpoint with Auth0 JWT validation, set the following environment variables:

- `FASTMCP_AUTH_TYPE=auth0`
- `FASTMCP_AUTH0_DOMAIN`: Your Auth0 tenant domain (e.g., `your-tenant.us.auth0.com`)
- `FASTMCP_AUTH0_AUDIENCE`: The API Identifier (Audience) from your Auth0 dashboard

When enabled, the server will validate the `Authorization: Bearer <token>` header against your Auth0 tenant's JWKS.

## Deployment Procedures

### Build the Docker image

From this directory:

```bash
docker build -t mcp-postgres-server .
```

### Run (read-only, recommended)

```bash
docker run --rm \
  -p 8000:8000 \
  -e DATABASE_URL="postgresql://mcp_readonly:change_me@your_db_host:5432/your_db" \
  -e MCP_ALLOW_WRITE=false \
  --name mcp-postgres-readonly \
  mcp-postgres-server
```

### Run (maintenance / writes enabled)

Use a separate role and separate port:

```bash
docker run --rm \
  -p 8001:8000 \
  -e DATABASE_URL="postgresql://mcp_maintenance:change_me@your_db_host:5432/your_db" \
  -e MCP_ALLOW_WRITE=true \
  --name mcp-postgres-maint \
  mcp-postgres-server
```

### Verify

- Health: `http://localhost:8000/health` should return `ok`
- MCP endpoint: `http://localhost:8000/mcp`

## VS Code Setup

To use this server from VS Code, you need a VS Code extension that supports MCP servers over Streamable HTTP. Configure the extension to point at your running MCP endpoint:

- `http://localhost:8000/mcp` (read-only)
- `http://localhost:8001/mcp` (maintenance, optional)

### Codex – OpenAI’s coding agent

Codex reads MCP servers from:

- `~/.codex/config.toml`

In the Codex extension:

- Open Codex panel
- Gear icon → MCP settings → Open `config.toml`

Add:

```toml
[mcp_servers.postgres_readonly]
url = "http://localhost:8000/mcp"
enabled = true
tool_timeout_sec = 60
startup_timeout_sec = 10
# If Auth0 is enabled, provide the token via an environment variable
bearer_token_env_var = "POSTGRES_MCP_TOKEN"
```

If you run the maintenance server:

```toml
[mcp_servers.postgres_maintenance]
url = "http://localhost:8001/mcp"
enabled = true
```

### Other VS Code MCP extensions

If you are using a different VS Code extension with MCP support, look for a setting like “MCP Servers” or “Tool Servers” and add an HTTP server entry with:

- Name: `postgres_readonly`
- URL: `http://localhost:8000/mcp`

If the extension supports per-server tool allowlists, you can restrict it to:

- `ping`, `server_info`, `list_schemas`, `list_tables`, `describe_table`, `run_query`, `explain_query`, `active_sessions`, `db_locks`, `table_sizes`, `index_usage`, `top_queries`

## PostgreSQL Role Recommendations

### Read-only role (recommended for production)

Create a dedicated role that can only read data and catalog views. Example (adjust DB and schema names):

```sql
CREATE ROLE mcp_readonly LOGIN PASSWORD 'change_me_strong_password';
GRANT CONNECT ON DATABASE your_db TO mcp_readonly;

\\c your_db

GRANT USAGE ON SCHEMA public TO mcp_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT ON TABLES TO mcp_readonly;
```

### Maintenance role (use carefully)

If you want a write-enabled MCP server, use a separate role and keep it off production unless you have strong operational controls.

## Troubleshooting

### Codex can’t see the MCP server

- Confirm the container is running and port is mapped:
  - MCP endpoint: `http://localhost:8000/mcp`
  - Health: `http://localhost:8000/health`
- Confirm `~/.codex/config.toml` has the server entry under `[mcp_servers.<name>]`.
- Restart the Codex panel after editing the config.

### Server fails to start: missing DATABASE_URL

The server requires either:

- `DATABASE_URL`, or
- `PGHOST` + `PGUSER` + `PGDATABASE` (and optionally `PGPASSWORD`, `PGPORT`)

### PostgreSQL connection errors

- Verify the DB host is reachable from inside the container network.
- If using a managed database, ensure inbound rules allow the container host.
- Confirm credentials and database name in `DATABASE_URL`.

### `top_queries` returns “pg_stat_statements is not available”

`pg_stat_statements` requires Postgres configuration and extension setup:

1. Set `shared_preload_libraries = 'pg_stat_statements'` and restart Postgres
2. In the target database:

```sql
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

### Local pip install fails with TLS CA bundle error (Windows)

If you see an error like “could not find a suitable TLS CA certificate bundle”, use Docker-based deployment instead of local installs, or repair your Python/pip certificate configuration.

