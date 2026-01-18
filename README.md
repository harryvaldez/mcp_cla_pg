# PostgreSQL MCP Server (Python + Docker)

Remote MCP server that exposes PostgreSQL DBA-oriented tools over Streamable HTTP, designed to be consumed by MCP-capable clients (including Codex – OpenAI’s coding agent in VS Code).

## Purpose

Provide a repeatable, automated PostgreSQL health and performance inspection service that MCP-capable agents can call to:

- Discover schemas, tables, and indexes.
- Assess table and index health (bloat, statistics freshness, maintenance needs).
- Analyze active sessions, locks, and blocking activity.
- Review configuration and capacity settings relevant to performance and safety.

## Scope

In scope:

- PostgreSQL instances where the MCP server can connect over the network.
- Read-only inspection of catalog views, statistics, and limited session metadata.
- Optional use of a maintenance role for user management and session termination.

Out of scope:

- Executing maintenance commands directly (VACUUM, ANALYZE, REINDEX, etc.).
- Modifying PostgreSQL configuration files or cluster-wide settings.
- Acting as a generic query runner for arbitrary write workloads.

## Overview

This server runs as an HTTP service and provides:

- Read-only safe database inspection by default (writes disabled unless explicitly enabled).
- Common DBA discovery and monitoring tools (schemas, tables, sizes, sessions, query stats).
- Ad-hoc SQL execution with a configurable row limit.
- EXPLAIN plan generation for query performance analysis.

The MCP endpoint is served at:

- `http://<host>:<port>/mcp`

Health endpoint:

- `http://<host>:<port>/health`

## Prerequisites

- A running PostgreSQL instance (9.6 or later) reachable from the MCP server.
- A database role suitable for this server:
  - Recommended: a read-only role (see PostgreSQL Role Recommendations below).
  - Optional: a separate maintenance role if you plan to use write-capable tools.
- At least one MCP-capable client, such as:
  - VS Code with Codex (OpenAI’s coding agent) or another MCP client.
- For container-based usage:
  - Docker installed on the machine where you run the MCP server.
- For local development usage:
  - Python 3.12+ for running the server directly.
  - Node.js and npm if you want to use the `npx .` entry point.

## Architecture Overview

- **MCP client**  
  - VS Code with Codex or another MCP-capable client sends tool calls over MCP (Streamable HTTP, SSE, or stdio) to this server.

- **MCP server process**  
  - Implemented in Python using the `FastMCP` framework (see `server.py`).
  - Exposes each DBA capability as a named MCP tool (for example `analyze_table_health`, `analyze_sessions`, `run_query`).
  - Supports multiple transports configured via environment:
    - HTTP / Streamable HTTP: `MCP_TRANSPORT=http` with `MCP_HOST` and `MCP_PORT`.
    - SSE: `MCP_TRANSPORT=sse`.
    - stdio: `MCP_TRANSPORT=stdio` (for local, process-based integration).

- **Authentication / authorization layer (optional)**  
  - Controlled by `FASTMCP_AUTH_TYPE`:
    - `oidc`: full OAuth/OIDC login flow via an external identity provider.
    - `jwt`: resource-server style JWT verification using a JWKS endpoint.
  - Applies auth checks before tool handlers run, so only authenticated clients can call tools.

- **Database access layer**  
  - Uses `psycopg` with a shared `ConnectionPool` for all tools.
  - Connection parameters come from `DATABASE_URL` or the `PG*` environment variables.
  - Each tool function checks `MCP_ALLOW_WRITE` and uses a session-level `statement_timeout` (`MCP_STATEMENT_TIMEOUT_MS`) to protect the database.
  - Read-only tools query PostgreSQL catalog views and statistics functions; maintenance-oriented tools use a separate role if configured.

- **Deployment surfaces**  
  - Local container: Docker / Docker Compose running the MCP server alongside or near PostgreSQL.
  - Local development: `uv run mcp-postgres`, `uvx --from . mcp-postgres`, or `npx .`.
  - Cloud: Azure Container Apps and AWS ECS Fargate using the templates under `deploy/`.

At runtime, the flow is:

1. An MCP client selects this server and issues a tool call (for example `analyze_table_health`).
2. FastMCP authenticates the request (if configured) and dispatches it to the corresponding Python function.
3. The tool function borrows a connection from the PostgreSQL pool, runs the necessary queries, and assembles a JSON result with findings and recommendations.
4. FastMCP returns the structured result to the client over the active transport, where it can be rendered in the UI or used by the agent for follow-up actions.

## Tools Exposed

The MCP server exposes these tools:

- `ping`: Health check.
- `server_info`: Get database version, user, and server settings.
- `db_stats`: Get database-level statistics (commits, rollbacks, temp files, deadlocks) with optional performance metrics.
- `analyze_sessions`: Comprehensive session analysis combining active queries, idle sessions, and locks.
- `analyze_table_health`: Comprehensive table health analysis combining bloat detection, maintenance needs, autovacuum recommendations, and materialized view candidate scoring with OLTP/OLAP profiles.
- `analyze_indexes`: Identify unused, duplicate, missing, and redundant indexes.
- `recommend_partitioning`: Suggest tables for partitioning based on size and access patterns.
- `database_security_performance_metrics`: Analyze security and performance metrics with optimization recommendations.
- `get_db_parameters`: Retrieve database configuration parameters (GUCs) with optional filtering.
- `list_databases`: List all available databases and their sizes.
- `list_schemas`: List schemas in the current database.
- `list_largest_schemas`: List schemas ranked by total size (tables, indexes, toast).
- `list_temp_objects`: List temporary schemas with object counts and total size.
- `list_tables`: List tables in a specific schema.
- `list_largest_tables`: List the largest tables in a specific schema ranked by size.
- `describe_table`: Get column details, indexes, and sizes for a table.
- `run_query`: Execute ad-hoc read-only SQL queries (with row limits).
- `explain_query`: Generate EXPLAIN plans for query analysis.
- `create_db_user`: Create a new database user and assign read or read/write privileges (requires `MCP_ALLOW_WRITE=true`).
- `drop_db_user`: Drop an existing database user (requires `MCP_ALLOW_WRITE=true`).
- `kill_session`: Terminate a database session by its PID (requires `MCP_ALLOW_WRITE=true`).

### Applying recommendations

Several tools (for example `analyze_table_health`, `check_bloat`, and `database_security_performance_metrics`) generate maintenance and tuning recommendations such as `VACUUM`, `ALTER TABLE ... SET (autovacuum_*)`, or changes to `postgresql.conf` parameters. These tools are **read-only**:

- They never execute `VACUUM`, `VACUUM FULL`, `ANALYZE`, `ALTER TABLE`, or `ALTER SYSTEM`.
- They do not modify `postgresql.conf` or any database settings.
- They only return suggested commands and configuration values that you can apply elsewhere.

To actually implement the recommendations you must:

- Review the suggested SQL or configuration changes.
- Apply them using your normal administration channel (psql, pgAdmin, migration scripts, or a separate write-enabled workflow).

Even when `MCP_ALLOW_WRITE=true`, this server only exposes a very small set of write-capable tools (`create_db_user`, `drop_db_user`, `kill_session`) and does **not** provide a generic “apply recommendations” or “run arbitrary maintenance SQL” tool.

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
- “Using `postgres_readonly`, call `db_stats` for the current database and summarize activity (commits, temp files, deadlocks).”
- “Using `postgres_readonly`, call `get_db_parameters(pattern='max_connections|shared_buffers')` to check current capacity settings.”

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

- “Using `postgres_readonly`, call `list_active_queries` and summarize the currently executing SQL statements.”
- “Using `postgres_readonly`, call `list_idle_sessions(min_idle_seconds=300)` to find long-running idle connections.”
- “Using `postgres_readonly`, call `active_sessions(min_duration_seconds=300)` and summarize what looks stuck.”

Lock triage:

- “Using `postgres_readonly`, call `db_locks(min_wait_seconds=30, limit=50)` and summarize blockers vs blocked.”

Capacity review:

- “Using `postgres_readonly`, call `list_largest_schemas(limit=30)` to identify the biggest schemas.”
- “Using `postgres_readonly`, call `list_temp_objects` to check for large or numerous temporary objects.”
- “Using `postgres_readonly`, call `list_largest_tables(schema='public', limit=30)` to find the largest tables in the public schema.”
- “Using `postgres_readonly`, call `table_sizes(limit=20)` and `index_usage(limit=20)`, then highlight the biggest objects.”
- “Using `postgres_readonly`, call `analyze_indexes(schema='public')` to find optimization opportunities.”
- “Using `postgres_readonly`, call `recommend_partitioning(min_size_gb=1.0)` to identify candidates for table partitioning.”
- “Using `postgres_readonly`, call `database_security_performance_metrics()` to analyze security and performance issues with optimization commands.”
- “Using `postgres_readonly`, call `analyze_table_health(schema='public', profile='oltp')` to get comprehensive table health analysis including bloat, maintenance, autovacuum recommendations, and materialized view candidate flags tuned for OLTP workloads.”
- “Using `postgres_readonly`, call `analyze_table_health(schema='analytics', profile='olap')` to tune thresholds for analytic workloads and highlight materialized view candidates.”
- “Using `postgres_readonly`, call `analyze_sessions()` to get comprehensive session analysis including active queries, idle sessions, and lock information.”
- “Using `postgres_readonly`, call `check_bloat(limit=50)` and summarize the top 10 most bloated objects and their fix commands.”
- “Using `postgres_readonly`, call `maintenance_stats` and identify tables with high dead tuple counts or freeze risk.”

User management (requires maintenance role):

- “Using `postgres_maintenance`, call `create_db_user(username='lenexa_analyst', password='change_me_123', privileges='read', database='lenexa')`”

- “Using `postgres_maintenance`, call `drop_db_user(username='old_analyst')`”

- “Using `postgres_maintenance`, call `kill_session(pid=1234)` to terminate a stuck session.”

## Requirements

### Runtime (recommended)

- Docker
- Network access from the container to PostgreSQL

### Development (optional)

- Python 3.12+
- Windows: if `pip install` fails with a TLS CA bundle error, use `python pipw.py install -r requirements.txt`.

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
- `MCP_STATEMENT_TIMEOUT_MS` (default: `30000`): session-level query execution timeout in milliseconds.

### Connection Pool

- `MCP_POOL_MIN_SIZE` (default: `1`)
- `MCP_POOL_MAX_SIZE` (default: `5`)
- `MCP_POOL_TIMEOUT` (default: `30.0`): time in seconds to wait for a connection from the pool.
- `MCP_POOL_MAX_WAITING` (default: `10`): maximum number of requests waiting for a connection.

### Server Transport

- `MCP_TRANSPORT` (default: `http`): `http`, `sse`, or `stdio`
- `MCP_HOST` (default: `0.0.0.0`)
- `MCP_PORT` (default: `8000`)
- `MCP_SERVER_NAME` (default: `PostgreSQL MCP Server`)

### OAuth (OIDC) Authentication

To secure the remote endpoint with generic OAuth (OIDC) authentication, set the following environment variables:

- `FASTMCP_AUTH_TYPE=oidc`
- `FASTMCP_OIDC_CONFIG_URL`: URL of your OAuth provider's OIDC configuration (e.g., `https://your-tenant.us.auth0.com/.well-known/openid-configuration`)
- `FASTMCP_OIDC_CLIENT_ID`: Client ID from your registered OAuth application
- `FASTMCP_OIDC_CLIENT_SECRET`: Client secret from your registered OAuth application
- `FASTMCP_OIDC_BASE_URL`: Public URL of your FastMCP server (e.g., `https://your-server.com`)
- `FASTMCP_OIDC_AUDIENCE`: (Optional) Audience parameter if required by your provider

When enabled, the server will manage OAuth client registration and token validation using the `OIDCProxy` provider.

### JWT Token Verification (Alternative)

If you only need to validate Bearer tokens without a full OAuth flow:

- `FASTMCP_AUTH_TYPE=jwt`
- `FASTMCP_JWT_JWKS_URI`: URL to the JWKS endpoint (e.g., `https://your-tenant.us.auth0.com/.well-known/jwks.json`)
- `FASTMCP_JWT_ISSUER`: The expected issuer (`iss` claim)
- `FASTMCP_JWT_AUDIENCE`: (Optional) The expected audience (`aud` claim)

## Deployment

This server can be deployed in read-only mode (default, recommended) or maintenance mode (write-enabled).
All commands are tailored for PowerShell.

- **Read-only Mode**: Safe for production. Disables tools that modify the database (`create_db_user`, `kill_session`, etc.).
- **Maintenance Mode**: Enables write operations. Use with caution and a dedicated maintenance role.

### 1. Docker (Recommended)

#### Start Server (Read-only)
Build and run the container. It will connect in read-only mode by default.

```powershell
# 1. Build the image
docker build -t mcp-postgres-server .

# 2. Run the container
docker run --rm -d `
  -p 8000:8000 `
  -e "DATABASE_URL=postgresql://mcp_readonly:your_password@your_db_host:5432/your_db" `
  --name mcp-postgres-readonly `
  mcp-postgres-server
```

#### Start Server (Maintenance Mode)
To enable maintenance mode, set `MCP_ALLOW_WRITE=true` and use a database role with write permissions.

```powershell
docker run --rm -d `
  -p 8001:8000 `
  -e "DATABASE_URL=postgresql://mcp_maintenance:your_password@your_db_host:5432/your_db" `
  -e "MCP_ALLOW_WRITE=true" `
  --name mcp-postgres-maintenance `
  mcp-postgres-server
```

#### Stop Server
Stop the container by its name:
```powershell
# Stop the read-only container
docker stop mcp-postgres-readonly

# Stop the maintenance container
docker stop mcp-postgres-maintenance
```

### 2. `uv` (for Local Development)

Requires `uv` to be installed. The server will run in the foreground.

#### Start Server (Read-only)
```powershell
# Set credentials and run
$env:DATABASE_URL="postgresql://mcp_readonly:your_password@localhost:5432/your_db"
uv run python server.py
```

#### Start Server (Maintenance Mode)
```powershell
$env:DATABASE_URL="postgresql://mcp_maintenance:your_password@localhost:5432/your_db"
$env:MCP_ALLOW_WRITE="true"
$env:MCP_PORT="8001"
uv run python server.py
```

#### Stop Server
Press `Ctrl+C` in the terminal where the server is running.

### 3. `npx` (for Node.js Ecosystem)

Requires Python 3.12+ on your system. The server will run in the foreground.

#### Start Server (Read-only)
```powershell
$env:DATABASE_URL="postgresql://mcp_readonly:your_password@localhost:5432/your_db"
npx .
```

#### Start Server (Maintenance Mode)
```powershell
$env:DATABASE_URL="postgresql://mcp_maintenance:your_password@localhost:5432/your_db"
$env:MCP_ALLOW_WRITE="true"
$env:MCP_PORT="8001"
npx .
```

#### Stop Server
Press `Ctrl+C` in the terminal where the server is running.


### Cloud Deployment (Azure & AWS)
... (rest of the section remains the same)

Infrastructure templates are provided in the `deploy/` directory.

#### Azure Container Apps (ACA)
Using the Azure CLI:
```bash
# Login and set your subscription
az login

# Create a resource group
az group create --name mcp-postgres-rg --location eastus

# Deploy using the Bicep template
az deployment group create \
  --resource-group mcp-postgres-rg \
  --template-file deploy/azure-aca.bicep \
  --parameters \
    containerImage="your-registry.azurecr.io/mcp-postgres:latest" \
    databaseUrl="your-db-url"
```

#### AWS ECS Fargate
Using the AWS CLI:
```bash
# Deploy the CloudFormation stack
aws cloudformation create-stack \
  --stack-name mcp-postgres-stack \
  --template-body file://deploy/aws-ecs.yaml \
  --capabilities CAPABILITY_IAM \
  --parameters \
    ParameterKey=VpcId,ParameterValue=vpc-xxxxxx \
    ParameterKey=SubnetIds,ParameterValue=subnet-xxxx\,subnet-yyyy \
    ParameterKey=ContainerImage,ParameterValue=xxxx.dkr.ecr.us-east-1.amazonaws.com/mcp-postgres:latest \
    ParameterKey=DatabaseUrl,ParameterValue="your-db-url"
```

### 5. Verification
- Health: `http://localhost:8000/health` should return `ok`.
- MCP endpoint: `http://localhost:8000/mcp`.

### 6. Accessing the Remote Server (Azure)

Once deployed to Azure Container Apps, the server will be available over HTTPS.

#### Get the URL
You can find the URL (FQDN) in the Azure Portal under the **Overview** tab of your Container App, or via CLI:
```bash
az containerapp show \
  --name mcp-postgres-server \
  --resource-group mcp-postgres-rg \
  --query properties.configuration.ingress.fqdn \
  --output tsv
```

The full MCP endpoint will be:
`https://<your-fqdn>/mcp`

#### Configure your client
In your MCP client (e.g., Codex `config.toml`), use the HTTPS URL:
```toml
[mcp_servers.azure_postgres]
url = "https://mcp-postgres-server.your-id.region.azurecontainerapps.io/mcp"
enabled = true
# If you enabled authentication (OIDC/JWT), provide the token
bearer_token_env_var = "AZURE_MCP_TOKEN"
```

### Docker Health Checks

The provided `Dockerfile` includes a built-in health check that monitors the `/health` endpoint. When running in environments like Docker Compose or Kubernetes, the container status will automatically reflect the health of the MCP server.

## VS Code Setup

To use this server from VS Code, you need a VS Code extension that supports MCP servers over Streamable HTTP. 

### 1. Codex – OpenAI’s coding agent

Codex reads MCP servers from `~/.codex/config.toml`. 

#### For Local Deployment
```toml
[mcp_servers.postgres_local]
url = "http://localhost:8000/mcp"
enabled = true
```

#### For Azure Deployment (Remote)
1. Get your Azure FQDN (see [Accessing the Remote Server (Azure)](#6-accessing-the-remote-server-azure)).
2. Add to `config.toml`:
```toml
[mcp_servers.postgres_azure]
url = "https://your-app.region.azurecontainerapps.io/mcp"
enabled = true
# If authentication is enabled, provide the token via an environment variable
bearer_token_env_var = "AZURE_MCP_TOKEN"
```

### 2. Other VS Code Extensions
If you are using other extensions (like Cursor or generic MCP clients), look for "MCP Servers" in settings and add:
- **Type**: HTTP / Streamable HTTP
- **URL**: `https://your-app.region.azurecontainerapps.io/mcp`
- **Auth**: Add `Authorization: Bearer <your-token>` header if required.

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

Use `python pipw.py install -r requirements.txt`, which repairs common cases where `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` point to a missing file for that process. If it still fails, use Docker-based deployment or repair your Python/pip certificate configuration.

## Security & Scalability Best Practices

### Security Hardening
- **Least Privilege**: Always use a read-only PostgreSQL role for `mcp_readonly` (see [PostgreSQL Role Recommendations](#postgresql-role-recommendations)).
- **Authentication**: Enable OIDC or JWT verification for remote endpoints.
- **Network Isolation**: Run the MCP server in a private network, exposing it only via an authenticated reverse proxy (e.g., Caddy, Nginx).
- **Statement Timeouts**: Keep `MCP_STATEMENT_TIMEOUT_MS` low (e.g., 30s) to prevent resource exhaustion from complex queries.

### Scalability Tuning
- **Connection Pooling**: Tune `MCP_POOL_MAX_SIZE` based on your expected concurrency and DB capacity.
- **Row Limits**: Use `MCP_MAX_ROWS` to prevent large result sets from consuming excessive memory in the MCP server or client.
- **Monitoring**: Check logs for "BLOCKED write attempt" warnings to identify unauthorized usage patterns.

## FAQ

### Should I use OAuth (OIDC) or JWT verification?

- Use OAuth (OIDC) if you want the server to participate in an interactive OAuth login/consent flow.
- Use JWT verification if you already have a separate system issuing Bearer tokens and you only need this server to validate them.

### Why does `db_locks` return an empty list?

`db_locks` only returns sessions that are actively blocked on locks and the sessions that are blocking them. If nothing is currently waiting on a lock, it returns `[]`.

### How do I run this over HTTPS?

Terminate TLS in front of the server (Caddy/Nginx/Traefik/Cloudflare) and reverse proxy to `http://localhost:8000`. The MCP endpoint becomes `https://your-domain/mcp`.

### How do I change the maximum rows returned by `run_query`?

- Set `MCP_MAX_ROWS` or pass `max_rows` when calling `run_query`.

## Getting Help

- Start with the Troubleshooting and FAQ sections above for common issues.
- If something still is not working as expected, open an issue on GitHub:
  - https://github.com/harryvaldez/mcp_cla_pg/issues
- When filing an issue, include:
  - PostgreSQL version and how the server is deployed (Docker, UV, NPX, cloud).
  - Relevant environment variables (redact passwords/secrets).
  - Any error messages or stack traces from the MCP server logs.
- For security-sensitive issues, avoid sharing details in public issues; instead, use GitHub’s security reporting flow if available, or open a minimal issue and request a private follow-up channel.
- For quick usage help from the command line, you can also run:
  - `uv run mcp-postgres --help`
  - `uvx --from . mcp-postgres --help`
  - `npx . --help`

## Enhancements / Suggestions

- Add per-tool authorization (scopes/roles) and tool allowlists by environment.
- Add optional query redaction for `pg_stat_activity` output.
- Add health checks for database connectivity and pool status.
- Add additional DBA tools (bloat, vacuum progress, replication status, long transactions).
- Add structured tests and a CI workflow (lint/typecheck, container build, smoke tests).

