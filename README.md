# PostgreSQL MCP Server

A powerful Model Context Protocol (MCP) server for PostgreSQL database administration, designed for AI agents like **Trae**, **Claude**, and **Codex**.

This server exposes a suite of DBA-grade tools to inspect schemas, analyze performance, check security, and troubleshoot issues—all through a safe, controlled interface.

## 🚀 Features

- **Deep Inspection**: Discover schemas, tables, indexes, and their sizes.
- **Performance Analysis**: Detect table bloat, missing indexes, and lock contention.
- **Security Audits**: Analyze database privileges and security settings.
- **Safe Execution**: Read-only by default, with optional write capabilities for specific maintenance tasks.
- **Multiple Transports**: Supports `http` (uses SSE) and `stdio`. HTTPS is supported via SSL configuration variables.
- **Secure Authentication**: Built-in support for **Azure AD (Microsoft Entra ID)** and standard token auth.
- **HTTPS Support**: Native SSL/TLS support for secure remote connections.
- **Broad Compatibility**: Fully tested with **PostgreSQL 9.6+**.

---

## 📦 Installation & Usage

### Option 1: Trae (Native Integration)

To add this MCP server to Trae:

1.  Open Trae Settings -> MCP Servers.
2.  Add a new server with the following configuration:
    *   **Type**: `stdio` (recommended for local) or `sse` (for remote/HTTP).
    *   **Command**: `uv run mcp-postgres` (if running from source) or the Docker command.

**Example `stdio` configuration for Trae (Local):**
```json
{
  "mcpServers": {
    "postgres-stdio": {
      "command": "uv",
      "args": ["run", "mcp-postgres"],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/dbname",
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

**Example `sse` configuration for Trae (HTTP/Remote):**
```json
{
  "mcpServers": {
    "postgres-http": {
      "url": "http://your-server-address:8000/mcp"
    }
  }
}
```

### Option 2: VS Code & Claude Desktop

This section explains how to configure the server for Claude Desktop and VS Code extensions.

1.  **Claude Desktop Integration**:
    Edit your `claude_desktop_config.json` (usually in `~/Library/Application Support/Claude/` on macOS or `%APPDATA%\Claude\` on Windows). This configures the server for the Claude Desktop application, which can be invoked from VS Code.

2.  **VS Code Extension Configuration**:
    For extensions like Cline or Roo Code, go to the extension settings in VS Code and look for "MCP Servers" configuration. You can use the same JSON structure as below.

**Configuration JSON:**
```json
{
  "mcpServers": {
    "postgres": {
      "command": "uv",
      "args": ["run", "mcp-postgres"],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/dbname"
      }
    }
  }
}
```

### Option 3: Docker (Recommended)

Since this image is not hosted on Docker Hub, you must build it locally first.

```bash
# 1. Build the image locally
docker build -t mcp-postgres .

# 2. Run in HTTP Mode (SSE)
docker run -d \
  --name mcp-postgres-http \
  -e DATABASE_URL=postgresql://user:password@host.docker.internal:5432/dbname \
  -e MCP_TRANSPORT=http \
  -p 8000:8000 \
  mcp-postgres

# 3. Run in Write Mode (HTTP)
docker run -d \
  --name mcp-postgres-write \
  -e DATABASE_URL=postgresql://user:password@host.docker.internal:5432/dbname \
  -e MCP_TRANSPORT=http \
  -e MCP_ALLOW_WRITE=true \
  -p 8001:8000 \
  mcp-postgres
```

**Using Docker Compose:**
The `docker-compose.yml` is configured for HTTP by default:
```bash
docker compose up --build -d
```

### Option 4: Local Python (uv)

```bash
# Set connection string
export DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Run in HTTP Mode (SSE)
export MCP_TRANSPORT=http
uv run .

# Run in Write Mode (HTTP)
export MCP_TRANSPORT=http
export MCP_ALLOW_WRITE=true
uv run .
```

### Option 5: Node.js (npx)

```bash
# Set connection string
export DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Run in HTTP Mode (SSE)
export MCP_TRANSPORT=http
npx .

# Run in Write Mode (HTTP)
export MCP_TRANSPORT=http
export MCP_ALLOW_WRITE=true
npx .
```


---

## ⚙️ Configuration

The server is configured entirely via environment variables.

### Core Connection
| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Full PostgreSQL connection string | *Required* |
| `MCP_HOST` | Host to bind the server to | `0.0.0.0` |
| `MCP_PORT` | Port to listen on | `8000` |
| `MCP_TRANSPORT` | Transport mode: `http` (uses SSE) or `stdio` | `http` |
| `MCP_ALLOW_WRITE` | Enable write tools (`create_db_user`, etc.) | `false` |
| `MCP_STATEMENT_TIMEOUT_MS` | Query execution timeout in milliseconds | `120000` |
| `MCP_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `MCP_LOG_FILE` | Optional path to write logs to a file | *None* |

### Authentication (Azure AD)
To enable Azure AD authentication, set `FASTMCP_AUTH_TYPE=azure-ad`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_AZURE_AD_TENANT_ID` | Your Azure Tenant ID |
| `FASTMCP_AZURE_AD_CLIENT_ID` | Your Azure Client ID |
| `FASTMCP_AZURE_AD_CLIENT_SECRET` | (Optional) Client secret for OIDC Proxy mode |
| `FASTMCP_AZURE_AD_BASE_URL` | (Optional) Base URL for OIDC Proxy mode |

### HTTPS / SSL
To enable HTTPS, provide both the certificate and key files.

| Variable | Description |
|----------|-------------|
| `MCP_SSL_CERT` | Path to SSL certificate file (`.crt` or `.pem`) |
| `MCP_SSL_KEY` | Path to SSL private key file (`.key`) |

---

## �️ Logging & Security

This server implements strict security practices for logging:

- **Sanitized INFO Logs**: High-level operations (like `run_query` and `explain_query`) are logged at `INFO` level, but **raw SQL queries and parameters are never included** to prevent sensitive data leaks.
- **Fingerprinting**: Instead of raw SQL, we log SHA-256 fingerprints (`sql_sha256`, `params_sha256`) to allow correlation and debugging without exposing data.
- **Debug Mode**: Raw SQL and parameters are only logged when `MCP_LOG_LEVEL=DEBUG` is explicitly set, and even then, sensitive parameters are hashed where possible.
- **Safe Defaults**: By default, the server runs in `INFO` mode, ensuring production logs are safe.

---

## ��️ Tools Reference

### 🏥 Health & Info
- `ping()`: Simple health check.
- `server_info()`: Get database version, current user, and connection details.
- `db_stats(database: str = None, include_performance: bool = False)`: Database-level statistics.
- `server_info_mcp()`: Get internal MCP server status and version.

### 🔍 Schema Discovery
- `list_databases()`: List all databases and their sizes.
- `list_schemas(include_system: bool = False)`: List schemas.
- `list_tables(schema: str = "public")`: List tables in a specific schema.
- `describe_table(schema: str, table: str)`: Get detailed column and index info for a table.
- `list_largest_schemas(limit: int = 30)`: Find schemas consuming the most space.
- `list_largest_tables(schema: str = "public", limit: int = 30)`: Find the largest tables in a schema.
- `table_sizes(schema: str = None, limit: int = 20)`: List tables by size across the database.
- `list_temp_objects()`: Monitor temporary schema usage.

### ⚡ Performance & Tuning
- `analyze_table_health(schema: str = None, min_size_mb: int = 50, profile: str = "oltp")`: **(Power Tool)** Comprehensive health check for bloat, vacuum needs, and optimization.
- `analyze_indexes(schema: str = None, limit: int = 50)`: Identify unused, duplicate, or missing indexes.
- `index_usage(schema: str = None, limit: int = 20)`: Show index usage statistics.
- `maintenance_stats(schema: str = None, limit: int = 50)`: Show vacuum and analyze statistics.
- `recommend_partitioning(min_size_gb: float = 1.0, schema: str = None)`: Suggest tables for partitioning.
- `explain_query(sql: str, analyze: bool = False, format: str = "json")`: Get the execution plan for a query.

### 🕵️ Session & Security
- `analyze_sessions(include_idle: bool = True, include_locked: bool = True)`: Detailed session analysis.
- `database_security_performance_metrics(profile: str = "oltp")`: Comprehensive security and performance audit.
- `get_db_parameters(pattern: str = None)`: Retrieve database configuration parameters (GUCs).

### 🔧 Maintenance (Requires `MCP_ALLOW_WRITE=true`)
- `create_db_user(username: str, password: str, privileges: str = "read")`: Create a new role.
- `drop_db_user(username: str)`: Remove a role.
- `kill_session(pid: int)`: Terminate a specific backend PID.
- `run_query(sql: str, params_json: str = None, max_rows: int = 500)`: Execute ad-hoc SQL and return up to `max_rows` rows (default `500`, configurable via `MCP_MAX_ROWS`). If the query produces more rows than this limit, the server returns the first `max_rows` rows and sets `truncated: true` in the response.

---

## 📖 Usage Examples

Here are some real-world examples of using the tools via an MCP client.

### 1. Check MCP Server Info
**Prompt:** `using postgres_readonly, call server_info_mcp() and display results`

**Result:**
```json
{
  "name": "PostgreSQL MCP Server",
  "version": "1.0.0",
  "status": "healthy",
  "transport": "http",
  "database": "lenexa"
}
```

### 2. Check Database Connection Info
**Prompt:** `using postgres_readonly, call server_info() and display results`

**Result:**
```json
{
  "database": "lenexa",
  "user": "enterprisedb",
  "server_addr": "10.100.2.20/32",
  "server_port": 5444,
  "version": "EnterpriseDB 9.6.2.7 on x86_64-pc-linux-gnu...",
  "allow_write": false,
  "default_max_rows": 500,
  "statement_timeout_ms": 120000
}
```

### 3. Analyze Table Health (Power Tool)
**Prompt:** `using postgres_readonly, call analyze_table_health(schema=smsadmin, profile=oltp) and display results`

**Result (Truncated):**
```json
{
  "summary": {
    "total_tables_analyzed": 30,
    "tables_with_issues": 0,
    "recommendations": []
  },
  "tables": [
    {
      "schema": "smsadmin",
      "table": "sms_fe_zp6_2025",
      "size_mb": 39440.3,
      "health_score": 85,
      "issues": ["No vacuum in 138 days", "No analyze in 138 days"],
      "recommendations": ["High modification rate - consider aggressive autovacuum settings"]
    },
    {
      "schema": "smsadmin",
      "table": "sms_app_log",
      "size_mb": 122.2,
      "health_score": 100,
      "issues": [],
      "recommendations": []
    }
  ]
}
```

### 4. Check Active Tables (Filtering Example)
**Prompt:** `using postgres_readonly, call analyze_table_health(schema=smsadmin, profile=oltp) and check tables that has been active in the past 60 days`

**Result (Filtered):**
```json
{
  "active_tables": [
    {
      "table": "sms_app_log",
      "size_mb": 122.2,
      "last_activity": "Recent (<24h or no issues)"
    },
    {
      "table": "collection_element",
      "size_mb": 2690.3,
      "last_vacuum": "18 days ago"
    },
    {
      "table": "sms_fe_zp6_2026",
      "size_mb": 20091.3,
      "last_analyze": "49 days ago"
    }
  ]
}
```

---

## 🧪 Testing & Validation

This project has been rigorously tested against **PostgreSQL 9.6** to ensure compatibility with legacy and modern environments.

### Test Results (2026-01-20)
- **Deployment**: Docker, `uv`, `npx` (All Passed)
- **Protocol**: SSE (HTTP/HTTPS), Stdio (All Passed)
- **Database**: PostgreSQL 9.6 (All Tools Verified)
- **Auth**: Token Auth, Azure AD Auth (Verified)

To run the full test suite locally:
```bash
# Provisions a Postgres 9.6 container and runs all tools
python test_docker_pg96.py
```

---

## ❓ Troubleshooting

**Browser Error: `Not Acceptable`**
If you visit `http://localhost:8000/mcp` in a browser, you will see a JSON error. This is normal; that endpoint is for MCP clients only. Visit `http://localhost:8000/` for the status page.

**Connection Refused**
Ensure your `DATABASE_URL` is correct. If running in Docker, remember that `localhost` inside the container refers to the container itself. Use `host.docker.internal` to reach the host machine.

**Duplicate Indexes Not Detected**
The `analyze_indexes` tool has been updated to group by the indexed column set. Ensure your indexes have the exact same column order and definition for detection.
