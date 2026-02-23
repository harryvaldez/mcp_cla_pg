# PostgreSQL MCP Server

A powerful Model Context Protocol (MCP) server for PostgreSQL database administration, designed for AI agents like **VS Code**, **Claude**, and **Codex**.

This server exposes a suite of DBA-grade tools to inspect schemas, analyze performance, check security, and troubleshoot issues—all through a safe, controlled interface.

## 🚀 Features

- **Deep Inspection**: Discover schemas, tables, indexes, and their sizes.
- **Logical Modeling**: Analyze foreign keys and table relationships to understand the data model.
- **Performance Analysis**: Detect table bloat, missing indexes, and lock contention.
- **Security Audits**: Analyze database privileges and security settings.
- **Safe Execution**: Read-only by default, with optional write capabilities for specific maintenance tasks.
- **Multiple Transports**: Supports `sse` (Server-Sent Events) and `stdio`. HTTPS is supported via SSL configuration variables.
- **Secure Authentication**: Built-in support for **Azure AD (Microsoft Entra ID)** and standard token auth.
- **HTTPS Support**: Native SSL/TLS support for secure remote connections.
- **SSH Tunneling**: Built-in support for connecting via SSH bastion hosts.
- **Python 3.13**: Built on the latest Python runtime for improved performance and security.
- **Broad Compatibility**: Fully tested with **PostgreSQL 9.6+**. (Note: PostgreSQL 9.6 reached EOL in Nov 2021; we recommend using supported releases, e.g., PostgreSQL 12+, for production.)

---

## 📦 Installation & Usage

### ⚡ Quickstart: Docker + n8n

Spin up a complete environment with **PostgreSQL**, **MCP Server**, and **n8n** in one command.

1.  **Download the Compose File**:
    Save [docker-compose-n8n.yml](docker-compose-n8n.yml) to your project directory.

2.  **Start the Stack**:
    ```bash
    docker compose -f docker-compose-n8n.yml up -d
    ```

3.  **Connect n8n**:
    *   Open n8n at [http://localhost:5678](http://localhost:5678).
    *   Add an **AI Agent** node.
    *   Add an **MCP Tool** to the agent.
    *   Set **Source** to `Remote (SSE)`.
    *   Set **URL** to `http://mcp-postgres:8000/sse` (Note: use container name).
    *   **Execute!** You can now ask the AI agent to "count rows in tables" or "check database stats".

---

For detailed deployment instructions on **Azure Container Apps**, **AWS ECS**, and **Docker**, please see our **[Deployment Guide](DEPLOYMENT.md)**.

> **Note**: For details on the required database privileges for read-only and read-write modes, see the **[Database Privileges](DEPLOYMENT.md#database-privileges)** section in the Deployment Guide.



### Option 1: VS Code & Claude Desktop

This section explains how to configure the server for Claude Desktop and VS Code extensions.

1.  **Claude Desktop Integration**:
    Edit your `claude_desktop_config.json` (usually in `~/Library/Application Support/Claude/` on macOS or `%APPDATA%\Claude\` on Windows).

2.  **VS Code Extension Configuration**:
    For extensions like Cline or Roo Code, go to the extension settings in VS Code and look for "MCP Servers" configuration.

You can use either of the following methods to configure the server.

#### Method A: Using Docker (Recommended)
This method ensures you have all dependencies pre-installed. Note the `-i` flag (interactive) and `MCP_TRANSPORT=stdio`.

```json
{
  "mcpServers": {
    "postgres": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e", "DATABASE_URL=postgresql://user:password@host.docker.internal:5432/dbname",
        "-e", "MCP_TRANSPORT=stdio",
        "harryvaldez/mcp-postgres:latest"
      ]
    }
  }
}
```

#### Method B: Using Local Python (uv)
If you prefer running the Python code directly and have `uv` installed:

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

### Option 2: Docker (Recommended)

The Docker image is available on Docker Hub at `harryvaldez/mcp-postgres`.

```bash
# 1. Pull the image
docker pull harryvaldez/mcp-postgres:latest

# 2. Run in HTTP Mode (SSE)
docker run -d \
  --name mcp-postgres-http \
  -e DATABASE_URL=postgresql://user:password@host.docker.internal:5432/dbname \
  -e MCP_TRANSPORT=http \
  -e MCP_ALLOW_WRITE=false
  -p 8000:8000 \
  harryvaldez/mcp-postgres:latest

# 3. Run in Write Mode (HTTP - Secure)
docker run -d \
  --name mcp-postgres-write \
  -e DATABASE_URL=postgresql://user:password@host.docker.internal:5432/dbname \
  -e MCP_TRANSPORT=http \
  -e MCP_ALLOW_WRITE=true \
  -e MCP_CONFIRM_WRITE=true \
  # ⚠️ Untested / Not Production Ready
  -e FASTMCP_AUTH_TYPE=azure-ad \
  -e FASTMCP_AZURE_AD_TENANT_ID=... \
  -e FASTMCP_AZURE_AD_CLIENT_ID=... \
  -p 8001:8000 \
  harryvaldez/mcp-postgres:latest
```

### Option 2b: Docker with SSH Tunneling

To connect to a database behind a bastion host (e.g., in a private subnet), you can mount your SSH key and configure the tunnel variables. Set `ALLOW_SSH_AGENT=true` to enable SSH agent forwarding if your SSH key is loaded in your SSH agent:

```bash
docker run -d \
  --name mcp-postgres-ssh \
  -v ~/.ssh/id_rsa:/root/.ssh/id_rsa:ro \
  -e DATABASE_URL=postgresql://user:password@db-internal-host:5432/dbname \
  -e SSH_HOST=bastion.example.com \
  -e SSH_USER=ec2-user \
  -e SSH_PKEY="/root/.ssh/id_rsa" \
  -e ALLOW_SSH_AGENT=true \
  -e MCP_TRANSPORT=http \
  -p 8000:8000 \
  harryvaldez/mcp-postgres:latest
```

**Using Docker Compose:**
The `docker-compose.yml` is configured to use the public image:
```bash
docker compose up -d
```

### Option 3: Local Python (uv)

```bash
# Set connection string
export DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Run in HTTP Mode (SSE)
export MCP_TRANSPORT=http
uv run .

# Run in Write Mode (HTTP)
export MCP_TRANSPORT=http
export MCP_ALLOW_WRITE=true
export MCP_CONFIRM_WRITE=true
export FASTMCP_AUTH_TYPE=azure-ad # ⚠️ Untested / Not Production Ready
# ... set auth vars ...
uv run .
```

### Option 4: Node.js (npx)

```bash
# Set connection string
export DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Run in HTTP Mode (SSE)
export MCP_TRANSPORT=http
npx .

# Run in Write Mode (HTTP)
export MCP_TRANSPORT=http
export MCP_ALLOW_WRITE=true
export MCP_CONFIRM_WRITE=true
export FASTMCP_AUTH_TYPE=azure-ad # ⚠️ Untested / Not Production Ready
# ... set auth vars ...
npx .
```

### Option 5: n8n Integration (AI Agent)

You can use this MCP server as a "Remote Tool" in n8n to empower AI agents with database capabilities.

1.  **Download Workflow**: Get the [n8n-mcp-workflow.json](n8n-mcp-workflow.json).
2.  **Import to n8n**:
    *   Open your n8n dashboard.
    *   Go to **Workflows** -> **Import from File**.
    *   Select `n8n-mcp-workflow.json`.
3.  **Configure Credentials**:
    *   Open the **AI Agent** node.
    *   Set your **OpenAI** credentials.
    *   If your MCP server is protected, open the **Postgres MCP** node and update the `Authorization` header in "Header Parameters".
4.  **Run**: Click "Execute Workflow" to test the connection (defaults to `db_pg96_ping`).

### Troubleshooting n8n Connection

If n8n (Cloud) cannot connect to your local MCP server:
1.  **Public Accessibility**: Your server must be reachable from the internet. `localhost` or local names won't work from n8n Cloud.
2.  **Firewall**: Ensure your firewall allows inbound traffic on the MCP port (default 8085).
    ```powershell
    # Allow port 8085 on Windows
    netsh advfirewall firewall add rule name="MCP Server 8085" dir=in action=allow protocol=TCP localport=8085
    ```
3.  **Quick Fix (ngrok)**: Use [ngrok](https://ngrok.com/) to tunnel your local server to the internet.
    ```bash
    ngrok http 8085
    ```
    Then use the generated `https://....ngrok-free.app/sse` URL in n8n.




---

## ⚙️ Configuration

The server is configured entirely via environment variables.

### Performance Limits
To prevent the MCP server from becoming unresponsive or overloading the database, the following safeguards are in place:

*   **Statement Timeout**: Queries are automatically cancelled if they run longer than **120 seconds** (default).
    *   **Behavior**: The MCP tool will return an error: `Query execution timed out.`
    *   **Configuration**: Set `MCP_STATEMENT_TIMEOUT_MS` (milliseconds) to adjust this limit.
*   **Max Rows**: Queries returning large result sets are truncated to **500 rows** (default).
    *   **Configuration**: Set `MCP_MAX_ROWS` to adjust.

### Core Connection
| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Full PostgreSQL connection string | *Required* |
| `MCP_HOST` | Host to bind the server to | `0.0.0.0` |
| `MCP_PORT` | Port to listen on (8000 for Docker, 8085 for local) | `8085` |
| `MCP_TRANSPORT` | Transport mode: `sse`, `http` (uses SSE), or `stdio` | `http` |
| `MCP_ALLOW_WRITE` | Enable write tools (`db_pg96_create_db_user`, etc.) | `false` |
| `MCP_CONFIRM_WRITE` | **Required if ALLOW_WRITE=true**. Safety latch to confirm write mode. | `false` |
| `MCP_POOL_MAX_WAITING` | Max queries queued when pool is full | `20` |
| `MCP_STATEMENT_TIMEOUT_MS` | Max execution time per query in milliseconds | `120000` (2 minutes) |
| `MCP_SKIP_CONFIRMATION` | Set to "true" to skip startup confirmation dialog (Windows) | `false` |
| `MCP_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `MCP_LOG_FILE` | Optional path to write logs to a file | *None* |

### Security Constraints
If `MCP_ALLOW_WRITE=true`, the server enforces the following additional security checks at startup:
1. **Explicit Confirmation**: You must set `MCP_CONFIRM_WRITE=true`.
2. **Mandatory Authentication (HTTP)**: If using `http` transport, you must configure `FASTMCP_AUTH_TYPE` (e.g., `azure-ad`, `oidc`, `jwt`). Write mode over unauthenticated HTTP is prohibited.

> ⚠️ **Warning: Authentication Verification Pending**
> **Token Auth** and **Azure AD Auth** have not been tested and are **not production-ready**.
> While the implementation follows standard FastMCP patterns, end-to-end verification is pending.
> See [Testing & Validation](#testing--validation) for current status.

### 🔐 Authentication & OAuth2

The server supports several authentication modes via `FASTMCP_AUTH_TYPE`.

#### 1. Generic OAuth2 Proxy
Bridge MCP dynamic registration with traditional OAuth2 providers.
Set `FASTMCP_AUTH_TYPE=oauth2`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_OAUTH_AUTHORIZE_URL` | Provider's authorization endpoint |
| `FASTMCP_OAUTH_TOKEN_URL` | Provider's token endpoint |
| `FASTMCP_OAUTH_CLIENT_ID` | Your registered client ID |
| `FASTMCP_OAUTH_CLIENT_SECRET` | Your registered client secret |
| `FASTMCP_OAUTH_BASE_URL` | Public URL of this MCP server |
| `FASTMCP_OAUTH_JWKS_URI` | Provider's JWKS endpoint (for token verification) |
| `FASTMCP_OAUTH_ISSUER` | Expected token issuer |
| `FASTMCP_OAUTH_AUDIENCE` | (Optional) Expected token audience |

#### 2. GitHub / Google (Managed)
Pre-configured OAuth2 providers for simplified setup.
Set `FASTMCP_AUTH_TYPE=github` or `google`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_GITHUB_CLIENT_ID` | GitHub App/OAuth Client ID |
| `FASTMCP_GITHUB_CLIENT_SECRET` | GitHub Client Secret |
| `FASTMCP_GITHUB_BASE_URL` | Public URL of this MCP server |
| `FASTMCP_GOOGLE_CLIENT_ID` | Google OAuth Client ID |
| `FASTMCP_GOOGLE_CLIENT_SECRET` | Google Client Secret |
| `FASTMCP_GOOGLE_BASE_URL` | Public URL of this MCP server |

#### 3. Azure AD (Microsoft Entra ID)
Simplified configuration for Azure AD.
Set `FASTMCP_AUTH_TYPE=azure-ad`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_AZURE_AD_TENANT_ID` | Your Azure Tenant ID |
| `FASTMCP_AZURE_AD_CLIENT_ID` | Your Azure Client ID |
| `FASTMCP_AZURE_AD_CLIENT_SECRET` | (Optional) Client secret for OIDC Proxy mode |
| `FASTMCP_AZURE_AD_BASE_URL` | (Optional) Base URL for OIDC Proxy mode |

#### 4. OpenID Connect (OIDC) Proxy
Standard OIDC flow with discovery.
Set `FASTMCP_AUTH_TYPE=oidc`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_OIDC_CONFIG_URL` | OIDC well-known configuration URL |
| `FASTMCP_OIDC_CLIENT_ID` | OIDC Client ID |
| `FASTMCP_OIDC_CLIENT_SECRET` | OIDC Client Secret |
| `FASTMCP_OIDC_BASE_URL` | Public URL of this MCP server |

#### 5. Pure JWT Verification
Validate tokens signed by known issuers (Resource Server mode).
Set `FASTMCP_AUTH_TYPE=jwt`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_JWT_JWKS_URI` | Provider's JWKS endpoint |
| `FASTMCP_JWT_ISSUER` | Expected token issuer |
| `FASTMCP_JWT_AUDIENCE` | (Optional) Expected token audience |

#### 6. API Key (Static Token)
Simple Bearer token authentication. Ideal for machine-to-machine communication (e.g., n8n, internal services).
Set `FASTMCP_AUTH_TYPE=apikey`.

| Variable | Description |
|----------|-------------|
| `FASTMCP_API_KEY` | The secret key clients must provide in the `Authorization: Bearer <key>` header. |

#### 7. n8n Integration (AI Agent & HTTP Request)
The server is fully compatible with n8n workflows.

**Using the MCP Client Tool (AI Agent):**
1. Run the server with `FASTMCP_AUTH_TYPE=apikey`.
2. In n8n, add an **AI Agent** node.
3. Add the **MCP Tool** to the agent.
4. Set **Source** to `Remote (SSE)`.
5. Set **URL** to `http://<your-ip>:8000/mcp`.
6. Add a header: `Authorization: Bearer <your-api-key>`.

**Using the HTTP Request Node:**
1. Run the server with `FASTMCP_AUTH_TYPE=github` (or another OAuth2 provider).
2. Create an **OAuth2 API** credential in n8n.
3. Use the **HTTP Request** node with that credential to call tools via JSON-RPC.

### HTTPS / SSL
To enable HTTPS, provide both the certificate and key files.

| Variable | Description |
|----------|-------------|
| `MCP_SSL_CERT` | Path to SSL certificate file (`.crt` or `.pem`) |
| `MCP_SSL_KEY` | Path to SSL private key file (`.key`) |

### SSH Tunneling
To access a PostgreSQL database behind a bastion host, configure the following SSH variables. The server will automatically establish a secure tunnel.

| Variable | Description | Default |
|----------|-------------|---------|
| `SSH_HOST` | Bastion/Jump host address | *None* |
| `SSH_USER` | SSH username | *None* |
| `SSH_PASSWORD` | SSH password (optional) | *None* |
| `SSH_PKEY` | Path to private key file (optional) | *None* |
| `SSH_PORT` | SSH port | `22` |
| `ALLOW_SSH_AGENT` | Enable SSH agent forwarding (`true`, `1`, `yes`, `on`) | `false` |

> **Note**: When SSH is enabled, the `DATABASE_URL` should point to the database host as seen from the *bastion* (e.g., internal IP or RDS endpoint).

---

## 🔒 Logging & Security

This server implements strict security practices for logging:

- **Sanitized INFO Logs**: High-level operations (like `db_pg96_run_query` and `db_pg96_explain_query`) are logged at `INFO` level, but **raw SQL queries and parameters are never included** to prevent sensitive data leaks.
- **Fingerprinting**: Instead of raw SQL, we log SHA-256 fingerprints (`sql_sha256`, `params_sha256`) to allow correlation and debugging without exposing data.
- **Debug Mode**: Raw SQL and parameters are only logged when `MCP_LOG_LEVEL=DEBUG` is explicitly set, and even then, sensitive parameters are hashed where possible.
- **Safe Defaults**: By default, the server runs in `INFO` mode, ensuring production logs are safe.

---

## 🛠️ Tools Reference

### 🏥 Health & Info
- `db_pg96_ping()`: Simple health check.
- `db_pg96_server_info()`: Get database version, current user, and connection details.
- `db_pg96_db_stats(database: str = None, include_performance: bool = False)`: Database-level statistics.
- `db_pg96_server_info_mcp()`: Get internal MCP server status and version.

### 🔍 Schema Discovery
- `db_pg96_list_objects`: **(Consolidated Tool)** Unified tool to list databases, schemas, tables, views, indexes, functions, sequences, and temporary objects.
    - **Signature**: `db_pg96_list_objects(object_type: str, schema: str = None, owner: str = None, name_pattern: str = None, order_by: str = None, limit: int = 50)`
    - **Common Use Cases**:
        - **Table Sizes**: `object_type='table', order_by='size'`
        - **Maintenance Stats**: `object_type='table', order_by='dead_tuples'`
        - **Index Usage**: `object_type='index', order_by='scans'`
        - **Find Function**: `object_type='function', name_pattern='%my_func%'`
- `db_pg96_describe_table(schema: str, table: str)`: Get detailed column and index info for a table.
- `db_pg96_analyze_logical_data_model(schema: str = "public")`: **(Interactive)** Generates a comprehensive HTML report with a **Mermaid.js Entity Relationship Diagram (ERD)**, a **Health Score** (0-100), and detailed findings on normalization, missing keys, and naming conventions. The tool returns a URL to view the report in your browser.

### ⚡ Performance & Tuning
- `db_pg96_analyze_table_health(schema: str = None, min_size_mb: int = 50, profile: str = "oltp")`: **(Power Tool)** Comprehensive health check for bloat, vacuum needs, and optimization.
- `db_pg96_check_bloat(limit: int = 50)`: Identifies the top bloated tables and indexes and provides maintenance commands.
- `db_pg96_analyze_indexes(schema: str = None, limit: int = 50)`: Identify unused, duplicate, or missing indexes.
- `db_pg96_recommend_partitioning(min_size_gb: float = 1.0, schema: str = None)`: Suggest tables for partitioning.
- `db_pg96_explain_query(sql: str, analyze: bool = False, output_format: str = "json")`: Get the execution plan for a query.

### 🕵️ Session & Security
- `db_pg96_monitor_sessions(limit: int = 50)`: Real-time session monitoring data for the UI dashboard.
- `db_pg96_analyze_sessions(include_idle: bool = True, include_locked: bool = True)`: Detailed session analysis.
- `db_pg96_db_sec_perf_metrics(profile: str = "oltp")`: Comprehensive security and performance audit.
- `db_pg96_get_db_parameters(pattern: str = None)`: Retrieve database configuration parameters (GUCs).

### 🔧 Maintenance (Requires `MCP_ALLOW_WRITE=true`)
- `db_pg96_create_db_user(username: str, password: str, privileges: str = "read", database: str | None = None)`: Create a new database user. Defaults to the current database if `database` is not specified.
- `db_pg96_drop_db_user(username: str)`: Remove a role.
- `db_pg96_kill_session(pid: int)`: Terminate a specific backend PID.
- `db_pg96_run_query(sql: str, params_json: str | None = None, max_rows: int | None = None)`: Execute ad-hoc SQL. `max_rows` defaults to 500 (configurable via `MCP_MAX_ROWS`). Returns up to `max_rows` rows; if truncated, `truncated: true` is set.
- `db_pg96_create_object(object_type: str, object_name: str, schema: str = None, owner: str = None, parameters: dict = None)`: Create database objects (table, view, index, function, etc.).
- `db_pg96_alter_object(object_type: str, object_name: str, operation: str, schema: str = None, owner: str = None, parameters: dict = None)`: Modify database objects (add/rename column, set owner, etc.).
- `db_pg96_drop_object(object_type: str, object_name: str, schema: str = None, parameters: dict = None)`: Drop database objects with optional `cascade` or `if_exists`.

---

## 📊 Session Monitor & Web UI
 
 The server includes built-in, real-time web interfaces for monitoring and analysis. These interfaces run on a background HTTP server, even when using the `stdio` transport (Hybrid Mode).
 
 **Default Port**: `8085` (to avoid conflicts with other local services). Configurable via `MCP_PORT`.
 
 ### 1. Real-time Session Monitor
 **Access**: `http://localhost:8085/sessions-monitor`
 
 **Features**:
 - **Real-time Graph**: Visualizes active vs. idle sessions over time.
 - **Auto-Refresh**: Updates every 5 seconds without page reload.
 - **Session Stats**: Instant view of Active, Idle, and Total connections.
 
 ### 2. Logical Data Model Report
 Generated on-demand via the `db_pg96_analyze_logical_data_model` tool.
 
 **Access**: `http://localhost:8085/data-model-analysis?id=<UUID>`
 
 **Features**:
 - **Interactive ERD**: Zoomable Mermaid.js diagram of your schema.
 - **Health Score**: Automated grading of your schema design.
 - **Issues List**: Detailed breakdown of missing keys, normalization risks, and naming violations.
 
 ---
 
 ## 🛠️ Usage Examples

Here are some real-world examples of using the tools via an MCP client.

### 1. Check MCP Server Info
**Prompt:** `using postgres_readonly, call db_pg96_server_info_mcp() and display results`

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
**Prompt:** `using postgres_readonly, call db_pg96_server_info() and display results`

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
**Prompt:** `using postgres_readonly, call db_pg96_analyze_table_health(schema=smsadmin, profile=oltp) and display results`

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
**Prompt:** `using postgres_readonly, call db_pg96_analyze_table_health(schema=smsadmin, profile=oltp) and check tables that has been active in the past 60 days`

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

### 5. Performance Analysis: Long-Running Queries & Index Recommendations
**Prompt:** `using postgres_readonly, display the top 10 longest running queries in the past 10 days and recommend indexes to be created/deleted`

**Result:**

**Top 10 Longest-Running Queries (Past 10 Days)**
| Rank | Mean Time | Total Time | Calls | Query (Truncated) |
| :--- | :--- | :--- | :--- | :--- |
| 1 | ~4.9 min | ~2000 hrs | 24,449 | `call smsadmin.report_util.getreport(...)` |
| 2 | ~4.0 min | ~510 hrs | 7,672 | `call smsadmin.sms_report_engine.getresult(...)` |
| 3 | ~34 sec | ~378 hrs | 39,586 | `call smsadmin.report_util.get_column_names_cursor(...)` |
| 4 | ~5.1 sec | ~24.8 hrs | 17,576 | `select widget_id, job_parameters from smsadmin.sms_job_details where job_id = $1` |
| 5 | ~2.1 min | ~16 hrs | 458 | `call smsadmin.sms_report_engine.getresult(...)` (Variant) |
| 6 | ~1.7 sec | ~240 hrs | 520,532 | `SELECT A.BGR_GCODE from BOUNDARY2026.BND_01_BGR A ... WHERE ST_Intersects(...)` |
| 7 | ~0.3 sec | ~3.5 hrs | 44,133 | `call smsadmin.my_content_util.get_assets_dev(...)` |
| 8 | ~3.6 sec | ~18.8 hrs | 18,560 | `select coalesce((select client_id from smsadmin.user_client_mapping ...` |
| 9 | ~20 min | ~0.1 hrs | 235 | `call smsadmin.analysis_area_manager.get_geo_json_table(...)` |
| 10 | ~0.15 sec | ~40 hrs | 931,954 | `SELECT column_name FROM information_schema.columns ...` |

**Index Recommendations:**

1.  **Delete Unused Index:** `smsadmin.job_deets_time` (2GB, 0 scans).
    *   *Reason:* High maintenance cost, no usage.
2.  **Create Index:** `CREATE INDEX bnd_01_bgr_geom_geometry_idx ON BOUNDARY2026.BND_01_BGR USING GIST ((geom::geometry));`
    *   *Reason:* Optimizes `ST_Intersects` queries using geometry casting.
3.  **Delete Duplicate Index:** `boundary2026.bnd_01_bgr_pk_idx` (Duplicate of `bnd_01_bgr_pkey`).
4.  **Create Index:** `CREATE INDEX user_client_mapping_lower_user_id_idx ON smsadmin.user_client_mapping (lower(user_id));`
    *   *Reason:* Optimizes frequent case-insensitive joins on `user_id`.

### 6. Logical Data Model Analysis
**Prompt:** `using postgres_readonly, call db_pg96_analyze_logical_data_model(schema='smsadmin'). Review the resulting logical data model, which includes entities, attributes, relationships, and identifiers.`

**Result (Summarized):**
The analysis of the `smsadmin` schema reveals a significant lack of structural enforcement. While the schema contains a substantial number of entities (200 tables), it completely lacks formal relationship definitions (Foreign Keys). Additionally, a majority of tables are missing Primary Key constraints.

**Key Findings:**
*   **Total Entities Analyzed:** 200
*   **Total Relationships (FKs):** 0 (Critical Issue)
*   **Identifier Issues:** 122 tables missing or having unclear Primary Keys.
*   **Normalization Issues:** 32 potential normalization violations detected.

**Detailed Entity Analysis (Selected Examples):**

| Entity Name | PK Status | Key Attributes | Issues Identified |
| :--- | :--- | :--- | :--- |
| **`analysis_area`** | **Missing** | `area_id` (float8) | IDs are floats; Recursive relationship not enforced; No PK. |
| **`app_log`** | Valid (`log_id`) | `client_id` (varchar) | `client_id` is varchar, potentially inconsistent. Missing FKs. |
| **`attribute`** | Valid (`attribute_id`) | `dimension_id` (numeric) | IDs are `numeric` instead of `integer`. Missing FK to Dimension. |
| **`client_master`** | Missing | `client_id` (varchar) | `client_id` is the logical PK but not enforced. |

**Recommendations:**
1.  **Define Primary Keys:** Immediate action required to define PKs for `analysis_area`, `client_master`, etc.
2.  **Create Foreign Keys:** Explicitly define relationships (e.g., `app_log.client_id` -> `client_master.client_id`).
3.  **Standardize ID Types:** Migrate `double precision` and `numeric` IDs to `bigint` for consistency and performance.

### 7. Real-time Session Monitor (MCP Apps)
**Prompt:** `call db_pg96_monitor_sessions()`
 
 **Result:**
 "Monitor available at: http://localhost:8085/sessions-monitor"
 
 (Opens a dashboard with a live line graph of active vs. inactive sessions, refreshing every 5 seconds)


### 8. List Top 10 Largest Tables (Consolidated Tool)
**Prompt:** `using postgres_readonly, call db_pg96_list_objects(object_type='table', order_by='size', limit=10) and display results`

**Result:**
```json
[
  {
    "schema": "smsadmin",
    "name": "sms_fe_zp6_2025",
    "owner": "sms_user",
    "size_pretty": "38 GB",
    "size_bytes": 41355673600,
    "rows": 150000000,
    "dead_tuples": 25000,
    "last_vacuum": "2025-01-20T10:00:00"
  },
  {
    "schema": "public",
    "name": "audit_logs",
    "owner": "postgres",
    "size_pretty": "5 GB",
    "size_bytes": 5368709120,
    "rows": 2000000,
    "dead_tuples": 0,
    "last_vacuum": "2025-02-01T12:00:00"
  }
]
```

---

## 🧪 Testing & Validation

This project has been rigorously tested against **PostgreSQL 9.6** to ensure compatibility with legacy and modern environments.

### Test Results (2026-01-27)
- **Deployment**: Docker, `uv`, `npx` (All Passed)
- **Protocol**: SSE (HTTP/HTTPS), Stdio (All Passed)
- **Database**: PostgreSQL 9.6 (All Tools Verified)
- **Auth**: Token Auth, Azure AD Auth (To be verified)
   > **Verification Status**: **Token Auth** and **Azure AD Auth** have not been tested and are **not production-ready**. End-to-end verification is currently pending setup of a dedicated Azure AD tenant. While the code implements standard FastMCP patterns, these specific providers have not been validated against a live identity provider.
   > 
   > **Limitation**: As noted in [Security Constraints](#security-constraints), **Write Mode** requires mandatory authentication when using HTTP. Until **Token Auth** or **Azure AD Auth** is verified, use `stdio` transport or ensure strict network isolation if testing Write Mode.
  > 
  > **Timeline**: Verification is scheduled for the next minor release. Follow status in [Repository Issues](https://github.com/harryvaldez/mcp_cla_pg/issues).

To run the full test suite locally:
```bash
# Provisions a Postgres 9.6 container and runs all tools
python test_docker_pg96.py
```

---

## ❓ FAQ & Troubleshooting

### Frequently Asked Questions

**Q: Why is everything prefixed with `db_pg96_`?**
A: This server is explicitly versioned for PostgreSQL 9.6 compatibility to ensure stability in legacy environments. This avoids naming conflicts if you run multiple MCP servers for different database versions.

**Q: Can I use this with newer PostgreSQL versions (13, 14, 15+)?**
A: Yes! Most tools are forward-compatible. The `db_pg96_` prefix just indicates the minimum supported version.

**Q: How do I enable write operations?**
A: By default, the server is read-only. To enable write tools (like creating users or killing sessions), set the environment variable `MCP_ALLOW_WRITE=true`.

### Common Issues

**Browser Error: `Not Acceptable`**
If you visit `http://localhost:8000/mcp` in a browser, you will see a JSON error. This is normal; that endpoint is for MCP clients only. Visit `http://localhost:8000/` for the status page.

**Connection Refused**
Ensure your `DATABASE_URL` is correct. If running in Docker, remember that `localhost` inside the container refers to the container itself. Use `host.docker.internal` to reach the host machine.

**Duplicate Indexes Not Detected**
The `db_pg96_analyze_indexes` tool has been updated to group by the indexed column set. Ensure your indexes have the exact same column order and definition for detection.

---

## ✨ Enhancement Recommendations

We are actively looking for contributions to make this server even better! Here are some recommended areas for enhancement:

- **Cloud Integrations**: Add specialized support for AWS RDS, Azure Database for PostgreSQL, and Google Cloud SQL.
- **Authentication**: Test Azure AD authentication for write mode.
- **Visualization**: Integration with MCP apps or hooks for dashboard tools like Grafana.
- **Deployment**:  Deploy the container image to a more secured container repository like Azure or AWS.

If you have an idea, please submit a feature request!

---

## 📬 Contact & Support

For comments, issues, or feature enhancements, please contact the maintainer or submit an issue to the repository:

- **Repository**: https://github.com/harryvaldez/mcp_cla_pg
- **Maintainer**: Harry Valdez
- **Issues**: https://github.com/harryvaldez/mcp_cla_pg/issues
