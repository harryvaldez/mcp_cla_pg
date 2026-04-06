# Deployment Guide for PostgreSQL MCP Server

This guide provides instructions for deploying the PostgreSQL MCP Server to various environments, including local development, Docker, Azure Container Apps, and AWS ECS.

## 📋 Prerequisites

Before deploying, ensure you have:
1.  **PostgreSQL Database**: A running instance (version 9.6+).
2.  **Connection String**: A valid `DATABASE_URL` (e.g., `postgresql://user:pass@host:5432/dbname`).
3.  **Container Registry**: A place to push your Docker image (e.g., Docker Hub, ACR, ECR) if deploying to the cloud.

---

## 🌐 Remote Access & Networking

### Exposing the Server
By default, the server binds to `0.0.0.0` (all interfaces) when running via Docker or if `MCP_HOST` is set. To allow external tools (like n8n Cloud) to connect:

1.  **Public IP / DNS**: Ensure your machine has a public IP or dynamic DNS hostname.
2.  **Firewall Rules**: Open the port (default 8085) in your OS firewall.
    *   **Windows (PowerShell)**:
        ```powershell
        netsh advfirewall firewall add rule name="MCP Server 8085" dir=in action=allow protocol=TCP localport=8085
        ```
    *   **Linux (ufw)**:
        ```bash
        sudo ufw allow 8085/tcp
        ```
3.  **Tunnels (Alternative)**: Use a tunneling service like [ngrok](https://ngrok.com/) to bypass firewall/NAT issues during development.
    ```bash
    ngrok http 8085
    ```

---

## 💻 Local Development

### Option 1: Python (uv)
Best for rapid development and testing.

```bash
# 1. Install dependencies
uv sync

# 2. Set environment variables
$env:DATABASE_URL="postgresql://user:pass@localhost:5432/dbname"

# 3. Run server
uv run mcp-postgres
```

### Option 2: Docker Compose
Best for testing the containerized environment locally.

```bash
# 1. Update docker-compose.yml with your database credentials if needed

# 2. Build and run
docker compose up --build
```

---

## 🐳 Building the Docker Image

To deploy to the cloud, you first need to build and push the image.

```bash
# Build
docker build -t harryvaldez/mcp-postgres:latest .

# Push
docker push harryvaldez/mcp-postgres:latest
```

Current published tags:
- `harryvaldez/mcp-postgres:latest`
- `harryvaldez/mcp-postgres:v1.0.1`
- `harryvaldez/mcp-postgres:bf1b5a2`

Notes:
- The base image is python:3.13-slim.
- System packages and Python tooling are upgraded during build to reduce CVE exposure.
- Default HTTP port is 8085; ensure it is available locally when testing.

---

## ☁️ Azure Container Apps (ACA)

We provide a Bicep template (`deploy/azure-aca.bicep`) for easy deployment to Azure.

### Features
*   **Serverless**: Scale to zero capability (though minReplicas=1 is recommended).
*   **Secure**: Secrets management for `DATABASE_URL`.
*   **Health Checks**: Built-in liveness and readiness probes.

### Deployment Steps

1.  **Login to Azure**:
    ```bash
    az login
    ```

2.  **Deploy using CLI**:
    ```bash
    az deployment group create \
      --resource-group <YourResourceGroup> \
      --template-file deploy/azure-aca.bicep \
      --parameters \
        containerImage="harryvaldez/mcp-postgres:latest" \
        databaseUrl="postgresql://user:pass@host:5432/dbname" \
        allowWrite=false
    ```

---

## ☁️ AWS ECS (Fargate)

We provide a CloudFormation template (`deploy/aws-ecs.yaml`) for deploying to AWS Fargate.

### Features
*   **Serverless Compute**: No EC2 instances to manage.
*   **Logging**: Integrated with CloudWatch Logs.
*   **IAM Roles**: Least privilege access for ECS tasks.

### Deployment Steps

1.  **Upload Template**: Go to the AWS CloudFormation console and upload `deploy/aws-ecs.yaml`.

2.  **Configure Parameters**:
    *   **VpcId**: Select your VPC (must have connectivity to your RDS/Database).
    *   **SubnetIds**: Select private subnets (recommended).
    *   **ContainerImage**: Your ECR image URI.
    *   **DatabaseUrl**: Your connection string.

3.  **Deploy**: Create the stack.

---

## 🔒 Security Checklist

When deploying to production, verify the following:

1. **Authentication**: If using HTTP transport, enable an auth provider (Azure AD, GitHub, Google, or API Key).
   * Set `FASTMCP_AUTH_TYPE` to your preferred mode.
   * For machine-to-machine (e.g., n8n), use `apikey` with `FASTMCP_API_KEY`.
   * For human-in-the-loop, use `github`, `google`, or `azure-ad`.
2. **Network**: Ensure the container can reach your PostgreSQL database.
   * **Azure**: Use VNet injection if using Azure Database for PostgreSQL.
   * **AWS**: Ensure Security Groups allow inbound port 5432 from the ECS tasks.
3. **Secrets**: Never hardcode passwords. Use Azure Key Vault or AWS Secrets Manager where possible (templates currently use environment variables/secrets).
4. **Write Access**: Keep `MCP_ALLOW_WRITE=false` unless explicitly required for maintenance tasks.

---


## ⚙️ Environment Variables

Key environment variables supported by the server (including all new runtime config toggles):

- `DATABASE_URL` PostgreSQL connection string.
- `MCP_TRANSPORT` Transport mode: `http` (recommended default), `stdio`, or `sse` (legacy compatibility).
- `MCP_HOST` Host for HTTP transport, default `0.0.0.0`.
- `MCP_PORT` Port for HTTP transport, default `8085`.
- `MCP_ALLOW_WRITE` Allow write operations, default `false`.
- `MCP_CONFIRM_WRITE` Require confirmation for writes, default `false`.
- `MCP_SKIP_CONFIRMATION` Skip startup confirmation dialog, default `false`.
- `MCP_STRICT_VALIDATION` Enable strict runtime validation of requests and config, default `false`.
- `MCP_MASK_ERROR_DETAILS` Mask error details in responses for security, default `false`.
- `MCP_DUPLICATE_REGISTRATION` Control duplicate registration behavior: `warn`, `error`, `silent` (default `warn`).
- `MCP_POOL_MAX_WAITING` Max queries queued when pool is full.
- `MCP_STATEMENT_TIMEOUT_MS` Max execution time per query in milliseconds.
- `MCP_RATE_LIMIT_ENABLED` Enable query-level token-bucket rate limiting and breaker.
- `MCP_RATE_LIMIT_PER_MINUTE` Allowed query executions per minute before throttling.
- `MCP_BREAKER_TRIP_REJECTIONS` Consecutive throttles before opening breaker.
- `MCP_BREAKER_OPEN_SECONDS` Seconds to hold breaker open after trip.
- `MCP_ENFORCE_TABLE_SCOPE` Validate DB credential can only `SELECT` allowed tables at startup.
- `MCP_ALLOWED_TABLES` Comma-separated allowed table list (`schema.table`) when scope enforcement is enabled.
- `MCP_AUDIT_LOG_FILE` JSONL file path for query audit events (includes `source_prompt`).
- `MCP_AUDIT_LOG_SQL_TEXT` Include raw SQL text in audit events (otherwise hash/length only).
- `MCP_AUDIT_REQUIRE_PROMPT` Require `source_prompt` for `run_query`/`explain_query` calls.
- `MCP_LOG_LEVEL` Logging level (DEBUG, INFO, WARNING, ERROR).
- `MCP_LOG_FILE` Optional path to write logs to a file.
- `FASTMCP_TASKS_ENABLED` Optional FastMCP background tasks toggle (`true`/`false`).
- `MCP_TASKS_ENABLED` Backward-compatible alias for `FASTMCP_TASKS_ENABLED`.
- `FASTMCP_LIST_PAGE_SIZE` Optional FastMCP pagination size for `tools/list`, `resources/list`, `resources/templates/list`, and `prompts/list` (must be positive integer).
- `MCP_LIST_PAGE_SIZE` Backward-compatible alias for `FASTMCP_LIST_PAGE_SIZE`.
- `FASTMCP_SAMPLING_HANDLER` Optional FastMCP sampling fallback provider: `openai`, `anthropic`, or `none`.
- `MCP_SAMPLING_HANDLER` Backward-compatible alias for `FASTMCP_SAMPLING_HANDLER`.
- `FASTMCP_SAMPLING_HANDLER_BEHAVIOR` Sampling handler mode: `fallback` (default) or `always`.
- `MCP_SAMPLING_HANDLER_BEHAVIOR` Backward-compatible alias for `FASTMCP_SAMPLING_HANDLER_BEHAVIOR`.
- `FASTMCP_SAMPLING_DEFAULT_MODEL` Optional default model hint for sampling handler (for example, `gpt-4o-mini`).
- `MCP_SAMPLING_DEFAULT_MODEL` Backward-compatible alias for `FASTMCP_SAMPLING_DEFAULT_MODEL`.
- `MCP_SKILLS_RESOURCES_ENABLED` Enable local "skills as resources" endpoints (`skills://index`, `skills://{skill_id}`).
- `MCP_SKILLS_DIRS` Optional skill root directories (comma-separated; semicolon also supported), each containing `<skill>/SKILL.md`.
- `FASTMCP_SKILLS_DIRS` Alias for `MCP_SKILLS_DIRS`.
- `MCP_SKILLS_PROVIDER_ENABLED` Enable FastMCP skills provider registration (default `true`).
- `MCP_SKILLS_PROVIDER_RELOAD` Enable provider auto-reload (default `false`; keep `false` in production).
- `MCP_SKILLS_SUPPORTING_FILES_MODE` Supporting files mode: `template` or `resources` (default `template`).

Production guidance:
- Keep `MCP_SKILLS_PROVIDER_RELOAD=false` in production.
- Restrict `MCP_SKILLS_DIRS` to trusted directories only.
- `FASTMCP_INCLUDE_TAGS` Optional server-level visibility allow-list tags (comma-separated; semicolon also supported).
- `MCP_INCLUDE_TAGS` Alias for `FASTMCP_INCLUDE_TAGS` (comma-separated; semicolon also supported).
- `FASTMCP_EXCLUDE_TAGS` Optional server-level visibility block-list tags (comma-separated; semicolon also supported).
- `MCP_EXCLUDE_TAGS` Alias for `FASTMCP_EXCLUDE_TAGS`.
- `FASTMCP_INCLUDE_META` Optional FastMCP metadata visibility toggle (`true`/`false`).
- `MCP_INCLUDE_META` Alias for `FASTMCP_INCLUDE_META`.
- `FASTMCP_GITHUB_CLIENT_ID` / `FASTMCP_GITHUB_CLIENT_SECRET` GitHub OAuth credentials.
- `FASTMCP_GOOGLE_CLIENT_ID` / `FASTMCP_GOOGLE_CLIENT_SECRET` Google OAuth credentials.
- `FASTMCP_AZURE_AD_TENANT_ID` / `FASTMCP_AZURE_AD_CLIENT_ID` Azure AD credentials.
- `FASTMCP_CLIENT_STORAGE_BACKEND` Optional OAuth client storage backend (`memory`, `disk`/`file`, `redis`).
- `FASTMCP_CLIENT_STORAGE_PATH` Directory for `disk` client storage (default `.fastmcp-client-storage`).
- `FASTMCP_CLIENT_STORAGE_REDIS_URL` Redis URL for client storage. If unset, configure `FASTMCP_CLIENT_STORAGE_REDIS_HOST` (default `localhost`), `FASTMCP_CLIENT_STORAGE_REDIS_PORT` (default `6379`), `FASTMCP_CLIENT_STORAGE_REDIS_DB` (default `0`), and optional `FASTMCP_CLIENT_STORAGE_REDIS_PASSWORD`.
- `FASTMCP_CLIENT_STORAGE_ENCRYPTION_KEY` Optional Fernet key for encrypting client storage values.
- `MCP_SSL_CERT` Path to TLS certificate for HTTPS.
- `MCP_SSL_KEY` Path to TLS private key for HTTPS.

These are exemplified in [docker-compose.yml](docker-compose.yml).

For Background Tasks support, install `fastmcp[auth,tasks]` (already reflected in this repository dependency manifests).

---

## ✅ Local Validation

Use Docker Compose tests to validate the image locally:
```bash
python test_docker_pg96.py
```
For the default local validation path used in this repository:
```bash
python -m pytest -q
```
If port 8000 is in use, stop conflicting services or run:
```bash
docker compose -f docker-compose.yml down
```

## 🔄 CI/CD (GitHub Actions)
---

## 🗝️ Database Privileges

Configure two roles aligned to MCP modes:

### Read-Only User
Minimal privileges for safe querying.

```sql
-- Create login role
CREATE ROLE mcp_readonly WITH LOGIN PASSWORD 'strong_password';

-- Database access
GRANT CONNECT ON DATABASE your_db TO mcp_readonly;

-- Schema access
GRANT USAGE ON SCHEMA public TO mcp_readonly;

-- Existing objects
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;
-- Optional if reading sequence values
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_readonly;

-- Future objects created by the executing role
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT ON TABLES TO mcp_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT ON SEQUENCES TO mcp_readonly;

-- If multiple creator roles exist, repeat with FOR ROLE
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
  GRANT SELECT ON TABLES TO mcp_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
  GRANT SELECT ON SEQUENCES TO mcp_readonly;
```

### Read/Write User
Full DML privileges and sequence access.

```sql
-- Create login role
CREATE ROLE mcp_rw WITH LOGIN PASSWORD 'strong_password';

-- Database privileges (CONNECT, CREATE, TEMPORARY)
GRANT ALL PRIVILEGES ON DATABASE your_db TO mcp_rw;

-- Schema privileges
GRANT ALL PRIVILEGES ON SCHEMA public TO mcp_rw;

-- Existing objects
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mcp_rw;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO mcp_rw;

-- Future objects created by the executing role
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON TABLES TO mcp_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO mcp_rw;

-- If multiple creator roles exist, repeat with FOR ROLE
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
  GRANT ALL ON TABLES TO mcp_rw;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO mcp_rw;
```

Notes:
- Repeat GRANTs per schema beyond `public` as needed.
- ALTER DEFAULT PRIVILEGES affects objects created by the specified role; include `FOR ROLE <creator>` to cover other creators.

### Optional Runtime Credential Scope Enforcement

To enforce least privilege at MCP startup (fail fast if the credential can read beyond approved tables):

```bash
MCP_ENFORCE_TABLE_SCOPE=true
MCP_ALLOWED_TABLES=public.customers,public.orders,analytics.daily_metrics
```

Behavior:
- Server startup fails if the DB user can `SELECT` any non-system table outside `MCP_ALLOWED_TABLES`.
- Server startup fails if `MCP_ALLOWED_TABLES` includes a table the user cannot `SELECT`.
- In read-only mode (`MCP_ALLOW_WRITE=false`), startup fails if table-level write privileges are detected.

### Query Flood Protection (Rate Limit + Circuit Breaker)

The server supports query-level throttling to protect against runaway AI loops:

```bash
MCP_RATE_LIMIT_ENABLED=true
MCP_RATE_LIMIT_PER_MINUTE=600
MCP_BREAKER_TRIP_REJECTIONS=20
MCP_BREAKER_OPEN_SECONDS=30
```

### Prompt-to-Query Audit Logging

`db_pg96_run_query` and `db_pg96_explain_query` accept optional `source_prompt` and write JSONL audit records.

```bash
MCP_AUDIT_LOG_FILE=mcp_audit.log
MCP_AUDIT_LOG_SQL_TEXT=false
MCP_AUDIT_REQUIRE_PROMPT=false
```

Set `MCP_AUDIT_REQUIRE_PROMPT=true` to reject query-tool calls that omit `source_prompt`.


To automate deployment, you can set up a GitHub Action workflow that:
1.  Triggers on push to `main`.
2.  Builds the Docker image.
3.  Pushes to ACR/ECR.
4.  Runs `az containerapp update` (with the new image tag) or updates the CloudFormation stack.
