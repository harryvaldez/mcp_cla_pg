# Deployment Guide for PostgreSQL MCP Server

This guide provides instructions for deploying the PostgreSQL MCP Server to various environments, including local development, Docker, Azure Container Apps, and AWS ECS.

## 📋 Prerequisites

Before deploying, ensure you have:
1.  **PostgreSQL Database**: A running instance (version 9.6+).
2.  **Connection String**: A valid `DATABASE_URL` (e.g., `postgresql://user:pass@host:5432/dbname`).
3.  **Container Registry**: A place to push your Docker image (e.g., Docker Hub, ACR, ECR) if deploying to the cloud.

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

Notes:
- The base image is python:3.13-slim.
- System packages and Python tooling are upgraded during build to reduce CVE exposure.
- Default HTTP port is 8000; ensure it is available locally when testing.

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

1.  **Authentication**: If using HTTP transport, enable Azure AD or another auth provider.
    *   Set `FASTMCP_AUTH_TYPE=azure-ad`.
    *   Configure Tenant/Client IDs.
2.  **Network**: Ensure the container can reach your PostgreSQL database.
    *   **Azure**: Use VNet injection if using Azure Database for PostgreSQL.
    *   **AWS**: Ensure Security Groups allow inbound port 5432 from the ECS tasks.
3.  **Secrets**: Never hardcode passwords. Use Azure Key Vault or AWS Secrets Manager where possible (templates currently use environment variables/secrets).
4.  **Write Access**: Keep `MCP_ALLOW_WRITE=false` unless explicitly required for maintenance tasks.

---

## ⚙️ Environment Variables

Key environment variables supported by the server:
- `DATABASE_URL` PostgreSQL connection string.
- `MCP_TRANSPORT` Transport mode: `http` (default) or `stdio`.
- `MCP_HOST` Host for HTTP transport, default `0.0.0.0`.
- `MCP_PORT` Port for HTTP transport, default `8000`.
- `MCP_ALLOW_WRITE` Allow write operations, default `false`.
- `MCP_CONFIRM_WRITE` Require confirmation for writes, default `false`.
- `FASTMCP_AUTH_TYPE` Authentication type (e.g., `azure-ad`).
- `FASTMCP_OIDC_CONFIG_URL` OIDC configuration URL when using Azure AD or other OIDC.
- `FASTMCP_OIDC_CLIENT_ID` OIDC client ID.
- `FASTMCP_OIDC_CLIENT_SECRET` OIDC client secret.
- `MCP_SSL_CERT` Path to TLS certificate for HTTPS.
- `MCP_SSL_KEY` Path to TLS private key for HTTPS.

These are exemplified in [docker-compose.yml](file:///c:/Users/HarryValdez/OneDrive/Documents/trae/mcp-postgres/docker-compose.yml#L5-L20).

---

## ✅ Local Validation

Use Docker Compose tests to validate the image locally:
```bash
python test_docker_pg96.py
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


To automate deployment, you can set up a GitHub Action workflow that:
1.  Triggers on push to `main`.
2.  Builds the Docker image.
3.  Pushes to ACR/ECR.
4.  Runs `az containerapp update` or updates the CloudFormation stack.
2.  Builds the Docker image.
3.  Pushes to ACR/ECR.
4.  Runs `az containerapp update` or updates the CloudFormation stack.
3.  Pushes to ACR/ECR.
4.  Runs `az containerapp update` (with the new image tag) or updates the CloudFormation stack.
