# Database Setup Guide — EDBAS 9.6

This guide outlines the minimum required privileges for the database account used by the FastMCP server.

## 1. Database Role Creation

Create a dedicated, low-privilege role for the MCP server:

```sql
CREATE ROLE mcp_readonly WITH LOGIN PASSWORD 'your_secure_password';
```

## 2. Core Privileges

The role requires access to connect to the target databases and view the schema metadata.

```sql
-- Run in each target database
GRANT CONNECT ON DATABASE your_database TO mcp_readonly;
GRANT USAGE ON SCHEMA public TO mcp_readonly;
-- Grant usage on all other schemas you wish to analyze
GRANT USAGE ON SCHEMA your_app_schema TO mcp_readonly;

-- Allow reading of table metadata
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA your_app_schema TO mcp_readonly;
```

## 3. Performance & Diagnostics Extensions

### pg_stat_statements
The `pg_stat_statements` extension must be installed in the `shared_preload_libraries`.

```sql
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
GRANT SELECT ON pg_stat_statements TO mcp_readonly;
```

### HypoPG (Virtual Indexing)
The `hypopg` extension allows the server to test potential indexes without affecting production performance.

```sql
CREATE EXTENSION IF NOT EXISTS hypopg;
-- Ensure the user can execute the virtual index functions
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mcp_readonly;
```

## 4. Advanced Diagnostics Note (Postgres 9.6)

In **Postgres 9.6/EDBAS 9.6**, certain diagnostic views have restricted visibility for non-superusers:

- **`pg_stat_activity`**: To see the full SQL text and details for sessions owned by *other* users (required for the `blocking_sessions` tool), the role typically requires **SUPERUSER** privileges. 
- If superuser status is not permitted, the `blocking_sessions` tool will only be able to analyze sessions and locks created by the `mcp_readonly` user itself, significantly limiting its diagnostic value.

## 5. Security Best Practices

- **SSL/TLS**: Ensure the user is configured to require SSL in `pg_hba.conf`.
- **Network Isolation**: The EDBAS instances should only be accessible from the MCP server's IP address/subnet.
- **Audit**: Every tool invocation is logged by the MCP server; rotate these logs to maintain a history of database activities.
