# MCP Tool Catalog — EDBAS 9.6

Canonical list of exposed MCP tools for the dual-instance EnterpriseDB Advanced Server 9.6 MCP server.

## `db_<n>_pg96_ping`

Check accessibility and identity of an EDBAS 9.6 database instance.

**Registered as:** `db_1_pg96_ping`, `db_2_pg96_ping`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `actor` | string | No | `"system"` | Caller identity for audit logging |

### Output Schema

| Field | Type | Description |
|---|---|---|
| `instance_name` | string | EDBAS cluster name from `current_setting('cluster_name')` |
| `database_version` | string | Full EDBAS version string from `version()` (e.g., "EnterpriseDB 9.6.24.10 on x86_64-pc-linux-gnu") |
| `edb_compat_mode` | string | Oracle compatibility mode: `"Oracle"` (redwood mode enabled) or `"PostgreSQL"` (default) |
| `ip_address` | string | Server IP address from `host(inet_server_addr())` |
| `current_utc_time` | string | Current UTC timestamp (ISO 8601) |

### FastMCP 3 Annotations

| Annotation | Value |
|---|---|
| `readOnlyHint` | `true` |
| `idempotentHint` | `true` |
| `openWorldHint` | `false` |
| `timeout` | `10.0` seconds |

### Tags

`read-only`, `diagnostics`, `instance-1` (or `instance-2`)

### Example Response

```json
{
  "instance_name": "edb-prod-cluster-01",
  "database_version": "EnterpriseDB 9.6.24.10 on x86_64-pc-linux-gnu, compiled by...",
  "edb_compat_mode": "Oracle",
  "ip_address": "10.125.1.15",
  "current_utc_time": "2026-05-25T18:30:00.000000Z"
}
```

### Error Codes

| Error | Description |
|---|---|
| `PING_ERROR: ...` | Database connectivity or query execution failure |
| `RATE_LIMIT_EXCEEDED` | Per-actor or global rate limit exceeded |
| `AUTH_FAILED` | Missing or invalid authentication |
