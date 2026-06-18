# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities via private email or your organization's security channel. Do not open public issues.

## Security Model

### Least Privilege

Dedicated EDBAS roles with read-only or scoped access are required. Each instance uses its own credentials via environment variables.

### Read-Only Default

The runtime policy enforces `write_mode_default: deny`. All write operations are blocked unless the tool is explicitly listed in `allowed_write_tools`.

### EDBAS-Specific DDL Blocking

The blocked SQL patterns include EDBAS Oracle-compatible DDL:
- `CREATE OR REPLACE PACKAGE`
- `CREATE TYPE BODY`
- `CREATE SYNONYM`
- `CREATE DIRECTORY`

### SSL Enforcement

All database connections use `sslmode: require` by default. Configure `verify-full` for production.

### Audit Logging

Structured JSON audit events are written to `/var/log/mcp/audit.log` for every tool invocation, including:
- Request ID, actor identity, tool name, instance target
- SQL text hash (SHA-256 truncated)
- Decision outcome (allow/deny), latency, row count
- Error codes for denied requests

### Container Hardening

- Non-root user (`mcpuser`, UID 10001)
- Read-only root filesystem
- All Linux capabilities dropped
- `no-new-privileges` security option
- Writable volume restricted to `/var/log/mcp` (tmpfs for `/tmp`)

### Error Masking

FastMCP 3 `mask_error_details=True` is enabled in production to prevent internal error information leakage.

### Stateless HTTP

`stateless_http=True` mode prevents cross-request session state accumulation.

## Configuration Guidance

- Never commit `.env` files
- Store secrets in environment variables or Docker secrets
- Rotate credentials according to your organization's policy
- Enable `verify-full` SSL mode when using trusted CA certificates
- Pin FastMCP dependency versions in production
