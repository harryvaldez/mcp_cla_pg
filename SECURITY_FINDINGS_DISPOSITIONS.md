# Security Findings Dispositions

## Scope
This document captures approved dispositions for scanner findings that are expected by design and are not exploitable in the current threat model.

## Dispositions

### 1) sensitive_file_access on environment lookups in server.py
- Finding class: medium
- Status: Accepted with documented rationale
- Rationale:
  - Environment variable reads such as MCP_SKILLS_DIRS, MCP_SERVER_NAME, MCP_TRANSPORT, and related runtime toggles are configuration lookups, not arbitrary file reads.
  - Values are consumed as process configuration and are constrained by explicit parsing/validation logic.
  - No direct user-supplied file path from untrusted network input is used for unrestricted filesystem access.

### 2) unknown_external_url for auth/provider domains
- Finding class: medium
- Status: Accepted with allowlist rationale
- Rationale:
  - Domains used by the server auth/integration path are fixed integration endpoints (for example login.microsoftonline.com and github.com).
  - These are service dependencies and are not dynamically composed from untrusted request input.
  - Outbound URL validation hardening is applied in remote workflow scripts/tests, and production integrations are documented as explicit dependencies.

### 3) excessive_permissions (filesystem/network/process)
- Finding class: medium
- Status: Accepted with compensating controls
- Rationale:
  - The MCP server requires process/network/filesystem capabilities for PostgreSQL operations, metadata discovery, and transport handling.
  - Destructive actions are guarded by write-mode controls (MCP_ALLOW_WRITE and MCP_CONFIRM_WRITE) and transport/auth policy checks.
  - Least-privilege operation is enforced operationally by defaulting to read-only workflows and requiring explicit opt-in for write operations.

### 4) shell_hardcoded for spawn/spawnSync in bin/mcp-postgres.js
- Finding class: medium
- Status: Accepted with compensating controls
- Rationale:
  - Process execution is required to launch the Python MCP server runtime from the Node wrapper.
  - Implementation uses explicit argument arrays and `shell: false` for both `spawnSync` probes and runtime `spawn`.
  - No user-controlled command strings are shell-interpreted.

### 5) description_empty false positives for selected tools
- Finding class: medium
- Status: Accepted as false positive after code verification
- Rationale:
  - `task_progress_demo`, `context_state_demo`, `db_pg96_create_db_user`, `db_pg96_drop_db_user`, and `db_pg96_alter_object` include non-empty `@mcp.tool(description=...)` values in code.
  - The scanner result appears to be stale or parser-limited for this pattern.

## Approval
- Owner: Security Team
- Date: 2026-04-12
- Review cadence: Revalidate on each security scan cycle and major transport/auth change.
