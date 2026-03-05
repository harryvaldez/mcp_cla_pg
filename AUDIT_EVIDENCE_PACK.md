# MCP Postgres Hardening Audit Evidence Pack

Date: 2026-03-05  
Scope: Credential scoping, rate limiting/circuit breaker, prompt audit logging

## Release History

| Date | Git commit | Docker tags | Image digest |
|------|------------|-------------|--------------|
| 2026-03-05 | `4aafa3e` | `latest`, `4aafa3e` | `sha256:81c7d249e4202277adcb6a20e4fbb21952e31b3d7b633e6ca8869f986a62b073` |
| 2026-03-05 | `c6286d4` | `latest`, `c6286d4` | `sha256:81c7d249e4202277adcb6a20e4fbb21952e31b3d7b633e6ca8869f986a62b073` |
| 2026-03-05 | `39fcfd2` | `latest`, `39fcfd2` | `sha256:d3bb0c2903f5a6e249d2d803fc87929f3ea9e350b15ab47c89e9998e0a3d82a8` |

## 1) Credential Scoping (Least Privilege)

### Control Objective
Ensure MCP uses DB credentials limited to approved tables only.

### Implementation Evidence
- Startup gate and config flags: `MCP_ENFORCE_TABLE_SCOPE`, `MCP_ALLOWED_TABLES` in `server.py`.
- Scope validation logic: `_validate_table_scope()` verifies:
  - user cannot `SELECT` outside allowed list,
  - allowed list is actually selectable,
  - in read-only mode, user has no write-capable table privileges.

Code references:
- `server.py` lines around `MCP_ENFORCE_TABLE_SCOPE` and `_validate_table_scope`

Documentation references:
- `README.md` hardening config table and notes
- `DEPLOYMENT.md` runtime credential scope enforcement section

### Test Evidence
- `tests/test_hardening.py::test_credential_scope_enforcement_blocks_out_of_scope_tables`

---

## 2) Rate Limiting + Circuit Breaker

### Control Objective
Prevent runaway AI loops from overwhelming the database.

### Implementation Evidence
- Query limiter/breaker config:
  - `MCP_RATE_LIMIT_ENABLED`
  - `MCP_RATE_LIMIT_PER_MINUTE`
  - `MCP_BREAKER_TRIP_REJECTIONS`
  - `MCP_BREAKER_OPEN_SECONDS`
- Token bucket + breaker implementation: `_QueryRateCircuitBreaker`.
- Enforcement point: `_enforce_query_rate_limit()` called in `_execute_safe()` before SQL execution.

Code references:
- `server.py` lines around `_QueryRateCircuitBreaker`, `_enforce_query_rate_limit`, `_execute_safe`

Documentation references:
- `README.md` configuration table
- `DEPLOYMENT.md` query flood protection section

### Test Evidence
- `tests/test_hardening.py::test_query_rate_circuit_breaker_opens_after_sustained_rejections`

---

## 3) Audit Logging of Exact AI Prompt

### Control Objective
Persist the originating natural-language prompt used to produce database queries.

### Implementation Evidence
- Audit event writer: `_write_audit_event()` writes JSONL records with:
  - `timestamp_utc`, `tool`, `sql_len`, `sql_sha256`,
  - `source_prompt` (exact prompt),
  - `source_prompt_sha256`,
  - optional raw SQL when `MCP_AUDIT_LOG_SQL_TEXT=true`.
- Query tools now accept `source_prompt`:
  - `db_pg96_run_query(..., source_prompt: str | None = None)`
  - `db_pg96_explain_query(..., source_prompt: str | None = None)`
- Enforce presence via `MCP_AUDIT_REQUIRE_PROMPT=true`.

Code references:
- `server.py` lines around `_write_audit_event`, `db_pg96_run_query`, `db_pg96_explain_query`

Documentation references:
- `README.md` tool signatures + audit env vars
- `DEPLOYMENT.md` prompt-to-query audit logging section

### Test Evidence
- `tests/test_hardening.py::test_audit_policy_requires_source_prompt`

---

## Test Run Evidence

Executed commands:
- `.\\.venv\\Scripts\\python.exe -m pytest -q tests/test_hardening.py`
- `.\\.venv\\Scripts\\python.exe -m pytest -q tests/test_logging.py tests/test_hardening.py`
- `.\\.venv\\Scripts\\python.exe -m pytest -q`

Observed results:
- `3 passed` (hardening tests)
- `4 passed` (logging + hardening)
- `7 passed, 2 skipped` (full suite)

---

## Recommended Production Settings

Set and tune based on workload:

```env
MCP_ALLOW_WRITE=false
MCP_ENFORCE_TABLE_SCOPE=true
MCP_ALLOWED_TABLES=public.customers,public.orders

MCP_RATE_LIMIT_ENABLED=true
MCP_RATE_LIMIT_PER_MINUTE=300
MCP_BREAKER_TRIP_REJECTIONS=10
MCP_BREAKER_OPEN_SECONDS=60

MCP_AUDIT_LOG_FILE=/var/log/mcp/mcp_audit.log
MCP_AUDIT_LOG_SQL_TEXT=false
MCP_AUDIT_REQUIRE_PROMPT=true
```

## Operational Notes
- Keep DB role privileges minimal (GRANT only required schemas/tables).
- Rotate and protect audit logs (file permissions, retention policy, central shipping).
- If `MCP_AUDIT_REQUIRE_PROMPT=true`, ensure AI tool callers always populate `source_prompt`.
