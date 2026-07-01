# Implementation Plan: analyze-sett-sec

## Overview

Add `db_{n}_pg96_analyze_sett_sec` (orchestrator) and three independently callable sub-tools
(`check_db_parameters`, `compute_db_metrics`, `analyze_db_security`) to the dual-instance MCP
server. All reusable logic lives in a new `src/tools/settings_security.py` module, mirroring the
`table_analysis.py` / `hypopg_tools.py` pattern. Registration, middleware wiring, config flags,
and catalog docs follow the established project conventions.

## Tasks

- [ ] 1. Create `src/tools/settings_security.py` — module scaffold and imports
  - Create the file with module-level docstring matching the style of `table_analysis.py`
  - Add `from __future__ import annotations`, stdlib imports (`logging`, `typing.Any`), and `asyncpg` type hint
  - Declare `logger = logging.getLogger(__name__)`
  - Do NOT import from `src/tools/pg_tools.py` or any FastMCP tool-registration API (Requirement 6.4)
  - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [ ] 2. Implement `check_db_parameters()` in `settings_security.py`
  - [ ] 2.1 Implement the function signature and pg_settings query
    - `async def check_db_parameters(conn: Any, database_name: str) -> dict[str, Any]`
    - Query `pg_settings` with `SELECT name, setting, unit, category, short_desc FROM pg_settings`
    - Build a lookup dict keyed by parameter name for all subsequent checks
    - _Requirements: 3.2, 6.2_

  - [ ] 2.2 Implement the 7-category parameter evaluation loop (Memory, WAL/Checkpoint, Planner/Optimizer, Autovacuum, Logging, Connections, Security/Auth)
    - Evaluate 60+ parameters against EDBAS 9.6 best-practice rules defined in a static curated list
    - Each rule specifies: `parameter`, `recommended_value`, `category`, `severity`, `rationale`
    - Produce a `findings` list — only emit entries for parameters that deviate from best practice
    - _Requirements: 3.2, 3.4_

  - [ ] 2.3 Apply CRITICAL/HIGH/MEDIUM/LOW severity rules exactly
    - `autovacuum = off` → CRITICAL (Requirement 3.5)
    - `ssl = off` → CRITICAL (Requirement 3.6)
    - `archive_mode = on` AND archive_command empty/unconfigured → CRITICAL (Requirement 3.7)
    - `shared_buffers` below 128 MB → HIGH (Requirement 3.8)
    - `logging_collector`, `log_connections`, `log_disconnections` all `off` → HIGH (Requirement 3.9)
    - Suboptimal planner cost params / `log_lock_waits` off → MEDIUM or LOW (Requirement 3.10)
    - _Requirements: 3.5, 3.6, 3.7, 3.8, 3.9, 3.10_

  - [ ] 2.4 Build and return the output dict
    - Return `{"parameter_analysis": {"total": N, "compliant": N, "warnings_count": N, "critical_count": N}, "findings": [...]}`
    - Each finding: `{"parameter", "current_value", "recommended_value", "category", "severity", "rationale"}`
    - Convert any non-JSON-serializable values (datetime, Decimal) to strings or numbers
    - _Requirements: 3.3, 3.4, 10.1, 10.2, 10.3_

  - [ ] 2.5 Write property test — P5: check_db_parameters Output Schema
    - **Property 5: check_db_parameters Output Schema**
    - For any mock pg_settings input, assert top-level keys `parameter_analysis` and `findings` present; `parameter_analysis` contains `total`, `compliant`, `warnings_count`, `critical_count`; every finding has `parameter`, `current_value`, `recommended_value`, `category`, `severity`, `rationale`
    - **Validates: Requirements 3.3, 3.4**

  - [ ] 2.6 Write property test — P4: Parameter Severity Classification
    - **Property 4: Parameter Severity Classification**
    - Generate mock pg_settings rows with controlled values for `autovacuum`, `ssl`, `archive_mode`/`archive_command`, `shared_buffers`, and logging params; assert the severity assigned matches the exact rules
    - **Validates: Requirements 3.5, 3.6, 3.7, 3.8, 3.9, 3.10**

- [ ] 3. Implement `compute_db_metrics()` in `settings_security.py`
  - [ ] 3.1 Implement the function signature and all required SQL queries
    - `async def compute_db_metrics(conn: Any, database_name: str) -> dict[str, Any]`
    - Query `pg_stat_database` (blks_hit, blks_read, xact_commit, xact_rollback, tup_*, deadlocks, blk_read_time, blk_write_time) WHERE `datname = $1`
    - Query `pg_stat_bgwriter` for checkpoint/buffer metrics
    - Query `pg_stat_user_tables` (aggregated totals: n_dead_tup, n_live_tup) for dead tuple ratio
    - Query `pg_settings` for `max_connections`
    - Query `pg_database` for `age(datfrozenxid)` and `pg_database_size()`
    - _Requirements: 4.2, 6.2_

  - [ ] 3.2 Compute cache hit ratio with null-safe division
    - `cache_hit_ratio_pct = 100.0 * blks_hit / (blks_hit + blks_read)` when denominator > 0
    - Return `null` or `0` when denominator is zero — never raise ZeroDivisionError (Requirement 4.5)
    - _Requirements: 4.4, 4.5_

  - [ ] 3.3 Compute connection utilization sub-dict
    - `{"used": numbackends, "max": max_connections, "utilization_pct": 100.0 * numbackends / max_connections}` with null-safe division
    - _Requirements: 4.6_

  - [ ] 3.4 Compute TXID wraparound risk level
    - Retrieve `age(datfrozenxid)` from `pg_database` WHERE `datname = $1`
    - Apply 4-tier thresholds: >1,500,000,000 → CRITICAL; 1,000,000,001–1,500,000,000 → HIGH; 500,000,001–1,000,000,000 → MEDIUM; ≤500,000,000 → LOW
    - Return `txid_metrics = {"max_xid_age": N, "database_frozen_xid_age": N, "wraparound_risk_level": "..."}`
    - _Requirements: 4.7, 4.8, 4.9, 4.10, 4.11_

  - [ ] 3.5 Assemble and return all 8 top-level keys
    - Return dict with exactly: `cache_hit_ratio_pct`, `transaction_metrics`, `tuple_metrics`, `query_latency`, `connection_utilization`, `txid_metrics`, `database_size`, `dead_tuple_ratio_pct`
    - Convert all datetime/Decimal/pg numeric types to Python float/int/str before returning
    - _Requirements: 4.3, 10.1, 10.3_

  - [ ] 3.6 Write property test — P7: compute_db_metrics Output Schema Completeness
    - **Property 7: compute_db_metrics Output Schema Completeness**
    - For any valid mock database stats input, assert all 8 top-level keys are present in the returned dict
    - **Validates: Requirement 4.3**

  - [ ] 3.7 Write property test — P6: Cache Hit Ratio Formula Correctness
    - **Property 6: Cache Hit Ratio Formula Correctness**
    - For arbitrary non-negative integers `blks_hit` and `blks_read` with sum > 0, assert `cache_hit_ratio_pct == 100.0 * blks_hit / (blks_hit + blks_read)`; for sum == 0, assert no exception and result is `null` or `0`
    - **Validates: Requirements 4.4, 4.5**

  - [ ] 3.8 Write property test — P8: TXID Wraparound Risk Level Classification
    - **Property 8: TXID Wraparound Risk Level Classification**
    - For arbitrary non-negative xid_age values, assert `wraparound_risk_level` matches the 4-tier thresholds exactly (boundary values included)
    - **Validates: Requirements 4.8, 4.9, 4.10, 4.11**

- [ ] 4. Implement `analyze_db_security()` in `settings_security.py`
  - [ ] 4.1 Implement the function signature and all required SQL queries
    - `async def analyze_db_security(conn: Any, database_name: str) -> dict[str, Any]`
    - Query `pg_settings` for `ssl`, `archive_mode`, `archive_command`, `password_encryption`, `log_connections`, `log_disconnections`, `log_statement`
    - Query `pg_stat_ssl` for rows WHERE `ssl = false`
    - Query `pg_stat_archiver` for `archived_count`, `failed_count`, `last_archived_time`
    - Query `pg_roles` WHERE `rolsuper = true` for superuser list
    - Query `pg_namespace` for public schema ACL to detect `CREATE` privilege granted to `PUBLIC`
    - _Requirements: 5.2, 6.2_

  - [ ] 4.2 Implement SSL and unencrypted connections checks (CRITICAL / HIGH)
    - `ssl = off` → CRITICAL finding: check="SSL Disabled", severity="CRITICAL" (Requirement 5.5)
    - `pg_stat_ssl` rows with `ssl = false` → HIGH finding for unencrypted active connections (Requirement 5.11)
    - _Requirements: 5.5, 5.11_

  - [ ] 4.3 Implement WAL archiver health checks (CRITICAL / HIGH)
    - `archive_mode = on` AND `failed_count > 0` → CRITICAL (Requirement 5.6)
    - `archive_mode = on` AND `last_archived_time IS NULL` → CRITICAL (Requirement 5.7)
    - `last_archived_time` > 24 hours ago → HIGH (Requirement 5.8)
    - Convert `last_archived_time` to ISO 8601 string in output — never raw datetime (Requirement 10.2)
    - _Requirements: 5.6, 5.7, 5.8, 10.2_

  - [ ] 4.4 Implement superuser sprawl, password encryption, and audit logging checks (MEDIUM)
    - Superuser count > 3 → MEDIUM; list role names in `detail` field (Requirement 5.9)
    - `password_encryption` not `scram-sha-256` and not `md5` → MEDIUM (Requirement 5.10)
    - All of `log_connections`, `log_disconnections`, `log_statement` are `off` → MEDIUM (Requirement 5.12)
    - Public schema CREATE to PUBLIC → MEDIUM (Requirement 5.13)
    - _Requirements: 5.9, 5.10, 5.12, 5.13_

  - [ ] 4.5 Enforce credential-safe output in all finding fields
    - Never include SSL key file paths, connection strings, passwords, or raw `pg_settings` secret values in any `detail` or `recommendation` field
    - Strip or omit any `pg_settings` value that matches patterns for file paths or auth credentials
    - _Requirements: 5.14, 7.4_

  - [ ] 4.6 Build and return the output dict
    - Return `{"total_checks": N, "passed": N, "warnings": N, "critical_findings": N, "findings": [...]}`
    - Each finding: `{"check", "status", "severity", "detail", "recommendation"}`
    - Ensure all values are JSON-serializable (Requirement 10.1)
    - _Requirements: 5.3, 5.4, 10.1_

  - [ ] 4.7 Write property test — P12: analyze_db_security Output Schema
    - **Property 12: analyze_db_security Output Schema**
    - For any mock database state, assert 5 required top-level keys present; assert every findings entry has `check`, `status`, `severity`, `detail`, `recommendation`
    - **Validates: Requirements 5.3, 5.4**

  - [ ] 4.8 Write property test — P9: Security Finding Severity for SSL Disabled
    - **Property 9: Security Finding Severity for SSL Disabled**
    - When mock pg_settings has `ssl = "off"`, assert at least one finding with `severity = "CRITICAL"` and a `check` field identifying the SSL disabled condition; assert `critical_findings >= 1`
    - **Validates: Requirement 5.5**

  - [ ] 4.9 Write property test — P10: Security Finding Severity for WAL Archiver Failure
    - **Property 10: Security Finding Severity for WAL Archiver Failure**
    - For mock pg_stat_archiver where `archive_mode = on` and `failed_count > 0`, assert CRITICAL severity finding; repeat with `last_archived_time = NULL`, assert CRITICAL
    - **Validates: Requirements 5.6, 5.7**

  - [ ] 4.10 Write property test — P11: Superuser Count Threshold Finding
    - **Property 11: Superuser Count Threshold Finding**
    - For mock pg_roles with more than 3 rows where `rolsuper = true`, assert MEDIUM severity finding whose `detail` or `recommendation` contains all superuser role names
    - **Validates: Requirement 5.9**

  - [ ] 4.11 Write property test — P13: No Credential Leakage in Security Output
    - **Property 13: No Credential Leakage in Security Output**
    - Inject mock pg_settings values resembling passwords, SSL key paths, and connection strings; assert none of those raw values appear verbatim in any `detail` or `recommendation` field of the output
    - **Validates: Requirements 5.14, 7.4**

- [ ] 5. Checkpoint — verify settings_security.py in isolation
  - Run `ruff check src/tools/settings_security.py` and fix any lint errors
  - Ensure all three functions are importable: `from src.tools.settings_security import check_db_parameters, compute_db_metrics, analyze_db_security`
  - Ask the user if any questions arise before proceeding to pg_tools.py changes

- [ ] 6. Add 4 tool_enable_flags to `config/runtime-policy.yaml`
  - Append under the existing `tool_enable_flags` block:
    ```yaml
    analyze_sett_sec: true
    check_db_parameters: true
    compute_db_metrics: true
    analyze_db_security: true
    ```
  - Verify the YAML parses cleanly (no duplicate keys, correct indentation)
  - _Requirements: 9.1, 9.2, 9.3_

- [ ] 7. Register the three sub-tools in `pg_tools.py`
  - [ ] 7.1 Add import for the new module at the top of `pg_tools.py`
    - Add `from src.tools import settings_security` alongside the existing `table_analysis` and `hypopg_tools` imports
    - _Requirements: 6.1_

  - [ ] 7.2 Implement `_register_sett_sec_sub_tool()` helper inside `register_pg_tools()`
    - Mirror the `_register_sub_tool()` helper pattern but accept `(toolname, func, timeout=45.0)` and use `database_name` (not `schema_name`/`table_name`) as the user-facing parameter
    - Annotations: `readOnlyHint=True`, `idempotentHint=False`, `openWorldHint=False`; tags: `read-only`, `maintenance`, `security`, `instance-{n}`; timeout 45.0s
    - Standard lifecycle: `validate_database_name` → `_resolve_actor_and_authorize` → `session_manager.touch` → `rate_limiter.allow` → `write_guard.enforce` → `async with acquire` → call `func(conn, database_name)` → audit in `finally`
    - Wrap unhandled exceptions in `ToolError` with error_code string (Requirement 8.6)
    - _Requirements: 1.3, 1.4, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [ ] 7.3 Register `check_db_parameters`, `compute_db_metrics`, `analyze_db_security` sub-tools
    - Inside the instance loop, guard each with `is_tool_enabled(state.policy, instance_id, "<toolname>")` before calling `_register_sett_sec_sub_tool()`
    - Append each full tool name to `registered`
    - _Requirements: 3.1, 4.1, 5.1, 9.2_

- [ ] 8. Register the orchestrator tool in `pg_tools.py`
  - [ ] 8.1 Implement the `analyze_sett_sec` orchestrator body inside the instance loop
    - Tool name: `db_{instance_number}_pg96_analyze_sett_sec`; annotations `readOnlyHint=True`, `idempotentHint=False`, `openWorldHint=False`; tags `read-only`, `maintenance`, `security`, `instance-{n}`; timeout 60.0s
    - Guard with `is_tool_enabled(state.policy, instance_id, "analyze_sett_sec")`
    - Standard lifecycle (Requirement 8): validate → authorize → session touch → rate limit → write guard → `async with acquire(instance_id) as conn`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 8.1, 8.2, 8.3, 8.4, 8.5_

  - [ ] 8.2 Call all three sub-functions and aggregate the Issues array
    - Call `await settings_security.check_db_parameters(conn, database_name)` → `params_result`
    - Call `await settings_security.compute_db_metrics(conn, database_name)` → `metrics_result`
    - Call `await settings_security.analyze_db_security(conn, database_name)` → `security_result`
    - Build `Issues` array with exactly 3 entries labelled `"DB Parameters Misconfiguration"`, `"Database Performance Metrics"`, `"Security Vulnerabilities"`; each entry contains `Issue`, `Impacted Metrics`, `Issue Priority`, `Recommendations/Fixes`
    - `Issue Priority` per entry = worst severity in that sub-tool's result (CRITICAL > HIGH > MEDIUM > LOW)
    - _Requirements: 2.3, 2.4, 2.5, 2.6, 2.7_

  - [ ] 8.3 Build and return the orchestrator output dict
    - Return `{"Category": "Maintenance", "Date Generated": <ISO date str>, "Source DB Server Name": instance_id, "Database": database_name, "Overall Assessment": <summary string counting CRITICAL/HIGH/MEDIUM/LOW>, "Issues": [...]}`
    - `Date Generated` must be a string (ISO 8601), not a datetime object (Requirement 10.2)
    - All values must be JSON-serializable (Requirement 10.1)
    - Append tool name to `registered`
    - _Requirements: 2.1, 2.2, 10.1, 10.2_

- [ ] 9. Run ruff check and fix any lint errors
  - Run `ruff check src/tools/pg_tools.py src/tools/settings_security.py`
  - Fix all reported errors before proceeding to tests
  - _Requirements: (code quality gate)_

- [ ] 10. Add `TestAnalyzeSettSec` class to `tests/test_performance_tools.py`
  - [ ] 10.1 Add tests for all 8 new tool names in the registry
    - In a new `TestAnalyzeSettSec` class with `mock_state` and `mock_mcp` fixtures (matching the existing pattern)
    - Assert all 8 names present: `db_1_pg96_analyze_sett_sec`, `db_2_pg96_analyze_sett_sec`, `db_1_pg96_check_db_parameters`, `db_2_pg96_check_db_parameters`, `db_1_pg96_compute_db_metrics`, `db_2_pg96_compute_db_metrics`, `db_1_pg96_analyze_db_security`, `db_2_pg96_analyze_db_security`
    - _Requirements: 1.1, 1.5, 3.1, 4.1, 5.1_

  - [ ] 10.2 Update `test_registered_count_matches` from 46 to 54
    - In `TestGetSlowStatements.test_registered_count_matches`, change `assert len(registered) == 46` to `assert len(registered) == 54`
    - _Requirements: 1.5_

  - [ ] 10.3 Write property test — P1: Tool Registration Completeness
    - **Property 1: Tool Registration Completeness**
    - For any number of enabled instances (1 or 2), assert all four tool name suffixes (`analyze_sett_sec`, `check_db_parameters`, `compute_db_metrics`, `analyze_db_security`) appear in `registered` for every instance number, using the `db_{n}_pg96_{toolname}` pattern
    - **Validates: Requirements 1.1, 3.1, 4.1, 5.1**

  - [ ] 10.4 Write property test — P2: Orchestrator Output Schema Invariant
    - **Property 2: Orchestrator Output Schema Invariant**
    - Mock the three sub-functions via patch; invoke the orchestrator with arbitrary valid `database_name` values; assert `Category == "Maintenance"`, `Issues` is a list of exactly 3 entries, each entry has `Issue` in `{"DB Parameters Misconfiguration", "Database Performance Metrics", "Security Vulnerabilities"}`
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4**

  - [ ] 10.5 Write property test — P3: Tool Disable Flag Exclusion
    - **Property 3: Tool Disable Flag Exclusion**
    - Set `tool_enable_flags` for one of the four tools to `false` in mock policy; assert that tool's name is absent from the registry for all instances; assert the other three tools remain registered
    - **Validates: Requirements 9.2, 9.3**

- [ ] 11. Create `tests/test_settings_security.py` with unit tests for the three reusable functions
  - [ ] 11.1 Write test fixtures: mock asyncpg connection factory
    - Create `AsyncMock`-based `mock_conn` fixture that can be configured with return values for `fetchrow`, `fetch`, `execute`
    - Mirror the fixture pattern from `test_hypopg_tools.py`
    - _Requirements: 6.1, 6.2, 6.3_

  - [ ] 11.2 Write unit tests for `check_db_parameters()` — compliant and non-compliant parameter sets
    - Test: all parameters compliant → empty findings, `critical_count == 0`
    - Test: `autovacuum = off` → finding with `severity = "CRITICAL"`
    - Test: `ssl = off` → finding with `severity = "CRITICAL"`
    - Test: `shared_buffers = 16MB` → finding with `severity = "HIGH"`
    - _Requirements: 3.3, 3.4, 3.5, 3.6, 3.8_

  - [ ] 11.3 Write unit tests for `compute_db_metrics()` — schema and null-safety
    - Test: normal stats input → all 8 top-level keys present
    - Test: `blks_hit = 0, blks_read = 0` → `cache_hit_ratio_pct` is `null` or `0`, no exception
    - Test: `numbackends = 0, max_connections = 100` → `utilization_pct = 0.0`
    - _Requirements: 4.3, 4.4, 4.5, 4.6_

  - [ ] 11.4 Write unit tests for `analyze_db_security()` — individual check coverage
    - Test: `ssl = off` → CRITICAL finding present, `critical_findings >= 1`
    - Test: `archive_mode = on, failed_count = 1` → CRITICAL finding present
    - Test: 4 superusers in pg_roles → MEDIUM finding listing all names
    - Test: all logging params `off` → MEDIUM finding present
    - Test: output contains no raw credential values when pg_settings has sensitive data
    - _Requirements: 5.5, 5.6, 5.9, 5.12, 5.14_

  - [ ] 11.5 Write property test — P14: Input Validation Rejects Injection Vectors
    - **Property 14: Input Validation Rejects Injection Vectors**
    - For any string containing `;` or `--`, call `validate_database_name()` and assert `ValueError` raised with prefix `"INVALID_INPUT:"`; assert no SQL is executed (mock_conn methods not called)
    - **Validates: Requirement 7.1**

  - [ ] 11.6 Write property test — P15: JSON Serializability of All Outputs
    - **Property 15: JSON Serializability of All Outputs**
    - For valid mock inputs, call each of the three functions, then `json.dumps(result)` and assert no `TypeError` is raised; assert no `datetime`, `Decimal`, `float('inf')`, or `float('nan')` values appear anywhere in the output dict (recursive check)
    - **Validates: Requirements 10.1, 10.2, 10.3**

- [ ] 12. Checkpoint — run full test suite
  - Run `pytest -q` and ensure 130+ tests pass with 0 failures
  - Fix any failures before proceeding to docs
  - Ask the user if questions arise

- [ ] 13. Add 4 tool entries to `docs/mcp-tool-catalog.md`
  - Append a new `## Settings & Security Tools` section after the existing `## Maintenance Tools` section
  - Add entries for `db_<n>_pg96_analyze_sett_sec` (orchestrator), `db_<n>_pg96_check_db_parameters`, `db_<n>_pg96_compute_db_metrics`, `db_<n>_pg96_analyze_db_security`
  - Each entry must include: Parameters table, Output Schema table, FastMCP 3 Annotations table, Tags, and Timeout
  - Match the formatting style of existing catalog entries (e.g., `## Maintenance Tools` block)
  - _Requirements: (documentation)_

- [ ] 14. Final checkpoint — end-to-end verification
  - Run `ruff check .` and confirm zero errors
  - Run `pytest -q` and confirm all tests pass (expect 130+)
  - Confirm `docs/mcp-tool-catalog.md` has all 4 new tool entries
  - Ask the user if any questions arise before closing out

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references specific requirements for traceability
- All 15 correctness properties from the design document are covered by property test sub-tasks (P1–P15)
- `settings_security.py` must never import from `pg_tools.py` or FastMCP registration APIs (Requirement 6.4)
- Closure binding (`_tool`, `_instance`, `_instance_number` as default arguments) is mandatory for dual-instance correctness — see AGENTS.md
- All datetime values returned from asyncpg must be serialized to ISO 8601 strings before being included in any output dict (Requirement 10.2)
- The `_register_sett_sec_sub_tool()` helper should follow the same pattern as `_register_sub_tool()` in pg_tools.py but uses `database_name` as the primary user parameter instead of `schema_name`/`table_name`
