# Requirements Document

## Introduction

This document defines the requirements for the `analyze-sett-sec` feature: a new MCP orchestrator tool `db_{n}_pg96_analyze_sett_sec` and three reusable sub-tools for comprehensive database settings analysis and security vulnerability assessment against EDBAS 9.6 instances.

The orchestrator delegates work to three independently callable sub-tools:
- `check_db_parameters` — retrieves all `pg_settings` and flags misconfigurations against EDBAS 9.6 best practices across 7 parameter categories
- `compute_db_metrics` — computes cache hit ratio, transaction ratios, tuple metrics, connection utilization, TXID wraparound age, and database size
- `analyze_db_security` — evaluates SSL encryption status, WAL archiving health, backup indicators, authentication weaknesses, audit logging gaps, and superuser sprawl

All sub-tool logic lives in a new `src/tools/settings_security.py` module, mirroring the `table_analysis.py` and `hypopg_tools.py` reusable module pattern, enabling direct import by other tools.

---

## Glossary

- **Orchestrator**: The `db_{n}_pg96_analyze_sett_sec` MCP tool that calls all three sub-tools and aggregates their output into a single structured response.
- **Sub-Tool**: One of the three independently callable tools (`check_db_parameters`, `compute_db_metrics`, `analyze_db_security`) that can be invoked directly as MCP tools or called as Python functions.
- **Settings_Security_Module**: The `src/tools/settings_security.py` Python module containing the three reusable async functions.
- **Instance**: An EDBAS 9.6 database server registered in `config/instances.yaml`, identified by an instance ID (e.g., `primary`, `secondary`).
- **Instance_Number**: The 1-based index of an instance as assigned during `register_pg_tools()` enumeration, used in tool names (`db_1_pg96_...`, `db_2_pg96_...`).
- **Dual-Instance Loop**: The registration pattern in `register_pg_tools()` that iterates over all enabled instances and registers each tool with closure-bound `_tool`, `_instance`, and `_instance_number` defaults.
- **Tool_Registry**: The list of tool name strings returned by `register_pg_tools()`.
- **WriteGuard**: `src/middleware/write_guard.py` — enforces read-only posture by raising `PermissionError` on disallowed SQL verbs.
- **RateLimiter**: `src/middleware/rate_limiter.py` — raises `RateLimitExceededError` when per-actor or global rate limits are exceeded.
- **AuditLogger**: `src/middleware/audit_logger.py` — writes a structured JSON event for every tool invocation in the `finally` block.
- **Input_Validator**: `src/tools/input_validation.py` — `validate_database_name()` that rejects empty strings and SQL injection vectors.
- **EDBAS_9_6**: EnterpriseDB Advanced Server 9.6, the target database engine for all tools in this service.
- **pg_settings**: PostgreSQL system view containing all GUC (Grand Unified Configuration) parameters.
- **TXID_Age**: The number of transactions since a database or relation's `relfrozenxid`/`datfrozenxid` was last frozen; high values indicate wraparound risk.
- **WAL_Archiver**: The PostgreSQL background process responsible for shipping WAL segments to the archive location; monitored via `pg_stat_archiver`.

---

## Requirements

### Requirement 1: Orchestrator Tool Registration and Interface

**User Story:** As an LLM agent or database operator, I want to invoke a single `db_{n}_pg96_analyze_sett_sec` tool per database instance so that I can get a consolidated settings, metrics, and security assessment without calling multiple tools manually.

#### Acceptance Criteria

1. THE Tool_Registry SHALL contain `db_{n}_pg96_analyze_sett_sec` for every enabled Instance, where `n` is the Instance_Number assigned during the Dual-Instance Loop.
2. THE Orchestrator SHALL accept `database_name` (string, default `"edb"`) and `actor` (string, default `"system"`) as its only user-facing parameters.
3. WHEN `db_{n}_pg96_analyze_sett_sec` is registered, THE Orchestrator SHALL carry annotations `readOnlyHint=True`, `idempotentHint=False`, `openWorldHint=False`, and a timeout of 60.0 seconds.
4. WHEN `db_{n}_pg96_analyze_sett_sec` is registered, THE Orchestrator SHALL be tagged with `read-only`, `maintenance`, `security`, and `instance-{n}`.
5. THE Tool_Registry count SHALL increase from 46 to 54 after adding 4 new tools (orchestrator + 3 sub-tools) × 2 enabled instances.

---

### Requirement 2: Orchestrator Output Schema

**User Story:** As an LLM agent consuming tool output, I want a consistently structured response so that I can reliably parse the assessment across all invocations.

#### Acceptance Criteria

1. WHEN `db_{n}_pg96_analyze_sett_sec` completes successfully, THE Orchestrator SHALL return a dict containing keys: `Category`, `Date Generated`, `Source DB Server Name`, `Database`, `Overall Assessment`, and `Issues`.
2. THE `Category` field SHALL always be the string `"Maintenance"`.
3. THE `Issues` field SHALL be an array containing exactly 3 entries.
4. THE `Issues` array entries SHALL be labelled `"DB Parameters Misconfiguration"`, `"Database Performance Metrics"`, and `"Security Vulnerabilities"` (each as the value of an `Issue` key within that entry).
5. EACH entry in the `Issues` array SHALL contain `Issue`, `Impacted Metrics`, `Issue Priority`, and `Recommendations/Fixes` fields.
6. THE `Overall Assessment` field SHALL include a human-readable summary that counts CRITICAL, HIGH, MEDIUM, and LOW findings aggregated across all three sub-tool results.
7. THE `Issue Priority` per entry SHALL reflect the worst severity level found in that sub-tool's result (CRITICAL > HIGH > MEDIUM > LOW).

---

### Requirement 3: DB Parameters Sub-Tool

**User Story:** As a database operator, I want to call `db_{n}_pg96_check_db_parameters` independently so that I can audit EDBAS 9.6 GUC settings against best practices without running a full assessment.

#### Acceptance Criteria

1. THE Tool_Registry SHALL contain `db_{n}_pg96_check_db_parameters` for every enabled Instance.
2. WHEN `db_{n}_pg96_check_db_parameters` is invoked, THE Sub-Tool SHALL query `pg_settings` for all parameters and evaluate a curated subset of 60 or more parameters across the Memory, WAL/Checkpoint, Planner/Optimizer, Autovacuum, Logging, Connections, and Security/Auth categories.
3. THE `check_db_parameters` Python function SHALL return a dict with a `parameter_analysis` key (containing `total`, `compliant`, `warnings_count`, and `critical_count` sub-fields) and a `findings` array.
4. EACH entry in the `findings` array SHALL contain `parameter`, `current_value`, `recommended_value`, `category`, `severity`, and `rationale` fields.
5. WHEN `autovacuum` is set to `off`, THE `check_db_parameters` function SHALL assign severity `CRITICAL` to that finding.
6. WHEN `ssl` setting is `off`, THE `check_db_parameters` function SHALL assign severity `CRITICAL` to that finding.
7. WHEN `archive_mode` is `on` but the archive command is empty or not configured, THE `check_db_parameters` function SHALL assign severity `CRITICAL` to that finding.
8. WHEN `shared_buffers` is below 128 MB, THE `check_db_parameters` function SHALL assign severity `HIGH` to that finding.
9. WHEN logging is not configured (all of `logging_collector`, `log_connections`, `log_disconnections` are `off`), THE `check_db_parameters` function SHALL assign severity `HIGH` to that finding.
10. WHEN a parameter is suboptimal but not dangerous (e.g., planner cost parameters not tuned for SSD storage, `log_lock_waits` off), THE `check_db_parameters` function SHALL assign severity `MEDIUM` or `LOW` as appropriate per the EDBAS 9.6 best-practice rules.

---

### Requirement 4: Database Metrics Sub-Tool

**User Story:** As a database operator, I want to call `db_{n}_pg96_compute_db_metrics` independently so that I can assess instance-level performance health without running a full assessment.

#### Acceptance Criteria

1. THE Tool_Registry SHALL contain `db_{n}_pg96_compute_db_metrics` for every enabled Instance.
2. WHEN `db_{n}_pg96_compute_db_metrics` is invoked, THE Sub-Tool SHALL query `pg_stat_database`, `pg_stat_bgwriter`, `pg_stat_user_tables` (aggregated), `pg_settings`, and `pg_database` to derive all metrics.
3. THE `compute_db_metrics` Python function SHALL return a dict containing all of: `cache_hit_ratio_pct`, `transaction_metrics`, `tuple_metrics`, `query_latency`, `connection_utilization`, `txid_metrics`, `database_size`, and `dead_tuple_ratio_pct`.
4. THE `cache_hit_ratio_pct` field SHALL be computed as `100.0 * blks_hit / (blks_hit + blks_read)` using null-safe division.
5. IF `blks_hit + blks_read` equals zero, THE `compute_db_metrics` function SHALL return `cache_hit_ratio_pct` as `null` or `0` without raising a division error.
6. THE `connection_utilization` sub-dict SHALL contain `used`, `max`, and `utilization_pct` fields, where `utilization_pct` is computed as `100.0 * numbackends / max_connections` using null-safe division.
7. THE `txid_metrics` sub-dict SHALL contain `max_xid_age`, `database_frozen_xid_age`, and `wraparound_risk_level` fields.
8. WHEN `age(datfrozenxid)` exceeds 1,500,000,000 transactions, THE `compute_db_metrics` function SHALL set `wraparound_risk_level` to `"CRITICAL"`.
9. WHEN `age(datfrozenxid)` is between 1,000,000,001 and 1,500,000,000 transactions, THE `compute_db_metrics` function SHALL set `wraparound_risk_level` to `"HIGH"`.
10. WHEN `age(datfrozenxid)` is between 500,000,001 and 1,000,000,000 transactions, THE `compute_db_metrics` function SHALL set `wraparound_risk_level` to `"MEDIUM"`.
11. WHEN `age(datfrozenxid)` is 500,000,000 or below, THE `compute_db_metrics` function SHALL set `wraparound_risk_level` to `"LOW"`.

---

### Requirement 5: Security Analysis Sub-Tool

**User Story:** As a security operator, I want to call `db_{n}_pg96_analyze_db_security` independently so that I can audit database security posture and receive actionable vulnerability findings.

#### Acceptance Criteria

1. THE Tool_Registry SHALL contain `db_{n}_pg96_analyze_db_security` for every enabled Instance.
2. WHEN `db_{n}_pg96_analyze_db_security` is invoked, THE Sub-Tool SHALL query `pg_settings` (for SSL and auth parameters), `pg_stat_ssl`, `pg_stat_archiver`, `pg_roles`, `pg_namespace` (for public schema ACL), and `pg_settings` (for logging parameters).
3. THE `analyze_db_security` Python function SHALL return a dict containing `total_checks`, `passed`, `warnings`, `critical_findings`, and `findings` fields.
4. EACH entry in the `findings` array SHALL contain `check`, `status`, `severity`, `detail`, and `recommendation` fields.
5. WHEN the `ssl` setting is `"off"`, THE `analyze_db_security` function SHALL include a `CRITICAL` severity finding in `critical_findings` and `findings`.
6. WHEN `pg_stat_archiver` shows `failed_count > 0` while `archive_mode` is `on`, THE `analyze_db_security` function SHALL include a `CRITICAL` severity finding for WAL archiver failure.
7. WHEN `last_archived_time` is NULL while `archive_mode` is `on`, THE `analyze_db_security` function SHALL include a `CRITICAL` severity finding indicating no successful archive has occurred.
8. WHEN `last_archived_time` indicates more than 24 hours have elapsed without a successful archive, THE `analyze_db_security` function SHALL include a `HIGH` severity finding.
9. WHEN the count of superusers in `pg_roles` (WHERE `rolsuper = true`) exceeds 3, THE `analyze_db_security` function SHALL include a `MEDIUM` severity finding that lists the superuser role names.
10. WHEN `password_encryption` is not `"scram-sha-256"` and not `"md5"`, THE `analyze_db_security` function SHALL include a `MEDIUM` severity finding for weak password encryption.
11. WHEN `pg_stat_ssl` contains rows WHERE `ssl = false`, THE `analyze_db_security` function SHALL include a `HIGH` severity finding for unencrypted active connections.
12. WHEN all of `log_connections`, `log_disconnections`, and `log_statement` settings are `"off"`, THE `analyze_db_security` function SHALL include a `MEDIUM` severity finding for audit logging gaps.
13. WHEN the `public` schema ACL in `pg_namespace` grants `CREATE` privilege to the `PUBLIC` role, THE `analyze_db_security` function SHALL include a `MEDIUM` severity finding recommending revocation.
14. THE `analyze_db_security` function SHALL never include connection strings, passwords, SSL key material, or host details in any `detail` or `recommendation` field of its output.

---

### Requirement 6: Reusable Python Module Interface

**User Story:** As a developer building other MCP tools, I want to import the three sub-tool functions directly from `src/tools/settings_security.py` so that I can reuse their analysis logic without re-registering MCP tools.

#### Acceptance Criteria

1. THE Settings_Security_Module SHALL expose `check_db_parameters`, `compute_db_metrics`, and `analyze_db_security` as public async Python functions.
2. EACH function SHALL accept `conn` (an `asyncpg.Connection` instance) as its first parameter and `database_name` (string) as its second parameter.
3. EACH function SHALL return a `dict[str, Any]` and SHALL NOT register any MCP tool or access `AppState` directly.
4. THE Settings_Security_Module SHALL NOT import from `src/tools/pg_tools.py` or `fastmcp` tool-registration APIs, ensuring it remains a pure data-access library.

---

### Requirement 7: Input Validation and Security Guardrails

**User Story:** As a security-conscious operator, I want all tool inputs validated and write access blocked so that the tools cannot be used as injection vectors or accidentally cause data modification.

#### Acceptance Criteria

1. WHEN `database_name` is an empty string or contains `;` or `--`, THE Input_Validator SHALL raise a `ValueError` with prefix `"INVALID_INPUT:"` before any SQL is executed.
2. WHEN any of the four new tools executes SQL, THE WriteGuard SHALL enforce the read-only policy and raise `PermissionError` if a disallowed SQL verb is detected.
3. THE Settings_Security_Module functions SHALL use only parameterized SQL queries and SHALL NOT interpolate user input directly into SQL strings.
4. THE `analyze_db_security` function output SHALL not expose connection strings, passwords, SSL private key paths, or host details even when those values appear in `pg_settings`.

---

### Requirement 8: Middleware Integration and Audit Logging

**User Story:** As a compliance officer, I want every tool invocation to be rate-limited, session-tracked, and audit-logged so that I have a complete record of all assessment activity.

#### Acceptance Criteria

1. WHEN any of the four tools is invoked, THE System SHALL call `session_manager.touch(actor, request_id)` before executing SQL.
2. WHEN any of the four tools is invoked, THE System SHALL call `rate_limiter.allow(actor)` before executing SQL.
3. WHEN `rate_limiter.allow(actor)` raises `RateLimitExceededError`, THE System SHALL increment `app_state.denied_requests`, set the audit decision to `"deny"`, and re-raise the error.
4. WHEN any exception occurs during tool execution, THE System SHALL record the audit event in the `finally` block with the `error_code` and `decision` set appropriately.
5. THE AuditLogger SHALL receive `request_id`, `actor`, `tool`, `instance`, `sql`, `decision`, `latency_ms`, `rows`, `error_code`, `auth_mode`, `auth_subject`, `privilege_level`, and `group_match_result` on every invocation.
6. WHEN an unhandled exception occurs that is not `PermissionError` or `RateLimitExceededError`, THE System SHALL wrap it in a `ToolError` with an `error_code` string before re-raising.

---

### Requirement 9: Runtime Policy Configuration

**User Story:** As a system administrator, I want to control which tools are enabled per instance via `config/runtime-policy.yaml` so that I can disable individual tools without code changes.

#### Acceptance Criteria

1. THE `config/runtime-policy.yaml` file SHALL contain `tool_enable_flags` entries for `analyze_sett_sec`, `check_db_parameters`, `compute_db_metrics`, and `analyze_db_security`, all set to `true` by default.
2. WHEN a tool's `tool_enable_flags` entry is `false`, THE System SHALL skip registration of that tool and its name SHALL NOT appear in the Tool_Registry.
3. WHEN a tool is disabled for one instance, THE System SHALL still register it for other instances where the flag is enabled, maintaining dual-instance symmetry for the remaining enabled instances.

---

### Requirement 10: Pretty-Printing and Serialization

**User Story:** As an LLM agent receiving tool output, I want all output values to be JSON-serializable so that I can parse and display them without encountering unserializable Python objects.

#### Acceptance Criteria

1. THE Orchestrator output dict SHALL contain only JSON-serializable values (strings, numbers, booleans, lists, dicts, or null).
2. WHEN database timestamps or datetime objects are included in output (e.g., `last_archived_time`, `Date Generated`), THE System SHALL convert them to ISO 8601 strings or formatted date strings before returning.
3. WHEN a numeric ratio cannot be computed due to a zero denominator, THE System SHALL return `null` or `0` rather than `Infinity` or `NaN`.
