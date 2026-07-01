# Design Document: analyze-sett-sec

## Feature: db_\<n\>_pg96_analyze_sett_sec — Settings & Security Orchestrator with Sub-Tools

### Overview

Add a new MCP orchestrator tool `db_{n}_pg96_analyze_sett_sec` that performs comprehensive database settings analysis and security vulnerability assessment. The orchestrator delegates to 3 reusable sub-tools:
- `check_db_parameters` — retrieves and analyzes all `pg_settings` against EDBAS 9.6 best practices
- `compute_db_metrics` — computes cache hit ratio, transaction ratios, tuple metrics, connection utilization, TXID age, and database size
- `analyze_db_security` — SSL encryption status, backup indicators, authentication risks, audit logging gaps, superuser sprawl

All sub-tools live in a new `src/tools/settings_security.py` module (mirroring the `table_analysis.py` and `hypopg_tools.py` reusable module pattern), enabling other tools to call them directly.

### Sub-Tool Architecture

Three sub-tools decompose the analysis into independently useful domains. Each sub-tool has dual interfaces:
1. **MCP tool** registered via `@mcp.tool()` in `pg_tools.py` — independently callable by LLMs
2. **Python function** in `settings_security.py` — takes `conn: asyncpg.Connection` + params, returns `dict[str, Any]`

| Sub-Tool | MCP Name | Python Function | Purpose |
|----------|----------|-----------------|---------|
| DB Parameters | `db_n_pg96_check_db_parameters` | `check_db_parameters()` | Retrieve all `pg_settings`, flag misconfigurations per EDBAS 9.6 best practices |
| DB Metrics | `db_n_pg96_compute_db_metrics` | `compute_db_metrics()` | Cache hit ratio, transaction ratio, tuple metrics, connection utilization, TXID age, DB size |
| DB Security | `db_n_pg96_analyze_db_security` | `analyze_db_security()` | SSL status, WAL archiving, backup heuristics, auth weaknesses, audit gaps, superuser count |

### Tool Contracts

**Orchestrator `db_{n}_pg96_analyze_sett_sec`:**
- Parameters: `database_name` (str, default `"edb"`), `actor` (str, default `"system"`)
- Annotations: `readOnlyHint=true`, `idempotentHint=false`, `openWorldHint=false`, `timeout=60.0s`
- Tags: `read-only`, `maintenance`, `security`, `instance-{n}`
- Output schema: `Category: "Maintenance"`, `Date Generated`, `Source DB Server Name`, `Overall Assessment`, `Issues` array with 3 entries: "DB Parameters Misconfiguration", "Database Performance Metrics", "Security Vulnerabilities"

**Sub-tools:** Each accepts `database_name` (str, default `"edb"`), `actor` (str, default `"system"`), timeout 45s each.

### Key SQL Queries
- `pg_settings` for DB parameters (all 250+ parameters, checking curated subset of 60+ against EDBAS 9.6 best practices)
- `pg_stat_database`, `pg_stat_bgwriter`, `pg_stat_user_tables` for metrics
- `pg_stat_ssl`, `pg_stat_archiver`, `pg_roles`, `pg_namespace` for security checks

### Implementation Files
- `src/tools/settings_security.py` — NEW — 3 reusable async functions
- `src/tools/pg_tools.py` — add import + 1 orchestrator + 3 sub-tools
- `config/runtime-policy.yaml` — add 4 tool_enable_flags
- `tests/test_performance_tools.py` — add TestAnalyzeSettSec class, update count 46→54
- `tests/test_settings_security.py` — NEW — unit tests for 3 reusable functions
- `docs/mcp-tool-catalog.md` — add 4 tool entries

### Security & Guardrails
- SELECT-only, write guard enforced, input validated via existing `validate_database_name()`
- Rate limited, audit logged
- Never expose connection strings, passwords, or host details in output
- Dual-instance closure-binding registration pattern
- 8 new tools total (4 per instance × 2 instances), updating registered count from 46 to 54

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Tool Registration Completeness

*For any* number of enabled EDBAS instances, the Tool_Registry returned by `register_pg_tools()` SHALL contain all four tool names (`analyze_sett_sec`, `check_db_parameters`, `compute_db_metrics`, `analyze_db_security`) for every instance, using the `db_{n}_pg96_{toolname}` naming pattern.

**Validates: Requirements 1.1, 2.1, 3.1, 4.1**

---

### Property 2: Orchestrator Output Schema Invariant

*For any* valid `database_name` input, the orchestrator's return value SHALL contain `Category`, `Date Generated`, `Source DB Server Name`, `Database`, `Overall Assessment`, and `Issues`, where `Category` is always `"Maintenance"` and `Issues` is always an array of exactly 3 entries labelled `"DB Parameters Misconfiguration"`, `"Database Performance Metrics"`, and `"Security Vulnerabilities"`.

**Validates: Requirements 2.1, 2.2, 2.3, 2.4**

---

### Property 3: Tool Disable Flag Exclusion

*For any* tool name whose `tool_enable_flags` entry is `false` in `runtime-policy.yaml`, the Tool_Registry SHALL not contain that tool's name for any instance.

**Validates: Requirements 9.2, 9.3**

---

### Property 4: Parameter Severity Classification

*For any* `pg_settings` row set provided to `check_db_parameters`, the severity assigned to each flagged parameter SHALL match the EDBAS 9.6 best-practice severity rules exactly — specifically: `autovacuum=off` → CRITICAL, `ssl=off` → CRITICAL, unconfigured archive command with `archive_mode=on` → CRITICAL, `shared_buffers` below 128 MB → HIGH, missing logging configuration → HIGH, suboptimal planner/autovacuum settings → MEDIUM or LOW.

**Validates: Requirements 3.5, 3.6, 3.7, 3.8, 3.9, 3.10**

---

### Property 5: check_db_parameters Output Schema

*For any* mock `pg_settings` input, `check_db_parameters()` SHALL return a dict where `parameter_analysis` contains `total`, `compliant`, `warnings_count`, and `critical_count`, and `findings` is an array where every entry contains `parameter`, `current_value`, `recommended_value`, `category`, `severity`, and `rationale`.

**Validates: Requirements 3.3, 3.4**

---

### Property 6: Cache Hit Ratio Formula Correctness

*For any* non-negative integers `blks_hit` and `blks_read` where their sum is greater than zero, `compute_db_metrics()` SHALL compute `cache_hit_ratio_pct` as exactly `100.0 * blks_hit / (blks_hit + blks_read)`. When their sum is zero, the function SHALL return `0` or `null` without raising an exception.

**Validates: Requirements 4.4, 4.5**

---

### Property 7: compute_db_metrics Output Schema Completeness

*For any* valid mock database stats input, `compute_db_metrics()` SHALL return a dict containing all of `cache_hit_ratio_pct`, `transaction_metrics`, `tuple_metrics`, `query_latency`, `connection_utilization`, `txid_metrics`, `database_size`, and `dead_tuple_ratio_pct` at the top level.

**Validates: Requirement 4.3**

---

### Property 8: TXID Wraparound Risk Level Classification

*For any* non-negative integer value of `age(datfrozenxid)`, the `wraparound_risk_level` computed by `compute_db_metrics()` SHALL be `"CRITICAL"` when the age exceeds 1,500,000,000; `"HIGH"` when between 1,000,000,001 and 1,500,000,000; `"MEDIUM"` when between 500,000,001 and 1,000,000,000; and `"LOW"` when 500,000,000 or below.

**Validates: Requirements 4.8, 4.9, 4.10, 4.11**

---

### Property 9: Security Finding Severity for SSL Disabled

*For any* mock `pg_settings` input where the `ssl` parameter value is `"off"`, `analyze_db_security()` SHALL include at least one entry in `critical_findings` and in `findings` with `severity = "CRITICAL"` and a `check` field identifying the SSL disabled condition.

**Validates: Requirement 5.5**

---

### Property 10: Security Finding Severity for WAL Archiver Failure

*For any* mock `pg_stat_archiver` input where `archive_mode` is `on` and either `failed_count > 0` or `last_archived_time` is NULL, `analyze_db_security()` SHALL include a `CRITICAL` severity finding for the WAL archiver failure condition.

**Validates: Requirements 5.6, 5.7**

---

### Property 11: Superuser Count Threshold Finding

*For any* mock `pg_roles` result containing more than 3 rows where `rolsuper = true`, `analyze_db_security()` SHALL include a `MEDIUM` severity finding that lists all superuser role names in its `detail` or `recommendation` field.

**Validates: Requirement 5.9**

---

### Property 12: analyze_db_security Output Schema

*For any* mock database state input, `analyze_db_security()` SHALL return a dict containing `total_checks`, `passed`, `warnings`, `critical_findings`, and `findings`, where `findings` is an array of entries each containing `check`, `status`, `severity`, `detail`, and `recommendation`.

**Validates: Requirements 5.3, 5.4**

---

### Property 13: No Credential Leakage in Security Output

*For any* mock `pg_settings` input that contains values resembling connection strings, passwords, or SSL key file paths, the `detail` and `recommendation` fields in every `analyze_db_security()` output finding SHALL NOT reproduce those raw values verbatim.

**Validates: Requirements 5.14, 7.4**

---

### Property 14: Input Validation Rejects Injection Vectors

*For any* string containing `;` or `--`, `validate_database_name()` SHALL raise a `ValueError` with the prefix `"INVALID_INPUT:"` before any database query is executed.

**Validates: Requirements 7.1**

---

### Property 15: JSON Serializability of All Outputs

*For any* valid database state, the complete output dict of the orchestrator and each sub-tool SHALL be JSON-serializable (all values are strings, numbers, booleans, lists, dicts, or null — no Python `datetime`, `Decimal`, or `Infinity`/`NaN` float values).

**Validates: Requirements 10.1, 10.2, 10.3**
