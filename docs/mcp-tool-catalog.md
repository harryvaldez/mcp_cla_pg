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

### Read-Group Access

✅ Always allowed for read-group callers.

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

---

## Read-Group Access Restrictions

When Okta authentication is enabled (`auth_mode: okta` in `config/runtime-policy.yaml`), callers authenticated with read-level privileges are **denied access** to the following tool categories:

| Restricted Tool Family | Suffix Pattern | Reason |
|---|---|---|
| HypoPG virtual indexes | `_pg96_hypopg_create_virtual_indexes` | Modifies session-level virtual index state |
| HypoPG explain with virtual | `_pg96_hypopg_explain_with_virtual` | Requires HypoPG session state |
| HypoPG optimal indexes | `_pg96_hypopg_find_optimal_indexes` | Creates/drops virtual indexes during testing |
| Blocking sessions | `_pg96_blocking_sessions` | Inspects cross-session activity |

Each restricted tool below includes a ⚠️ **Read-Group Access** annotation. Unrestricted tools include a ✅ marker.

The restricted suffix lists are configurable via `okta_read_restricted_tool_suffixes` and `okta_cross_session_tool_suffixes` in the `auth` section of `config/runtime-policy.yaml`.

---

## `db_<n>_pg96_exec_query`

Execute a user-supplied SELECT query against an EDBAS 9.6 instance and return the result set. Only SELECT statements are permitted. Results are capped at `max_rows`.

**Registered as:** `db_1_pg96_exec_query`, `db_2_pg96_exec_query`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `sql_statement` | string | **Yes** | — | SELECT SQL statement to execute |
| `database_name` | string | No | `"edb"` | Target database on the instance |
| `max_rows` | int | No | `5000` | Maximum rows to return (1–5000, capped by server policy) |
| `actor` | string | No | `"system"` | Caller identity for audit logging |

### Output Schema

| Field | Type | Description |
|---|---|---|
| `rows` | list[dict] | Array of result rows as column→value mappings |
| `row_count` | int | Number of rows returned |
| `truncated` | bool | `true` if result exceeded `max_rows` |
| `instance` | string | Instance ID that served the query |
| `execution_ms` | int | Query execution latency in milliseconds |

### FastMCP 3 Annotations

| Annotation | Value |
|---|---|
| `readOnlyHint` | `true` |
| `idempotentHint` | `false` |
| `openWorldHint` | `false` |
| `timeout` | `30.0` seconds |

### Tags

`read-only`, `query`, `instance-1` (or `instance-2`)

### Example Response

```json
{
  "rows": [
    {"id": 1, "name": "alice"},
    {"id": 2, "name": "bob"}
  ],
  "row_count": 2,
  "truncated": false,
  "instance": "primary",
  "execution_ms": 15
}
```

### Error Codes

| Error | Description |
|---|---|
| `INVALID_INPUT: sql_statement is required` | Empty or missing `sql_statement` |
| `INVALID_INPUT: only SELECT queries are allowed` | Non-SELECT verb detected |
| `INVALID_INPUT: sql_statement contains invalid characters` | `;` or `--` found |
| `INVALID_INPUT: max_rows must be between 1 and 5000` | `max_rows` out of range |
| `RATE_LIMIT_EXCEEDED` | Per-actor or global rate limit exceeded |
| `TOOL_ERROR: ...` | Database or query execution failure |

---

## `db_<n>_pg96_get_slow_statements`

Retrieves long-running SQL statements from `pg_stat_statements`, reporting execution stats and recommending optimizations or virtual indexes via `hypopg`.

**Registered as:** `db_1_pg96_get_slow_statements`, `db_2_pg96_get_slow_statements`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Name of the database to query |
| `max_combinations` | integer | No | `10` | Maximum HypoPG index combinations to test per statement (min 5) |
| `actor` | string | No | `"system"` | Caller identity for audit logging |

### Output Schema (Performance Analysis Schema)

| Field | Type | Description |
|---|---|---|
| `Category` | string | Constantly `"Performance"` |
| `Date Generated` | string | UTC date of execution `YYYY-MM-DD` |
| `Source DB Server Name` | string | Bound instance ID |
| `Issues Identified` | string | High-level summary of long-running statements found |
| `Impacted Metrics` | string | The DB system resources affected by these issues |
| `Issue Priority` | string | Derived priority depending on query length counts (`High` or `Low`) |
| `Recommendations/Fixes` | array | Recommendations and execution plan breakdowns |

### FastMCP 3 Annotations

| Annotation | Value |
|---|---|
| `readOnlyHint` | `true` |
| `idempotentHint` | `false` |
| `openWorldHint` | `false` |
| `timeout` | `60.0` seconds |

### Tags

`read-only`, `performance`, `instance-1` (or `instance-2`)

---

## `db_<n>_pg96_blocking_sessions`

Analyzes `pg_stat_activity` targeting locking, waits, queue length, and transaction state to isolate background process blockages.

**Registered as:** `db_1_pg96_blocking_sessions`, `db_2_pg96_blocking_sessions`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Name of the database to scan |
| `actor` | string | No | `"system"` | Caller identity for audit logging |

### Output Schema

Complies with standard Performance Analysis Schema reporting lock event resolutions natively.

### FastMCP 3 Annotations

| Annotation | Value |
|---|---|
| `readOnlyHint` | `true` |
| `idempotentHint` | `false` |
| `openWorldHint` | `false` |
| `timeout` | `30.0` seconds |

### Tags

`read-only`, `performance`, `instance-1` (or `instance-2`)

### Read-Group Access

⚠️ **Restricted** — inspects cross-session activity (other users' locks, queries, and sessions).

---

## `db_<n>_pg96_analyze_data_model`

Orchestrates comprehensive data model analysis by delegating to sub-tools internally and aggregating findings. Includes HyperPG index recommendations for tables with sequential scan abuse.

**Registered as:** `db_1_pg96_analyze_data_model`, `db_2_pg96_analyze_data_model`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Target database context |
| `schema_name` | string | Yes | - | The target schema space inside the database to evaluate |
| `actor` | string | No | `"system"` | Caller identity for audit logging |

### Output Schema

Complies with standard Performance Analysis Schema. The `Recommendations/Fixes` array includes sections for:
- Constraints & Foreign Keys
- Normalization - Type Mismatches
- Index Statistics (stale/missing ANALYZE)
- 3NF Decomposition Analysis
- HypoPG Index Recommendations (when applicable)

### FastMCP 3 Annotations

| Annotation | Value |
|---|---|
| `readOnlyHint` | `true` |
| `idempotentHint` | `false` |
| `openWorldHint` | `false` |
| `timeout` | `60.0` seconds |

### Tags

`read-only`, `performance`, `instance-1` (or `instance-2`)

---

## `db_<n>_pg96_extract_schema_model`

Generates the raw physical data model of a schema (tables, columns, types).

**Registered as:** `db_1_pg96_extract_schema_model`, `db_2_pg96_extract_schema_model`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Target database context |
| `schema_name` | string | Yes | - | Target schema space |

### Tags

`read-only`, `performance`, `instance-1` (or `instance-2`)

---

## `db_<n>_pg96_analyze_constraints_and_fks`

Scans relationships to find missing foreign keys and missing required constraints.

**Registered as:** `db_1_pg96_analyze_constraints_and_fks`, `db_2_pg96_analyze_constraints_and_fks`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Target database context |
| `schema_name` | string | Yes | - | Target schema space |

### Tags

`read-only`, `performance`, `instance-1` (or `instance-2`)

---

## `db_<n>_pg96_analyze_normalization`

Identifies column data type mismatches across tables and structural anomalies.

**Registered as:** `db_1_pg96_analyze_normalization`, `db_2_pg96_analyze_normalization`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Target database context |
| `schema_name` | string | Yes | - | Target schema space |

### Tags

`read-only`, `performance`, `instance-1` (or `instance-2`)

---

## `db_<n>_pg96_analyze_index_statistics`

Evaluates statistics and metrics to flag missing, stale, or severely outdated table/index stats.

**Registered as:** `db_1_pg96_analyze_index_statistics`, `db_2_pg96_analyze_index_statistics`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Target database context |
| `schema_name` | string | Yes | - | Target schema space |

### Tags

`read-only`, `performance`, `instance-1` (or `instance-2`)

---

## `db_<n>_pg96_analyze_3nf_and_decomposition`

Analyzes data row repetition to detect M:N relationships requiring decomposition to achieve 3rd Normal Form (3NF).

**Registered as:** `db_1_pg96_analyze_3nf_and_decomposition`, `db_2_pg96_analyze_3nf_and_decomposition`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Target database context |
| `schema_name` | string | Yes | - | Target schema space |

### Tags

`read-only`, `performance`, `instance-1` (or `instance-2`)

---

## `db_<n>_pg96_hypopg_create_virtual_indexes`

Parses a SELECT query and creates candidate virtual indexes via HypoPG. Extracts referenced tables/columns, generates B-tree virtual index definitions, and creates them in the session.

**Registered as:** `db_1_pg96_hypopg_create_virtual_indexes`, `db_2_pg96_hypopg_create_virtual_indexes`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Database to connect to |
| `query_text` | string | Yes | - | The SELECT query to analyze for index candidates |
| `actor` | string | No | `"system"` | Caller identity for audit logging |

### Output Schema

| Field | Type | Description |
|---|---|---|
| `virtual_indexes_created` | array | List of created virtual indexes with index_name, oid, indexdef |
| `query_analysis` | object | Parsed table/column references from the query |
| `count` | integer | Number of virtual indexes created |

### FastMCP 3 Annotations

| Annotation | Value |
|---|---|
| `readOnlyHint` | `false` |
| `idempotentHint` | `false` |
| `openWorldHint` | `false` |
| `timeout` | `30.0` seconds |

### Tags

`hypopg`, `performance`, `instance-1` (or `instance-2`)

### Read-Group Access

⚠️ **Restricted** — creates/modifies session-level virtual index state.

---

## `db_<n>_pg96_hypopg_explain_with_virtual`

Runs EXPLAIN (FORMAT JSON) for a query using the current session's virtual indexes.

**Registered as:** `db_1_pg96_hypopg_explain_with_virtual`, `db_2_pg96_hypopg_explain_with_virtual`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Database to connect to |
| `query_text` | string | Yes | - | The SELECT query to explain |
| `actor` | string | No | `"system"` | Caller identity for audit logging |

### Output Schema

| Field | Type | Description |
|---|---|---|
| `plan` | object | Raw JSON plan from EXPLAIN |
| `total_cost` | float | Total cost extracted from the plan |

### FastMCP 3 Annotations

| Annotation | Value |
|---|---|
| `readOnlyHint` | `true` |
| `idempotentHint` | `false` |
| `openWorldHint` | `false` |
| `timeout` | `30.0` seconds |

### Tags

`hypopg`, `performance`, `instance-1` (or `instance-2`)

### Read-Group Access

⚠️ **Restricted** — requires HypoPG session state, excluded for read-group consistency.

---

## `db_<n>_pg96_hypopg_find_optimal_indexes`

Finds the optimal HypoPG virtual index combination for a query. Captures baseline EXPLAIN cost, creates candidate virtual indexes, tests combinations (singletons, pairwise, triplets), ranks by cost, and returns the best recommendation.

**Registered as:** `db_1_pg96_hypopg_find_optimal_indexes`, `db_2_pg96_hypopg_find_optimal_indexes`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Database to connect to |
| `query_text` | string | Yes | - | The SELECT query to optimize |
| `max_combinations` | integer | No | 10 | Maximum index combinations to test (min 5) |
| `actor` | string | No | `"system"` | Caller identity for audit logging |

### Output Schema

| Field | Type | Description |
|---|---|---|
| `baseline_cost` | float | EXPLAIN total cost without any virtual indexes |
| `baseline_plan` | object | Raw JSON baseline explain plan |
| `ranked_plans` | array | Ranked plans (ascending by cost) with virtual_indexes_used, total_cost, cost_improvement_pct |
| `best_recommendation` | object | The single best plan with virtual_indexes, total_cost, improvement_pct |

### FastMCP 3 Annotations

| Annotation | Value |
|---|---|
| `readOnlyHint` | `false` |
| `idempotentHint` | `false` |
| `openWorldHint` | `false` |
| `timeout` | `60.0` seconds |

### Tags

`hypopg`, `performance`, `instance-1` (or `instance-2`)

### Read-Group Access

⚠️ **Restricted** — creates and drops virtual indexes during combination testing.

---

## HypoPG Operational Notes

### Prerequisites

1. **HypoPG Extension**: Must be installed on the target EDBAS 9.6 instance:
   ```sql
   CREATE EXTENSION IF NOT EXISTS hypopg;
   ```

2. **Required Privileges**: The database user must have `EXECUTE` on HypoPG functions:
   ```sql
   GRANT EXECUTE ON FUNCTION hypopg_create_index(text) TO edb_readonly_user;
   GRANT EXECUTE ON FUNCTION hypopg_reset() TO edb_readonly_user;
   GRANT EXECUTE ON FUNCTION hypopg_drop_index(oid) TO edb_readonly_user;
   GRANT EXECUTE ON FUNCTION hypopg_get_indexdef(oid) TO edb_readonly_user;
   GRANT EXECUTE ON FUNCTION hypopg_list_indexes(oid) TO edb_readonly_user;
   ```

3. **pg_stat_statements**: Required by `get_slow_statements` to retrieve query metrics.
   ```sql
   CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
   ```

### Fallback Behavior

If HypoPG is not installed or `hypopg_reset()` raises a function-not-found error:
- `hypopg_create_virtual_indexes`: Raises `RuntimeError` with message `"HypoPG extension is not available on this instance"`.
- `hypopg_find_optimal_indexes`: Returns only the baseline plan and cost with no ranked recommendations.
- `get_slow_statements`: Includes a note in the output for each statement that HypoPG analysis is unavailable.

### Ranking Behavior

The `hypopg_find_optimal_indexes` tool and `get_slow_statements` use the following ranking algorithm:
1. **Baseline capture**: `EXPLAIN (FORMAT JSON)` is run first without any virtual indexes.
2. **Candidate generation**: Referenced tables/columns are extracted from the query text. Single-column B-tree virtual indexes are created for columns in `WHERE`, `JOIN ON`, and `ORDER BY` clauses.
3. **Combination testing**: Singleton, pairwise, and triplet combinations of virtual indexes are tested, capped at `max_combinations` (default 10, minimum 5 enforced in code).
4. **Ranking**: All tested plans plus the baseline are sorted by `total_cost` ascending. The `best_recommendation` is the plan with the lowest cost.
5. **Cleanup**: `hypopg_reset()` is always called in a `finally` block to clear virtual indexes from the session, preventing state leaks across connections.

### Tool Type Annotations

| Tool | readOnlyHint | Reason | Timeout |
|------|---|---|---|
| `get_slow_statements` | `true` | Read-only; uses HypoPG internally but does not expose session state to caller | 60s |
| `blocking_sessions` | `true` | Read-only session/lock queries | 30s |
| `analyze_data_model` | `true` | Read-only schema/statistics queries | 60s |
| Data model sub-tools | `true` | Read-only analysis | 30s |
| `hypopg_create_virtual_indexes` | `false` | Modifies session memory state via hypopg_create_index | 30s |
| `hypopg_explain_with_virtual` | `true` | Read-only EXPLAIN (uses existing session state) | 30s |
| `hypopg_find_optimal_indexes` | `false` | Creates/drops virtual indexes during testing | 60s |
| `exec_query` | `true` | Read-only SELECT execution | 30s |
| `analyze_table` | `true` | Read-only maintenance analysis | 30s |
| `check_table_bloat` | `true` | Read-only bloat analysis | 30s |
| `check_table_wraparound` | `true` | Read-only wraparound check | 30s |
| `check_table_statistics` | `true` | Read-only statistics check | 30s |
| `check_index_health` | `true` | Read-only index health | 30s |
| `list_objects` | `true` | Read-only object discovery | 30s |
| `list_tables` | `true` | Read-only table listing | 30s |
| `list_indexes` | `true` | Read-only index listing | 30s |
| `list_views` | `true` | Read-only view listing | 30s |
| `list_objects_by_type` | `true` | Read-only generic object listing | 30s |

---

## Maintenance Tools

### `db_<n>_pg96_analyze_table`

Orchestrates comprehensive single-table maintenance analysis across 4 domains: bloat, wraparound, statistics, and index health.

**Registered as:** `db_1_pg96_analyze_table`, `db_2_pg96_analyze_table`

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `schema_name` | string | **Yes** | — | Schema containing the table |
| `table_name` | string | **Yes** | — | Table to analyze |
| `database_name` | string | No | `"edb"` | Target database |
| `actor` | string | No | `"system"` | Caller identity |

**Output:** `Category: "Maintenance"` with `Issues` array of independent entries per analysis domain (Bloat, Wraparound, Statistics, Index Health), each with own `Impacted Metrics`, `Issue Priority`, `Recommendations/Fixes`.

**Tags:** `read-only`, `maintenance` | **Timeout:** 30s

### `db_<n>_pg96_check_table_bloat`

Analyze dead tuple ratio and vacuum staleness for a specific table.

**Parameters:** `schema_name`, `table_name` (required), `database_name` (optional)

**Output:** `dead_tuple_pct`, `hot_update_pct`, `last_vacuum`, `last_autovacuum`, `bloat_severity` (LOW/MEDIUM/HIGH)

**Tags:** `read-only`, `maintenance` | **Timeout:** 30s

### `db_<n>_pg96_check_table_wraparound`

Check transaction ID wraparound risk for a specific table.

**Parameters:** `schema_name`, `table_name` (required), `database_name` (optional)

**Output:** `xid_age`, `risk_level` (LOW/MEDIUM/HIGH/CRITICAL), `recommended_action`

**Tags:** `read-only`, `maintenance` | **Timeout:** 30s

### `db_<n>_pg96_check_table_statistics`

Check staleness of table statistics for the query planner.

**Parameters:** `schema_name`, `table_name` (required), `database_name` (optional)

**Output:** `last_analyze`, `days_since_analyze`, `n_mod_since_analyze`, `is_stale`, `recommendation`

**Tags:** `read-only`, `maintenance` | **Timeout:** 30s

### `db_<n>_pg96_check_index_health`

Assess index health: invalid, unused, duplicate indexes, and total bloat.

**Parameters:** `schema_name`, `table_name` (required), `database_name` (optional)

**Output:** `invalid_indexes`, `unused_indexes`, `duplicate_indexes`, `total_bloat_bytes`, `recommended_actions`

**Tags:** `read-only`, `maintenance` | **Timeout:** 30s

---

## Settings & Security Tools

### `db_<n>_pg96_analyze_sett_sec`

Orchestrates a comprehensive database settings and security analysis across 3 domains: parameter misconfiguration, performance metrics, and security vulnerabilities.

**Registered as:** `db_1_pg96_analyze_sett_sec`, `db_2_pg96_analyze_sett_sec`

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `database_name` | string | No | `"edb"` | Target database |
| `actor` | string | No | `"system"` | Caller identity |

**Output:** `Category: "Maintenance"`, `Overall Assessment`, `Issues` array with 3 entries: "DB Parameters Misconfiguration", "Database Performance Metrics", "Security Vulnerabilities". Each entry contains `Issue`, `Impacted Metrics`, `Issue Priority`, `Recommendations/Fixes`.

**Tags:** `read-only`, `maintenance`, `security` | **Timeout:** 60s

### `db_<n>_pg96_check_db_parameters`

Evaluate all `pg_settings` against EDBAS 9.6 best-practice rules across 7 categories (Memory, WAL/Checkpoint, Planner/Optimizer, Autovacuum, Logging, Connections, Security/Auth).

**Parameters:** `database_name` (optional, default `"edb"`), `actor`

**Output:** `parameter_analysis: {total, compliant, warnings_count, critical_count}`, `findings: [{parameter, current_value, recommended_value, category, severity, rationale}]`

**Tags:** `read-only`, `maintenance`, `security` | **Timeout:** 45s

### `db_<n>_pg96_compute_db_metrics`

Compute key database performance metrics: cache hit ratio, transaction ratios, tuple metrics, connection utilization, TXID age, and database size.

**Parameters:** `database_name` (optional, default `"edb"`), `actor`

**Output:** 8 top-level metric keys: `cache_hit_ratio_pct`, `transaction_metrics`, `tuple_metrics`, `query_latency`, `connection_utilization`, `txid_metrics`, `database_size`, `dead_tuple_ratio_pct`

**Tags:** `read-only`, `maintenance` | **Timeout:** 45s

### `db_<n>_pg96_analyze_db_security`

Perform security vulnerability assessment: SSL configuration, WAL archiver health, superuser sprawl, password encryption, audit logging gaps, and public schema privileges.

**Parameters:** `database_name` (optional, default `"edb"`), `actor`

**Output:** `{total_checks, passed, warnings, critical_findings, findings: [{check, status, severity, detail, recommendation}]}`

**Tags:** `read-only`, `maintenance`, `security` | **Timeout:** 45s

---

## Discovery Tools

### `db_<n>_pg96_list_objects`

List database objects of a specific type within a schema.

**Registered as:** `db_1_pg96_list_objects`, `db_2_pg96_list_objects`

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `schema_name` | string | **Yes** | — | Schema to query |
| `object_type` | string | **Yes** | — | Type: `table`, `index`, `view`, `sequence`, `materialized_view`, `composite_type`, `foreign_table` |
| `database_name` | string | No | `"edb"` | Target database |
| `actor` | string | No | `"system"` | Caller identity |

**Output:** `Category: "Discovery"`, `Schema`, `Object Type`, `Object Count`, `Objects` array

**Tags:** `read-only`, `discovery` | **Timeout:** 30s

### `db_<n>_pg96_list_tables`

List all tables in a schema with row counts, sizes, and descriptions.

**Parameters:** `schema_name` (required), `database_name` (optional)

**Output:** `Objects` array with `name`, `owner`, `row_count`, `size_bytes`, `description`

**Tags:** `read-only`, `discovery` | **Timeout:** 30s

### `db_<n>_pg96_list_indexes`

List all indexes in a schema with type, size, and scan statistics.

**Parameters:** `schema_name` (required), `database_name` (optional)

**Output:** `Objects` array with `name`, `table_name`, `index_type`, `size_bytes`, `idx_scan`

**Tags:** `read-only`, `discovery` | **Timeout:** 30s

### `db_<n>_pg96_list_views`

List all views in a schema with definition and owner.

**Parameters:** `schema_name` (required), `database_name` (optional)

**Output:** `Objects` array with `name`, `owner`, `definition` (truncated to 500 chars), `description`

**Tags:** `read-only`, `discovery` | **Timeout:** 30s

### `db_<n>_pg96_list_objects_by_type`

Generic object lister for any `pg_class.relkind` value (sequences, materialized views, composite types, foreign tables).

**Parameters:** `schema_name`, `object_type` (required), `database_name` (optional)

**Output:** `Objects` array with `name`, `owner`, `size_bytes`, `description`

**Tags:** `read-only`, `discovery` | **Timeout:** 30s
