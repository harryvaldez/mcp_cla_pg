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

---

## `db_<n>_pg96_get_slow_statements`

Retrieves long-running SQL statements from `pg_stat_statements`, reporting execution stats and recommending optimizations or virtual indexes via `hypopg`.

**Registered as:** `db_1_pg96_get_slow_statements`, `db_2_pg96_get_slow_statements`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Name of the database to query |
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
| `timeout` | `30.0` seconds |

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

---

## `db_<n>_pg96_analyze_data_model`

Evaluates physical structure health (e.g. `pg_class`, `pg_stat_user_tables`) identifying massive sequential scan impacts masking inefficient architecture for partitioning or materialized views.

**Registered as:** `db_1_pg96_analyze_data_model`, `db_2_pg96_analyze_data_model`

### Parameters

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `database_name` | string | Yes | - | Target database context |
| `schema_name` | string | Yes | - | The target schema space inside the database to evaluate |
| `actor` | string | No | `"system"` | Caller identity for audit logging |

### Output Schema

Complies with standard Performance Analysis Schema highlighting structural health assessing partition boundaries and indexing efficiencies.

### FastMCP 3 Annotations

| Annotation | Value |
|---|---|
| `readOnlyHint` | `true` |
| `idempotentHint` | `false` |
| `openWorldHint` | `false` |
| `timeout` | `30.0` seconds |

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
