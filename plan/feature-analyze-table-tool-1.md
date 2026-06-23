---
goal: Add db_<n>_pg96_analyze_table and db_<n>_pg96_list_objects Tools
version: 1.2
date_created: 2026-06-23
last_updated: 2026-06-23
owner: harryvaldez
status: Completed
tags: [feature, tool, analyze_table, list_objects, maintenance, discovery, sub-tools, reusable]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-completed-brightgreen)

Add a new MCP orchestrator tool `db_<n>_pg96_analyze_table` that accepts `schema_name` and `table_name`, then delegates to 4 reusable sub-tools analyzing bloat/fragmentation, wraparound risk, stale statistics, and index health. Additionally add `db_<n>_pg96_list_objects` that accepts `schema_name` and `object_type` to list database objects by type. Both feature sets share a new `src/tools/table_analysis.py` module (mirroring the `hypopg_tools.py` pattern), enabling reuse by other tools.

## 1. Requirements & Constraints

- **REQ-001**: Tool: `db_{n}_pg96_analyze_table` — orchestrates 4 sub-tools against a single table
- **REQ-002**: Inputs: `schema_name` (str, required), `table_name` (str, required), `database_name` (str, default `"edb"`)
- **REQ-003**: Output schema: `Category` = `"Maintenance"`, `Date Generated`, `Source DB Server Name`, `Overall Assessment`, `Issues` (array of independent issue objects). Each issue object contains `Issue` (section label), `Impacted Metrics`, `Issue Priority` (per-section severity), `Recommendations/Fixes` (per-section actions). This ensures each analysis domain (Bloat, Wraparound, Statistics, Index Health) is independently assessed with its own priority and remediation plan.
- **REQ-004**: Analyze: **fragmentation/bloat** (dead tuples, last vacuum), **wraparound** (XID age), **stale statistics**, **index health** (invalid, unused, duplicate, bloat)
- **REQ-005**: Sub-tools must be both independently callable MCP tools AND importable as Python functions (reuse pattern from `hypopg_tools.py`)
- **REQ-006**: Follow dual-instance closure-binding registration pattern
- **REQ-007**: SELECT-only, write guard enforced, input validated, rate limited, audit logged
- **REQ-008**: Tool: `db_{n}_pg96_list_objects` — accepts `schema_name` and `object_type`, returns list of matching database objects
- **REQ-009**: Inputs for `list_objects`: `schema_name` (str, required), `object_type` (str, required — mapped to `pg_class.relkind`: `table`→`r`, `index`→`i`, `view`→`v`, `sequence`→`S`, `materialized_view`→`m`, `composite_type`→`c`, `foreign_table`→`f`), `database_name` (str, default `"edb"`)
- **REQ-010**: Output for `list_objects`: `Category` = `"Discovery"`, `Date Generated`, `Source DB Server Name`, `Schema`, `Object Type`, `Object Count`, `Objects` (array of `{name, owner, size_bytes, description}`)
- **REQ-011**: `list_objects` delegates to reusable sub-tools: `list_tables_by_schema`, `list_indexes_by_schema`, `list_views_by_schema`, `list_objects_by_type` (generic fallback) — each is both an MCP tool and a Python function
- **REQ-012**: Validate `object_type` against allowed EDBAS 9.6 relkind values; reject unknown types with `INVALID_INPUT`
- **SEC-001**: Validate `schema_name` via existing `validate_schema_name`, add new `validate_table_name` for `table_name`
- **SEC-002**: Read-only — `readOnlyHint=True`
- **SEC-003**: Validate `object_type` input via new `validate_object_type()` — rejects `;`/`--` injection, only allows predefined EDBAS 9.6 types
- **PAT-001**: Reusable analysis functions in `src/tools/table_analysis.py` (mirroring `hypopg_tools.py`)

## 2. Sub-Tool Architecture

### Maintenance Analysis Sub-Tools (analyze_table)
1. **MCP tool** registered via `@mcp.tool()` in `pg_tools.py` — independently callable by LLMs
2. **Python function** in `table_analysis.py` — takes `conn: asyncpg.Connection` + params, returns `dict[str, Any]`

| Sub-Tool | MCP Name | Python Function | Purpose | Key SQL Views |
|----------|----------|-----------------|---------|---------------|
| Bloat | `db_n_pg96_check_table_bloat` | `check_table_bloat()` | Dead tuple %, HOT update %, last vacuum | `pg_stat_user_tables` |
| Wraparound | `db_n_pg96_check_table_wraparound` | `check_table_wraparound()` | XID age, risk level | `pg_class.relfrozenxid`, `age()` |
| Statistics | `db_n_pg96_check_table_statistics` | `check_table_statistics()` | Stale/missing `last_analyze` | `pg_stat_user_tables` |
| Index Health | `db_n_pg96_check_index_health` | `check_index_health()` | Invalid, unused, duplicate indexes, bloat | `pg_index`, `pg_stat_user_indexes` |

### Object Discovery Sub-Tools (list_objects)

The 4 discovery sub-tools each have dual interfaces:
1. **MCP tool** registered via `@mcp.tool()` in `pg_tools.py` — independently callable by LLMs
2. **Python function** in `table_analysis.py` — takes `conn: asyncpg.Connection` + params, returns `dict[str, Any]`

| Sub-Tool | MCP Name | Python Function | Purpose | Key SQL Views |
|----------|----------|-----------------|---------|---------------|
| List Tables | `db_n_pg96_list_tables` | `list_tables_by_schema()` | List all tables with row counts, sizes | `pg_class`, `pg_namespace`, `pg_stat_user_tables` |
| List Indexes | `db_n_pg96_list_indexes` | `list_indexes_by_schema()` | List all indexes with type, size, scan stats | `pg_class`, `pg_index`, `pg_stat_user_indexes` |
| List Views | `db_n_pg96_list_views` | `list_views_by_schema()` | List all views with definition source | `pg_class`, `pg_namespace`, `pg_views` (EDBAS) |
| Generic by Type | `db_n_pg96_list_objects_by_type` | `list_objects_by_type()` | Generic fallback for any relkind | `pg_class`, `pg_namespace` |

### `object_type` Mapping Table

| User Input | `pg_class.relkind` | Description |
|------------|-------------------|-------------|
| `table` | `r` | Ordinary table |
| `index` | `i` | Index |
| `view` | `v` | View |
| `sequence` | `S` | Sequence |
| `materialized_view` | `m` | Materialized view |
| `composite_type` | `c` | Composite type |
| `foreign_table` | `f` | Foreign table |

## 3. Implementation Steps

### Implementation Phase 1 — Reusable Analysis Module

- GOAL-001: Create `src/tools/table_analysis.py` with 8 pure async functions (4 maintenance + 4 discovery).

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Create `src/tools/table_analysis.py` — module docstring, imports (`asyncpg`, `typing`). Pattern: each function takes `conn: asyncpg.Connection` + params, returns `dict[str, Any]` | ✅ | 2026-06-23 |
| TASK-002 | Implement `check_table_bloat(conn, schema, table)` — queries `pg_stat_user_tables` for `n_live_tup`, `n_dead_tup`, `n_tup_hot_upd`, `last_vacuum`, `last_autovacuum`. Returns dead tuple %, HOT update %, vacuum staleness flags | ✅ | 2026-06-23 |
| TASK-003 | Implement `check_table_wraparound(conn, schema, table)` — queries `age(c.relfrozenxid)` from `pg_class`. Returns XID age, risk level (LOW < 500M, MEDIUM < 1B, HIGH < 1.5B, CRITICAL >= 1.5B), freeze recommendation | ✅ | 2026-06-23 |
| TASK-004 | Implement `check_table_statistics(conn, schema, table)` — queries `last_analyze`, `last_autoanalyze`, `n_mod_since_analyze`. Flags stale when > 7 days or never analyzed with live tuples > 0 | ✅ | 2026-06-23 |
| TASK-005 | Implement `check_index_health(conn, schema, table)` — queries `pg_index` for `indisvalid`, `pg_stat_user_indexes` for `idx_scan`/usage, checks duplicate definitions, reports index bloat via `pg_relation_size` | ✅ | 2026-06-23 |
| TASK-005a | Implement `list_tables_by_schema(conn, schema)` — queries `pg_class` JOIN `pg_namespace` WHERE `relkind='r'`, includes `pg_stat_user_tables` for row counts, `pg_relation_size()` for table size | ✅ | 2026-06-23 |
| TASK-005b | Implement `list_indexes_by_schema(conn, schema)` — queries `pg_class` JOIN `pg_index` JOIN `pg_namespace` WHERE `relkind='i'`, includes index type (`amname`), `pg_relation_size()`, `idx_scan` from `pg_stat_user_indexes` | ✅ | 2026-06-23 |
| TASK-005c | Implement `list_views_by_schema(conn, schema)` — queries `pg_class` JOIN `pg_namespace` WHERE `relkind='v'`, includes view definition from `pg_get_viewdef()` or `pg_views` | ✅ | 2026-06-23 |
| TASK-005d | Implement `list_objects_by_type(conn, schema, relkind)` — generic query by any `relkind` value, returns `name`, `owner` (from `pg_roles`), `size_bytes`, `description` (from `pg_description`/`obj_description()`) | ✅ | 2026-06-23 |

### Implementation Phase 2 — Input Validation & Config

- GOAL-002: Add validation and policy flags.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-006 | Add `validate_table_name(name: str) -> str` to `src/tools/input_validation.py` — strips whitespace, rejects `;`/`--`, rejects empty, enforces alphanumeric+underscore | ✅ | 2026-06-23 |
| TASK-006a | Add `validate_object_type(object_type: str) -> str` to `src/tools/input_validation.py` — maps user-friendly names to `pg_class.relkind` values using `OBJECT_TYPE_MAP` dict; rejects unknown types | ✅ | 2026-06-23 |
| TASK-007 | Add 5 analyze_table flags to `config/runtime-policy.yaml`: `analyze_table: true`, `check_table_bloat: true`, `check_table_wraparound: true`, `check_table_statistics: true`, `check_index_health: true` | ✅ | 2026-06-23 |
| TASK-007a | Add 5 list_objects flags to `config/runtime-policy.yaml`: `list_objects: true`, `list_tables: true`, `list_indexes: true`, `list_views: true`, `list_objects_by_type: true` | ✅ | 2026-06-23 |

### Implementation Phase 3 — Tool Registration

- GOAL-003: Register the orchestrators + sub-tools inside the instance loop in `pg_tools.py`.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-008 | Add imports: `validate_table_name`, `validate_object_type`, `import src.tools.table_analysis as table_analysis` | ✅ | 2026-06-23 |
| TASK-009 | Register `analyze_table` orchestrator — calls all 4 maintenance `table_analysis.*` functions via single `acquire()`. Aggregates each sub-result into an independent issue entry in the `Issues` array. Each entry has: `Issue` (e.g., "Bloat/Fragmentation"), `Impacted Metrics`, `Issue Priority`, `Recommendations/Fixes`. Also populates `Overall Assessment`. | ✅ | 2026-06-23 |
| TASK-009a | Register `list_objects` orchestrator — accepts `object_type`, maps to relkind via `OBJECT_TYPE_MAP`, delegates to appropriate `table_analysis.list_*` function. Returns `Category: "Discovery"` with `Schema`, `Object Type`, `Object Count`, `Objects` array. | ✅ | 2026-06-23 |
| TASK-010 | Register 4 analyze_table sub-tools as standalone MCP tools, each gated by `is_tool_enabled`. Each acquires a connection, calls its `table_analysis.*` function, returns standardized output | ✅ | 2026-06-23 |
| TASK-010a | Register 4 list_objects sub-tools as standalone MCP tools: `list_tables`, `list_indexes`, `list_views`, `list_objects_by_type` — each gated by `is_tool_enabled`. Each accepts `schema_name` and returns `Category: "Discovery"` output | ✅ | 2026-06-23 |
| TASK-011 | Run `ruff check .` | ✅ | 2026-06-23 |

### Implementation Phase 4 — Tests

- GOAL-004: Verify validation and tool registration.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-012 | Add `TestValidateTableName` and `TestValidateObjectType` to `tests/test_input_validation.py` | ✅ | 2026-06-23 |
| TASK-013 | Add `TestAnalyzeTable` and `TestListObjects` to `tests/test_performance_tools.py` — verify all tool names in registered list, verify output schemas, verify `Category` values | ✅ | 2026-06-23 |
| TASK-014 | Update `test_registered_count_matches` from 26 to 46 (20 new tools: 10 per instance x 2 instances) | ✅ | 2026-06-23 |
| TASK-015 | Run `pytest -q` — expect 120+ passing | ✅ | 2026-06-23 |

### Implementation Phase 5 — Docs & Deploy

- GOAL-005: Document and ship.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-016 | Add 10 tool entries to `docs/mcp-tool-catalog.md` (5 analyze_table + 5 list_objects) | ✅ | 2026-06-23 |
| TASK-017 | Rebuild Docker image, push to Docker Hub, restart container with Redis backend | ✅ | 2026-06-23 |

## 4. Tool Contracts

### `db_<n>_pg96_list_objects` (Orchestrator)

**Parameters:** `schema_name` (str, required), `object_type` (str, required — one of `table`, `index`, `view`, `sequence`, `materialized_view`, `composite_type`, `foreign_table`), `database_name` (str, default `"edb"`), `actor` (str, default `"system"`)

**Output:**
```json
{
  "Category": "Discovery",
  "Date Generated": "2026-06-23",
  "Source DB Server Name": "primary",
  "Schema": "public",
  "Object Type": "table",
  "Object Count": 3,
  "Objects": [
    {"name": "orders", "owner": "app_user", "size_bytes": 1048576, "description": "Customer order records"},
    {"name": "users", "owner": "app_user", "size_bytes": 524288, "description": null},
    {"name": "products", "owner": "app_user", "size_bytes": 2097152, "description": "Product catalog"}
  ]
}
```

**Annotations:** `readOnlyHint=true`, `timeout=30.0s`, tags: `read-only`, `discovery`, `instance-{n}`

### List Objects Sub-Tool Quick Reference

| Sub-Tool | Parameters | relkind | Key Output Fields |
|----------|-----------|---------|-------------------|
| `list_tables` | `schema_name`, `database_name` | `r` | `name`, `owner`, `row_count`, `size_bytes`, `description` |
| `list_indexes` | `schema_name`, `database_name` | `i` | `name`, `table_name`, `index_type` (btree/hash/gist/gin), `size_bytes`, `idx_scan` |
| `list_views` | `schema_name`, `database_name` | `v` | `name`, `owner`, `definition` (truncated to 500 chars), `size_bytes` |
| `list_objects_by_type` | `schema_name`, `object_type`, `database_name` | any | `name`, `owner`, `size_bytes`, `description` |

### `db_<n>_pg96_analyze_table` (Orchestrator)

**Parameters:** `schema_name` (str, required), `table_name` (str, required), `database_name` (str, default `"edb"`), `actor` (str, default `"system"`)

**Output:**
```json
{
  "Category": "Maintenance",
  "Date Generated": "2026-06-23",
  "Source DB Server Name": "primary",
  "Overall Assessment": "Table public.orders has 1 CRITICAL issue (wraparound), 1 HIGH issue (bloat), and 2 MEDIUM issues (stale statistics, unused indexes).",
  "Issues": [
    {
      "Issue": "Bloat/Fragmentation",
      "Impacted Metrics": "Disk I/O, Vacuum Frequency, Table Scan Performance",
      "Issue Priority": "High",
      "Recommendations/Fixes": [
        "VACUUM FULL public.orders; -- 34% dead tuples, last vacuumed 12 days ago"
      ]
    },
    {
      "Issue": "Wraparound Risk",
      "Impacted Metrics": "Transaction ID Exhaustion, Cluster Availability",
      "Issue Priority": "Critical",
      "Recommendations/Fixes": [
        "VACUUM FREEZE public.orders; -- XID age 780M, approaching wraparound threshold"
      ]
    },
    {
      "Issue": "Stale Statistics",
      "Impacted Metrics": "Query Plan Quality, Join Order Accuracy",
      "Issue Priority": "Medium",
      "Recommendations/Fixes": [
        "ANALYZE public.orders; -- Last analyzed 45 days ago, 120K modifications since"
      ]
    },
    {
      "Issue": "Index Health",
      "Impacted Metrics": "Write Amplification, Storage Waste, Query Performance",
      "Issue Priority": "Medium",
      "Recommendations/Fixes": [
        "DROP INDEX idx_orders_status_old; -- 0 scans, 64MB wasted",
        "DROP INDEX idx_orders_date_dup; -- Duplicate of idx_orders_date, 64MB wasted"
      ]
    }
  ]
}
```

**Annotations:** `readOnlyHint=true`, `timeout=60.0s`, tags: `read-only`, `maintenance`, `instance-{n}`

### Sub-Tool Quick Reference

| Sub-Tool | Parameters | Key Output Fields |
|----------|-----------|-------------------|
| `check_table_bloat` | `schema_name`, `table_name`, `database_name` | `dead_tuple_pct`, `hot_update_pct`, `last_vacuum`, `bloat_severity` |
| `check_table_wraparound` | `schema_name`, `table_name`, `database_name` | `xid_age`, `risk_level` (LOW/MEDIUM/HIGH/CRITICAL), `recommended_action` |
| `check_table_statistics` | `schema_name`, `table_name`, `database_name` | `last_analyze`, `days_since_analyze`, `n_mod_since_analyze`, `is_stale` |
| `check_index_health` | `schema_name`, `table_name`, `database_name` | `invalid_indexes`, `unused_indexes`, `duplicate_indexes`, `total_bloat_bytes` |

## 5. Key SQL Queries

### Bloat Detection
```sql
SELECT relname, n_live_tup, n_dead_tup,
       ROUND(100.0 * n_dead_tup / NULLIF(n_live_tup + n_dead_tup, 0), 2) AS dead_pct,
       n_tup_hot_upd,
       ROUND(100.0 * n_tup_hot_upd / NULLIF(n_tup_upd, 0), 2) AS hot_update_pct,
       last_vacuum, last_autovacuum
FROM pg_stat_user_tables
WHERE schemaname = $1 AND relname = $2
```

### Wraparound Risk
```sql
SELECT c.relname, age(c.relfrozenxid) AS xid_age,
       CASE WHEN age(c.relfrozenxid) > 1500000000 THEN 'CRITICAL'
            WHEN age(c.relfrozenxid) > 1000000000 THEN 'HIGH'
            WHEN age(c.relfrozenxid) >  500000000 THEN 'MEDIUM'
            ELSE 'LOW' END AS risk_level
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind = 'r'
```

### Stale Statistics
```sql
SELECT relname, last_analyze, last_autoanalyze, n_mod_since_analyze,
       EXTRACT(DAY FROM NOW() - COALESCE(last_analyze, '1970-01-01')) AS days_since_analyze
FROM pg_stat_user_tables
WHERE schemaname = $1 AND relname = $2
```

### Index Health
```sql
-- Invalid indexes
SELECT indexrelid::regclass AS index_name FROM pg_index
WHERE indrelid = $1::regclass AND NOT indisvalid

-- Unused indexes (idx_scan = 0)
SELECT indexrelname, pg_relation_size(indexrelid) AS size_bytes
FROM pg_stat_user_indexes
WHERE schemaname = $1 AND relname = $2 AND idx_scan = 0

-- Duplicate indexes
SELECT array_agg(indexrelname) AS duplicates, indkey::text AS columns, count(*)
FROM pg_index i JOIN pg_stat_user_indexes s ON s.indexrelid = i.indexrelid
WHERE s.schemaname = $1 AND s.relname = $2
GROUP BY indkey::text HAVING count(*) > 1
```
### Object Discovery Queries (list_objects)

#### List Tables by Schema
```sql
SELECT c.relname AS name,
       pg_get_userbyid(c.relowner) AS owner,
       pg_relation_size(c.oid) AS size_bytes,
       COALESCE(s.n_live_tup, 0) AS row_count,
       obj_description(c.oid, 'pg_class') AS description
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
WHERE n.nspname = $1 AND c.relkind = 'r'
ORDER BY c.relname
```

#### List Indexes by Schema
```sql
SELECT c.relname AS name,
       t.relname AS table_name,
       am.amname AS index_type,
       pg_relation_size(c.oid) AS size_bytes,
       COALESCE(s.idx_scan, 0) AS idx_scan
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_index i ON i.indexrelid = c.oid
JOIN pg_class t ON t.oid = i.indrelid
JOIN pg_am am ON am.oid = c.relam
LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = c.oid
WHERE n.nspname = $1 AND c.relkind = 'i'
ORDER BY c.relname
```

#### List Views by Schema
```sql
SELECT c.relname AS name,
       pg_get_userbyid(c.relowner) AS owner,
       LEFT(pg_get_viewdef(c.oid), 500) AS definition,
       obj_description(c.oid, 'pg_class') AS description
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relkind = 'v'
ORDER BY c.relname
```
## 6. Alternatives

- **ALT-001 — Single monolithic tool**: Could put all 4 analyses into one tool without sub-tools. Rejected because sub-tools enable reuse (e.g., `blocking_sessions` could call `check_table_bloat` for specific tables it identifies).
- **ALT-002 — Use `pgstattuple` extension**: Provides exact bloat metrics but requires the extension to be installed on EDBAS 9.6. Rejected in favor of `pg_stat_user_tables` approximations which work without extensions.
- **ALT-003 — Group sub-tools under `analyze_data_model` check**: Could nest them inside the existing `is_tool_enabled("analyze_data_model")` block. Rejected — independent flags give finer-grained control.
- **ALT-004 — Single `list_objects` tool without sub-tools**: Could put all relkind queries into one function with a CASE switch. Rejected — sub-tools give richer per-type output (e.g., `list_indexes` includes `index_type` and `idx_scan` that don't apply to tables). They also enable other tools like `analyze_data_model` to call `list_tables_by_schema()` directly to enumerate tables.

## 7. Dependencies

- **DEP-001**: `ConnectionManager.acquire()` — ✅ exists, context manager for raw `asyncpg.Connection`
- **DEP-002**: `validate_schema_name()` — ✅ exists in `input_validation.py`
- **DEP-003**: `is_tool_enabled()` — ✅ exists in `tool_flags.py`
- **DEP-004**: `WriteGuard.enforce()` — ✅ exists, SELECT is `_READ_VERBS`
- **DEP-005**: Closure binding pattern — ✅ established in all existing tools
- **DEP-006**: `pg_get_userbyid()`, `pg_get_viewdef()`, `obj_description()` — ✅ standard PostgreSQL/EDBAS functions available in 9.6

## 8. Files

- **FILE-001**: `src/tools/table_analysis.py` — **NEW** — 8 reusable async functions (4 maintenance + 4 discovery)
- **FILE-002**: `src/tools/pg_tools.py` — add imports + 2 orchestrators + 8 sub-tools (~700 lines)
- **FILE-003**: `src/tools/input_validation.py` — add `validate_table_name()` + `validate_object_type()` + `OBJECT_TYPE_MAP` (~30 lines)
- **FILE-004**: `config/runtime-policy.yaml` — add 10 `tool_enable_flags`
- **FILE-005**: `tests/test_input_validation.py` — add `TestValidateTableName` + `TestValidateObjectType`
- **FILE-006**: `tests/test_performance_tools.py` — add `TestAnalyzeTable` + `TestListObjects`, update count 26→46
- **FILE-007**: `docs/mcp-tool-catalog.md` — add 10 tool entries

## 9. Testing

- **TEST-001**: `validate_table_name` accepts `"orders"`, `"my_table"`, strips whitespace
- **TEST-002**: `validate_table_name` rejects `""`, `";DROP"`, `"my-table"`, `"--comment"`
- **TEST-003**: All 20 new tool names (10 per instance x 2) appear in registered list
- **TEST-004**: `analyze_table` output has `Category: "Maintenance"` and `Issues` array with 4 independent entries
- **TEST-004a**: `list_objects` output has `Category: "Discovery"` and `Objects` array with expected fields per type
- **TEST-005**: Sub-tool output schemas match specification
- **TEST-006**: Total registered count updates from 26 to 46

## 10. Risks & Assumptions

- **RISK-001**: `pgstattuple` may not be installed on EDBAS 9.6 — plan uses `pg_stat_user_tables` approximations (no extension dependency)
- **RISK-002**: Index health `pg_relation_size()` may be approximate — acceptable for diagnostic tool
- **ASSUMPTION-001**: `pg_stat_user_tables` stats are populated (`track_counts` enabled) — standard on EDBAS
- **ASSUMPTION-002**: `age()` function is available — standard PostgreSQL/EDBAS function
- **ASSUMPTION-003**: Sub-tools with independent flags can coexist with existing `analyze_data_model` gating
- **ASSUMPTION-004**: `pg_get_viewdef()` works on EDBAS 9.6 — standard PostgreSQL function, verified available
- **ASSUMPTION-005**: `obj_description()` is available for object comments — standard PostgreSQL function since 8.0

## 11. Related Specifications / Further Reading

- [AGENTS.md — Tool Authoring Pattern](../AGENTS.md)
- [HypoPG Tools Module](../src/tools/hypopg_tools.py) — reusable module pattern reference
- [Analyze Data Model Tool](../src/tools/pg_tools.py#L762) — orchestrator + sub-tool pattern reference
- [Runtime Policy Config](../config/runtime-policy.yaml)
