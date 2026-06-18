---
goal: PostgreSQL 9.6 Performance Enhancement Tools with HypoPG Index Optimization
version: 2.0
date_created: 2026-06-17
last_updated: 2026-06-17
owner: MCP Postgres Team
status: In progress
tags: feature, performance, postgresql, hypopg, index-optimization
---

# Introduction

![Status: In progress](https://img.shields.io/badge/status-In%20progress-yellow)

This plan outlines the integration of three performance-focused diagnostics tools into the FastMCP Postgres 9.6 server, with special emphasis on the `get_slow_statements` tool which uses HypoPG virtual indexes to generate and rank the top 5+ improved explain plans by cost. Reusable sub-tools are created for HypoPG operations so other tools can leverage virtual index optimization independently.

## 1. Requirements & Constraints

- **REQ-001**: Implement `db_<n>_pg96_get_slow_statements` to retrieve long-running SQL from `pg_stat_statements`, generate the current `EXPLAIN` plan, then produce at least 5 improved explain plans by testing HypoPG virtual index combinations, ranking them by total cost (ascending), and selecting the best combination.
- **REQ-002**: Implement `db_<n>_pg96_blocking_sessions` to analyze active/idle-in-transaction sessions, lock trees, deadlocks, and seq_scan abuse.
- **REQ-003**: Implement `db_<n>_pg96_analyze_data_model` as an aggregator that delegates to sub-tools for schema extraction, constraint analysis, normalization checks, index statistics, and 3NF decomposition analysis.
- **REQ-004**: Create reusable HypoPG sub-tools (`hypopg_create_virtual_indexes`, `hypopg_explain_with_virtual`, `hypopg_find_optimal_indexes`) that can be invoked independently by other MCP tools and agents.
- **REQ-005**: The `get_slow_statements` tool must identify referenced tables/columns from each slow query, generate candidate virtual indexes, test combinations of virtual + existing indexes via EXPLAIN, rank the top 5+ plans by total cost, and present the best index recommendation.
- **SEC-001**: The HypoPG `hypopg_create_index()` function is session-state-modifying (creates virtual indexes in backend memory). It must be explicitly allowlisted in `runtime-policy.yaml` under `allowed_write_tools` since it modifies session state, even though no persistent DDL changes occur.
- **SEC-002**: The readonly user (`edb_readonly_user`) must have `EXECUTE` privilege granted on the HypoPG extension functions (`hypopg_create_index`, `hypopg_drop_index`, `hypopg_reset`, `hypopg_get_indexdef`, `hypopg_list_indexes`) in target databases.
- **CON-001**: All tools must follow the dual-instance closure binding pattern — never hardcode instance names in tool logic.
- **CON-002**: All SQL-facing parameters must pass through `src/tools/input_validation.py` validators. Never concatenate user input into SQL.
- **CON-003**: The output schema for all three performance tools must use the standardized Performance Analysis Schema with fields: `Category`, `Date Generated`, `Source DB Server Name`, `Issues Identified`, `Impacted Metrics`, `Issue Priority`, `Recommendations/Fixes`.
- **GUD-001**: Follow the tool authoring pattern from `AGENTS.md`: closure-bound `_tool`, `_instance`, `_instance_number` defaults; `_resolve_actor_and_authorize`; `session_manager.touch`; `rate_limiter.allow`; `write_guard.enforce`; structured audit logging; deterministic error contracts.
- **GUD-002**: HypoPG sub-tools must accept `query_text` (the SQL to analyze) and `database_name` as primary inputs, making them portable for reuse by any tool or external agent.
- **PAT-001**: Reusable HypoPG sub-tools use the same dual-instance registration pattern as all other tools, with the `readOnlyHint` set to `false` since they create/drop virtual indexes in session memory.

## 2. Implementation Steps

### Implementation Phase 1: Input Validation & Security Policy Updates

- GOAL-001: Update input validation and security policy to prepare for new tools and HypoPG operations.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Ensure `validate_database_name` and `validate_schema_name` in `src/tools/input_validation.py` are robust. Add `validate_query_text(query_text: str)` to sanitize SQL statement input for HypoPG sub-tools — strip surrounding whitespace, reject `;` and `--` sequences, and reject DDL/DML statements (must start with `SELECT`). | | |
| TASK-002 | Update `config/runtime-policy.yaml`: add `hypopg_create_index`, `hypopg_drop_index`, `hypopg_reset`, `hypopg_get_indexdef`, `hypopg_list_indexes` to `allowed_write_tools` list since they modify session memory state. | | |
| TASK-003 | Add `get_slow_statements`, `blocking_sessions`, `analyze_data_model`, `extract_schema_model`, `analyze_constraints_and_fks`, `analyze_normalization`, `analyze_index_statistics`, `analyze_3nf_and_decomposition`, `hypopg_create_virtual_indexes`, `hypopg_explain_with_virtual`, `hypopg_find_optimal_indexes` to `tool_enable_flags` in `config/runtime-policy.yaml` (all set to `true`). | | |

### Implementation Phase 2: Reusable HypoPG Sub-Tools

- GOAL-002: Create three reusable HypoPG sub-tools that can be called independently by `get_slow_statements` and by any other MCP tool or external agent.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | **Create `src/tools/hypopg_tools.py`** module containing the core HypoPG logic as standalone async functions: | | |
| | **`async def parse_tables_and_columns(conn, query_text: str) -> dict`**: Parses SQL text using regex to extract referenced tables and columns from `FROM`, `JOIN`, `WHERE`, `ORDER BY`, and `GROUP BY` clauses. Uses `pg_catalog` and `information_schema` lookups to resolve fully-qualified table/column names. Returns `{"database_name": str, "tables": {table_name: {"columns": [col_names], "is_referenced_in_where": bool, "is_referenced_in_join": bool, "is_referenced_in_order_by": bool}}}`. | | |
| | **`async def hypopg_create_virtual_indexes(conn, query_analysis: dict) -> list[dict]`**: Takes the parsed query analysis, generates candidate single-column B-tree index definitions for columns in WHERE/JOIN/ORDER BY clauses, creates each virtual index via `SELECT * FROM hypopg_create_index($1)` with the index definition string, and returns a list of `{"index_name": str, "oid": int, "indexdef": str}` for each created virtual index. | | |
| | **`async def hypopg_explain_with_virtual(conn, query_text: str) -> dict`**: Runs `EXPLAIN (FORMAT JSON)` for the given query against the current session (which may have virtual indexes active), parses the JSON plan output, and returns `{"plan": dict, "total_cost": float}`, extracting `"Total Cost"` from the top-level plan node. | | |
| | **`async def hypopg_find_optimal_indexes(conn, query_text: str, max_combinations: int = 10) -> dict`**: Orchestrator that: (a) captures baseline `EXPLAIN` cost **before** creating any virtual indexes; (b) calls `parse_tables_and_columns` and `hypopg_create_virtual_indexes` to get candidate indexes; (c) generates up to `max_combinations` combinations of virtual indexes (singletons first, then pairwise, then triplets, capped at `max_combinations`); (d) for each combination: calls `hypopg_reset()`, creates that subset of virtual indexes, runs `hypopg_explain_with_virtual` to get cost; (e) after testing all combos, calls `hypopg_reset()` to clean up; (f) returns `{"baseline_cost": float, "ranked_plans": [{"rank": int, "virtual_indexes_used": list[str], "total_cost": float, "cost_improvement_pct": float, "explain_plan": dict}, ...], "best_recommendation": {"virtual_indexes": list[str], "total_cost": float, "improvement_pct": float}}`. | | |
| TASK-005 | **Register HypoPG sub-tools in `src/tools/pg_tools.py`** inside the instance loop, following the dual-instance closure binding pattern: | | |
| | **`db_{n}_pg96_hypopg_create_virtual_indexes`**: Accepts `database_name: str` and `query_text: str`. Calls `validate_database_name` and `validate_query_text`. Uses `connection_manager.acquire` to get a raw connection. Calls `parse_tables_and_columns` then `hypopg_create_virtual_indexes`. Returns the list of created virtual indexes `{"virtual_indexes_created": list, "query_analysis": dict}`. | | |
| | **`db_{n}_pg96_hypopg_explain_with_virtual`**: Accepts `database_name: str` and `query_text: str`. Acquires a raw connection from the pool, runs `EXPLAIN (FORMAT JSON)`, returns `{"plan": dict, "total_cost": float}`. | | |
| | **`db_{n}_pg96_hypopg_find_optimal_indexes`**: Accepts `database_name: str`, `query_text: str`, and optional `max_combinations: int = 10`. Orchestrates the full search: captures baseline cost, generates candidates, tests combinations, ranks by cost, resets HypoPG at the end, and returns the ranked results with the best recommendation. | | |
| TASK-006 | **Implement SQL parsing for HypoPG candidates** in `src/tools/hypopg_tools.py` `parse_tables_and_columns()`: Use regex patterns to extract table references from `FROM` clauses (including aliases), `JOIN ... ON` conditions, `WHERE` predicate columns, and `ORDER BY` columns. Query `information_schema.columns` for the referenced tables to validate column names and get data types. Generate B-tree index definitions (`CREATE INDEX ON <table> (<column>)`) for columns appearing in WHERE predicates, JOIN conditions, and ORDER BY clauses — these are the columns most likely to benefit from indexing. | | |

### Implementation Phase 3: Logic Implementation (`get_slow_statements`)

- GOAL-003: Rewrite the `get_slow_statements` tool to leverage HypoPG sub-tools for generating and ranking top 5+ improved explain plans.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-007 | **Rewrite `get_slow_statements` logic** in `src/tools/pg_tools.py`: | | |
| | (a) Query `pg_stat_statements` joined with `pg_database` and `pg_roles` to get top 5 slowest queries by `total_time / calls` (mean time) descending, filtering to the requested `database_name`. | | |
| | (b) For each identified slow query, retrieve its full query text (truncate to 1000 chars for processing). | | |
| | (c) Get the baseline `EXPLAIN (FORMAT JSON)` plan and its total cost **without** any virtual indexes. | | |
| | (d) Call `hypopg_find_optimal_indexes` (via its core Python function in `hypopg_tools.py`) to generate candidate virtual indexes, test combinations, and get ranked plans. | | |
| | (e) For each ranked plan (at least 5), format the output showing: the virtual indexes used (their `indexdef` strings), the total cost, cost improvement %, and the JSON explain plan. | | |
| | (f) Identify the best recommendation (lowest cost plan) and highlight the cost improvement percentage vs baseline. | | |
| | (g) Include `ANALYZE` suggestions if `pg_stats` shows stale statistics for relevant tables (check `last_analyze` vs `last_autoanalyze`). | | |
| TASK-008 | **Format output into standardized Performance Analysis Schema** with `Recommendations/Fixes` containing per-statement entries. Each statement entry includes: `"Long Running Statement"`, `"Calls"`, `"Mean Time"`, `"Total Time"`, `"Baseline Explain Plan"` (JSON), `"Baseline Total Cost"` (float), `"Ranked Improved Plans"` (array of at least 5 plans each with `rank`, `total_cost`, `cost_improvement_pct`, `virtual_indexes_tested`, `explain_plan`), `"Best Recommendation"` (the single best plan with `virtual_indexes_to_create`, `expected_cost`, `improvement_pct`), and `"Statistics Recommendations"` (list of `ANALYZE` statements if stale stats detected). | | |

### Implementation Phase 4: Logic Implementation (`blocking_sessions`)

- GOAL-004: Implement the blocking sessions analysis tool.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-009 | **Implement `blocking_sessions` logic** in `src/tools/pg_tools.py`: | | |
| | (a) Query `pg_stat_activity` for sessions in the target database with `state = 'active'` or `state = 'idle in transaction'`, ordered by `query_start` ascending, limited to 20 rows. | | |
| | (b) Query `pg_locks` joined with `pg_stat_activity` to build the blocking tree: find sessions waiting on locks (`granted = false`) and the blocking sessions (`granted = true` with matching `relation`). | | |
| | (c) Query `pg_stat_user_tables` for high `seq_scan` counts vs `idx_scan` to identify sequential scan abuse. | | |
| | (d) Detect deadlocks by examining `pg_locks` for cyclical wait dependencies. | | |
| | (e) Format output: `"Issues Identified"` summarizes number of blocking chains and deadlocks; `"Impacted Metrics"` lists wait times and seq_scan counts; `"Recommendations/Fixes"` contains per-session entries with `session_pid`, `state`, `wait_event_type`, `wait_event`, `query` (truncated), `blocked_by_pid` (if applicable), and `recommendation` (e.g., "Terminate blocking PID N", "Add index to eliminate seq scan on table T"). | | |

### Implementation Phase 5: Logic Implementation (`analyze_data_model` & Sub-Tools)

- GOAL-005: Implement the data model analysis aggregator and its five reusable sub-tools.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-010 | **Implement `extract_schema_model` sub-tool**: Query `information_schema.columns` joined with `pg_class` and `pg_namespace` to serialize all tables, their columns, data types, and nullability for the target schema. Return as structured data. | | |
| TASK-011 | **Implement `analyze_constraints_and_fks` sub-tool**: Query `pg_constraint` joined with `pg_class` and `pg_namespace`. Flag tables missing primary keys. Identify foreign key references that lack corresponding indexes on the referencing columns. Report dropped or disabled constraints. | | |
| TASK-012 | **Implement `analyze_normalization` sub-tool**: Compare columns across tables that share common join patterns (by naming convention like `_id` suffixes). Flag data type size mismatches (e.g., `int` PK in one table vs `bigint` FK reference in another). Report columns with overly permissive types (e.g., `text` where `varchar(N)` is appropriate). | | |
| TASK-013 | **Implement `analyze_index_statistics` sub-tool**: Read `pg_stats` and `pg_stat_user_tables`. Flag tables where `last_analyze` is NULL or older than 7 days, or where `n_dead_tup` / `n_live_tup` ratio exceeds 0.2. Provide explicit `ANALYZE` and `VACUUM` SQL statements as fix recommendations. | | |
| TASK-014 | **Implement `analyze_3nf_and_decomposition` sub-tool**: Sample rows from tables with high seq_scan counts. Detect repeated column values that suggest M:N relationships embedded in a single table. Flag insertion/deletion/update anomalies. Recommend decomposition into parent-child entity structures. | | |
| TASK-015 | **Implement `analyze_data_model` aggregator**: Call the core Python functions from TASK-010 through TASK-014 internally (not via MCP tool calls). Aggregate all findings into a unified report. Group findings by category (constraints, normalization, statistics, 3NF). Prioritize issues by severity (High/Medium/Low). | | |

### Implementation Phase 6: HypoPG Sub-Tool Integration into `analyze_data_model`

- GOAL-006: Leverage HypoPG sub-tools within the data model analysis pipeline for index recommendations.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-016 | **Integrate HypoPG into `analyze_index_statistics`**: After flagging stale/missing statistics, run sample queries from the affected tables through `hypopg_find_optimal_indexes` to provide concrete virtual index recommendations alongside `ANALYZE` suggestions. | | |
| TASK-017 | **Expose HypoPG findings in `analyze_data_model` output**: Include a `"HypoPG Index Recommendations"` section in the aggregated report that lists optimal virtual indexes found across all analyzed tables, tagged with the table name and estimated cost improvement. | | |

### Implementation Phase 7: Documentation & Testing

- GOAL-007: Document all new tools and implement comprehensive tests.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-018 | Update `docs/mcp-tool-catalog.md` with full documentation for all new tools: `get_slow_statements` (updated), `blocking_sessions`, `analyze_data_model`, `extract_schema_model`, `analyze_constraints_and_fks`, `analyze_normalization`, `analyze_index_statistics`, `analyze_3nf_and_decomposition`, `hypopg_create_virtual_indexes`, `hypopg_explain_with_virtual`, `hypopg_find_optimal_indexes`. Include parameter tables, output schema, annotations, tags, and example responses for each. | | |
| TASK-019 | Create `tests/test_hypopg_tools.py` — unit tests for the HypoPG core functions in `src/tools/hypopg_tools.py`. Mock `asyncpg.Connection` to simulate `hypopg_create_index()`, `hypopg_reset()`, and `EXPLAIN (FORMAT JSON)` responses. Test: candidate index generation from SQL text, cost ranking of virtual index combinations, baseline cost capture, empty candidate handling, and error recovery when HypoPG extension is not installed. | | |
| TASK-020 | Create `tests/test_performance_tools.py` — integration-style tests for the three main tools using patched connection managers: | | |
| | (a) Test `_get_slow_statements`: mock `pg_stat_statements` row data, mock `hypopg_find_optimal_indexes` return value, verify the output contains `"Ranked Improved Plans"` with at least 5 entries and `"Best Recommendation"`. | | |
| | (b) Test `_blocking_sessions`: mock `pg_stat_activity` and `pg_locks` data to simulate a blocking chain, verify blocking tree detection. | | |
| | (c) Test `_analyze_data_model`: mock responses from all five sub-tool functions, verify aggregated output contains all expected sections. | | |
| | (d) Test `registered` list length assertion updates (currently `assert len(registered) == 18`, must be recalculated). | | |

## 3. Alternatives

- **ALT-001 (pg_hint_plan)**: Using `pg_hint_plan` extension to force plan shapes was considered but rejected because it requires fixed plan hints rather than exploring virtual index combinations. HypoPG provides more actionable index recommendations.
- **ALT-002 (External optimization service)**: Sending queries to an external service (e.g., PostgreSQL's auto_explain with machine learning analysis) was considered but rejected due to added latency, dependency on external infrastructure, and the requirement for the tool to work fully offline inside the MCP server.
- **ALT-003 (All combinations brute-force)**: Testing all possible virtual index combinations (powerset) was considered but rejected due to exponential explosion. The chosen approach tests singletons, then pairwise combinations, capped at `max_combinations` (default 10), which provides high-quality recommendations without excessive latency.
- **ALT-004 (Inline HypoPG logic in `get_slow_statements`)**: Embedding all HypoPG logic directly in `get_slow_statements` was considered but rejected in favor of separate sub-tools for reusability across the codebase and by external agents.

## 4. Dependencies

- **DEP-001**: The HypoPG extension must be installed on the target EDBAS 9.6 instances (`CREATE EXTENSION IF NOT EXISTS hypopg;`). This must be verified before the tool can operate. If missing, the tool should return an error indicating HypoPG is not available.
- **DEP-002**: `pg_stat_statements` extension must be enabled on target instances for `get_slow_statements` to retrieve query execution statistics.
- **DEP-003**: The `edb_readonly_user` must be granted `EXECUTE` on HypoPG functions (`hypopg_create_index`, `hypopg_drop_index`, `hypopg_reset`, `hypopg_get_indexdef`, `hypopg_list_indexes`) in each target database.
- **DEP-004**: Python 3.11+ with `asyncpg` must be available (already satisfied by existing `pyproject.toml`).
- **DEP-005**: The `re` module (Python standard library) is needed for SQL text parsing in HypoPG candidate generation.

## 5. Files

| File | Description | Action |
|------|-------------|--------|
| `src/tools/input_validation.py` | Add `validate_query_text()` function | Modify |
| `config/runtime-policy.yaml` | Add HypoPG functions to `allowed_write_tools`; add tool enable flags for all new tools | Modify |
| `src/tools/hypopg_tools.py` | New module: core HypoPG async functions (`parse_tables_and_columns`, `hypopg_create_virtual_indexes`, `hypopg_explain_with_virtual`, `hypopg_find_optimal_indexes`) | Create |
| `src/tools/pg_tools.py` | Rewrite `get_slow_statements` to use HypoPG sub-tools; register `blocking_sessions`, `analyze_data_model`, all sub-tools, and HypoPG sub-tools | Modify |
| `docs/mcp-tool-catalog.md` | Document all new and updated tools | Modify |
| `tests/test_hypopg_tools.py` | Unit tests for HypoPG core functions | Create |
| `tests/test_performance_tools.py` | Integration tests for the three main performance tools | Create |
| `tests/test_ping_tool.py` | Update `registered` count assertion | Modify |

## 6. Testing

| Test | Description |
|------|-------------|
| TEST-001 | `test_hypopg_tools.py::test_parse_tables_from_query` — Verify SQL text parsing extracts correct table references from various query patterns (simple SELECT, JOIN, subquery, CTE). |
| TEST-002 | `test_hypopg_tools.py::test_generate_candidate_indexes` — Verify candidate B-tree index definitions are generated for columns in WHERE/JOIN/ORDER BY clauses. |
| TEST-003 | `test_hypopg_tools.py::test_rank_plans_by_cost` — Verify that given mocked EXPLAIN results with different costs, the ranking orders plans by ascending cost and picks the best. |
| TEST-004 | `test_hypopg_tools.py::test_baseline_capture` — Verify baseline cost is captured before any virtual indexes are created. |
| TEST-005 | `test_hypopg_tools.py::test_no_candidates` — Verify graceful handling when no candidate indexes can be generated (e.g., query references no tables). |
| TEST-006 | `test_hypopg_tools.py::test_hypopg_not_installed` — Verify error handling when HypoPG functions are not available. |
| TEST-007 | `test_performance_tools.py::test_get_slow_statements_output` — Verify the output contains `Ranked Improved Plans` with ≥5 entries, `Baseline Total Cost`, `Best Recommendation`, and `Statistics Recommendations`. |
| TEST-008 | `test_performance_tools.py::test_blocking_sessions_lock_tree` — Verify blocking chain detection with mocked lock data. |
| TEST-009 | `test_performance_tools.py::test_blocking_sessions_deadlock` — Verify deadlock detection with cyclical lock wait data. |
| TEST-010 | `test_performance_tools.py::test_analyze_data_model_aggregation` — Verify aggregated report contains constraint, normalization, statistics, and 3NF sections. |
| TEST-011 | `test_performance_tools.py::test_validate_query_text` — Verify `validate_query_text` rejects DDL/DML and allows SELECT statements. |
| TEST-012 | `test_ping_tool.py::test_registered_tools_list` — Update the expected count for the new tools registered. |

## 7. Risks & Assumptions

- **RISK-001**: HypoPG may not be installed or available on target EDBAS 9.6 instances. **Mitigation**: Graceful degradation — if `hypopg_create_index` function is not found, the tool skips virtual index testing and reports only baseline stats with a note that HypoPG is unavailable.
- **RISK-002**: SQL parsing via regex for table/column extraction may be incomplete for very complex queries (CTEs, subqueries, window functions). **Mitigation**: Use `pg_catalog` queries combined with regex; document limitations; the system still works with partial recommendations.
- **RISK-003**: Virtual index testing causes additional load on the database via repeated `EXPLAIN` calls. **Mitigation**: Cap `max_combinations` at 10 (default); single-connection-per-request ensures session isolation; timeout set to 30s.
- **RISK-004**: `pg_stat_statements` may have rotated out the target queries or may not capture all long-running queries. **Mitigation**: The tool reads the top 5 by `total_time / calls`, which captures the most impactful queries even if rotation has occurred.
- **RISK-005**: The `hypopg_reset()` call at the end of `hypopg_find_optimal_indexes` clears all virtual indexes from the session, but if an error occurs mid-operation, virtual indexes may leak across subsequent tool calls on the same connection. **Mitigation**: Use `try/finally` to ensure `hypopg_reset()` is always called. Additionally, the connection pool may reuse connections, so consider calling `hypopg_reset()` at the start of each HypoPG operation as defensive cleanup.
- **ASSUMPTION-001**: The target EDBAS 9.6 instances have `pg_stat_statements` loaded via `shared_preload_libraries` (standard for EDBAS deployments).
- **ASSUMPTION-002**: The target databases allow CREATE TEMP TABLE-style session operations (HypoPG creates virtual objects in session memory, not persistent DDL).
- **ASSUMPTION-003**: The HypoPG extension version available on EDBAS 9.6 supports `hypopg_create_index(text)` and `hypopg_list_indexes()` functions with the standard PostgreSQL API.

## 8. Related Specifications / Further Reading

- [FastMCP 3 Documentation](https://gofastmcp.com/)
- [HypoPG Extension Documentation](https://github.com/HypoPG/hypopg)
- [PostgreSQL 9.6 pg_stat_statements Documentation](https://www.postgresql.org/docs/9.6/pgstatstatements.html)
- [AGENTS.md](../AGENTS.md) — Project architecture, guardrails, and tool authoring patterns
- [docs/mcp-tool-catalog.md](../docs/mcp-tool-catalog.md) — Canonical tool contract documentation
- [Implementation Plan v1.0](feature-performance-tools-plan-1.md) — Previous version of this plan (archived)
