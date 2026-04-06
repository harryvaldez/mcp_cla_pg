---
goal: Implement db_pg96_create_virtual_indexes tool to evaluate HypoPG virtual index sets and return lowest execution-time explain plan
version: 1.0
date_created: 2026-04-05
last_updated: 2026-04-05
owner: Harry Valdez
status: Complete
tags: [feature, postgres, hypopg, explain, performance, mcp-tool]
---

# Introduction

![Status: Complete](https://img.shields.io/badge/status-Complete-brightgreen)

This plan defines deterministic implementation of a new MCP tool named db_pg96_create_virtual_indexes. The tool accepts schema_name and sql_statement, generates candidate HypoPG virtual index sets for referenced tables, executes EXPLAIN ANALYZE for each set, and returns the set producing the minimum execution time.

## 1. Requirements & Constraints

- REQ-001: Add new MCP tool named db_pg96_create_virtual_indexes in server.py.
- REQ-002: Tool input parameters are schema_name and sql_statement exactly as requested.
- REQ-003: Tool uses HypoPG extension APIs to create virtual indexes for tuning session only.
- REQ-004: Tool must evaluate multiple index sets and corresponding EXPLAIN plans.
- REQ-005: Tool output must include best virtual index set and explain plan with least execution time.
- REQ-006: Tool must return deterministic structured JSON-compatible payload.
- REQ-007: Tool must support PostgreSQL 9.6 behavior constraints used by this repository.
- SEC-001: Do not persist real indexes; use only HypoPG session-scoped virtual indexes.
- SEC-002: Enforce read-only SQL validation for sql_statement before execution.
- SEC-003: Prevent SQL injection for schema/table/column identifiers by using psycopg.sql.Identifier for generated statements.
- CON-001: Existing tool signatures and behavior in server.py must remain backward compatible.
- CON-002: Expected static tool inventory in tests/test_tools_pg96.py must be updated to include the new tool.
- CON-003: Existing explain tool at server.py line ~5291 is the canonical plan extraction style and should be reused.
- GUD-001: Hard cap candidate combinations to prevent combinatorial blowups.
- GUD-002: Fail with actionable error when HypoPG extension is unavailable.
- PAT-001: Follow existing mcp.tool decorator style used by db_pg96_explain_query and db_pg96_analyze_indexes.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Add deterministic helper primitives for HypoPG capability checks, candidate extraction, and explain-time parsing.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | In server.py add helper _ensure_hypopg_available(cur) that executes select extname from pg_extension where extname='hypopg' and raises RuntimeError with installation guidance when missing. | ✅ | 2026-04-05 |
| TASK-002 | In server.py add helper _extract_plan_nodes(plan_json: dict[str, Any]) to recursively walk Plan tree and emit normalized nodes containing relation, alias, node_type, filter, index_cond, hash_cond, merge_cond, sort_key, group_key, join_filter. | ✅ | 2026-04-05 |
| TASK-003 | In server.py add helper _collect_candidate_index_specs(schema_name: str, plan_json: dict[str, Any]) to derive candidate index column tuples per table from Index Cond/Filter/Join/Sort keys with de-duplication and stable ordering. | ✅ | 2026-04-05 |
| TASK-004 | In server.py add helper _normalize_identifier_list(expr_text: str) for extracting column identifiers from simple predicates and sort keys; ignore expressions that cannot be safely reduced to identifiers. | ✅ | 2026-04-05 |
| TASK-005 | In server.py add helper _parse_execution_time_ms(plan_json: dict[str, Any]) that returns Execution Time from EXPLAIN ANALYZE JSON root and errors if missing. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Implement db_pg96_create_virtual_indexes tool and evaluation loop across candidate index sets.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-006 | Add mcp.tool function db_pg96_create_virtual_indexes(schema_name: str, sql_statement: str) in server.py near other db_pg96 query-analysis tools. Use annotations readOnlyHint=true, idempotentHint=true, openWorldHint=false, timeout=180.0. | ✅ | 2026-04-05 |
| TASK-007 | Inside tool enforce _require_readonly(sql_statement) and validate schema_name non-empty plus existence in pg_namespace. | ✅ | 2026-04-05 |
| TASK-008 | Execute baseline EXPLAIN (ANALYZE, FORMAT JSON) for sql_statement and store baseline_plan plus baseline_execution_time_ms. | ✅ | 2026-04-05 |
| TASK-009 | Build candidate index specs by parsing baseline plan and filtering to relations in requested schema_name. | ✅ | 2026-04-05 |
| TASK-010 | Generate candidate sets deterministically: single indexes plus pair combinations up to max_set_size=2 and max_sets=64 (constants in function scope). | ✅ | 2026-04-05 |
| TASK-011 | For each candidate set: run select * from hypopg_reset(); create all indexes using select * from hypopg_create_index('create index on schema.table (col1,col2,...)'); run EXPLAIN (ANALYZE, FORMAT JSON) sql_statement; capture execution_time_ms and full plan. | ✅ | 2026-04-05 |
| TASK-012 | Track best result by strict minimum execution_time_ms; tie-break by fewer indexes, then lexical order of index DDL strings. | ✅ | 2026-04-05 |
| TASK-013 | Return output payload containing baseline, evaluated_sets_count, best_virtual_index_set, best_execution_time_ms, improvement_ms, improvement_pct, best_explain_plan_json, and per_set_summary list with top 10 fastest sets. | ✅ | 2026-04-05 |
| TASK-014 | Ensure function always calls hypopg_reset before return and on exceptions using try/finally to prevent leaked virtual state in pooled connections. | ✅ | 2026-04-05 |

### Implementation Phase 3

- GOAL-003: Add tests, inventory updates, and documentation for reliable operation.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-015 | Update EXPECTED_TOOLS in tests/test_tools_pg96.py to include db_pg96_create_virtual_indexes so static inventory check passes. | ✅ | 2026-04-05 |
| TASK-016 | Add unit-style test in tests/test_tools_pg96.py that monkeypatches server.pool.connection and verifies tool returns required keys and chooses minimal execution_time_ms from mocked explain outputs. | ✅ | 2026-04-05 |
| TASK-017 | Add error-path test in tests/test_tools_pg96.py for missing HypoPG extension returning actionable RuntimeError message mentioning create extension hypopg. | ✅ | 2026-04-05 |
| TASK-018 | Add functional smoke invocation in tests/functional_test.py tool call sequence with safe SQL query and assert response includes best_virtual_index_set and best_execution_time_ms. | ✅ | 2026-04-05 |
| TASK-019 | Update README.md tools or tuning section to document db_pg96_create_virtual_indexes purpose, parameters, and HypoPG prerequisite. | ✅ | 2026-04-05 |
| TASK-020 | Run pytest -q tests/test_tools_pg96.py tests/functional_test.py and record pass/fail summary in plan/IMPLEMENTATION_SUMMARY.md only after successful implementation. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Generate all power-set combinations of candidates. Rejected because runtime grows exponentially and is unsafe for large SQL statements.
- ALT-002: Use only single-column indexes. Rejected because many query plans improve only with composite indexes.
- ALT-003: Build real temporary indexes in transaction and rollback. Rejected because it is slower and can require elevated privileges, while HypoPG is purpose-built for this workflow.

## 4. Dependencies

- DEP-001: PostgreSQL extension HypoPG installed in target database.
- DEP-002: Permissions to execute HypoPG functions and EXPLAIN ANALYZE for the tuned query.
- DEP-003: Existing server.py helpers _require_readonly and _execute_safe.
- DEP-004: Test framework pytest already present in requirements and pytest.ini.

## 5. Files

- FILE-001: server.py - Add helper functions and db_pg96_create_virtual_indexes tool implementation.
- FILE-002: tests/test_tools_pg96.py - Add tool inventory and behavior tests.
- FILE-003: tests/functional_test.py - Add end-to-end smoke test call for new tool.
- FILE-004: README.md - Document new tool and HypoPG requirement.
- FILE-005: plan/IMPLEMENTATION_SUMMARY.md - Update completion matrix after implementation and validation.

## 6. Testing

- TEST-001: Static tool inventory includes db_pg96_create_virtual_indexes.
- TEST-002: Happy path returns baseline and best plan fields with numeric execution time values.
- TEST-003: Best-set chooser selects minimum execution time and deterministic tie-break result.
- TEST-004: Missing HypoPG extension produces deterministic RuntimeError with remediation text.
- TEST-005: Empty candidate extraction falls back to baseline result with evaluated_sets_count=0 and improvement_ms=0.
- TEST-006: Tool resets HypoPG state on both success and raised exceptions.

## 7. Risks & Assumptions

- RISK-001: Predicate parser may miss useful expression indexes (for example lower(column)) and produce suboptimal recommendations.
- RISK-002: EXPLAIN ANALYZE executes SQL and can still be expensive for very large queries.
- RISK-003: Connection pool reuse can leak virtual indexes if reset logic is incomplete.
- RISK-004: Candidate set caps may omit globally best combination in complex workloads.
- ASSUMPTION-001: Input sql_statement is a single SELECT/CTE statement suitable for EXPLAIN ANALYZE.
- ASSUMPTION-002: schema_name corresponds to objects referenced by the tuned statement.
- ASSUMPTION-003: Users accept plan-quality approximation based on explored candidate set limits.

## 8. Related Specifications / Further Reading

- https://hypopg.readthedocs.io/
- https://www.postgresql.org/docs/9.6/sql-explain.html
- [server.py](server.py)
- [tests/test_tools_pg96.py](tests/test_tools_pg96.py)
- [tests/functional_test.py](tests/functional_test.py)