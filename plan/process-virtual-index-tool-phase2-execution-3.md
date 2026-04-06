---
goal: Execute Phase 2 for db_pg96_create_virtual_indexes by defining patch-ready tool implementation and evaluation algorithm
version: 1.0
date_created: 2026-04-05
last_updated: 2026-04-05
owner: Harry Valdez
status: Complete
tags: [process, phase-2, tool-implementation, hypopg, explain-analyze]
---

# Introduction

![status: Complete](https://img.shields.io/badge/status-Complete-brightgreen)

This document executes Phase 2 in planning mode by providing deterministic implementation instructions for the db_pg96_create_virtual_indexes tool, including function signature, SQL sequence, bounded candidate-set generation, best-plan selection rules, and response payload schema.

## 1. Requirements & Constraints

- REQ-001: Implement MCP tool named db_pg96_create_virtual_indexes.
- REQ-002: Tool inputs are schema_name and sql_statement.
- REQ-003: Tool must use HypoPG to create virtual indexes for referenced tables only.
- REQ-004: Tool must compare EXPLAIN ANALYZE plans across candidate index sets and return least execution time winner.
- REQ-005: Tool output must include winning index set and explain plan.
- SEC-001: Tool must reject non-read-only SQL via existing read-only enforcement. Additionally, schema_name must never be concatenated into dynamic SQL as a raw string; it must either be validated by an exact-match whitelist lookup against the database catalog (pg_namespace) or passed as a bound/query parameter using psycopg sql.Identifier. Raw string interpolation of schema_name into SQL statements is forbidden.
- SEC-003: Schema name injection policy - schema_name must be validated against pg_namespace before use (exact-match whitelist) to prevent SQL injection. If validation fails, raise a ValueError with a clear message. This requirement applies to TASK-003 and any direct use of schema_name in SQL construction.
- SEC-002: Tool must clear HypoPG state before and after each set evaluation and on exceptions. Additionally, each tool invocation must use a dedicated DB session or an explicit transaction-scoped connection (HypoPG virtual indexes are session-scoped, so they do not leak between sessions; each invocation must open its own connection from the pool). EXPLAIN ANALYZE failures for a candidate set must be caught and logged per-candidate (do not abort the whole run); hypopg_reset and finally-block cleanup must still execute regardless. A configurable skip-vs-fail-fast policy must be surfaced (default: skip failed candidates and continue). Reference TASK-010 finally block.
- CON-001: Candidate set exploration must be bounded by deterministic caps.
- CON-002: No existing tool contracts may be modified.
- GUD-001: Use deterministic tie-break ordering when execution times are equal.
- PAT-001: Follow same decorator and return dict conventions as existing explain/query tools.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Define exact tool signature, decorator, and validation gates.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Add function in [server.py](server.py): def db_pg96_create_virtual_indexes(schema_name: str, sql_statement: str) -> dict[str, Any]. | ✅ | 2026-04-05 |
| TASK-002 | Add decorator in [server.py](server.py): mcp.tool(tags={"public"}, annotations={"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False}, timeout=180.0). Note: this timeout may be insufficient when max_sets=64 with expensive queries. The timeout should be configurable via an env var (e.g., VIDX_TOOL_TIMEOUT_SECONDS, default 180.0) or set to max_sets * expected_max_query_time_s + buffer. Document the trade-off: higher max_sets requires proportionally higher timeout. The deterministic lexical ordering for candidate sets: sort candidates by (schema, table, columns) tuple and enumerate pairs in itertools.combinations order. | ✅ | 2026-04-05 |
| TASK-003 | Add input validation gates in [server.py](server.py): schema_name.strip() required; _require_readonly(sql_statement) call required; reject empty SQL. | ✅ | 2026-04-05 |
| TASK-004 | Add HypoPG availability gate in [server.py](server.py): call _ensure_hypopg_available(cur) before baseline explain. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Define deterministic evaluation algorithm and SQL execution sequence.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-005 | Baseline run sequence in [server.py](server.py): EXPLAIN (ANALYZE, FORMAT JSON) <sql_statement>; parse baseline_execution_time_ms with _parse_execution_time_ms. | ✅ | 2026-04-05 |
| TASK-006 | Candidate extraction in [server.py](server.py): call _collect_candidate_index_specs(schema_name, baseline_plan_json) and store stable candidate list. | ✅ | 2026-04-05 |
| TASK-007 | Candidate set generation in [server.py](server.py): generate singles and pairs only; deterministic lexical ordering; apply caps max_set_size=2 and max_sets=64. | ✅ | 2026-04-05 |
| TASK-008 | Per-set evaluation sequence in [server.py](server.py): hypopg_reset -> create virtual indexes for set -> EXPLAIN ANALYZE JSON -> parse execution time -> capture summary record -> hypopg_reset. | ✅ | 2026-04-05 |
| TASK-009 | Tie-break rules in [server.py](server.py): lower execution_time_ms wins; then fewer indexes; then lexical order of index statement list. | ✅ | 2026-04-05 |
| TASK-010 | Exception safety in [server.py](server.py): enforce final hypopg_reset in finally block. | ✅ | 2026-04-05 |
| TASK-015 | No-improvement baseline check in [server.py](server.py): after selecting best candidate via TASK-009 tie-breaks, compare best_execution_time_ms against baseline_execution_time_ms; if best_execution_time_ms >= baseline_execution_time_ms, return baseline as selected best with improvement_ms=0, improvement_pct=0.0, and add recommendation: "none" to the payload indicating no beneficial indexes were found. Update result payload to include recommendation key so callers can distinguish no-recommendation outcomes from genuine improvements. | ✅ | 2026-04-05 |

### Implementation Phase 3

- GOAL-003: Define output payload contract and deterministic response shape.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-011 | Return payload in [server.py](server.py) with keys: schema_name, sql_statement_hash, baseline_execution_time_ms, baseline_plan_json, evaluated_sets_count, best_virtual_index_set, best_execution_time_ms, improvement_ms, improvement_pct, best_explain_plan_json, evaluated_sets_top10. | ✅ | 2026-04-05 |
| TASK-012 | best_virtual_index_set object shape in [server.py](server.py): {index_count, indexes:[{schema,table,columns,ddl,hypopg_index_oid}], tie_break_rank}. | ✅ | 2026-04-05 |
| TASK-013 | evaluated_sets_top10 shape in [server.py](server.py): ordered fastest-first list of {rank, execution_time_ms, index_count, indexes}. | ✅ | 2026-04-05 |
| TASK-014 | Fallback behavior in [server.py](server.py): if no candidates, return baseline as best with evaluated_sets_count=0, improvement_ms=0, improvement_pct=0.0. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Evaluate all combinations of candidate indexes. Rejected due to exponential complexity.
- ALT-002: Use estimated cost only from EXPLAIN without ANALYZE. Rejected because requirement is least execution time.
- ALT-003: Return only winning index DDL without plan details. Rejected because requirement explicitly asks for corresponding explain plan.

## 4. Dependencies

- DEP-001: Helpers planned in Phase 1 document: _ensure_hypopg_available, _parse_execution_time_ms, _collect_candidate_index_specs.
- DEP-002: Existing query safety helpers in [server.py](server.py): _require_readonly and _execute_safe.
- DEP-003: HypoPG SQL functions: hypopg_reset, hypopg_create_index.

## 5. Files

- FILE-001: [server.py](server.py)
- FILE-002: [plan/feature-virtual-index-tuning-tool-1.md](plan/feature-virtual-index-tuning-tool-1.md)
- FILE-003: [plan/process-virtual-index-tool-execution-1.md](plan/process-virtual-index-tool-execution-1.md)
- FILE-004: [plan/process-virtual-index-tool-phase1-execution-2.md](plan/process-virtual-index-tool-phase1-execution-2.md)
- FILE-005: [plan/process-virtual-index-tool-phase2-execution-3.md](plan/process-virtual-index-tool-phase2-execution-3.md)

## 6. Testing

- TEST-001: Tool symbol appears in static tool scan list.
- TEST-002: SQL read-only guard blocks non-SELECT statement input.
- TEST-003: Missing HypoPG produces actionable RuntimeError.
- TEST-004: Deterministic tie-break behavior for equal execution_time_ms.
- TEST-005: Output includes both baseline and best plan JSON objects.
- TEST-006: HypoPG state reset confirmed after success and exception paths.
- TEST-007: When every candidate's execution_time_ms >= baseline, assert tool returns no improvement: improvement_ms=0, improvement_pct=0.0, recommendation="none", and best_explain_plan_json equals the baseline plan.
- TEST-008: Inject a failing candidate (e.g., invalid index specification causing hypopg_create_index to error) and assert the evaluator skips/logs the failure but completes other candidate evaluations without crashing; verify final output includes results from non-failing candidates and hypopg_reset was still called.
- TEST-009: Run two concurrent invocations of the tool (exercising HypoPG setup/teardown code paths) and assert HypoPG state isolation (no cross-contamination of created hypothetical indexes between invocations) and proper cleanup on both success and exception paths; verify each invocation uses its own session-scoped connection.

## 7. Risks & Assumptions

- RISK-001: EXPLAIN ANALYZE run-to-run noise may affect selection around close timings.
- RISK-002: Candidate extraction may miss expression-based opportunities.
- RISK-003: Statement timeout may truncate long-running candidate evaluations.
- ASSUMPTION-001: Input SQL is valid in target database context.
- ASSUMPTION-002: Schema-scoped filtering is sufficient for candidate relevance.
- ASSUMPTION-003: Existing database role can execute HypoPG functions.

## 8. Related Specifications / Further Reading

- [plan/feature-virtual-index-tuning-tool-1.md](plan/feature-virtual-index-tuning-tool-1.md)
- [plan/process-virtual-index-tool-phase1-execution-2.md](plan/process-virtual-index-tool-phase1-execution-2.md)
- https://hypopg.readthedocs.io/
- https://www.postgresql.org/docs/9.6/sql-explain.html