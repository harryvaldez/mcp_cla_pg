---
goal: Execute implementation of db_pg96_create_virtual_indexes with HypoPG candidate-set evaluation and deterministic validation
version: 1.0
date_created: 2026-04-05
last_updated: 2026-04-05
owner: Harry Valdez
status: Complete
tags: [process, implementation, feature, hypopg, testing]
---

# Introduction

![status: Complete](https://img.shields.io/badge/status-Complete-brightgreen)

This process plan is the executable companion to the feature plan for db_pg96_create_virtual_indexes. It provides deterministic sequencing, task dependencies, command-level validation, and completion criteria to implement and verify the feature end-to-end.

## 1. Requirements & Constraints

- REQ-001: Implement db_pg96_create_virtual_indexes in server.py with input args schema_name and sql_statement.
- REQ-002: Use HypoPG extension to create only virtual indexes for candidate index sets.
- REQ-003: Evaluate EXPLAIN ANALYZE JSON for baseline and each candidate set.
- REQ-004: Return the set with least execution time and the corresponding explain plan.
- REQ-005: Preserve behavior of existing db_pg96 tools and resources.
- SEC-001: Tool must enforce read-only query validation before any explain execution.
- SEC-002: Tool must reset HypoPG state after each candidate and before return.
- CON-001: Candidate combinations must be bounded (max_set_size and max_sets) to avoid runaway runtime. Default values: max_set_size = 2 (singles and pairs only), max_sets = 64 (cap on total evaluated sets). These are exposed as module-level constants VIDX_MAX_SET_SIZE_DEFAULT and VIDX_MAX_SETS_DEFAULT in server.py and can be overridden by callers. Validation must reject or clamp inputs outside allowed ranges (max_set_size >= 1, max_sets >= 1). Candidate combination generation uses these caps deterministically: generate all singles, then pairs up to max_set_size=2, then truncate the full list at max_sets.
- CON-002: No schema/object mutations outside HypoPG virtual index catalog.
- GUD-001: Use deterministic tie-breaker when execution times are equal. Tie-breaking order: (1) lower execution_time_ms wins; (2) if still equal, fewer indexes in the candidate set wins; (3) if still equal, compare the serialized index definitions (DDL strings) lexicographically using canonical string representation (sorted list of DDL strings compared element-by-element); (4) if still equal, the candidate that appears first in the evaluated candidate list wins (first-evaluated wins). All implementers must use this exact ordering. The canonicalization method is: represent each candidate set as a sorted list of its DDL strings and compare as Python tuples.
- GUD-002: Include actionable error message when HypoPG is missing.
- PAT-001: Follow existing FastMCP tool decorator style and structured dict response pattern in server.py.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Implement core server-side logic and helper functions.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Edit server.py to add helper _ensure_hypopg_available(cur) and fail with RuntimeError containing remediation SQL create extension if missing. | ✅ | 2026-04-05 |
| TASK-002 | Edit server.py to add helper _parse_execution_time_ms(plan_json) and helper _extract_plan_nodes(plan_json) for deterministic node traversal. | ✅ | 2026-04-05 |
| TASK-003 | Edit server.py to add helper _collect_candidate_index_specs(schema_name, plan_json) that outputs stable candidate list of table/columns tuples. | ✅ | 2026-04-05 |
| TASK-004 | Implement db_pg96_create_virtual_indexes(schema_name: str, sql_statement: str) with baseline explain, candidate generation, HypoPG evaluation loop, best-set tracking, and final structured payload. | ✅ | 2026-04-05 |
| TASK-005 | Add per-candidate HypoPG reset: inside the candidate evaluation loop, call hypopg_reset after each candidate's EXPLAIN ANALYZE (after capturing the evaluation result) to clear virtual indexes before the next candidate is created. Additionally add a finally-block safety reset: select * from hypopg_reset() as a last-resort cleanup for every execution path including exceptions. The per-iteration reset is the primary mechanism; the finally block is a safety net. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Integrate tool into static inventory and regression guards.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-006 | Update tests/test_tools_pg96.py EXPECTED_TOOLS list with db_pg96_create_virtual_indexes. | ✅ | 2026-04-05 |
| TASK-007 | Add unit-style test for best-plan selection from mocked explain outputs and deterministic tie-break behavior. | ✅ | 2026-04-05 |
| TASK-008 | Add unit-style test for missing HypoPG extension path asserting RuntimeError contains hypopg remediation text. | ✅ | 2026-04-05 |
| TASK-009 | Add functional_test.py smoke invocation asserting output keys best_virtual_index_set, best_explain_plan_json, best_execution_time_ms, baseline_execution_time_ms are present. | ✅ | 2026-04-05 |
| TASK-010 | Confirm no changes are required in read-only enforcement internals beyond _require_readonly(sql_statement) use in new tool. | ✅ | 2026-04-05 |

### Implementation Phase 3

- GOAL-003: Validate implementation with deterministic local checks and update completion status.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-011 | Run targeted tests: python -m pytest -q tests/test_tools_pg96.py -k "virtual_indexes or static". | ✅ | 2026-04-05 |
| TASK-012 | Run targeted tests: python -m pytest -q tests/functional_test.py -k "virtual_indexes or explain". | ✅ | 2026-04-05 |
| TASK-013 | If failures occur, apply minimal patch and re-run failing tests up to 3 iterations maximum. | ✅ | 2026-04-05 |
| TASK-014 | Update plan/feature-virtual-index-tuning-tool-1.md status to In progress or Completed with task checkmarks and dates based on executed work. | ✅ | 2026-04-05 |
| TASK-015 | Update plan/IMPLEMENTATION_SUMMARY.md with brief section for this feature only after all required tests pass. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Use EXPLAIN without ANALYZE and compare estimated costs only. Rejected because request explicitly requires least execution time.
- ALT-002: Evaluate three-column and larger index sets by default. Rejected for runtime and combinatorial risk.
- ALT-003: Depend on pg_stat_statements for candidate extraction. Rejected because request scope is single SQL statement tuning.

## 4. Dependencies

- DEP-001: HypoPG extension installed in target PostgreSQL instance.
- DEP-002: Existing server.py helper utilities _execute_safe and _require_readonly.
- DEP-003: pytest and existing test harness under tests/.
- DEP-004: Docker or local PostgreSQL test fixture used by repository tests.

## 5. Files

- FILE-001: server.py
- FILE-002: tests/test_tools_pg96.py
- FILE-003: tests/functional_test.py
- FILE-004: plan/feature-virtual-index-tuning-tool-1.md
- FILE-005: plan/IMPLEMENTATION_SUMMARY.md

## 6. Testing

- TEST-001: Tool appears in static tool inventory scan.
- TEST-002: Missing HypoPG extension returns actionable failure.
- TEST-003: Candidate evaluation returns deterministic best set with minimal execution_time_ms.
- TEST-004: Tool returns baseline explain and best explain objects in JSON-compatible form.
- TEST-005: Tool leaves no residual virtual indexes in connection state after completion.

## 7. Risks & Assumptions

- RISK-001: Query parser heuristics may miss some indexable expressions.
- RISK-002: EXPLAIN ANALYZE can execute long-running SQL and hit statement timeout.
- RISK-003: Plan variance due to caching may affect per-run execution times.
- ASSUMPTION-001: SQL statement references objects in provided schema_name.
- ASSUMPTION-002: Connection role has execute privilege for HypoPG functions.
- ASSUMPTION-003: Existing CI environment either has HypoPG-enabled DB fixture or uses mocks for unit coverage.

## 8. Related Specifications / Further Reading

- plan/feature-virtual-index-tuning-tool-1.md
- plan/feature-fastmcp-server-alignment-1.md
- https://hypopg.readthedocs.io/
- https://www.postgresql.org/docs/9.6/sql-explain.html