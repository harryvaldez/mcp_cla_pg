---
goal: Consolidate execution of db_pg96_create_virtual_indexes across phases 1 to 3 into one deterministic runbook
version: 1.0
date_created: 2026-04-05
last_updated: 2026-04-05
owner: Harry Valdez
status: Complete
tags: [process, consolidated, virtual-indexes, hypopg, execution]
---

# Introduction

![status: Complete](https://img.shields.io/badge/status-Complete-brightgreen)

This consolidated runbook provides one ordered execution path for implementing and validating db_pg96_create_virtual_indexes, combining the prior phase documents into a single deterministic sequence.

## 1. Requirements & Constraints

- REQ-001: Deliver db_pg96_create_virtual_indexes in server.py with inputs schema_name and sql_statement.
- REQ-002: Use HypoPG virtual indexes only, never persistent index creation.
- REQ-003: Return best virtual index set based on minimum EXPLAIN ANALYZE execution time.
- REQ-004: Keep existing db_pg96 tools backward compatible.
- SEC-001: Enforce read-only SQL validation before any evaluation.
- SEC-002: Guarantee hypopg_reset on success and failure paths.
- CON-001: Candidate search bounded by max_set_size=2 and max_sets=64.
- CON-002: Fix loop cap of 3 iterations for test-failure repair cycle.
- GUD-001: Deterministic tie-break: execution_time_ms, then fewer indexes, then lexical DDL order.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Implement helper primitives and constants in server.py.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Insert helper functions in server.py: _ensure_hypopg_available, _parse_execution_time_ms, _extract_plan_nodes, _normalize_candidate_columns, _collect_candidate_index_specs. | ✅ | 2026-04-05 |
| TASK-002 | Insert constants in server.py helper section: VIDX_MAX_SET_SIZE_DEFAULT=2 and VIDX_MAX_SETS_DEFAULT=64. | ✅ | 2026-04-05 |
| TASK-003 | Verify helper placement near existing SQL helper block and no mcp decorators attached. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Implement tool logic and payload contract in server.py.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-004 | Add db_pg96_create_virtual_indexes tool with readOnlyHint/idempotentHint/openWorldHint annotations and timeout=180.0. | ✅ | 2026-04-05 |
| TASK-005 | Add validation gates: schema_name required, sql_statement required, _require_readonly(sql_statement). | ✅ | 2026-04-05 |
| TASK-006 | Run baseline EXPLAIN ANALYZE JSON and parse baseline execution time. | ✅ | 2026-04-05 |
| TASK-007 | Build candidate specs, generate bounded single and pair sets, and evaluate each set with HypoPG create/reset cycle. | ✅ | 2026-04-05 |
| TASK-008 | Select winner by deterministic tie-break and return full response payload including baseline and best plans. | ✅ | 2026-04-05 |
| TASK-009 | Enforce final hypopg_reset in finally block. | ✅ | 2026-04-05 |

### Implementation Phase 3

- GOAL-003: Apply test updates and execute validation pipeline.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-010 | Update tests/test_tools_pg96.py EXPECTED_TOOLS with db_pg96_create_virtual_indexes. | ✅ | 2026-04-05 |
| TASK-011 | Add tests for winner selection, tie-break behavior, missing HypoPG, and reset safety in tests/test_tools_pg96.py. | ✅ | 2026-04-05 |
| TASK-012 | Add functional smoke invocation and conditional HypoPG skip path in tests/functional_test.py. | ✅ | 2026-04-05 |
| TASK-013 | Run targeted test set A: python -m pytest -q tests/test_tools_pg96.py -k "virtual_indexes or static_tools_inventory". | ✅ | 2026-04-05 |
| TASK-014 | Run targeted test set B: python -m pytest -q tests/functional_test.py -k "virtual_indexes or explain_query". | ✅ | 2026-04-05 |
| TASK-015 | If A and B pass, run expanded regression set: python -m pytest -q tests/test_tools_pg96.py tests/functional_test.py. | ✅ | 2026-04-05 |
| TASK-016 | On any failure, apply minimal patch and re-run failing set only; max 3 loops. | ✅ | 2026-04-05 |

### Implementation Phase 4

- GOAL-004: Close out planning artifacts and completion records.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-017 | Update status and checkmarks in plan/feature-virtual-index-tuning-tool-1.md after tests pass. | ✅ | 2026-04-05 |
| TASK-018 | Add completion section to plan/IMPLEMENTATION_SUMMARY.md with scope, commands run, outcomes, and residual risks. | ✅ | 2026-04-05 |
| TASK-019 | Verify changed file set is limited to intended files before final completion signal. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Keep separate phase documents only. Rejected because execution overhead increases and sequencing ambiguity remains.
- ALT-002: Run full repository test suite before targeted tests. Rejected to reduce cycle time and isolate failures quickly.

## 4. Dependencies

- DEP-001: plan/process-virtual-index-tool-phase1-execution-2.md
- DEP-002: plan/process-virtual-index-tool-phase2-execution-3.md
- DEP-003: plan/process-virtual-index-tool-phase3-execution-4.md
- DEP-004: HypoPG available in runtime fixture or guarded test path.

## 5. Files

- FILE-001: server.py
- FILE-002: tests/test_tools_pg96.py
- FILE-003: tests/functional_test.py
- FILE-004: plan/feature-virtual-index-tuning-tool-1.md
- FILE-005: plan/IMPLEMENTATION_SUMMARY.md
- FILE-006: plan/process-virtual-index-tool-consolidated-5.md

## 6. Testing

- TEST-001: Static inventory includes db_pg96_create_virtual_indexes.
- TEST-002: Deterministic best-set selection verified.
- TEST-003: Missing-extension path verified with remediation text.
- TEST-004: Reset behavior verified for success and exceptions.
- TEST-005: Functional payload contract verified.

## 7. Risks & Assumptions

- RISK-001: Timing noise in EXPLAIN ANALYZE may create near-tie instability for very close plans.
- RISK-002: Candidate extraction may underfit expression-index opportunities.
- ASSUMPTION-001: Statement timeout settings permit completion of bounded candidate evaluation.
- ASSUMPTION-002: Existing tests can mock cursor responses for deterministic unit assertions.

## 8. Related Specifications / Further Reading

- plan/feature-virtual-index-tuning-tool-1.md
- plan/process-virtual-index-tool-execution-1.md
- plan/process-virtual-index-tool-phase1-execution-2.md
- plan/process-virtual-index-tool-phase2-execution-3.md
- plan/process-virtual-index-tool-phase3-execution-4.md
- https://hypopg.readthedocs.io/
- https://www.postgresql.org/docs/9.6/sql-explain.html