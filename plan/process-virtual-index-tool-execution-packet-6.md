---
goal: Provide strict go/no-go checklist to execute db_pg96_create_virtual_indexes implementation and validation end-to-end
version: 1.0
date_created: 2026-04-05
last_updated: 2026-04-05
owner: Harry Valdez
status: Complete
tags: [process, checklist, execution-packet, go-no-go, virtual-indexes]
---

# Introduction

![status: Complete](https://img.shields.io/badge/status-Complete-brightgreen)

This packet is a strict, linear execution checklist with stop conditions. Each step has explicit go/no-go criteria and no implied decisions.

## 1. Requirements & Constraints

- REQ-001: Execute helper implementation before tool implementation.
- REQ-002: Execute tool implementation before test edits.
- REQ-003: Execute targeted tests before expanded regression tests.
- REQ-004: Stop immediately on checkpoint failure and apply only minimal corrective patch.
- SEC-001: Preserve read-only enforcement for sql_statement.
- SEC-002: Ensure hypopg_reset is always called in success and exception paths.
- CON-001: Maximum corrective loops per failing checkpoint is 3.
- CON-002: Do not modify unrelated files.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Helper and constant insertion in server.py

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Insert helpers: _ensure_hypopg_available, _parse_execution_time_ms, _extract_plan_nodes, _normalize_candidate_columns, _collect_candidate_index_specs in server.py helper block. | ✅ | 2026-04-05 |
| TASK-002 | Insert constants: VIDX_MAX_SET_SIZE_DEFAULT=2 and VIDX_MAX_SETS_DEFAULT=64. | ✅ | 2026-04-05 |
| TASK-003 | GO/NO-GO Checkpoint CP-1: grep symbol check in server.py returns all 7 symbols. If missing any symbol: NO-GO and patch missing symbol only. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Tool implementation in server.py

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-004 | Add db_pg96_create_virtual_indexes tool function with required signature and decorator. | ✅ | 2026-04-05 |
| TASK-005 | Add baseline EXPLAIN ANALYZE JSON run and candidate extraction flow. | ✅ | 2026-04-05 |
| TASK-006 | Add bounded set generation and per-set HypoPG evaluation loop with deterministic tie-break. | ✅ | 2026-04-05 |
| TASK-007 | Add structured payload fields: baseline, best set, best plan, improvement metrics, evaluated_sets_top10. | ✅ | 2026-04-05 |
| TASK-008 | Add try/finally hypopg_reset finalizer. | ✅ | 2026-04-05 |
| TASK-009 | GO/NO-GO Checkpoint CP-2: static AST scan confirms tool name appears and function compiles. If fail: NO-GO and patch tool function only. | ✅ | 2026-04-05 |

### Implementation Phase 3

- GOAL-003: Test and inventory updates

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-010 | Update EXPECTED_TOOLS list in tests/test_tools_pg96.py with db_pg96_create_virtual_indexes. | ✅ | 2026-04-05 |
| TASK-011 | Add unit-style tests: winner selection, tie-break, missing HypoPG, reset safety. | ✅ | 2026-04-05 |
| TASK-012 | Add functional smoke call in tests/functional_test.py with HypoPG guard behavior. | ✅ | 2026-04-05 |
| TASK-013 | GO/NO-GO Checkpoint CP-3: run python -m pytest -q tests/test_tools_pg96.py -k "virtual_indexes or static_tools_inventory". If fail: NO-GO and patch failing test or implementation minimally. | ✅ | 2026-04-05 |
| TASK-014 | GO/NO-GO Checkpoint CP-4: run python -m pytest -q tests/functional_test.py -k "virtual_indexes or explain_query". If fail: NO-GO and patch minimally. | ✅ | 2026-04-05 |

### Implementation Phase 4

- GOAL-004: Regression pass and closeout

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-015 | Run expanded regression: python -m pytest -q tests/test_tools_pg96.py tests/functional_test.py. | ✅ | 2026-04-05 |
| TASK-016 | Update plan/feature-virtual-index-tuning-tool-1.md status/task checkmarks when all checkpoints pass. | ✅ | 2026-04-05 |
| TASK-017 | Update plan/IMPLEMENTATION_SUMMARY.md with feature result and residual risks. | ✅ | 2026-04-05 |
| TASK-018 | GO/NO-GO Checkpoint CP-5: get_changed_files review confirms only intended files changed. If unexpected changes: NO-GO and isolate before completion. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Free-form implementation workflow. Rejected due ambiguity and inconsistent execution behavior.
- ALT-002: Full-suite-only validation. Rejected due poor failure localization.

## 4. Dependencies

- DEP-001: plan/process-virtual-index-tool-consolidated-5.md
- DEP-002: plan/process-virtual-index-tool-phase1-execution-2.md
- DEP-003: plan/process-virtual-index-tool-phase2-execution-3.md
- DEP-004: plan/process-virtual-index-tool-phase3-execution-4.md

## 5. Files

- FILE-001: server.py
- FILE-002: tests/test_tools_pg96.py
- FILE-003: tests/functional_test.py
- FILE-004: plan/feature-virtual-index-tuning-tool-1.md
- FILE-005: plan/IMPLEMENTATION_SUMMARY.md
- FILE-006: plan/process-virtual-index-tool-execution-packet-6.md

## 6. Testing

- TEST-001: CP-1 symbol presence check
- TEST-002: CP-2 static tool presence/compilation check
- TEST-003: CP-3 targeted unit/static tests
- TEST-004: CP-4 targeted functional smoke tests
- TEST-005: CP-5 changed-files scope verification

## 7. Risks & Assumptions

- RISK-001: Timing variance may produce near-tie instability in some environments.
- RISK-002: Functional fixture may lack HypoPG and trigger guarded behavior.
- ASSUMPTION-001: Database test fixture is reachable for functional smoke path.
- ASSUMPTION-002: Existing test harness supports patch-minimal correction loops.

## 8. Related Specifications / Further Reading

- plan/process-virtual-index-tool-consolidated-5.md
- plan/feature-virtual-index-tuning-tool-1.md
- https://hypopg.readthedocs.io/
- https://www.postgresql.org/docs/9.6/sql-explain.html