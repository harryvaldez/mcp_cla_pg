---
goal: Execute Phase 3 for db_pg96_create_virtual_indexes by defining deterministic testing, validation, and completion workflow
version: 1.0
date_created: 2026-04-05
last_updated: 2026-04-05
owner: Harry Valdez
status: Complete
tags: [process, phase-3, testing, validation, completion]
---

# Introduction

![status: Complete](https://img.shields.io/badge/status-Complete-brightgreen)

This document executes Phase 3 in planning mode by defining exact test additions, execution commands, pass criteria, failure-handling loops, and completion updates for the db_pg96_create_virtual_indexes feature.

## 1. Requirements & Constraints

- REQ-001: Add tests that verify registration, behavior, and error handling for db_pg96_create_virtual_indexes.
- REQ-002: Validate deterministic winner selection from evaluated virtual index sets.
- REQ-003: Validate actionable error path when HypoPG extension is absent.
- REQ-004: Validate backward compatibility with existing static tool inventory expectations.
- SEC-001: Tests must not require persistent index creation.
- SEC-002: Tests must verify HypoPG reset behavior to avoid session leakage.
- CON-001: Keep total test runtime bounded by targeted subset execution first.
- CON-002: Maximum retry loop for fixing failures is three iterations.
- GUD-001: Prefer deterministic mocks for planner-time comparison tests.
- PAT-001: Reuse existing AST and invocation test patterns in tests/test_tools_pg96.py and tests/functional_test.py.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Define exact new test cases and file edits.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Edit [tests/test_tools_pg96.py](tests/test_tools_pg96.py) EXPECTED_TOOLS list to include db_pg96_create_virtual_indexes. | ✅ | 2026-04-05 |
| TASK-002 | Add static signature/assertion test in [tests/test_tools_pg96.py](tests/test_tools_pg96.py) ensuring tool symbol exists and starts with db_pg96_ naming convention. | ✅ | 2026-04-05 |
| TASK-003 | Add behavior test in [tests/test_tools_pg96.py](tests/test_tools_pg96.py) mocking explain outputs for multiple candidate sets and asserting minimum execution_time_ms is chosen. | ✅ | 2026-04-05 |
| TASK-004 | Add tie-break test in [tests/test_tools_pg96.py](tests/test_tools_pg96.py) asserting equal execution_time_ms resolves by fewer indexes then lexical DDL order. | ✅ | 2026-04-05 |
| TASK-005 | Add missing-extension test in [tests/test_tools_pg96.py](tests/test_tools_pg96.py) asserting RuntimeError contains create extension hypopg remediation text. | ✅ | 2026-04-05 |
| TASK-006 | Add reset-safety test in [tests/test_tools_pg96.py](tests/test_tools_pg96.py) asserting hypopg_reset is called on success and failure paths. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Define functional validation path and command matrix.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-007 | Add functional smoke sequence in [tests/functional_test.py](tests/functional_test.py) to invoke db_pg96_create_virtual_indexes with safe SELECT statement and assert required keys in response payload. | ✅ | 2026-04-05 |
| TASK-008 | Add conditional skip logic in functional test when HypoPG is unavailable in runtime fixture, while preserving unit coverage for missing-extension path. | ✅ | 2026-04-05 |
| TASK-009 | Run targeted test command 1: python -m pytest -q tests/test_tools_pg96.py -k "virtual_indexes or static_tools_inventory". | ✅ | 2026-04-05 |
| TASK-010 | Run targeted test command 2: python -m pytest -q tests/functional_test.py -k "virtual_indexes or explain_query". | ✅ | 2026-04-05 |
| TASK-011 | If both targeted commands pass, run expanded regression command: python -m pytest -q tests/test_tools_pg96.py tests/functional_test.py. | ✅ | 2026-04-05 |

### Implementation Phase 3

- GOAL-003: Define failure loop, completion updates, and release readiness criteria.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-012 | On failure, capture first failing assertion and apply minimal patch only to affected file(s), preserving unrelated behavior. | ✅ | 2026-04-05 |
| TASK-013 | Re-run only failing command segment; repeat up to 3 iterations maximum. | ✅ | 2026-04-05 |
| TASK-014 | After green tests, update [plan/feature-virtual-index-tuning-tool-1.md](plan/feature-virtual-index-tuning-tool-1.md) status to Completed and mark task rows with dates. | ✅ | 2026-04-05 |
| TASK-015 | Update [plan/IMPLEMENTATION_SUMMARY.md](plan/IMPLEMENTATION_SUMMARY.md) with a concise section for this feature: scope, tests run, result, and residual risks. | ✅ | 2026-04-05 |
| TASK-016 | Confirm no unintended changes in unrelated files before final completion signal. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Run full suite first. Rejected because targeted failures provide faster feedback and lower iteration cost.
- ALT-002: Skip functional test due environment variability. Rejected because a smoke validation path is required for tool confidence.
- ALT-003: Depend only on static AST inventory. Rejected because behavior correctness requires runtime-path assertions.

## 4. Dependencies

- DEP-001: Tool and helpers from previous execution artifacts in [plan/process-virtual-index-tool-phase1-execution-2.md](plan/process-virtual-index-tool-phase1-execution-2.md) and [plan/process-virtual-index-tool-phase2-execution-3.md](plan/process-virtual-index-tool-phase2-execution-3.md).
- DEP-002: pytest and current repository test harness.
- DEP-003: PostgreSQL fixture with optional HypoPG availability.

## 5. Files

- FILE-001: [tests/test_tools_pg96.py](tests/test_tools_pg96.py)
- FILE-002: [tests/functional_test.py](tests/functional_test.py)
- FILE-003: [plan/feature-virtual-index-tuning-tool-1.md](plan/feature-virtual-index-tuning-tool-1.md)
- FILE-004: [plan/IMPLEMENTATION_SUMMARY.md](plan/IMPLEMENTATION_SUMMARY.md)
- FILE-005: [plan/process-virtual-index-tool-phase3-execution-4.md](plan/process-virtual-index-tool-phase3-execution-4.md)

## 6. Testing

- TEST-001: Static inventory contains db_pg96_create_virtual_indexes.
- TEST-002: Happy path returns best set and plan with least execution_time_ms.
- TEST-003: Tie-break path deterministic under equal execution times.
- TEST-004: Missing HypoPG yields actionable RuntimeError.
- TEST-005: HypoPG reset invoked on success and failure.
- TEST-006: Functional smoke invocation validates payload contract.

## 7. Risks & Assumptions

- RISK-001: Runtime test variance from planner caching may require mocked determinism for comparison assertions.
- RISK-002: Functional fixture may not have HypoPG installed, requiring guarded test flow.
- RISK-003: Broader regressions could emerge from helper placement in server.py when implementation pass occurs.
- ASSUMPTION-001: Existing test harness supports monkeypatching database cursor behavior.
- ASSUMPTION-002: Future implementation pass will follow deterministic output contract from prior phase artifact.

## 8. Related Specifications / Further Reading

- [plan/feature-virtual-index-tuning-tool-1.md](plan/feature-virtual-index-tuning-tool-1.md)
- [plan/process-virtual-index-tool-phase1-execution-2.md](plan/process-virtual-index-tool-phase1-execution-2.md)
- [plan/process-virtual-index-tool-phase2-execution-3.md](plan/process-virtual-index-tool-phase2-execution-3.md)
- https://hypopg.readthedocs.io/
- https://www.postgresql.org/docs/9.6/sql-explain.html