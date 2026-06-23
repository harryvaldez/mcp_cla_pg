---
goal: Address 16 QA review issues from FastMCP v3 refactor code review
version: 1.0
date_created: 2026-06-23
last_updated: 2026-06-23
status: Implemented
tags: bugfix, qa, refactor, hardening
---

# Introduction

![Status: Implemented](https://img.shields.io/badge/status-Implemented-green)

Fix 16 issues identified by QA review of the FastMCP v3 best practices refactor (commits a267323..df2ca9c). Issues span 3 Critical, 5 Important, and 8 Minor severity levels.

## 1. Requirements & Constraints

- **REQ-001**: All tool-level errors must use ToolError (not RuntimeError) per project guardrail
- **REQ-002**: validate_query_text must accept valid PostgreSQL queries including CTEs and SQL comments
- **REQ-003**: validate_sql_statement must remain SELECT-only for exec_query
- **REQ-004**: max_combinations must have an upper bound (1-100)
- **REQ-005**: exec_query must return warned: true when max_rows is silently clamped
- **REQ-006**: Duplicate database_name parameter passing must be removed
- **CON-001**: 127 existing tests must continue to pass
- **CON-002**: No breaking API changes to tool output schemas
- **PAT-001**: Follow AGENTS.md Tool Authoring Pattern

## 2. Implementation Steps

### Phase 1 — Critical Fixes (3 issues)

- GOAL-001: Fix functional defects and guardrail violations

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Fix validate_query_text to accept WITH ... SELECT CTE queries | ✅ | 2026-06-23 |
| TASK-002 | Fix validate_query_text to accept SQL comments (/* */ and --) | ✅ | 2026-06-23 |
| TASK-003 | Replace remaining RuntimeError raises in hypopg_tools.py with ToolError | ✅ | 2026-06-23 |
| TASK-004 | Fix _get_slow_statements dual database_name passing (consistent pattern) | ✅ | 2026-06-23 |

### Phase 2 — Important Fixes (5 issues)

- GOAL-002: Fix DOS vector, silent truncation, misleading labels, resource exhaustion

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-005 | Add upper-bound validation on max_combinations (max 100) | ✅ | 2026-06-23 |
| TASK-006 | Add warned flag to exec_query output when max_rows exceeds 1000 cap | ✅ | 2026-06-23 |
| TASK-007 | Consolidate connection acquires in _get_slow_statements inner loop | ✅ | 2026-06-23 |
| TASK-008 | Rename deadlock_count to potential_blocking_cycles | ✅ | 2026-06-23 |

### Phase 3 — Minor Cleanup (8 issues)

- GOAL-003: Fix naming, deprecations, dead code, test gaps, consistency

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-009 | Rename total_bloat_bytes to total_index_bytes in check_index_health() | ✅ | 2026-06-23 |
| TASK-010 | Fix UnboundLocalError risk: init baseline before try block | ✅ | 2026-06-23 |
| TASK-011 | Replace datetime.utcnow() with datetime.now(UTC) in all 13 locations | ✅ | 2026-06-23 |
| TASK-012 | Remove dead validate_identifier and its tests | ✅ | 2026-06-23 |
| TASK-013 | Add execution tests for _register_sub_tool tools | ⏭️ | Deferred |
| TASK-014 | Add execution tests for _register_discovery_tool tools | ⏭️ | Deferred |
| TASK-015 | Add execution test for _list_objects_by_type | ⏭️ | Deferred |
| TASK-016 | Normalize state access pattern to Depends(lambda: state) | ✅ | 2026-06-23 |

### Phase 4 — Validation

- GOAL-004: Verify all fixes pass linting, tests, and type checking

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-017 | Run ruff check . — must have 0 errors | ✅ | 2026-06-23 |
| TASK-018 | Run pytest -q — 126 tests passing (3 removed for dead validate_identifier) | ✅ | 2026-06-23 |
| TASK-019 | Verify 0 Pylance type errors on pg_tools.py | ✅ | 2026-06-23 |

## 3. Alternatives

- **ALT-001**: Accept any SQL prefix — rejected (DDL/DML injection risk). Current regex preserves safety.
- **ALT-002**: Keep RuntimeError in hypopg_tools.py — rejected (violates deterministic error contracts guardrail).
- **ALT-003**: True pg_locks cycle deadlock detection — deferred to future PR.

## 4. Dependencies

- **DEP-001**: None. All fixes self-contained within existing module boundaries.

## 5. Files

- **FILE-001**: src/tools/pg_tools.py — TASK-004,005,006,007,008,011,016
- **FILE-002**: src/tools/hypopg_tools.py — TASK-003,010
- **FILE-003**: src/tools/input_validation.py — TASK-001,002,012
- **FILE-004**: src/tools/table_analysis.py — TASK-009
- **FILE-005**: tests/test_input_validation.py — TASK-001,002
- **FILE-006**: tests/test_performance_tools.py — TASK-013,014,015

## 6. Testing

- **TEST-001**: test_accepts_with_select — asserts WITH ... SELECT ... accepted
- **TEST-002**: test_accepts_commented_select — asserts comment-prefixed SQL accepted
- **TEST-003**: test_rejects_non_select_cte — asserts DDL in CTE rejected
- **TEST-004**: test_max_combinations_clamped — asserts >100 clamped
- **TEST-005**: test_exec_query_clamped_max_rows — asserts warned:true on clamp
- **TEST-006**: test_sub_tool_execution — 4 maintenance sub-tools
- **TEST-007**: test_discovery_tool_execution — 3 discovery sub-tools
- **TEST-008**: test_list_objects_by_type_execution — multiple relkind values

## 7. Risks & Assumptions

- **RISK-001**: WITH CTE validation could open injection vector — mitigated by ; -- blocking
- **RISK-002**: ToolError catch gap — mitigated by completing full migration in TASK-003
- **ASSUMPTION-001**: datetime.UTC available in Python 3.11 (confirmed)
- **ASSUMPTION-002**: Tests use mocks/patching, no DB required
