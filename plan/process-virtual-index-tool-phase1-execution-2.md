---
goal: Execute Phase 1 for db_pg96_create_virtual_indexes by producing deterministic, patch-ready implementation instructions
version: 1.0
date_created: 2026-04-05
last_updated: 2026-04-05
owner: Harry Valdez
status: Complete
tags: [process, phase-1, virtual-indexes, hypopg, server.py]
---

# Introduction

![status: Complete](https://img.shields.io/badge/status-Complete-brightgreen)

This document executes Phase 1 in planning mode by delivering exact, patch-ready implementation instructions for helper primitives and tool wiring in server.py, including function signatures, algorithm steps, insertion anchors, and verification criteria.

## 1. Requirements & Constraints

- REQ-001: Add Phase 1 helper functions into server.py without changing existing tool behavior.
- REQ-002: Helpers must be deterministic, pure where possible, and JSON-plan compatible.
- REQ-003: New helper logic must rely on existing _execute_safe and _require_readonly safety controls.
- REQ-004: Phase 1 output must identify exact insertion anchors in server.py for implementation.
- SEC-001: No dynamic SQL identifier interpolation using f-strings for schema/table/column objects.
- SEC-002: Any future SQL emitted by these helpers must be bounded and sanitized.
- CON-001: Keep Python compatibility with current project runtime and typing style in server.py.
- CON-002: Do not modify existing tool signatures in this phase.
- GUD-001: Use stable sorted output for candidate specs to guarantee deterministic evaluation ordering.
- PAT-001: Place helper functions in existing helper section near SQL parsing and execution helpers.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Define and place helper primitives required by the virtual index tool.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Insert helper _ensure_hypopg_available(cur) directly after _execute_safe_with_fallback in server.py. Function behavior: query pg_extension for hypopg; if absent raise RuntimeError("HypoPG extension is required. Run: CREATE EXTENSION hypopg;"). | ✅ | 2026-04-05 |
| TASK-002 | Insert helper _parse_execution_time_ms(plan_json: Any) after TASK-001 helper. Function behavior: validate nested shape list[0]["Plan"] envelope from EXPLAIN FORMAT JSON output and extract numeric "Execution Time" from root object. Raise ValueError when missing or non-numeric. | ✅ | 2026-04-05 |
| TASK-003 | Insert helper _extract_plan_nodes(plan_root: dict[str, Any]) returning list[dict[str, Any]] with recursive depth-first traversal. Captured fields per node: node_type, relation_name, schema, alias, index_name, filter, index_cond, recheck_cond, hash_cond, merge_cond, join_filter, sort_key, group_key, plans_count. | ✅ | 2026-04-05 |
| TASK-004 | Insert helper _normalize_candidate_columns(expr: Any) that converts cond/sort/group content into ordered deduplicated identifier list by regex extraction from simple identifier tokens; strip quoting and exclude SQL keywords. | ✅ | 2026-04-05 |
| TASK-005 | Insert helper _collect_candidate_index_specs(schema_name: str, plan_json: Any) returning list[dict[str, Any]] sorted by relation then column tuple. Candidate spec shape: {"schema": str, "table": str, "columns": list[str], "source": str}. | ✅ | 2026-04-05 |
| TASK-006 | Add local constants for downstream phase compatibility in helper section: VIDX_MAX_SET_SIZE_DEFAULT = 2 and VIDX_MAX_SETS_DEFAULT = 64. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Define Phase 1 insertion anchors and code boundaries for future patch execution.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-007 | Anchor A identified: helper zone around _execute_safe, _execute_safe_async, _execute_safe_with_fallback in server.py (near line region around 1798 to 1915) for all new helper insertions. | ✅ | 2026-04-05 |
| TASK-008 | Anchor B identified: tool zone around db_pg96_explain_query in server.py (near line region around 5291) as insertion target for future db_pg96_create_virtual_indexes tool in Phase 2 implementation. | ✅ | 2026-04-05 |
| TASK-009 | Anchor C identified: tests/test_tools_pg96.py EXPECTED_TOOLS list at top of file for future tool registration assertion update. | ✅ | 2026-04-05 |

### Implementation Phase 3

- GOAL-003: Define deterministic acceptance checks for Phase 1 helper implementation.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-010 | Acceptance check AC-001: server.py contains all six new helper symbols plus two constants with exact names defined in this plan. | ✅ | 2026-04-05 |
| TASK-011 | Acceptance check AC-002: Helper functions perform no MCP registration side effects and are not decorated with mcp.tool/resource/prompt. | ✅ | 2026-04-05 |
| TASK-012 | Acceptance check AC-003: Candidate extraction output ordering is deterministic for identical plan input. | ✅ | 2026-04-05 |
| TASK-013 | Acceptance check AC-004: HypoPG availability helper emits actionable RuntimeError text with create extension command. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Derive candidates from raw SQL parsing only. Rejected because baseline plan nodes provide more accurate access paths and predicates.
- ALT-002: Include expression indexes in Phase 1 extraction. Rejected for initial complexity and safety; defer to later enhancement.
- ALT-003: Use randomized candidate ordering to diversify search. Rejected because determinism is required for stable automated testing.

## 4. Dependencies

- DEP-001: Existing helper stack in server.py: _strip_sql_noise, _is_sql_readonly, _execute_safe.
- DEP-002: Existing imports in server.py include typing.Any and re; no new third-party dependency required for Phase 1.
- DEP-003: Existing plan files: plan/feature-virtual-index-tuning-tool-1.md and plan/process-virtual-index-tool-execution-1.md.

## 5. Files

- FILE-001: server.py (target for helper insertions in future code-edit pass)
- FILE-002: plan/feature-virtual-index-tuning-tool-1.md (feature traceability)
- FILE-003: plan/process-virtual-index-tool-execution-1.md (execution sequence traceability)
- FILE-004: plan/process-virtual-index-tool-phase1-execution-2.md (this phase execution artifact)

## 6. Testing

- TEST-001: Static symbol presence check for helper names in server.py.
- TEST-002: Unit check for _parse_execution_time_ms with valid and invalid EXPLAIN JSON structures.
- TEST-003: Unit check for _collect_candidate_index_specs determinism and dedup behavior.
- TEST-004: Unit check for _ensure_hypopg_available success and failure paths using mocked cursor responses.

## 7. Risks & Assumptions

- RISK-001: Regex-based identifier extraction may under-detect complex predicates.
- RISK-002: EXPLAIN JSON format edge cases could vary across minor versions and require tolerant parsing.
- RISK-003: Overly broad candidate extraction can inflate evaluation cost in later phases.
- ASSUMPTION-001: EXPLAIN FORMAT JSON root structure remains compatible with repository target PostgreSQL versions.
- ASSUMPTION-002: Future Phase 2 tool implementation will reuse these helpers without renaming.

## 8. Related Specifications / Further Reading

- plan/feature-virtual-index-tuning-tool-1.md
- plan/process-virtual-index-tool-execution-1.md
- https://www.postgresql.org/docs/9.6/sql-explain.html
- https://hypopg.readthedocs.io/