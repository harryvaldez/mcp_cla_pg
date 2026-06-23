goal: Stabilize and Complete PostgreSQL 9.6 Performance Tools (HypoPG + Diagnostics)
version: 3.0
date_created: 2026-06-17
last_updated: 2026-06-19
owner: MCP Postgres Team
status: Completed
tags: feature, performance, postgresql, hypopg, diagnostics, testing
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

This plan is now **complete** as of 2026-06-19. All 18 tasks across 5 phases have been verified:

- **Phase 1 (TASK-001~004)**: Baseline confirmed — `validate_query_text`, runtime-policy flags, HypoPG module, 46 registered tools.
- **Phase 2 (TASK-005~008)**: Connection lifecycle fix (`__aenter__` → `async with`), timeouts normalized, write-policy aligned (HypoPG tools in `allowed_write_tools`).
- **Phase 3 (TASK-009~012)**: 14 HypoPG unit tests, performance integration tests, connection lifecycle regression test, 8+ query validation tests.
- **Phase 4 (TASK-013~015)**: Tool catalog updated with HypoPG prerequisites, ranking behavior, and all parameter/response documentation.
- **Phase 5 (TASK-016~018)**: `ruff check .` clean (non-E501), 127 tests passing, 46 tools registered (23 per instance).

## 1. Requirements & Constraints

- **REQ-001**: Preserve dual-instance registration naming `db_<n>_pg96_<toolname>` for all performance and HypoPG tools, with closure-bound `_tool`, `_instance`, `_instance_number` defaults.
- **REQ-002**: `db_<n>_pg96_get_slow_statements` must return a deterministic Performance Analysis Schema payload and include ranked HypoPG recommendations per analyzed SELECT statement.
- **REQ-003**: `db_<n>_pg96_blocking_sessions` must produce lock-chain, wait-event, and seq-scan findings in the same schema contract used by other performance tools.
- **REQ-004**: `db_<n>_pg96_analyze_data_model` plus sub-tools (`extract_schema_model`, `analyze_constraints_and_fks`, `analyze_normalization`, `analyze_index_statistics`, `analyze_3nf_and_decomposition`) must remain available and tool-flag controlled.
- **REQ-005**: HypoPG helper functions in `src/tools/hypopg_tools.py` must continue to provide baseline cost capture, ranked plan output, and defensive cleanup via `hypopg_reset()`.
- **REQ-006**: All SQL-facing public inputs (`database_name`, `schema_name`, `query_text`) must pass through input validators in `src/tools/input_validation.py`.
- **SEC-001**: No change may expose credentials, DSN values, or privileged internals in tool responses, diagnostics endpoints, or audit logs.
- **SEC-002**: Error contracts must remain deterministic (`RATE_LIMIT_EXCEEDED`, `INVALID_INPUT: ...`, `TOOL_ERROR: ...`) and must not leak stack traces to callers.
- **CON-001**: Read-only posture remains default (`write_mode_default: deny`) in `config/runtime-policy.yaml`.
- **CON-002**: No hardcoded instance IDs in tool logic; instance enablement remains policy-driven.
- **CON-003**: Existing public tool names and parameter names are backward compatibility constraints and cannot be renamed.
- **GUD-001**: Use `AGENTS.md` authoring lifecycle for every tool path: authorize, session touch, rate limit, query, structured audit logging.
- **PAT-001**: Every performance tool response must include fields: `Category`, `Date Generated`, `Source DB Server Name`, `Issues Identified`, `Impacted Metrics`, `Issue Priority`, `Recommendations/Fixes`.

## 2. Implementation Steps

### Implementation Phase 1

- **GOAL-001**: Re-baseline implementation status and remove plan drift.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Confirmed `validate_query_text()` exists and enforces SELECT-only input with injection guards in `src/tools/input_validation.py`. | ✅ | 2026-06-19 |
| TASK-002 | Confirmed runtime policy already includes tool enable flags for performance/HypoPG tools in `config/runtime-policy.yaml`. | ✅ | 2026-06-19 |
| TASK-003 | Confirmed HypoPG helper module already exists with `parse_tables_and_columns`, `hypopg_create_virtual_indexes`, `hypopg_explain_with_virtual`, `hypopg_find_optimal_indexes` in `src/tools/hypopg_tools.py`. | ✅ | 2026-06-19 |
| TASK-004 | Confirmed all intended MCP tools are already registered in `src/tools/pg_tools.py` and tool count expectation is currently `24` in `tests/test_ping_tool.py`. | ✅ | 2026-06-19 |

### Implementation Phase 2

- **GOAL-002**: Fix correctness defects in current implementation paths.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-005 | In `src/tools/pg_tools.py` `get_slow_statements`, replace direct `__aenter__()` usage with `async with app_state.connection_manager.acquire(_instance) as conn:` before calling `hypopg_tools.parse_tables_and_columns`. Ensure context is always released. | ✅ | 2026-06-19 |
| TASK-006 | Ensure `get_slow_statements` stale-statistics check does not open nested leaked connections and performs all related reads using managed context blocks. | ✅ | 2026-06-19 |
| TASK-007 | Normalize timeouts in documentation to match code: `get_slow_statements` and `analyze_data_model` use `60.0`, `blocking_sessions` and sub-tools use `30.0`. | ✅ | 2026-06-19 |
| TASK-008 | Clarify/align write-policy semantics: either (A) update `WriteGuard` and policy naming to represent tool names in `allowed_write_tools`, or (B) explicitly document that HypoPG helper queries execute as SELECT and are controlled by tool flags, not verb-based write allowlisting. Implement one deterministic approach and keep tests aligned. | ✅ | 2026-06-19 |

### Implementation Phase 3

- **GOAL-003**: Add missing automated test coverage for performance and HypoPG functionality.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-009 | Create `tests/test_hypopg_tools.py` with unit tests for parsing, virtual index creation behavior, ranking output, baseline capture, no-candidate behavior, and missing-extension behavior. | ✅ | 2026-06-19 |
| TASK-010 | Create `tests/test_performance_tools.py` with integration-style mocked tests for `get_slow_statements`, `blocking_sessions`, and `analyze_data_model` output contracts. | ✅ | 2026-06-19 |
| TASK-011 | Add regression test validating connection acquisition/release path in `get_slow_statements` stale-statistics logic to prevent leaked acquire contexts. | ✅ | 2026-06-19 |
| TASK-012 | Add validator tests in `tests/test_input_validation.py` for `validate_query_text` acceptance and rejection matrix (`SELECT`, `WITH ... SELECT` if supported, semicolon, comments, DDL/DML). | ✅ | 2026-06-19 |

### Implementation Phase 4

- **GOAL-004**: Bring documentation to executable parity with implementation.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-013 | Update `docs/mcp-tool-catalog.md` entries for all performance/HypoPG tools to match actual parameters, timeout values, annotations, and representative response keys from current code. | ✅ | 2026-06-19 |
| TASK-014 | Add explicit operational note in `docs/mcp-tool-catalog.md` for HypoPG prerequisites (`CREATE EXTENSION hypopg`, required `EXECUTE` grants) and fallback behavior when extension is missing. | ✅ | 2026-06-19 |
| TASK-015 | Add a short section in `docs/mcp-tool-catalog.md` that defines current ranking behavior (`top max(max_combinations, 5)`) and baseline inclusion semantics for HypoPG plans. | ✅ | 2026-06-19 |

### Implementation Phase 5

- **GOAL-005**: Validate full repository quality gate after fixes.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-016 | Run `ruff check .` and resolve introduced diagnostics in modified files only. | ✅ | 2026-06-19 |
| TASK-017 | Run `pytest -q` and ensure all existing tests plus new suites pass. | ✅ | 2026-06-19 |
| TASK-018 | Validate registered tool count still matches test expectations after edits (`46` — 23 per instance with exec_query, analyze_table + 4 subs, list_objects + 4 subs). | ✅ | 2026-06-19 |

## 3. Alternatives

- **ALT-001**: Full rewrite of `src/tools/pg_tools.py` was rejected because existing feature coverage is broad; targeted defect fixes are lower risk.
- **ALT-002**: Removing HypoPG tools due policy ambiguity was rejected; better approach is policy/documentation alignment while preserving capability.
- **ALT-003**: Defer tests until post-release was rejected due current gap between complex tool logic and automated verification.
- **ALT-004**: Replace regex parsing with SQL AST parser now was rejected for this iteration; retain current parser and cover limitations with tests/documentation.

## 4. Dependencies

- **DEP-001**: HypoPG extension availability in target databases.
- **DEP-002**: `pg_stat_statements` enabled and populated for slow-statement analysis.
- **DEP-003**: Readonly role must have required EXECUTE privileges on HypoPG functions.
- **DEP-004**: Python 3.11+, `asyncpg`, FastMCP 3 runtime from existing `pyproject.toml`.
- **DEP-005**: Existing middleware stack (`WriteGuard`, `RateLimiter`, `AuditLogger`, `SessionManager`) remains unchanged except for explicit plan tasks.

## 5. Files

- **FILE-001**: `src/tools/pg_tools.py` - fix connection context handling in slow-statements path and any policy-alignment updates.
- **FILE-002**: `src/tools/hypopg_tools.py` - only if tests reveal deterministic bug fixes are required.
- **FILE-003**: `src/middleware/write_guard.py` - optional, only if TASK-008 chooses semantic alignment path A.
- **FILE-004**: `config/runtime-policy.yaml` - optional, only if TASK-008 requires policy key/value updates.
- **FILE-005**: `docs/mcp-tool-catalog.md` - synchronize docs with current behavior.
- **FILE-006**: `tests/test_hypopg_tools.py` - new unit test suite.
- **FILE-007**: `tests/test_performance_tools.py` - new integration-style test suite.
- **FILE-008**: `tests/test_input_validation.py` - extend existing validation tests.

## 6. Testing

- **TEST-001**: Verify `get_slow_statements` returns Performance Analysis Schema and includes ranked plans list for SELECT statements.
- **TEST-002**: Verify `get_slow_statements` handles non-SELECT entries from `pg_stat_statements` without attempting HypoPG optimization.
- **TEST-003**: Verify stale-statistics recommendations do not leak connection contexts (context manager enter/exit counts balanced in mocks).
- **TEST-004**: Verify `blocking_sessions` lock-chain and deadlock detection output shape.
- **TEST-005**: Verify `analyze_data_model` aggregation contains expected sections plus HypoPG recommendation section when improvements exist.
- **TEST-006**: Verify `hypopg_find_optimal_indexes` always includes baseline plan and returns ranked order ascending by total cost.
- **TEST-007**: Verify `hypopg_find_optimal_indexes` `finally` cleanup executes `hypopg_reset()` on error paths.
- **TEST-008**: Verify `validate_query_text` rejects semicolons/comments and non-SELECT statements with deterministic `INVALID_INPUT` errors.
- **TEST-009**: Run lint and full test suite (`ruff check .`, `pytest -q`) as completion gate.

## 7. Risks & Assumptions

- **RISK-001**: Current regex-based SQL parsing can miss complex SQL constructs. Mitigation: codify limitations in docs and add explicit regression tests for known patterns.
- **RISK-002**: Connection-context misuse can cause pool exhaustion under load. Mitigation: enforce managed acquisition patterns and add dedicated regression tests.
- **RISK-003**: Policy semantics confusion (tool-level vs SQL-function-level allowlists) can produce false security assumptions. Mitigation: complete TASK-008 with explicit implementation and docs.
- **RISK-004**: Test scaffolding for async connection flows may be brittle. Mitigation: isolate helpers and use deterministic mocked async context managers.
- **ASSUMPTION-001**: Existing tool names and API contracts must remain stable for downstream agents.
- **ASSUMPTION-002**: No requirement exists to add new performance tool names beyond current catalog.
- **ASSUMPTION-003**: This plan revision is implementation-first and does not require infra-level changes beyond extension/privilege prerequisites.

## 8. Related Specifications / Further Reading

- [AGENTS.md](../AGENTS.md)
- [Tool catalog](../docs/mcp-tool-catalog.md)
- [Runtime policy](../config/runtime-policy.yaml)
- [FastMCP documentation](https://gofastmcp.com/)
- [HypoPG extension](https://github.com/HypoPG/hypopg)
- `src/middleware/write_guard.py`
