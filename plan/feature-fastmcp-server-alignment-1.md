---
goal: FastMCP Server Alignment for PostgreSQL MCP Server
version: 1.1
date_created: 2026-04-01
last_updated: 2026-04-01
owner: Harry Valdez
status: Completed
tags: [feature, architecture, fastmcp, mcp, server]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

This plan defines deterministic implementation steps to align the existing MCP server with FastMCP best practices across Resources, Prompts, Context, Tasks, Composition, Dependency Injection, Elicitation, and Logging while preserving current tool behavior and public compatibility.

## 1. Requirements & Constraints

- REQ-001: Implement resource endpoints using FastMCP resource patterns in server.py with explicit URI schemas and stable MIME types.
- REQ-002: Add prompt definitions for recurring operational workflows in server.py with typed prompt arguments and deterministic output messages.
- REQ-003: Introduce CurrentContext-based context injection for selected long-running analysis flows and request-scoped logging.
- REQ-004: Preserve existing tool names and signatures for all db_pg96_* tools.
- REQ-005: Keep backward compatibility for legacy response formats where currently supported.
- REQ-006: Provide task-capable example tools using TaskConfig and Progress dependency patterns.
- REQ-007: Demonstrate server composition via namespaced mounted child server components.
- REQ-008: Demonstrate dependency injection with CurrentFastMCP, Depends, and helper-based context access.
- REQ-009: Implement advanced elicitation examples (multi-turn, titled options, multi-select, structured response, no-response approval).
- REQ-010: Add client logging demonstration with structured extra payloads.
- REQ-011: Add environment-driven server behavior toggles for strict input validation, mask error details, and duplicate registration behavior.
- SEC-001: Do not expose write-capable operations as read-only resources or prompts.
- SEC-002: Keep existing audit logging and write-protection gates unchanged for query execution paths.
- SEC-003: Ensure no sensitive runtime details are leaked through new resources or prompts.
- CON-001: Modify only existing project files in this repository; do not add external runtime services.
- CON-002: Avoid changing transport bootstrap behavior in server.py main().
- CON-003: Keep Python compatibility with project requirements and existing FastMCP major version.
- GUD-001: Use explicit annotations for readOnlyHint and idempotentHint on new resources.
- GUD-002: Use PromptResult only when prompt-level runtime metadata is required.
- PAT-001: Use response envelope helper pattern already present in server.py for consistency where applicable.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Add baseline Resources and Prompts scaffolding with deterministic registration and zero behavior regression for existing tools.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | In server.py, add FastMCP imports for ResourceResult/ResourceContent, Message/PromptResult, CurrentContext, and Context near existing FastMCP imports. | Yes | 2026-04-01 |
| TASK-002 | In server.py, register resource data://server/status exposing allow_write, transport, statement_timeout_ms, and db identity derived from existing variables and db_pg96_server_info logic. | Yes | 2026-04-01 |
| TASK-003 | In server.py, register resource data://db/settings{?pattern,limit} using pg_settings query logic from db_pg96_get_db_parameters and return JSON string payload. | Yes | 2026-04-01 |
| TASK-004 | In server.py, register prompt explain_slow_query(sql, analyze, buffers) generating deterministic optimization instructions and referencing db_pg96_explain_query behavior. | Yes | 2026-04-01 |
| TASK-005 | In server.py, register prompt maintenance_recommendations(profile) generating focused checklist mapped to db_pg96_db_sec_perf_metrics thresholds. | Yes | 2026-04-01 |

### Implementation Phase 2

- GOAL-002: Apply Context capabilities for logging, progress, and request metadata in selected long-running operations.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-006 | In server.py, update db_pg96_analyze_logical_data_model_async signature to include ctx: Context = CurrentContext() and add ctx.info logs at phase boundaries without changing output schema. | Yes | 2026-04-01 |
| TASK-007 | In server.py, update db_pg96_analyze_indexes_async signature to include ctx dependency and emit ctx.debug records for row counts and truncation decisions. | Yes | 2026-04-01 |
| TASK-008 | In server.py, update db_pg96_analyze_sessions_async to record ctx.request_id and ctx.transport in diagnostics-safe logs without exposing client meta in result payload. | Yes | 2026-04-01 |
| TASK-009 | In server.py, add helper function for context-safe logging that no-ops outside request context and reuse in async analysis tasks. | Yes | 2026-04-01 |

### Implementation Phase 3

- GOAL-003: Validate, document, and harden runtime behavior for newly introduced resources/prompts/context wiring.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-010 | In README.md, add Resources section documenting URIs, parameters, MIME types, and expected payload shapes for new resources. | Yes | 2026-04-01 |
| TASK-011 | In README.md, add Prompts section documenting prompt names, arguments, and example render outputs. | Yes | 2026-04-01 |
| TASK-012 | In tests/test_tools_pg96.py, add tests that assert existing db_pg96_* tool signatures and outputs remain unchanged after context injection. | Yes | 2026-04-01 |
| TASK-013 | In tests/functional_test.py, add integration checks for resources list/read and prompts list/get flows under HTTP transport. | Yes | 2026-04-01 |
| TASK-014 | Execute pytest subset for modified tests and resolve failures; then run full get_errors diagnostics on server.py and touched test files. | Yes | 2026-04-01 |

### Implementation Phase 4

- GOAL-004: Extend server-level FastMCP alignment for composition/tasks/DI/elicitation/logging and runtime config safety.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-015 | In server.py, add resource data://server/capabilities and prompt runtime_context_brief using CurrentContext-based request metadata. | Yes | 2026-04-03 |
| TASK-016 | In server.py, add task_progress_demo using TaskConfig(mode="optional") and Progress updates. | Yes | 2026-04-03 |
| TASK-017 | In server.py, add composition_demo child server and mount with namespace composed. | Yes | 2026-04-03 |
| TASK-018 | In server.py, add dependency_injection_snapshot using Depends, CurrentFastMCP, header injection, and helper context request id. | Yes | 2026-04-03 |
| TASK-019 | In server.py, expand elicitation_collect_maintenance_window with titled options, multi-select, and response_type=None approval. | Yes | 2026-04-03 |
| TASK-020 | In server.py, add elicitation_create_maintenance_ticket with structured dataclass response. | Yes | 2026-04-03 |
| TASK-021 | In server.py, add logging_demo with debug/info/warning/error and structured extra payloads. | Yes | 2026-04-03 |
| TASK-022 | In server.py, add server_runtime_config_snapshot and env-driven constructor toggles (strict validation, mask error details, duplicate behavior). | Yes | 2026-04-03 |
| TASK-023 | In server.py, add robust context state helpers and retrofit session_counter for sync/async Context API compatibility. | Yes | 2026-04-03 |
| TASK-024 | Expand automated tests for newly added resources/prompts/tools and run targeted validation matrix. | Yes | 2026-04-03 |

## 3. Alternatives

- ALT-001: Implement resources/prompts in a new module instead of server.py. Rejected because current architecture centralizes registrations in server.py and minimizes initialization divergence.
- ALT-002: Use legacy Context type-hint injection only. Rejected because CurrentContext dependency is the preferred FastMCP pattern and excludes dependency parameters from schemas deterministically.
- ALT-003: Return only plain strings for all resources/prompts. Rejected because ResourceResult and PromptResult provide controlled metadata and multi-part content when required.

## 4. Dependencies

- DEP-001: fastmcp version already pinned in requirements.txt and pyproject.toml must remain compatible with CurrentContext and PromptResult/ResourceResult APIs.
- DEP-002: Existing psycopg and connection pool helpers in server.py are required for db settings resource query execution.
- DEP-003: Existing test framework configuration in pytest.ini is required for integration validation.

## 5. Files

- FILE-001: server.py - Add server-wide FastMCP alignment features (resources/prompts/context/tasks/composition/DI/elicitation/logging/config toggles).
- FILE-002: README.md - Document new resources/prompts and usage examples.
- FILE-003: tests/test_tools_pg96.py - Preserve behavior tests for existing tool compatibility.
- FILE-004: tests/functional_test.py - End-to-end MCP resources/prompts interaction coverage.
- FILE-005: plan/feature-fastmcp-server-alignment-1.md - Track expanded scope, completion evidence, and validation backlog.

## 6. Testing

- TEST-001: Validate list_resources contains data://server/status, data://db/settings{?pattern,limit}, and data://server/capabilities.
- TEST-002: Validate read_resource for data://server/status and data://server/capabilities returns parseable JSON with required keys.
- TEST-003: Validate get_prompt for explain_slow_query and runtime_context_brief returns deterministic message sequence/shape.
- TEST-004: Validate async analysis tools still return legacy and envelope formats without schema changes.
- TEST-005: Validate task_progress_demo supports progress updates and completes in both sync and background execution modes.
- TEST-006: Validate namespaced composition entries are discoverable (tool prefix composed_ and resource URI prefix data://composed/).
- TEST-007: Validate dependency_injection_snapshot returns server name, transport, and request metadata without exposing secrets.
- TEST-008: Validate elicitation tools handle accept/decline/cancel branches and non-supporting clients with deterministic errors.
- TEST-009: Validate logging_demo emits structured client logs for selected level and returns emitted-level summary.
- TEST-010: Validate session_counter works with reset and increment semantics under active session context.
- TEST-011: Validate env toggles for strict validation, mask_error_details, and duplicate behavior are accepted/rejected deterministically.
- TEST-012: Validate no new diagnostics in server.py and modified tests using workspace problem diagnostics.

## 7. Risks & Assumptions

- RISK-001: Context usage inside synchronous code paths may require async-safe adaptation; mitigation is to scope context methods to async tools only in this iteration.
- RISK-002: Resource template argument coercion may fail for invalid query types; mitigation is strict type hints and explicit validation messages.
- RISK-003: Additional MCP surface area may increase client discovery complexity; mitigation is tags and clear README sections.
- ASSUMPTION-001: FastMCP APIs used in this plan are available in the pinned major version already used by the repository.
- ASSUMPTION-002: Existing clients consuming db_pg96_* tools require backward compatibility and should not be migrated in this change set.

## 8. Related Specifications / Further Reading

- https://gofastmcp.com/servers/resources
- https://gofastmcp.com/servers/prompts
- https://gofastmcp.com/servers/context
- https://gofastmcp.com/servers/tools

## 9. Execution Command Matrix

The following commands are deterministic execution references for each phase. Run commands from repository root.

| Ref | Command | Expected Result | Failure Condition |
| --- | --- | --- | --- |
| CMD-001 | `python -m pytest tests/test_tools_pg96.py -q` | Existing tool behavior tests pass before modifications. | Any failing test or import error. |
| CMD-002 | `python -m pytest tests/functional_test.py -q` | Baseline functional behavior confirmed before modifications. | Any failing test or transport startup failure. |
| CMD-003 | `python -m pytest tests/test_tools_pg96.py::test_db_pg96_server_info -q` | Server info contract remains unchanged after Resource/Prompt additions. | Assertion mismatch for output keys/types. |
| CMD-004 | `python -m pytest tests/functional_test.py -k "resources or prompts" -q` | New resources/prompts integration checks pass. | Missing list/read/get behavior or schema mismatch. |
| CMD-005 | `python -m pytest -q` | Full suite passes for regression validation. | Any test failure. |
| CMD-006 | `python -m pytest tests/test_logging.py -q` | Logging-related behavior and safety checks pass. | Any failing assertion or runtime error. |
| CMD-007 | `python -m pytest tests/functional_test.py -k "resources or prompts or task" -q` | New alignment surfaces validate under functional harness. | Missing resource/prompt/task behavior. |
| CMD-008 | `python -m pytest tests/test_hardening.py -q` | Security and hardening checks remain green after config toggle additions. | Any hardening regression. |

## 10. Measurable Completion Criteria

- MCC-001: `server.py` contains at least two new `@mcp.resource(...)` definitions with explicit URIs and deterministic MIME types.
- MCC-002: `server.py` contains at least two new `@mcp.prompt` definitions with typed parameters and deterministic outputs.
- MCC-003: `server.py` async analysis functions include `ctx: Context = CurrentContext()` on all targeted functions from TASK-006 to TASK-008.
- MCC-004: `README.md` includes one Resources section and one Prompts section with concrete request/response examples.
- MCC-005: `tests/test_tools_pg96.py` verifies backward compatibility of existing db_pg96_* outputs touched by plan scope.
- MCC-006: `tests/functional_test.py` verifies list/read resources and list/get prompts end-to-end.
- MCC-007: Workspace diagnostics report zero new errors in modified files.
- MCC-008: New FastMCP alignment tools are discoverable and callable without breaking db_pg96_* tool contracts.
- MCC-009: Elicitation and logging demo flows execute deterministically (or fail with explicit unsupported-client messaging).
- MCC-010: Constructor env toggles for strict validation/masked errors/duplicate behavior apply without startup regression.

## 11. Task Dependency Graph

- DEPGRAPH-001: TASK-001 is a prerequisite for TASK-002 through TASK-009.
- DEPGRAPH-002: TASK-002 and TASK-003 can run in parallel after TASK-001.
- DEPGRAPH-003: TASK-004 and TASK-005 can run in parallel after TASK-001.
- DEPGRAPH-004: TASK-006 through TASK-009 can run in parallel after TASK-001.
- DEPGRAPH-005: TASK-010 and TASK-011 depend on completion of TASK-002 through TASK-005.
- DEPGRAPH-006: TASK-012 and TASK-013 depend on completion of TASK-002 through TASK-009.
- DEPGRAPH-007: TASK-014 depends on TASK-010 through TASK-013.
- DEPGRAPH-008: TASK-015 through TASK-023 depend on TASK-001 baseline import and constructor wiring.
- DEPGRAPH-009: TASK-024 depends on TASK-015 through TASK-023.

## 12. TASK to CMD to MCC Runbook

This runbook provides direct execution mappings with deterministic verification targets.

| Runbook ID | Task IDs | Execution Commands | Verification Criteria |
| --- | --- | --- | --- |
| RBK-001 | TASK-001 | No standalone command. Perform import edits in server.py and run CMD-001. | MCC-001 precondition satisfied and no import/runtime failures in CMD-001. |
| RBK-002 | TASK-002,TASK-003 | Implement resources in server.py, then run CMD-004. | MCC-001 and MCC-004 satisfied for resources list/read behavior. |
| RBK-003 | TASK-004,TASK-005 | Implement prompts in server.py, then run CMD-004. | MCC-002 and MCC-004 satisfied for prompts list/get behavior. |
| RBK-004 | TASK-006,TASK-007,TASK-008,TASK-009 | Implement Context dependency and logging updates in server.py, then run CMD-003 and CMD-001. | MCC-003 and MCC-005 satisfied with no schema regressions. |
| RBK-005 | TASK-010,TASK-011 | Update README.md documentation sections, then run CMD-002. | MCC-004 documentation requirements satisfied and no functional regressions. |
| RBK-006 | TASK-012,TASK-013 | Add/adjust tests in tests/test_tools_pg96.py and tests/functional_test.py, then run CMD-001 and CMD-004. | MCC-005 and MCC-006 satisfied. |
| RBK-007 | TASK-014 | Execute CMD-005 and run workspace diagnostics check for modified files. | MCC-007 satisfied and plan phase considered implementation-ready. |
| RBK-008 | TASK-015,TASK-016,TASK-017,TASK-018,TASK-019,TASK-020,TASK-021,TASK-022,TASK-023 | Implement expanded FastMCP alignment in server.py and run CMD-006 through CMD-008 plus diagnostics checks. | MCC-008 through MCC-010 satisfied without regressions in legacy tool contracts. |

## 13. Rollback Strategy

- ROL-001: If CMD-004 fails after TASK-002 through TASK-005, revert only newly added resource/prompt definitions in server.py and rerun CMD-001.
- ROL-002: If CMD-003 or CMD-001 fails after TASK-006 through TASK-009, revert Context signature updates in async functions and helper additions, then rerun CMD-001.
- ROL-003: If CMD-005 fails after TASK-012 through TASK-013, keep test additions isolated and bisect by file: run CMD-001 first, then CMD-004.
- ROL-004: Rollback operations must preserve existing db_pg96_* tool names and public signatures.
- ROL-005: If expanded alignment introduces functional regressions, rollback TASK-015 through TASK-023 as an isolated block while retaining Phase 1-3 baseline.

## 14. Phase Exit Gates

- GATE-001 (Phase 1 Exit): TASK-001 through TASK-005 complete and CMD-004 passes with resource/prompt discovery and execution checks.
- GATE-002 (Phase 2 Exit): TASK-006 through TASK-009 complete and CMD-003 plus CMD-001 pass without signature regressions.
- GATE-003 (Phase 3 Exit): TASK-010 through TASK-014 complete and CMD-005 plus diagnostics checks satisfy MCC-004 through MCC-007.
- GATE-004 (Final Exit): All MCC identifiers (MCC-001 through MCC-007) satisfied and no open rollback condition active.
- GATE-005 (Phase 4 Exit): TASK-015 through TASK-023 complete, diagnostics pass, and no startup regressions observed.
- GATE-006 (Validation Exit): TASK-024 complete and MCC-008 through MCC-010 satisfied.

## 15. Implementation Start Point

- START-001: Begin execution at TASK-001 in server.py import section.
- START-002: Execute TASK-002 and TASK-003 in parallel after START-001 completion.
- START-003: Execute TASK-004 and TASK-005 in parallel after START-001 completion.
- START-004: Use RBK-004 sequence for Context injection tasks after Phase 1 gate passes.
- START-005: Do not execute TASK-014 until TASK-010 through TASK-013 are complete.
- START-006: Execute TASK-015 through TASK-023 before TASK-024 validation expansion.

## 16. Final Validation Snapshot

- VAL-001: `& .venv\Scripts\python.exe -m pytest tests/test_logging.py -q` -> 1 passed.
- VAL-002: `& .venv\Scripts\python.exe -m pytest tests/test_hardening.py -q` -> 4 passed.
- VAL-003: `& .venv\Scripts\python.exe -m pytest tests/functional_test.py -k "resources or prompts or task" -q` -> 1 passed, 1 deselected.
- VAL-004: Expanded functional coverage now includes new resources (`data://server/capabilities`, `data://composed/info`), prompt (`runtime_context_brief`), and discoverability checks for newly added alignment tools.
- VAL-005: Regression fix applied during validation: context-safe request/session/transport reads and JSON-safe resource URI serialization in `resource_server_capabilities`.
- VAL-006: Workspace diagnostics for `server.py`, `tests/functional_test.py`, and plan file report no errors.