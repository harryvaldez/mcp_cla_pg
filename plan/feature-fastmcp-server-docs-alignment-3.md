---
goal: FastMCP Servers Docs-to-Code Alignment with Line-Anchored Execution
version: 2.1
date_created: 2026-04-02
last_updated: 2026-04-03
owner: Harry Valdez
status: Completed
tags: [feature, documentation, fastmcp, transport, hardening, validation]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

This plan defines deterministic, line-anchored steps to align repository behavior and documentation with FastMCP server guidance, especially transport semantics (HTTP primary, SSE legacy) while preserving backward compatibility.

## 1. Requirements & Constraints

- REQ-001: Update transport documentation statements at README.md line 58 and README.md line 450 to describe `http` as recommended and `sse` as legacy compatibility transport.
- REQ-002: Update deployment transport references at DEPLOYMENT.md line 160 and DEPLOYMENT.md line 162 to match executable defaults in server.py.
- REQ-003: Correct port guidance drift at DEPLOYMENT.md line 84 from 8000 to 8085 to match server.py line 6089.
- REQ-004: Add deterministic SSE legacy runtime warning in server.py main() after transport normalization at line 6086.
- REQ-005: Add deterministic SSE hard-disable gate using MCP_ALLOW_LEGACY_SSE (fallback FASTMCP_ALLOW_LEGACY_SSE) in server.py main().
- REQ-006: Preserve support for transport values `http`, `sse`, and `stdio` unless MCP_ALLOW_LEGACY_SSE is explicitly false and transport is `sse`.
- REQ-007: Preserve db_pg96_* tool names, signatures, and return schema contracts.
- SEC-001: Maintain auth middleware coverage for HTTP and SSE branches in server.py lines 6098-6115.
- SEC-002: Do not introduce any new unauthenticated route paths during transport hardening changes.
- OPS-001: Keep startup behavior deterministic for invalid transport values with explicit ValueError message at line 6196.
- CON-001: Modify only server.py, README.md, DEPLOYMENT.md, tests/functional_test.py, tests/test_tools_pg96.py, and this plan file.
- CON-002: Avoid FastMCP major-version upgrades in this change set.
- GUD-001: Reuse existing helper pattern (_env_optional_bool) for new SSE gating variable parsing.
- PAT-001: Implement additive compatibility changes only; no silent transport remapping.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Align transport documentation with executable behavior using line-anchored edits.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Edit README.md at line 58 to replace the transport feature bullet with explicit statement: HTTP recommended, STDIO supported, SSE legacy compatibility mode. | ✅ | 2026-04-05 |
| TASK-002 | Edit README.md at line 450 to change MCP_TRANSPORT description to `http` (recommended), `stdio`, `sse` (legacy). | ✅ | 2026-04-05 |
| TASK-003 | Edit DEPLOYMENT.md at line 84 to set default HTTP port guidance to 8085. | ✅ | 2026-04-05 |
| TASK-004 | Edit DEPLOYMENT.md at lines 160-162 to document MCP_TRANSPORT and MCP_PORT defaults consistent with server.py lines 6086 and 6089. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Add runtime legacy-SSE signaling and optional hard-disable safety control.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | In server.py near line 6086, add `allow_legacy_sse = _env_optional_bool("MCP_ALLOW_LEGACY_SSE")` with fallback to `_env_optional_bool("FASTMCP_ALLOW_LEGACY_SSE")` when None. | ✅ | 2026-04-05 |
| TASK-006 | In server.py immediately after TASK-005 logic, add branch: if `transport == "sse"` then emit logger.warning indicating SSE legacy mode and recommendation to use HTTP. | ✅ | 2026-04-05 |
| TASK-007 | In server.py within same branch, enforce gate: if `allow_legacy_sse is False`, raise ValueError("Legacy SSE transport is disabled. Set MCP_TRANSPORT=http or set MCP_ALLOW_LEGACY_SSE=true."). | ✅ | 2026-04-05 |
| TASK-008 | Keep existing `if transport in {"http", "sse"}` branch at line 6098 unchanged except for insertion points from TASK-005..TASK-007. | ✅ | 2026-04-05 |

### Implementation Phase 3

- GOAL-003: Validate transport gate behavior and regression safety for existing tools.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-009 | Add test in tests/functional_test.py that configures transport=`sse`, MCP_ALLOW_LEGACY_SSE=false, and asserts deterministic startup ValueError message. | ✅ | 2026-04-05 |
| TASK-010 | Add test in tests/functional_test.py that configures transport=`sse`, MCP_ALLOW_LEGACY_SSE=true, and asserts run path remains reachable. | ✅ | 2026-04-05 |
| TASK-011 | Add regression test in tests/test_tools_pg96.py for representative db_pg96_* output keys to verify no API contract drift. | ✅ | 2026-04-05 |
| TASK-012 | Execute command runbook CMD-001 through CMD-006 and record outcomes in Section 10 Validation Snapshot. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Remove SSE support entirely. Rejected due to backward compatibility risk for existing integrations.
- ALT-002: Documentation-only fix with no runtime controls. Rejected because accidental legacy deployment must be actively signaled.
- ALT-003: Auto-convert SSE to HTTP silently. Rejected because it hides operator intent and complicates incident diagnosis.

## 4. Dependencies

- DEP-001: Existing helper `_env_optional_bool` in server.py must remain available for deterministic bool parsing.
- DEP-002: Existing logger configuration must remain intact to surface legacy warnings.
- DEP-003: Existing pytest infrastructure from pytest.ini and functional test harness must be usable without adding external services.

## 5. Files

- FILE-001: server.py (line anchors: 6083, 6086, 6098, 6117, 6196) - runtime transport gate and warning logic.
- FILE-002: README.md (line anchors: 58, 450) - transport documentation alignment.
- FILE-003: DEPLOYMENT.md (line anchors: 84, 160, 162) - deployment default correction and transport guidance.
- FILE-004: tests/functional_test.py - startup behavior tests for SSE gate allow/deny branches.
- FILE-005: tests/test_tools_pg96.py - backward compatibility regression assertions.
- FILE-006: plan/feature-fastmcp-server-docs-alignment-3.md - line-anchored deterministic execution plan.

## 6. Testing

- TEST-001: Assert warning path for MCP_TRANSPORT=sse when gate variable is unset.
- TEST-002: Assert startup failure and exact ValueError text for MCP_TRANSPORT=sse with MCP_ALLOW_LEGACY_SSE=false.
- TEST-003: Assert startup success path for MCP_TRANSPORT=sse with MCP_ALLOW_LEGACY_SSE=true.
- TEST-004: Assert no behavior change for MCP_TRANSPORT=http and MCP_TRANSPORT=stdio startup paths.
- TEST-005: Assert representative db_pg96_* output schema keys remain unchanged.
- TEST-006: Assert docs mention default port 8085 consistently where startup defaults are described.

## 7. Risks & Assumptions

- RISK-001: Operators currently on SSE may encounter warnings and treat them as incidents; mitigation is explicit docs and optional gate variable.
- RISK-002: Startup tests may need mocking of mcp.run to avoid side effects in CI.
- ASSUMPTION-001: FastMCP guidance continues to classify SSE as legacy in current documentation set.
- ASSUMPTION-002: Existing users still require temporary SSE compatibility.

## 8. Related Specifications / Further Reading

- https://gofastmcp.com/servers/server
- https://gofastmcp.com/deployment/running-server
- https://gofastmcp.com/deployment/http

## 9. Line-Anchored Edit Map

| MAP ID | File | Anchor Line | Anchor Text | Deterministic Edit Intent |
|---|---|---:|---|---|
| MAP-001 | README.md | 58 | Multiple Transports | Replace bullet text to mark HTTP as recommended and SSE as legacy compatibility mode. |
| MAP-002 | README.md | 450 | MCP_TRANSPORT | Update env var table description to preferred ordering and semantics. |
| MAP-003 | DEPLOYMENT.md | 84 | Default HTTP port is 8000 | Correct to 8085 to match runtime default. |
| MAP-004 | DEPLOYMENT.md | 160 | MCP_TRANSPORT Transport mode | Add explicit recommendation and legacy label for SSE. |
| MAP-005 | DEPLOYMENT.md | 162 | MCP_PORT Port for HTTP transport | Correct default value from 8000 to 8085. |
| MAP-006 | server.py | 6086 | transport = os.environ.get("MCP_TRANSPORT", "http") | Insert SSE gate variable parsing after transport normalization. |
| MAP-007 | server.py | 6098 | if transport in {"http", "sse"}: | Preserve branch and prepend SSE warning/gate guard before this branch executes run. |
| MAP-008 | server.py | 6196 | Unknown transport | Keep error path unchanged except for allowable new SSE-disabled ValueError branch. |

## 10. Task-to-Command Runbook

| CMD ID | Applies To | Command | Expected Outcome | Failure Signal |
|---|---|---|---|---|
| CMD-001 | TASK-001..TASK-004 | python -m pytest tests/functional_test.py -k "transport or startup" -q | Existing startup tests pass after documentation-only edits. | Any startup-related test failure. |
| CMD-002 | TASK-005..TASK-008 | python -m pytest tests/functional_test.py -k "sse" -q | New SSE gate tests pass with deterministic allow/deny behavior. | Missing ValueError branch or incorrect warning/gate behavior. |
| CMD-003 | TASK-011 | python -m pytest tests/test_tools_pg96.py -k "server_info or ping" -q | Representative db_pg96 contracts remain unchanged. | Output key/type mismatch. |
| CMD-004 | TASK-009..TASK-011 | python -m pytest tests/functional_test.py tests/test_tools_pg96.py -q | Combined targeted suite passes. | Any regression in startup or tool contracts. |
| CMD-005 | TASK-012 | python -m pytest -q | Full regression validation passes. | Any test failure. |
| CMD-006 | TASK-012 | python -m pytest tests/test_hardening.py -q | Hardening checks remain green after transport gate additions. | Any hardening failure. |

## 11. Measurable Completion Criteria

- MCC-001: README.md transport statements at lines 58 and 450 explicitly classify SSE as legacy.
- MCC-002: DEPLOYMENT.md startup and env sections no longer reference 8000 as the default HTTP port.
- MCC-003: server.py includes deterministic SSE warning and hard-disable gate branch controlled by MCP_ALLOW_LEGACY_SSE.
- MCC-004: tests/functional_test.py contains at least one positive and one negative SSE gate test.
- MCC-005: tests/test_tools_pg96.py confirms representative contract stability for existing tools.
- MCC-006: CMD-001 through CMD-006 outcomes are recorded in Validation Snapshot with pass/fail markers.

## 12. Validation Snapshot

- VAL-001: CMD-001 -> Passed (2026-04-05)
- VAL-002: CMD-002 -> Passed (2026-04-05)
- VAL-003: CMD-003 -> Passed (2026-04-05)
- VAL-004: CMD-004 -> Passed (2026-04-05)
- VAL-005: CMD-005 -> Passed (2026-04-05)
- VAL-006: CMD-006 -> Passed (2026-04-05)
