---
goal: FastMCP Servers Docs-to-Code Alignment with Executable Test Skeletons
version: 2.2
date_created: 2026-04-02
last_updated: 2026-04-02
owner: Harry Valdez
status: Planned
tags: [feature, documentation, fastmcp, transport, tests, hardening]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This plan extends the 2.1 alignment plan by adding executable Given/When/Then test skeleton specifications for SSE legacy gating behavior and startup-path regression protection.

## 1. Requirements & Constraints

- REQ-001: Keep transport documentation aligned with runtime behavior in README.md and DEPLOYMENT.md.
- REQ-002: Keep runtime support for http, sse, and stdio unless SSE is explicitly disabled by environment configuration.
- REQ-003: Add deterministic runtime warning when transport is sse and startup is allowed.
- REQ-004: Add deterministic runtime failure when transport is sse and legacy SSE is explicitly disabled.
- REQ-005: Add executable Given/When/Then skeletons for TASK-009 and TASK-010 in this plan.
- REQ-006: Preserve db_pg96_* tool contracts with no signature or payload schema regressions.
- SEC-001: Maintain existing auth middleware coverage for HTTP/SSE endpoints.
- SEC-002: Do not introduce new unauthenticated write-capable execution paths.
- OPS-001: Maintain explicit ValueError for invalid transport values.
- CON-001: Restrict implementation scope to server.py, README.md, DEPLOYMENT.md, tests/functional_test.py, tests/test_tools_pg96.py.
- CON-002: Do not perform FastMCP major-version changes in this workstream.
- GUD-001: Use existing environment helper pattern for bool parsing.
- PAT-001: Prefer additive compatibility controls over breaking removals.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Align docs and runtime transport semantics with FastMCP guidance.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Update README.md transport summary text to mark HTTP as recommended and SSE as legacy compatibility mode. |  |  |
| TASK-002 | Update README.md env table row for MCP_TRANSPORT to ordering: http, stdio, sse (legacy). |  |  |
| TASK-003 | Update DEPLOYMENT.md default HTTP port references to 8085 where startup defaults are described. |  |  |
| TASK-004 | Update DEPLOYMENT.md MCP_TRANSPORT and MCP_PORT descriptions to match server.py startup defaults. |  |  |

### Implementation Phase 2

- GOAL-002: Add deterministic SSE legacy gate behavior in startup logic.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | In server.py main(), parse MCP_ALLOW_LEGACY_SSE with FASTMCP_ALLOW_LEGACY_SSE fallback using existing optional bool helper. |  |  |
| TASK-006 | In server.py main(), when transport is sse and gate is unset/true, log warning stating SSE is legacy and HTTP is recommended. |  |  |
| TASK-007 | In server.py main(), when transport is sse and gate is false, raise deterministic ValueError with remediation text. |  |  |
| TASK-008 | Keep existing http/sse and stdio branching unchanged except for gate/warning insertion. |  |  |

### Implementation Phase 3

- GOAL-003: Add and execute deterministic test coverage for startup gating and contract safety.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-009 | Add functional test for denied SSE startup: transport=sse and MCP_ALLOW_LEGACY_SSE=false must raise expected ValueError. |  |  |
| TASK-010 | Add functional test for allowed SSE startup: transport=sse and MCP_ALLOW_LEGACY_SSE=true must continue to run path. |  |  |
| TASK-011 | Add regression assertion in tests/test_tools_pg96.py for representative db_pg96_* output key stability. |  |  |
| TASK-012 | Execute targeted and full test commands; update Validation Snapshot with pass/fail status. |  |  |

## 3. Alternatives

- ALT-001: Remove SSE support immediately. Rejected due to backward compatibility break.
- ALT-002: Docs-only updates with no runtime gate. Rejected due to accidental legacy transport risk.
- ALT-003: Auto-rewrite sse to http at runtime. Rejected because it obscures operator intent.

## 4. Dependencies

- DEP-001: server.py helper functions for environment bool parsing and logging remain available.
- DEP-002: Existing startup test harness in tests/functional_test.py supports environment-driven transport setup.
- DEP-003: Existing regression tests in tests/test_tools_pg96.py can validate contract stability.

## 5. Files

- FILE-001: server.py
- FILE-002: README.md
- FILE-003: DEPLOYMENT.md
- FILE-004: tests/functional_test.py
- FILE-005: tests/test_tools_pg96.py
- FILE-006: plan/feature-fastmcp-server-docs-alignment-4.md

## 6. Testing

- TEST-001: Denied SSE startup produces deterministic ValueError text.
- TEST-002: Allowed SSE startup follows run path without startup exception.
- TEST-003: HTTP and STDIO startup paths remain unchanged.
- TEST-004: Representative db_pg96_* tool contract keys remain stable.
- TEST-005: Documentation references for default port and transport modes are consistent with runtime defaults.

## 7. Risks & Assumptions

- RISK-001: Some active users on SSE may treat new warning logs as incidents.
- RISK-002: Startup-path tests may require mcp.run mocking to avoid side effects.
- ASSUMPTION-001: SSE remains supported in current FastMCP version used by repository.
- ASSUMPTION-002: Team wants staged deprecation, not immediate removal.

## 8. Related Specifications / Further Reading

- https://gofastmcp.com/servers/server
- https://gofastmcp.com/deployment/running-server
- https://gofastmcp.com/deployment/http

## 9. Line-Anchored Edit Targets

| MAP ID | File | Anchor Line | Anchor Text |
|---|---|---:|---|
| MAP-001 | README.md | 58 | Multiple Transports |
| MAP-002 | README.md | 450 | MCP_TRANSPORT |
| MAP-003 | DEPLOYMENT.md | 84 | Default HTTP port is 8000 |
| MAP-004 | DEPLOYMENT.md | 160 | MCP_TRANSPORT Transport mode |
| MAP-005 | DEPLOYMENT.md | 162 | MCP_PORT Port for HTTP transport |
| MAP-006 | server.py | 6086 | transport = os.environ.get("MCP_TRANSPORT", "http").strip().lower() |
| MAP-007 | server.py | 6098 | if transport in {"http", "sse"}: |
| MAP-008 | server.py | 6196 | Unknown transport |

## 10. Task-to-Command Runbook

| CMD ID | Applies To | Command | Expected Outcome |
|---|---|---|---|
| CMD-001 | TASK-001..TASK-004 | python -m pytest tests/functional_test.py -k "startup or transport" -q | Startup baseline remains green after docs edits. |
| CMD-002 | TASK-005..TASK-010 | python -m pytest tests/functional_test.py -k "sse" -q | SSE allow/deny behaviors pass deterministically. |
| CMD-003 | TASK-011 | python -m pytest tests/test_tools_pg96.py -k "server_info or ping" -q | Representative contract checks remain green. |
| CMD-004 | TASK-009..TASK-011 | python -m pytest tests/functional_test.py tests/test_tools_pg96.py -q | Combined targeted suite passes. |
| CMD-005 | TASK-012 | python -m pytest -q | Full regression suite passes. |
| CMD-006 | TASK-012 | python -m pytest tests/test_hardening.py -q | Hardening checks remain unchanged. |

## 11. Measurable Completion Criteria

- MCC-001: Runtime warning path exists for allowed SSE startup.
- MCC-002: Runtime failure path exists for denied SSE startup.
- MCC-003: README.md and DEPLOYMENT.md transport guidance matches server defaults.
- MCC-004: TASK-009 and TASK-010 tests exist with deterministic assertions.
- MCC-005: Representative db_pg96_* contract regression checks remain green.

## 12. Validation Snapshot

- VAL-001: CMD-001 -> Pending
- VAL-002: CMD-002 -> Pending
- VAL-003: CMD-003 -> Pending
- VAL-004: CMD-004 -> Pending
- VAL-005: CMD-005 -> Pending
- VAL-006: CMD-006 -> Pending

## 13. Executable Test Skeletons (Given/When/Then)

### TSK-009-SSE-DENIED

- Scope: TASK-009 in tests/functional_test.py
- Test ID: CASE-009
- Function Name: test_startup_rejects_legacy_sse_when_disabled

Given:
- Environment variable MCP_TRANSPORT is set to sse.
- Environment variable MCP_ALLOW_LEGACY_SSE is set to false.
- No override value is set for FASTMCP_ALLOW_LEGACY_SSE.
- Startup path is invoked via server.main().

When:
- server.main() evaluates transport normalization and SSE gate logic.

Then:
- A ValueError is raised before mcp.run is called.
- Error message equals: Legacy SSE transport is disabled. Set MCP_TRANSPORT=http or set MCP_ALLOW_LEGACY_SSE=true.
- No HTTP server startup side effects occur.

Implementation Notes:
- Use pytest monkeypatch to set environment variables.
- Use monkeypatch on mcp.run to assert call count equals zero.
- Use pytest.raises(ValueError, match=exact_text_pattern) for deterministic validation.

### TSK-010-SSE-ALLOWED

- Scope: TASK-010 in tests/functional_test.py
- Test ID: CASE-010
- Function Name: test_startup_allows_legacy_sse_when_enabled

Given:
- Environment variable MCP_TRANSPORT is set to sse.
- Environment variable MCP_ALLOW_LEGACY_SSE is set to true.
- Startup path is invoked via server.main().

When:
- server.main() executes transport branch resolution.

Then:
- No ValueError is raised by SSE gate logic.
- mcp.run is called exactly once.
- mcp.run call kwargs include transport=sse and include host and port keys.

Implementation Notes:
- Replace mcp.run with a capture stub that records kwargs and returns immediately.
- Assert captured kwargs['transport'] == 'sse'.
- Assert 'host' in kwargs and 'port' in kwargs.

### TSK-011-CONTRACT-GUARD

- Scope: TASK-011 in tests/test_tools_pg96.py
- Test ID: CASE-011
- Function Name: test_transport_gate_changes_do_not_modify_db_pg96_contract

Given:
- Existing callable tool functions db_pg96_ping and db_pg96_server_info are available.

When:
- Both tools are invoked with default arguments.

Then:
- db_pg96_ping output includes key ok with boolean value.
- db_pg96_server_info output includes expected top-level metadata keys used by existing tests.
- No additional required input arguments are introduced.

Implementation Notes:
- Keep assertions key-based and deterministic.
- Do not depend on mutable environment-specific values such as timestamp content.
