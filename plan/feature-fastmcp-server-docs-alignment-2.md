---
goal: FastMCP Servers Documentation Alignment and Transport Hardening
version: 2.0
date_created: 2026-04-02
last_updated: 2026-04-02
owner: Harry Valdez
status: Planned
tags: [feature, documentation, fastmcp, transport, hardening]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This plan defines deterministic tasks to align this repository with current FastMCP Servers documentation, with emphasis on transport behavior, server metadata, and deployment documentation consistency.

## 1. Requirements & Constraints

- REQ-001: Align transport documentation in README.md and DEPLOYMENT.md with FastMCP guidance where HTTP is primary and SSE is treated as legacy.
- REQ-002: Preserve runtime support for http, sse, and stdio in server.py unless an explicit deprecation gate is configured.
- REQ-003: Add deterministic runtime warnings when transport is set to sse to communicate legacy status without breaking compatibility.
- REQ-004: Ensure documented default port values match executable defaults in server.py.
- REQ-005: Expose clear server identity metadata guidance (name, instructions, version, website_url) in docs with exact environment variable names.
- REQ-006: Keep existing db_pg96_* tool names, signatures, and behavior unchanged.
- SEC-001: Do not reduce authentication middleware coverage for HTTP/SSE endpoints.
- SEC-002: Do not expose new unauthenticated write paths while performing transport and docs alignment.
- CON-001: Restrict code changes to existing files server.py, README.md, DEPLOYMENT.md, and tests.
- CON-002: Maintain compatibility with current FastMCP major version declared by project dependencies.
- CON-003: Avoid changing default transport from MCP_TRANSPORT=http in executable code.
- GUD-001: Prefer additive compatibility changes (warnings, docs updates, tests) over breaking removals.
- PAT-001: Use existing environment-variable helper patterns in server.py for any new transport gate variables.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Establish baseline parity map between FastMCP servers docs and current repository behavior.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | In server.py, document current transport execution paths inside main() for http, sse, and stdio using concise inline comments above the `if transport in {"http", "sse"}` and `elif transport == "stdio"` branches. |  |  |
| TASK-002 | In README.md, replace transport marketing text that implies SSE parity with HTTP and explicitly mark SSE as legacy transport while preserving mention of compatibility support. |  |  |
| TASK-003 | In DEPLOYMENT.md, update transport variable section so MCP_TRANSPORT describes `http` as recommended default, `stdio` as local process mode, and `sse` as legacy compatibility mode. |  |  |
| TASK-004 | In DEPLOYMENT.md, update default HTTP port references from 8000 to 8085 to match `_env_int("MCP_PORT", 8085)` in server.py. |  |  |

### Implementation Phase 2

- GOAL-002: Add deterministic runtime safety signals for legacy transport usage.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-005 | In server.py main(), add a logger.warning message when transport == "sse" indicating legacy status and recommending MCP_TRANSPORT=http for new deployments. |  |  |
| TASK-006 | In server.py, add environment flag parsing for MCP_ALLOW_LEGACY_SSE (fallback FASTMCP_ALLOW_LEGACY_SSE) using existing optional bool helper pattern. |  |  |
| TASK-007 | In server.py main(), enforce deterministic behavior: if transport == "sse" and MCP_ALLOW_LEGACY_SSE is explicitly false, raise ValueError with remediation text; if unset or true, continue with warning. |  |  |
| TASK-008 | In README.md and DEPLOYMENT.md, add one configuration example showing how to disable SSE by setting MCP_ALLOW_LEGACY_SSE=false. |  |  |

### Implementation Phase 3

- GOAL-003: Validate no regression in MCP surface and deployment guidance.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-009 | In tests/functional_test.py, add test case that starts server with MCP_TRANSPORT=sse and MCP_ALLOW_LEGACY_SSE=false and asserts startup failure with deterministic error message. |  |  |
| TASK-010 | In tests/functional_test.py, add test case that starts server with MCP_TRANSPORT=sse and MCP_ALLOW_LEGACY_SSE=true and asserts startup proceeds to FastMCP run invocation path. |  |  |
| TASK-011 | In tests/test_tools_pg96.py, add a guard test asserting representative db_pg96_* tool outputs are unchanged after transport-gating additions. |  |  |
| TASK-012 | Execute `python -m pytest tests/functional_test.py -q` and `python -m pytest tests/test_tools_pg96.py -q`; record pass/fail summary in this plan under a validation snapshot subsection. |  |  |

## 3. Alternatives

- ALT-001: Remove SSE support entirely from server.py. Rejected because this introduces a breaking change for existing remote clients.
- ALT-002: Keep current behavior and only edit docs. Rejected because runtime safeguards are needed to prevent accidental legacy transport usage.
- ALT-003: Force-upgrade sse requests to http at runtime. Rejected because silent transport mutation can break client assumptions and troubleshooting.

## 4. Dependencies

- DEP-001: FastMCP runtime behavior in installed project version must continue to accept transport values used by server.py.
- DEP-002: Existing logging setup in server.py must remain active for new warning/error messages.
- DEP-003: Existing pytest harness in tests/functional_test.py and tests/test_tools_pg96.py must be reusable without introducing new external services.

## 5. Files

- FILE-001: server.py - transport branch behavior, legacy SSE gate variable parsing, warning/error messaging.
- FILE-002: README.md - transport guidance and legacy SSE note.
- FILE-003: DEPLOYMENT.md - environment variable guidance, default port correction, SSE disable example.
- FILE-004: tests/functional_test.py - startup behavior tests for SSE gate conditions.
- FILE-005: tests/test_tools_pg96.py - regression guard for db_pg96_* tool contracts.
- FILE-006: plan/feature-fastmcp-server-docs-alignment-2.md - execution tracking and validation evidence.

## 6. Testing

- TEST-001: Verify startup logs include legacy warning when MCP_TRANSPORT=sse and SSE gate is not disabled.
- TEST-002: Verify startup fails deterministically when MCP_TRANSPORT=sse and MCP_ALLOW_LEGACY_SSE=false.
- TEST-003: Verify startup succeeds when MCP_TRANSPORT=sse and MCP_ALLOW_LEGACY_SSE=true.
- TEST-004: Verify http and stdio startup paths are unaffected by SSE gate logic.
- TEST-005: Verify representative db_pg96_* tools remain callable and return unchanged schema/keys.
- TEST-006: Verify README.md and DEPLOYMENT.md transport sections are consistent with server.py defaults (transport=http, port=8085).

## 7. Risks & Assumptions

- RISK-001: Some existing users may rely on SSE without explicit awareness; new warnings can surface operational noise.
- RISK-002: Test harness startup assertions may be brittle if current tests mock mcp.run indirectly.
- ASSUMPTION-001: This repository intentionally retains SSE support for backward compatibility at this stage.
- ASSUMPTION-002: FastMCP documentation guidance on SSE legacy status remains stable for this implementation window.

## 8. Related Specifications / Further Reading

- https://gofastmcp.com/servers/server
- https://gofastmcp.com/deployment/running-server
- https://gofastmcp.com/deployment/http