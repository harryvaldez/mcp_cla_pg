---
goal: FastMCP Transport Alignment 2.3 with Paste-Ready Assertion Checklist
version: 2.3
date_created: 2026-04-02
last_updated: 2026-04-03
owner: Harry Valdez
status: Completed
tags: [feature, fastmcp, transport, testing, checklist]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

This plan is a planning-only execution checklist that adds exact assertion snippets for startup transport gating tests and db_pg96 contract regression checks.

## 1. Requirements & Constraints

- REQ-001: Provide exact Given/When/Then checklist steps for the denied-SSE and allowed-SSE startup tests.
- REQ-002: Provide paste-ready assertion snippets compatible with pytest patterns already used in the repository.
- REQ-003: Keep all snippets deterministic and independent of timestamps or host-specific values.
- REQ-004: Preserve startup support for http and stdio without behavioral changes.
- REQ-005: Preserve db_pg96 tool contracts while adding startup transport guard tests.
- SEC-001: Do not reduce auth middleware enforcement coverage during transport hardening implementation.
- CON-001: This artifact is planning only and does not modify runtime code or tests directly.
- CON-002: Snippets must target existing files and existing test framework.
- GUD-001: Follow current naming and assertion style in tests/functional_test.py and tests/test_tools_pg96.py.
- PAT-001: Prefer monkeypatch-driven isolation for environment variable controlled startup paths.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Prepare startup test insertion checklist with explicit locations.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | In tests/functional_test.py, add helper setup for startup monkeypatching near existing imports and fixtures. |  |  |
| TASK-002 | Add test_startup_rejects_legacy_sse_when_disabled in tests/functional_test.py. |  |  |
| TASK-003 | Add test_startup_allows_legacy_sse_when_enabled in tests/functional_test.py. |  |  |
| TASK-004 | Add deterministic assertions for mcp.run call-count and kwargs capture behavior. |  |  |

### Implementation Phase 2

- GOAL-002: Prepare db_pg96 contract guard checklist.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | In tests/test_tools_pg96.py, add test_transport_gate_changes_do_not_modify_db_pg96_contract. |  |  |
| TASK-006 | Assert db_pg96_ping output contains ok boolean field. |  |  |
| TASK-007 | Assert db_pg96_server_info output contains stable top-level keys used by existing tests. |  |  |
| TASK-008 | Ensure contract guard assertions do not depend on mutable runtime values. |  |  |

### Implementation Phase 3

- GOAL-003: Run and verify checklist commands.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-009 | Run targeted startup tests in tests/functional_test.py and confirm deterministic allow/deny behavior. |  |  |
| TASK-010 | Run contract guard test in tests/test_tools_pg96.py and confirm no regressions. |  |  |
| TASK-011 | Run combined targeted suite for startup and tool contract checks. |  |  |
| TASK-012 | Record pass or fail outcomes in Validation Snapshot section of this plan. |  |  |

## 3. Alternatives

- ALT-001: Provide high-level testing guidance only. Rejected because execution required paste-ready assertions.
- ALT-002: Implement full code changes directly instead of planning-only checklist. Rejected because current request is option 2 planning path.

## 4. Dependencies

- DEP-001: Existing pytest and monkeypatch fixtures.
- DEP-002: Existing server module import path used by tests.
- DEP-003: Existing db_pg96_ping and db_pg96_server_info tool availability.

## 5. Files

- FILE-001: tests/functional_test.py
- FILE-002: tests/test_tools_pg96.py
- FILE-003: plan/feature-fastmcp-server-docs-alignment-5.md

## 6. Testing

- TEST-001: Denied SSE startup raises deterministic ValueError before mcp.run.
- TEST-002: Allowed SSE startup calls mcp.run once with transport set to sse.
- TEST-003: Contract guard verifies db_pg96_ping and db_pg96_server_info key stability.
- TEST-004: Targeted command matrix executes without unexpected failures.

## 7. Risks & Assumptions

- RISK-001: Startup tests may require strict monkeypatch reset to avoid cross-test contamination.
- RISK-002: Contract guard can become brittle if server_info schema is intentionally expanded.
- ASSUMPTION-001: tests/functional_test.py can safely monkeypatch server_module.mcp.run.
- ASSUMPTION-002: Existing CI environment supports current startup test harness.

## 8. Related Specifications / Further Reading

- https://gofastmcp.com/servers/server
- https://gofastmcp.com/deployment/running-server

## 9. Command Checklist

| CMD ID | Command | Expected Result |
|---|---|---|
| CMD-001 | python -m pytest tests/functional_test.py -k sse -q | SSE allow and deny tests pass deterministically. |
| CMD-002 | python -m pytest tests/test_tools_pg96.py -k contract -q | Contract guard passes. |
| CMD-003 | python -m pytest tests/functional_test.py tests/test_tools_pg96.py -q | Combined targeted suite passes. |

## 10. Measurable Completion Criteria

- MCC-001: Functional test file contains denied-SSE and allowed-SSE startup tests.
- MCC-002: Denied-SSE test asserts exact failure message and zero mcp.run calls.
- MCC-003: Allowed-SSE test asserts one mcp.run call and transport equals sse.
- MCC-004: Contract guard test verifies stable key-level expectations for db_pg96_ping and db_pg96_server_info.
- MCC-005: CMD-001 through CMD-003 outcomes are recorded in Validation Snapshot.

## 11. Validation Snapshot

- VAL-001: CMD-001 -> Pending
- VAL-002: CMD-002 -> Pending
- VAL-003: CMD-003 -> Pending

## 12. Paste-Ready Checklist

- CHK-001: Add startup monkeypatch helper in tests/functional_test.py for capturing mcp.run kwargs.
- CHK-002: Add denied-SSE test using monkeypatch for environment values and pytest.raises check.
- CHK-003: Add allowed-SSE test using monkeypatch and assertion on captured run kwargs.
- CHK-004: Add contract guard test in tests/test_tools_pg96.py with key-based asserts only.
- CHK-005: Execute CMD-001, CMD-002, CMD-003 and update VAL statuses.

## 13. Paste-Ready Assertion Snippets

SNIP-001 for tests/functional_test.py denied-SSE case:

    def test_startup_rejects_legacy_sse_when_disabled(monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        monkeypatch.setenv("MCP_ALLOW_LEGACY_SSE", "false")
        monkeypatch.delenv("FASTMCP_ALLOW_LEGACY_SSE", raising=False)

        calls = []
        def _fake_run(**kwargs):
            calls.append(kwargs)

        monkeypatch.setattr(server_module.mcp, "run", _fake_run)

        expected = "Legacy SSE transport is disabled. Set MCP_TRANSPORT=http or set MCP_ALLOW_LEGACY_SSE=true."
        with pytest.raises(ValueError, match="^" + expected.replace(".", r"\\.") + "$"):
            server_module.main()

        assert len(calls) == 0

SNIP-002 for tests/functional_test.py allowed-SSE case:

    def test_startup_allows_legacy_sse_when_enabled(monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        monkeypatch.setenv("MCP_ALLOW_LEGACY_SSE", "true")

        calls = []
        def _fake_run(**kwargs):
            calls.append(kwargs)

        monkeypatch.setattr(server_module.mcp, "run", _fake_run)

        server_module.main()

        assert len(calls) == 1
        assert calls[0].get("transport") == "sse"
        assert "host" in calls[0]
        assert "port" in calls[0]

SNIP-003 for tests/test_tools_pg96.py contract guard case:

    def test_transport_gate_changes_do_not_modify_db_pg96_contract(monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "http")

        import importlib
        import server as server_module_local
        server_module_local = importlib.reload(server_module_local)

        ping_result = server_module_local.db_pg96_ping()
        assert "ok" in ping_result
        assert isinstance(ping_result["ok"], bool)

        info_result = server_module_local.db_pg96_server_info()
        assert isinstance(info_result, dict)
        assert "version" in info_result
        assert "database" in info_result

## 14. Open Questions

- QST-001: Whether to assert exact kwargs set for stateless_http and json_response in allowed-SSE test.
- QST-002: Whether to include fallback precedence test for FASTMCP_ALLOW_LEGACY_SSE when MCP_ALLOW_LEGACY_SSE is unset.
