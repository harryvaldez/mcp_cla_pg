---
goal: FastMCP Transport Alignment 2.4 with Deterministic Replace-Block Patches
version: 2.4
date_created: 2026-04-02
last_updated: 2026-04-03
owner: Harry Valdez
status: Completed
tags: [feature, fastmcp, transport, documentation, tests, execution]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

This plan provides deterministic, planning-only replace-block patches for runtime, documentation, and tests so implementation can be executed without interpretation.

## 1. Requirements & Constraints

- REQ-001: Mark HTTP as recommended transport and SSE as legacy compatibility mode in documentation.
- REQ-002: Keep runtime support for http, sse, stdio with optional SSE hard-disable gate.
- REQ-003: Add deterministic warning on SSE startup when allowed.
- REQ-004: Add deterministic ValueError on SSE startup when explicitly disabled.
- REQ-005: Correct deployment documentation default HTTP port to 8085.
- REQ-006: Add startup tests for SSE deny and allow branches.
- REQ-007: Add db_pg96 contract guard test for key stability.
- SEC-001: Preserve middleware authentication coverage in HTTP/SSE startup branch.
- CON-001: Do not modify runtime behavior outside startup transport gate, docs transport text, and targeted tests.
- CON-002: Use existing helper patterns and test style.
- GUD-001: Keep assertions deterministic and independent of host-specific timestamps.
- PAT-001: Prefer additive compatibility controls over transport removal.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Apply deterministic runtime startup transport guard changes.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Update server.py main() to parse MCP_ALLOW_LEGACY_SSE with FASTMCP_ALLOW_LEGACY_SSE fallback. |  |  |
| TASK-002 | Add warning when transport is sse and gate is not false. |  |  |
| TASK-003 | Add ValueError branch when transport is sse and gate is false. |  |  |

### Implementation Phase 2

- GOAL-002: Apply deterministic documentation alignment changes.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Update README feature bullet transport wording. |  |  |
| TASK-005 | Update README MCP_TRANSPORT env row wording. |  |  |
| TASK-006 | Update DEPLOYMENT default port and env transport wording. |  |  |

### Implementation Phase 3

- GOAL-003: Apply deterministic tests for startup gate and contract guard.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-007 | Add denied-SSE startup test in tests/functional_test.py. |  |  |
| TASK-008 | Add allowed-SSE startup test in tests/functional_test.py. |  |  |
| TASK-009 | Add contract guard test in tests/test_tools_pg96.py. |  |  |
| TASK-010 | Execute command matrix and record outcomes. |  |  |

## 3. Alternatives

- ALT-001: Remove SSE support now. Rejected for backward compatibility.
- ALT-002: Docs-only change. Rejected due to lack of runtime guard.

## 4. Dependencies

- DEP-001: server.py helper `_env_optional_bool`.
- DEP-002: pytest monkeypatch fixture.
- DEP-003: Existing callable db_pg96 tools.

## 5. Files

- FILE-001: server.py
- FILE-002: README.md
- FILE-003: DEPLOYMENT.md
- FILE-004: tests/functional_test.py
- FILE-005: tests/test_tools_pg96.py
- FILE-006: plan/feature-fastmcp-server-docs-alignment-6.md

## 6. Testing

- TEST-001: SSE denied branch raises deterministic ValueError and does not call mcp.run.
- TEST-002: SSE allowed branch calls mcp.run exactly once with transport=sse.
- TEST-003: Contract guard verifies db_pg96_ping and db_pg96_server_info key stability.
- TEST-004: Transport docs now align with runtime defaults.

## 7. Risks & Assumptions

- RISK-001: Startup test isolation may require environment cleanup between tests.
- ASSUMPTION-001: Current test harness can monkeypatch server_module.mcp.run.

## 8. Related Specifications / Further Reading

- https://gofastmcp.com/servers/server
- https://gofastmcp.com/deployment/running-server

## 9. Deterministic Replace-Block Patches

PATCH-001 for server.py:

Replace this block:

    transport = os.environ.get("MCP_TRANSPORT", "http").strip().lower()
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    # Default to 8085 to avoid common 8000 conflicts
    port = _env_int("MCP_PORT", 8085)

    stateless = _env_bool("MCP_STATELESS", False)
    json_resp = _env_bool("MCP_JSON_RESPONSE", False)

    # SSL Configuration for HTTPS
    ssl_cert = os.environ.get("MCP_SSL_CERT")
    ssl_key = os.environ.get("MCP_SSL_KEY")

    if transport in {"http", "sse"}:

With this block:

    transport = os.environ.get("MCP_TRANSPORT", "http").strip().lower()
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    # Default to 8085 to avoid common 8000 conflicts
    port = _env_int("MCP_PORT", 8085)

    stateless = _env_bool("MCP_STATELESS", False)
    json_resp = _env_bool("MCP_JSON_RESPONSE", False)

    allow_legacy_sse = _env_optional_bool("MCP_ALLOW_LEGACY_SSE")
    if allow_legacy_sse is None:
        allow_legacy_sse = _env_optional_bool("FASTMCP_ALLOW_LEGACY_SSE")

    if transport == "sse":
        if allow_legacy_sse is False:
            raise ValueError(
                "Legacy SSE transport is disabled. Set MCP_TRANSPORT=http or set MCP_ALLOW_LEGACY_SSE=true."
            )
        logger.warning(
            "MCP_TRANSPORT=sse is legacy compatibility mode. Use MCP_TRANSPORT=http for new deployments."
        )

    # SSL Configuration for HTTPS
    ssl_cert = os.environ.get("MCP_SSL_CERT")
    ssl_key = os.environ.get("MCP_SSL_KEY")

    if transport in {"http", "sse"}:

PATCH-002 for README.md (features bullet):

Replace line containing:

    - **Multiple Transports**: Supports `sse` (Server-Sent Events) and `stdio`. HTTPS is supported via SSL configuration variables.

With:

    - **Multiple Transports**: Supports `http` (recommended), `stdio`, and legacy `sse` compatibility mode. HTTPS is supported via SSL configuration variables.

PATCH-003 for README.md (env table row):

Replace line containing:

    | `MCP_TRANSPORT` | Transport mode: `sse`, `http` (uses SSE), or `stdio` | `http` |

With:

    | `MCP_TRANSPORT` | Transport mode: `http` (recommended), `stdio`, or `sse` (legacy compatibility) | `http` |

PATCH-004 for DEPLOYMENT.md:

Replace line containing:

    - Default HTTP port is 8000; ensure it is available locally when testing.

With:

    - Default HTTP port is 8085; ensure it is available locally when testing.

Replace lines containing:

    - `MCP_TRANSPORT` Transport mode: `sse`, `http` (default), or `stdio`.
    - `MCP_PORT` Port for HTTP transport, default `8000`.

With:

    - `MCP_TRANSPORT` Transport mode: `http` (recommended default), `stdio`, or `sse` (legacy compatibility).
    - `MCP_PORT` Port for HTTP transport, default `8085`.

PATCH-005 for tests/functional_test.py:

Append near other tests:

    def test_startup_rejects_legacy_sse_when_disabled(monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        monkeypatch.setenv("MCP_ALLOW_LEGACY_SSE", "false")
        monkeypatch.delenv("FASTMCP_ALLOW_LEGACY_SSE", raising=False)

        calls = []

        def _fake_run(**kwargs):
            calls.append(kwargs)

        monkeypatch.setattr(server_module.mcp, "run", _fake_run)

        expected_message = "Legacy SSE transport is disabled. Set MCP_TRANSPORT=http or set MCP_ALLOW_LEGACY_SSE=true."
        with pytest.raises(ValueError, match="^" + expected_message.replace(".", r"\\.") + "$"):
            server_module.main()

        assert len(calls) == 0

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

PATCH-006 for tests/test_tools_pg96.py:

Append near other tests:

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

## 10. Command Matrix

| CMD ID | Command | Expected Outcome |
|---|---|---|
| CMD-001 | python -m pytest tests/functional_test.py -k "legacy_sse or startup" -q | New deny/allow startup tests pass. |
| CMD-002 | python -m pytest tests/test_tools_pg96.py -k "transport_gate_changes" -q | Contract guard passes. |
| CMD-003 | python -m pytest tests/functional_test.py tests/test_tools_pg96.py -q | Combined targeted suite passes. |

## 11. Measurable Completion Criteria

- MCC-001: server.py includes MCP_ALLOW_LEGACY_SSE and FASTMCP_ALLOW_LEGACY_SSE parsing.
- MCC-002: server.py raises deterministic ValueError for denied SSE.
- MCC-003: README.md and DEPLOYMENT.md transport language aligns with HTTP-recommended guidance.
- MCC-004: New functional tests for denied and allowed SSE startup exist and pass.
- MCC-005: New db_pg96 contract guard test exists and passes.

## 12. Validation Snapshot

- VAL-001: CMD-001 -> Pending
- VAL-002: CMD-002 -> Pending
- VAL-003: CMD-003 -> Pending
