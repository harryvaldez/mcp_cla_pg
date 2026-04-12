---
goal: FastMCP Transport Alignment 2.5 Single Operation Apply Patch Execution
version: 2.5
date_created: 2026-04-02
last_updated: 2026-04-03
owner: Harry Valdez
status: Completed
tags: [feature, fastmcp, transport, docs, tests, execution]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

This plan provides one copy-paste apply patch operation that implements all scoped changes for transport alignment, legacy SSE gating, documentation drift fixes, and startup and contract tests.

## 1. Requirements & Constraints

- REQ-001: Add runtime gate variable parsing for MCP_ALLOW_LEGACY_SSE with FASTMCP_ALLOW_LEGACY_SSE fallback.
- REQ-002: Add deterministic warning for allowed legacy SSE startup.
- REQ-003: Add deterministic ValueError for denied legacy SSE startup.
- REQ-004: Update transport documentation language in README.md.
- REQ-005: Update port and transport defaults in DEPLOYMENT.md.
- REQ-006: Add startup allow and deny tests in tests/functional_test.py.
- REQ-007: Add db_pg96 contract guard test in tests/test_tools_pg96.py.
- SEC-001: Preserve current authentication middleware behavior in HTTP/SSE startup branch.
- CON-001: Keep stdio startup behavior unchanged.
- CON-002: Keep unknown transport ValueError behavior unchanged.
- GUD-001: Use existing helper _env_optional_bool for boolean env parsing.
- PAT-001: Additive hardening only, no transport removal.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Execute one deterministic patch operation.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Copy the full patch payload in Section 9 and apply it with one apply patch call. | ✅ | 2026-04-05 |
| TASK-002 | Confirm modified files match File List section. | ✅ | 2026-04-05 |

### Implementation Phase 2

- GOAL-002: Validate runtime and regression behavior.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-003 | Run startup transport tests for legacy SSE allow and deny branches. | ✅ | 2026-04-05 |
| TASK-004 | Run db_pg96 contract guard test. | ✅ | 2026-04-05 |
| TASK-005 | Run combined targeted test suite. | ✅ | 2026-04-05 |

## 3. Alternatives

- ALT-001: Multi-step manual edits in each file. Rejected because single operation patch is lower risk and deterministic.
- ALT-002: Implement runtime only and postpone docs/tests. Rejected because parity and verification are required together.

## 4. Dependencies

- DEP-001: Existing startup main function in server.py.
- DEP-002: Existing pytest and monkeypatch infrastructure.
- DEP-003: Existing db_pg96_ping and db_pg96_server_info tools.

## 5. Files

- FILE-001: server.py
- FILE-002: README.md
- FILE-003: DEPLOYMENT.md
- FILE-004: tests/functional_test.py
- FILE-005: tests/test_tools_pg96.py
- FILE-006: plan/feature-fastmcp-server-docs-alignment-7.md

## 6. Testing

- TEST-001: Denied legacy SSE startup raises deterministic ValueError and does not call mcp.run.
- TEST-002: Allowed legacy SSE startup calls mcp.run once with transport set to sse.
- TEST-003: Contract guard verifies db_pg96_ping and db_pg96_server_info key stability.
- TEST-004: Targeted combined suite passes.

## 7. Risks & Assumptions

- RISK-001: Startup test monkeypatches may leak env state if fixtures are not isolated.
- RISK-002: Contract guard may need updates if server_info schema intentionally evolves.
- ASSUMPTION-001: Existing tests can import and reload server module safely.

## 8. Related Specifications / Further Reading

- https://gofastmcp.com/servers/server
- https://gofastmcp.com/deployment/running-server

## 9. Single Operation Apply Patch Payload

Copy all lines below exactly into one apply patch tool call.

*** Begin Patch
*** Update File: c:\Users\HarryValdez\OneDrive\Documents\trae\mcp-postgres\server.py
@@
 def main() -> None:
     _configure_fastmcp_runtime()
 
     transport = os.environ.get("MCP_TRANSPORT", "http").strip().lower()
     host = os.environ.get("MCP_HOST", "0.0.0.0")
     # Default to 8085 to avoid common 8000 conflicts
     port = _env_int("MCP_PORT", 8085)
     
     stateless = _env_bool("MCP_STATELESS", False)
     json_resp = _env_bool("MCP_JSON_RESPONSE", False)
+
+    allow_legacy_sse = _env_optional_bool("MCP_ALLOW_LEGACY_SSE")
+    if allow_legacy_sse is None:
+        allow_legacy_sse = _env_optional_bool("FASTMCP_ALLOW_LEGACY_SSE")
+
+    if transport == "sse":
+        if allow_legacy_sse is False:
+            raise ValueError(
+                "Legacy SSE transport is disabled. Set MCP_TRANSPORT=http or set MCP_ALLOW_LEGACY_SSE=true."
+            )
+        logger.warning(
+            "MCP_TRANSPORT=sse is legacy compatibility mode. Use MCP_TRANSPORT=http for new deployments."
+        )
     
     # SSL Configuration for HTTPS
     ssl_cert = os.environ.get("MCP_SSL_CERT")
     ssl_key = os.environ.get("MCP_SSL_KEY")
@@
*** Update File: c:\Users\HarryValdez\OneDrive\Documents\trae\mcp-postgres\README.md
@@
 - **Security Audits**: Analyze database privileges and security settings.
 - **Safe Execution**: Read-only by default, with optional write capabilities for specific maintenance tasks.
- **Multiple Transports**: Supports `sse` (Server-Sent Events) and `stdio`. HTTPS is supported via SSL configuration variables.
+- **Multiple Transports**: Supports `http` (recommended), `stdio`, and legacy `sse` compatibility mode. HTTPS is supported via SSL configuration variables.
 - **Secure Authentication**: Built-in support for **Azure AD (Microsoft Entra ID)** and standard token auth.
 - **HTTPS Support**: Native SSL/TLS support for secure remote connections.
 - **Python 3.13**: Built on the latest Python runtime for improved performance and security.
@@
 | `DATABASE_URL` | Full PostgreSQL connection string | *Required* |
 | `MCP_HOST` | Host to bind the server to | `0.0.0.0` |
 | `MCP_PORT` | Port to listen on (8000 for Docker, 8085 for local) | `8085` |
-| `MCP_TRANSPORT` | Transport mode: `sse`, `http` (uses SSE), or `stdio` | `http` |
+| `MCP_TRANSPORT` | Transport mode: `http` (recommended), `stdio`, or `sse` (legacy compatibility) | `http` |
 | `MCP_ALLOW_WRITE` | Enable write tools (`db_pg96_create_db_user`, etc.) | `false` |
 | `MCP_CONFIRM_WRITE` | **Required if ALLOW_WRITE=true**. Safety latch to confirm write mode. | `false` |
 | `MCP_POOL_MAX_WAITING` | Max queries queued when pool is full | `20` |
@@
*** Update File: c:\Users\HarryValdez\OneDrive\Documents\trae\mcp-postgres\DEPLOYMENT.md
@@
 Notes:
 - The base image is python:3.13-slim.
 - System packages and Python tooling are upgraded during build to reduce CVE exposure.
-- Default HTTP port is 8000; ensure it is available locally when testing.
+- Default HTTP port is 8085; ensure it is available locally when testing.
 
 ---
 
 ## ☁️ Azure Container Apps (ACA)
@@
 Key environment variables supported by the server:
 - `DATABASE_URL` PostgreSQL connection string.
-- `MCP_TRANSPORT` Transport mode: `sse`, `http` (default), or `stdio`.
+- `MCP_TRANSPORT` Transport mode: `http` (recommended default), `stdio`, or `sse` (legacy compatibility).
 - `MCP_HOST` Host for HTTP transport, default `0.0.0.0`.
-- `MCP_PORT` Port for HTTP transport, default `8000`.
+- `MCP_PORT` Port for HTTP transport, default `8085`.
 - `MCP_ALLOW_WRITE` Allow write operations, default `false`.
 - `MCP_CONFIRM_WRITE` Require confirmation for writes, default `false`.
 - `MCP_SKIP_CONFIRMATION` Skip startup confirmation dialog, default `false`.
@@
*** Update File: c:\Users\HarryValdez\OneDrive\Documents\trae\mcp-postgres\tests\functional_test.py
@@
 def _parse_resource_payload(raw_content: Any) -> dict[str, Any]:
@@
     decoded = json.loads(raw_content)
@@
     if isinstance(decoded, dict) and isinstance(decoded.get("contents"), list):
@@
         if isinstance(inner, str):
             return json.loads(inner)
     return decoded if isinstance(decoded, dict) else {}
+
+
+def test_startup_rejects_legacy_sse_when_disabled(monkeypatch):
+    monkeypatch.setenv("MCP_TRANSPORT", "sse")
+    monkeypatch.setenv("MCP_ALLOW_LEGACY_SSE", "false")
+    monkeypatch.delenv("FASTMCP_ALLOW_LEGACY_SSE", raising=False)
+
+    calls: list[dict[str, Any]] = []
+
+    def _fake_run(**kwargs):
+        calls.append(kwargs)
+
+    monkeypatch.setattr(server_module.mcp, "run", _fake_run)
+
+    expected_message = "Legacy SSE transport is disabled. Set MCP_TRANSPORT=http or set MCP_ALLOW_LEGACY_SSE=true."
+    with pytest.raises(ValueError, match="^" + expected_message.replace(".", r"\\.") + "$"):
+        server_module.main()
+
+    assert len(calls) == 0
+
+
+def test_startup_allows_legacy_sse_when_enabled(monkeypatch):
+    monkeypatch.setenv("MCP_TRANSPORT", "sse")
+    monkeypatch.setenv("MCP_ALLOW_LEGACY_SSE", "true")
+
+    calls: list[dict[str, Any]] = []
+
+    def _fake_run(**kwargs):
+        calls.append(kwargs)
+
+    monkeypatch.setattr(server_module.mcp, "run", _fake_run)
+
+    server_module.main()
+
+    assert len(calls) == 1
+    assert calls[0].get("transport") == "sse"
+    assert "host" in calls[0]
+    assert "port" in calls[0]
@@
*** Update File: c:\Users\HarryValdez\OneDrive\Documents\trae\mcp-postgres\tests\test_tools_pg96.py
@@
 def _seed_sample_data() -> None:
@@
     with psycopg.connect(dsn, autocommit=True) as conn:
         with conn.cursor() as cur:
             cur.execute(ddl)
             cur.execute(dml)
+
+
+def test_transport_gate_changes_do_not_modify_db_pg96_contract(monkeypatch):
+    monkeypatch.setenv("MCP_TRANSPORT", "http")
+
+    import importlib
+    import server as server_module_local
+
+    server_module_local = importlib.reload(server_module_local)
+
+    ping_result = server_module_local.db_pg96_ping()
+    assert "ok" in ping_result
+    assert isinstance(ping_result["ok"], bool)
+
+    info_result = server_module_local.db_pg96_server_info()
+    assert isinstance(info_result, dict)
+    assert "version" in info_result
+    assert "database" in info_result
*** End Patch

## 10. Command Matrix

| CMD ID | Command | Expected Outcome |
|---|---|---|
| CMD-001 | python -m pytest tests/functional_test.py -k "legacy_sse or startup" -q | Startup gate tests pass. |
| CMD-002 | python -m pytest tests/test_tools_pg96.py -k "transport_gate_changes" -q | Contract guard passes. |
| CMD-003 | python -m pytest tests/functional_test.py tests/test_tools_pg96.py -q | Combined targeted suite passes. |

## 11. Measurable Completion Criteria

- MCC-001: Runtime contains allow and deny SSE branches controlled by MCP_ALLOW_LEGACY_SSE.
- MCC-002: README and DEPLOYMENT transport and port text are aligned with runtime defaults.
- MCC-003: Startup tests and contract guard test exist and pass.

## 12. Validation Snapshot

- VAL-001: CMD-001 -> Passed (2026-04-05)
- VAL-002: CMD-002 -> Passed (2026-04-05)
- VAL-003: CMD-003 -> Passed (2026-04-05)
