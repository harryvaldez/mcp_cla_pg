---
goal: Enforce Okta Group-Based Tool Authorization for MCP Tools
version: 1.0
date_created: 2026-06-30
last_updated: 2026-06-30
owner: harryvaldez
status: Implemented
tags: [feature, security, auth, okta, authorization, rbac]
---

# Introduction

![Status: Implemented](https://img.shields.io/badge/status-implemented-green)

Implement deterministic authorization enforcement for Okta-authenticated users so that members of write groups can execute all tools, while members of read groups can execute all tools except HypoPG-based tools and tools that inspect data related to other database sessions.

## 1. Requirements & Constraints

- **REQ-001**: Authorization rules apply only when `auth.auth_mode` is set to `okta` in [config/runtime-policy.yaml](config/runtime-policy.yaml).
- **REQ-002**: A caller in any configured `okta_write_groups` must be authorized for all registered tools.
- **REQ-003**: A caller in any configured `okta_read_groups` must be authorized for all registered tools except restricted tool categories.
- **REQ-004**: Restricted categories for read-group callers are:
  - all HypoPG tools: `db_<n>_pg96_hypopg_create_virtual_indexes`, `db_<n>_pg96_hypopg_explain_with_virtual`, `db_<n>_pg96_hypopg_find_optimal_indexes`
  - all cross-session inspection tools: `db_<n>_pg96_blocking_sessions`
- **REQ-005**: Existing behavior for `auth_mode: disabled` remains unchanged.
- **REQ-006**: Existing behavior for scope parsing remains available; group-based decision is enforced before scope-only fallback.
- **SEC-001**: Authorization deny decisions must return deterministic errors without leaking token contents.
- **SEC-002**: Every allow/deny decision must be captured in audit logs via existing `_log_audit_event` path in [src/tools/pg_tools.py](src/tools/pg_tools.py).
- **SEC-003**: Rate limiting and session tracking semantics must not be bypassed for authorized requests.
- **CON-001**: No breaking change to existing tool names or registration loop pattern in [src/tools/pg_tools.py](src/tools/pg_tools.py).
- **CON-002**: Restriction logic must be centralized (single source of truth) to avoid drift across tool handlers.
- **CON-003**: Policy must be testable without live Okta dependency.
- **GUD-001**: Restriction matching should use canonical tool-name suffixes to preserve dual-instance symmetry (`db_1_...`, `db_2_...`).
- **PAT-001**: Enforce authorization immediately after `_resolve_actor_and_authorize(...)` and before SQL execution in each tool handler.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Define explicit authorization matrix and restricted tool classification.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Add a centralized restriction classifier in [src/tools/pg_tools.py](src/tools/pg_tools.py) that maps tool names to categories: `hypopg`, `cross_session`, `standard`. | ✅ | 2026-06-30 |
| TASK-002 | Define canonical restricted suffix constants in [src/tools/pg_tools.py](src/tools/pg_tools.py): `_pg96_hypopg_create_virtual_indexes`, `_pg96_hypopg_explain_with_virtual`, `_pg96_hypopg_find_optimal_indexes`, `_pg96_blocking_sessions`. | ✅ | 2026-06-30 |
| TASK-003 | Add helper function ` _is_tool_allowed_for_okta_groups(tool_name: str, auth_ctx: dict[str, Any], policy: RuntimePolicy) -> tuple[bool, str | None]` in [src/tools/pg_tools.py](src/tools/pg_tools.py). | ✅ | 2026-06-30 |

### Implementation Phase 2

- GOAL-002: Enforce group-based allow/deny in execution flow for all tools.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-004 | In each registered tool handler in [src/tools/pg_tools.py](src/tools/pg_tools.py), call the centralized helper after `_resolve_actor_and_authorize(...)` and before `session_manager.touch(...)` and SQL execution. | ✅ | 2026-06-30 |
| TASK-005 | If helper denies access, raise `PermissionError("AUTHZ_DENIED: insufficient group privileges for tool")` and set audit `decision="deny"` and `error_code` accordingly in existing `finally` block path. | ✅ | 2026-06-30 |
| TASK-006 | Ensure decision precedence in helper is deterministic: write-group match -> allow all; read-group match -> deny restricted categories else allow; no group match -> fallback to existing scope logic behavior. | ✅ | 2026-06-30 |

### Implementation Phase 3

- GOAL-003: Expand policy schema/documentation for operator-controlled restricted tools.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-007 | Extend `AuthConfig` in [src/models.py](src/models.py) with optional lists: `okta_read_restricted_tool_suffixes` and `okta_cross_session_tool_suffixes`, defaulting to current required set. | ✅ | 2026-06-30 |
| TASK-008 | Add new keys under `auth` in [config/runtime-policy.yaml](config/runtime-policy.yaml) and align loading behavior in [src/config_loader.py](src/config_loader.py) if required by model changes. | ✅ | 2026-06-30 |
| TASK-009 | Update operator guidance in [docs/okta-authentication-setup.md](docs/okta-authentication-setup.md) and catalog caveats in [docs/mcp-tool-catalog.md](docs/mcp-tool-catalog.md) for read-group restrictions. | ✅ | 2026-06-30 |

### Implementation Phase 4

- GOAL-004: Validate behavior with deterministic tests and quality gates.

| Task | Description | Completed | Date |
| -------- | --------------------- | --------- | ---------- |
| TASK-010 | Add/extend tests in [tests/test_okta_auth.py](tests/test_okta_auth.py) for allow/deny matrix: write-group all-allow, read-group deny HypoPG, read-group deny blocking sessions, read-group allow non-restricted tools. | ✅ | 2026-06-30 |
| TASK-011 | Add targeted registration/assertion tests in [tests/test_performance_tools.py](tests/test_performance_tools.py) to ensure restricted tool names remain covered by policy classifier. | ✅ | 2026-06-30 |
| TASK-012 | Run `ruff check .` and `pytest -q`; require zero regressions before merge. | ✅ | 2026-06-30 |

## 3. Alternatives

- **ALT-001**: Enforce using only OAuth scopes (`mcp:read`/`mcp:write`) and ignore groups. Rejected because requirement mandates group-based access control.
- **ALT-002**: Hardcode restrictions inline per tool handler. Rejected because it duplicates logic and increases drift risk.
- **ALT-003**: Create separate MCP servers for read and write users. Rejected due to operational complexity and duplicate deployment/runtime management.

## 4. Dependencies

- **DEP-001**: Existing Okta auth integration and claim extraction in [src/server.py](src/server.py) and [src/tools/pg_tools.py](src/tools/pg_tools.py).
- **DEP-002**: Policy model definitions in [src/models.py](src/models.py) and runtime policy parsing in [src/config_loader.py](src/config_loader.py).
- **DEP-003**: Existing audit and deny-path handling in [src/tools/pg_tools.py](src/tools/pg_tools.py).
- **DEP-004**: Current tool inventory and naming in [docs/mcp-tool-catalog.md](docs/mcp-tool-catalog.md).

## 5. Files

- **FILE-001**: [src/tools/pg_tools.py](src/tools/pg_tools.py) - add centralized group-based authorization helper and invoke it across tool handlers.
- **FILE-002**: [src/models.py](src/models.py) - add optional auth policy fields for restricted suffix configuration.
- **FILE-003**: [src/config_loader.py](src/config_loader.py) - ensure new auth fields are loaded/validated.
- **FILE-004**: [config/runtime-policy.yaml](config/runtime-policy.yaml) - define restricted suffix lists under `auth`.
- **FILE-005**: [tests/test_okta_auth.py](tests/test_okta_auth.py) - add matrix tests for allow/deny outcomes.
- **FILE-006**: [tests/test_performance_tools.py](tests/test_performance_tools.py) - add classifier coverage tests.
- **FILE-007**: [docs/okta-authentication-setup.md](docs/okta-authentication-setup.md) - document group restriction behavior and examples.
- **FILE-008**: [docs/mcp-tool-catalog.md](docs/mcp-tool-catalog.md) - annotate restricted tools for read-group users.

## 6. Testing

- **TEST-001**: `auth_mode=okta`, user in `okta_write_groups`, call each restricted and non-restricted tool -> all allowed.
- **TEST-002**: `auth_mode=okta`, user in `okta_read_groups`, call HypoPG tools -> denied with deterministic `AUTHZ_DENIED` message.
- **TEST-003**: `auth_mode=okta`, user in `okta_read_groups`, call `db_<n>_pg96_blocking_sessions` -> denied.
- **TEST-004**: `auth_mode=okta`, user in `okta_read_groups`, call standard tools (`ping`, `exec_query`, settings/security tools) -> allowed.
- **TEST-005**: `auth_mode=disabled`, existing flows remain unchanged.
- **TEST-006**: Audit records include denied `decision` and `error_code` for blocked calls.
- **TEST-007**: Lint and full suite pass: `ruff check .` and `pytest -q`.

## 7. Risks & Assumptions

- **RISK-001**: Misclassification of tool names can over-restrict or under-restrict access.
- **RISK-002**: Future new cross-session or HypoPG-related tools may be added without updating restriction lists.
- **RISK-003**: Group claim format differences across Okta authorization servers can impact matching.
- **ASSUMPTION-001**: Okta JWT includes `groups` claim for authenticated users.
- **ASSUMPTION-002**: Existing helper `_resolve_actor_and_authorize(...)` continues to populate group data in auth context.
- **ASSUMPTION-003**: `db_<n>_pg96_blocking_sessions` is the only current cross-session inspection tool requiring read-group exclusion.

## 8. Related Specifications / Further Reading

- [plan/feature-okta-oauth-auth-1.md](plan/feature-okta-oauth-auth-1.md)
- [docs/okta-authentication-setup.md](docs/okta-authentication-setup.md)
- [docs/mcp-tool-catalog.md](docs/mcp-tool-catalog.md)
- [AGENTS.md](AGENTS.md)