---
goal: Replace manual dual-instance alias registration with FastMCP transforms-based routing
version: 1.0
date_created: 2026-04-05
last_updated: 2026-04-05
owner: MCP Postgres Maintainers
status: Planned
tags: [refactor, fastmcp, transforms, routing, migration]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This plan refactors dual-instance tool exposure from custom runtime alias wrapper generation to FastMCP transforms so tool naming and lookup mapping are declarative, testable, and maintainable while preserving existing client-facing tool names and behavior.

## 1. Requirements & Constraints

- **REQ-001**: Preserve existing unprefixed tool contract `db_pg96_*` mapped to instance `01` semantics.
- **REQ-002**: Preserve prefixed tool contracts `db_01_pg96_*` and `db_02_pg96_*` for all tools currently exported as `db_pg96_*`.
- **REQ-003**: Preserve sync and async tool behavior, return types, and timeout metadata.
- **REQ-004**: Remove runtime alias function generation in `_register_dual_instance_tool_aliases` from [server.py](server.py) after transform migration is validated.
- **SEC-001**: Retain existing write safeguards controlled by `MCP_ALLOW_WRITE` and `MCP_CONFIRM_WRITE`; transform migration must not bypass guard checks in tool bodies.
- **SEC-002**: Retain existing instance-2 configuration failure behavior when `DATABASE_URL_INSTANCE_2` is absent and a client requests instance-2 tools.
- **ARC-001**: Implement transform pipeline using FastMCP transform APIs (`Namespace`, `ToolTransform`, or custom `Transform`) available in installed FastMCP version.
- **CON-001**: No breaking changes to external docker image invocation or existing environment variable names.
- **CON-002**: Complete migration in repository code only; no external service dependency changes.
- **GUD-001**: Use provider-level transforms for instance-specific naming and server-level transforms only when globally required.
- **GUD-002**: Keep deterministic transform order and document order rationale in code comments.
- **PAT-001**: Prefer declarative component transformation over generated wrapper functions.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Introduce transform-based architecture for dual-instance naming without removing legacy path.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | In [server.py](server.py), identify and isolate current alias path: `_register_dual_instance_tool_aliases`, `_run_in_instance_sync`, `_run_in_instance_async`, `_PoolRouter`, and `_ACTIVE_DB_INSTANCE` usage map; record exact symbol dependencies in comments near migration block. |  |  |
| TASK-002 | Add FastMCP transform imports in [server.py](server.py) and create `InstanceToolPrefixTransform` custom transform class implementing `list_tools` and `get_tool` deterministic name mapping (`db_pg96_*` <-> `db_01_pg96_*` or `db_02_pg96_*`). |  |  |
| TASK-003 | Introduce provider assembly function `build_instance_provider(instance_id: str)` in [server.py](server.py) that mounts the same base tool provider twice with instance-aware context routing and attaches instance-specific transform configuration. |  |  |
| TASK-004 | Ensure transform `get_tool` reverse mapping routes incoming `db_01_pg96_*` to canonical `db_pg96_*` for instance `01` and `db_02_pg96_*` to canonical `db_pg96_*` for instance `02`, then executes tool within corresponding instance context. |  |  |
| TASK-005 | Keep temporary compatibility toggle `MCP_USE_LEGACY_ALIAS_WRAPPERS` (default `true`) in [server.py](server.py) to allow side-by-side verification of legacy and transform modes. |  |  |

### Implementation Phase 2

- GOAL-002: Validate parity and remove legacy alias wrappers after transform path passes automated tests.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-006 | Add parity tests in [tests/test_tools_pg96.py](tests/test_tools_pg96.py) verifying tool inventory includes `db_pg96_*`, `db_01_pg96_*`, and `db_02_pg96_*` for representative tools under transform mode. |  |  |
| TASK-007 | Add routing behavior tests in [tests/functional_test.py](tests/functional_test.py) asserting instance-specific calls hit the correct pool and preserve existing error semantics when `DATABASE_URL_INSTANCE_2` is unset. |  |  |
| TASK-008 | Remove `_register_dual_instance_tool_aliases` and legacy wrapper code paths from [server.py](server.py) once TASK-006 and TASK-007 pass. |  |  |
| TASK-009 | Update dual-instance documentation in [README.md](README.md) to describe transform-based routing architecture and remove wrapper-specific implementation notes. |  |  |
| TASK-010 | Run validation suite `python -m pytest -q tests/functional_test.py tests/test_tools_pg96.py` and `python -m py_compile server.py`; record outputs in [plan/IMPLEMENTATION_SUMMARY.md](plan/IMPLEMENTATION_SUMMARY.md). |  |  |

### Implementation Phase 3

- GOAL-003: Operationalize transform migration in deployment artifacts and finalize rollout readiness.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-011 | Update deployment guidance in [DEPLOYMENT.md](DEPLOYMENT.md) with migration toggle behavior and final target state where legacy wrapper mode is disabled by default. |  |  |
| TASK-012 | Add smoke-check script updates in [scripts/verify_skill_install.ps1](scripts/verify_skill_install.ps1) or new verification script to confirm discovery of prefixed/unprefixed tools from running server endpoint. |  |  |
| TASK-013 | Set `MCP_USE_LEGACY_ALIAS_WRAPPERS=false` as default after successful staging verification and document rollback instruction (`true`) in [README.md](README.md). |  |  |
| TASK-014 | Tag migration completion in [plan/IMPLEMENTATION_SUMMARY.md](plan/IMPLEMENTATION_SUMMARY.md) with pass/fail matrix for inventory parity, execution parity, and error parity. |  |  |

## 3. Alternatives

- **ALT-001**: Keep manual wrapper generation in `_register_dual_instance_tool_aliases`; rejected due to maintenance complexity, static-analysis friction, and duplicated runtime dispatch logic.
- **ALT-002**: Duplicate every tool function into explicit `db_01_pg96_*` and `db_02_pg96_*` definitions; rejected due to high code duplication and increased risk of behavioral drift.
- **ALT-003**: Use only namespace prefix transform and remove unprefixed `db_pg96_*`; rejected because it breaks existing clients depending on canonical unprefixed tool names.

## 4. Dependencies

- **DEP-001**: FastMCP transform APIs must be present in installed package version (`fastmcp.server.transforms` and related types).
- **DEP-002**: Existing connection routing primitives in [server.py](server.py) (`_ACTIVE_DB_INSTANCE`, `_resolve_pool_for_instance`) remain available until transform routing parity is proven.
- **DEP-003**: Existing test harness and fixtures in [tests/conftest.py](tests/conftest.py) remain compatible with transform mode configuration.

## 5. Files

- **FILE-001**: [server.py](server.py) - Introduce transform classes/provider setup, remove legacy alias wrappers after parity.
- **FILE-002**: [tests/test_tools_pg96.py](tests/test_tools_pg96.py) - Add tool inventory parity tests for prefixed/unprefixed names.
- **FILE-003**: [tests/functional_test.py](tests/functional_test.py) - Add instance routing parity and missing-instance error-path tests.
- **FILE-004**: [README.md](README.md) - Update architecture notes and migration/rollback configuration.
- **FILE-005**: [DEPLOYMENT.md](DEPLOYMENT.md) - Update rollout guidance and operational defaults.
- **FILE-006**: [plan/IMPLEMENTATION_SUMMARY.md](plan/IMPLEMENTATION_SUMMARY.md) - Record execution evidence and migration status.

## 6. Testing

- **TEST-001**: Static inventory test verifies transformed tool list contains `db_pg96_ping`, `db_01_pg96_ping`, and `db_02_pg96_ping` under transform mode.
- **TEST-002**: Functional routing test verifies `db_01_pg96_server_info` and `db_02_pg96_server_info` route through expected instance context and pool resolver path.
- **TEST-003**: Misconfiguration test verifies calling `db_02_pg96_*` without `DATABASE_URL_INSTANCE_2` raises the expected runtime configuration error.
- **TEST-004**: Regression suite `python -m pytest -q tests/functional_test.py tests/test_tools_pg96.py` passes with zero new failures.
- **TEST-005**: Compile check `python -m py_compile server.py` passes after wrapper removal.

## 7. Risks & Assumptions

- **RISK-001**: Transform reverse mapping implementation error could make tools undiscoverable or uncallable by prefixed name.
- **RISK-002**: FastMCP transform ordering mismatch could create name collisions between prefixed and unprefixed tools.
- **RISK-003**: Async and sync execution parity could regress if `get_tool` wraps callables without preserving metadata.
- **ASSUMPTION-001**: FastMCP version in this repository supports transform hooks documented at gofastmcp.com.
- **ASSUMPTION-002**: Existing clients require both prefixed and unprefixed names during migration window.
- **ASSUMPTION-003**: Current pool router and contextvar strategy remains valid as execution substrate after naming migration.

## 8. Related Specifications / Further Reading

- [FastMCP Transforms Overview](https://gofastmcp.com/servers/transforms/transforms)
- [FastMCP Namespace Transform](https://gofastmcp.com/servers/transforms/namespace)
- [FastMCP Tool Transformation](https://gofastmcp.com/servers/transforms/tool-transformation)
- [README.md](README.md)
- [plan/IMPLEMENTATION_SUMMARY.md](plan/IMPLEMENTATION_SUMMARY.md)