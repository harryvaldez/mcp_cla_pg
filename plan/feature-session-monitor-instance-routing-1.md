---
goal: Add deterministic instance routing and instance identity metadata to session monitor routes
version: 1.0
date_created: 2026-04-06
last_updated: 2026-04-06
owner: Platform DBA Tooling
status: Planned
tags: [feature, routing, monitoring, dual-instance, api, ui]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

This plan defines deterministic support for selecting database instance `01` or `02` in the session monitor endpoints, returning instance identity fields in the API payload, and rendering the active instance badge in the monitor header.

## 1. Requirements & Constraints

- **REQ-001**: Support query parameter `instance` on `GET /sessions-monitor` with allowed values `01` and `02`.
- **REQ-002**: Support query parameter `instance` on `GET /api/sessions` with allowed values `01` and `02`.
- **REQ-003**: When `instance` is omitted, both routes must default to instance `01`.
- **REQ-004**: `GET /api/sessions` response must include `instance_id`, `host`, and `database` fields in addition to existing counters.
- **REQ-005**: The monitor page must show a visible active instance badge in the page header using the resolved instance id.
- **REQ-006**: The monitor frontend data fetch must preserve the selected `instance` query parameter when calling `/api/sessions`.
- **REQ-007**: Existing counter fields (`active`, `idle`, `idle_in_transaction`, `total`, `timestamp`) must remain backward compatible.
- **SEC-001**: Reject unsupported `instance` values with HTTP `400` and a deterministic JSON error payload.
- **SEC-002**: Do not expose credentials in API payload; expose only non-secret metadata (`instance_id`, `host`, `database`).
- **CON-001**: Reuse existing helpers `_normalize_instance_id`, `_resolve_instance_metadata`, and `_run_in_instance_sync` for consistency.
- **CON-002**: Do not introduce new environment variables for this feature.
- **GUD-001**: Keep all route changes in `server.py` and avoid broad refactors.
- **PAT-001**: Use per-request explicit instance routing; no global mutable state changes beyond existing context variable usage.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Implement deterministic instance parsing and routing for monitor routes.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Update `sessions_monitor(_request: Request)` in `server.py` to parse `instance` from query params, normalize via `_normalize_instance_id`, and on invalid value return `JSONResponse(status_code=400)` with payload `{ "ok": false, "error": "Unsupported database instance id", "instance": "<input>" }`. |  |  |
| TASK-002 | Update `api_sessions(_request: Request)` in `server.py` to parse and normalize `instance` from query params with same validation/error behavior as `TASK-001`. |  |  |
| TASK-003 | In `api_sessions`, execute the existing `pg_stat_activity` query inside `_run_in_instance_sync(normalized_instance, _query_fn)` where `_query_fn` contains the current DB query logic to ensure pool selection is deterministic by instance. |  |  |
| TASK-004 | In `api_sessions`, append metadata from `_resolve_instance_metadata(normalized_instance)` and return fields: `instance_id`, `host`, `database` alongside existing counters. |  |  |

### Implementation Phase 2

- GOAL-002: Render active instance identity in UI and keep data polling aligned to selected instance.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | Modify `SESSION_MONITOR_HTML` in `server.py` to include an instance badge container in the header with deterministic id attributes (example: `id="instance-badge"`). |  |  |
| TASK-006 | Modify client-side JS in `SESSION_MONITOR_HTML` to read `instance` from `window.location.search`, default to `01`, and call `/api/sessions?instance=<resolved>` for every refresh cycle. |  |  |
| TASK-007 | Update UI render logic to set badge content from API payload (`instance_id`, `host`, `database`) and keep badge synchronized across refreshes. |  |  |
| TASK-008 | Ensure invalid instance route behavior is visible and deterministic in UI (render error state in page text if `/api/sessions` returns non-2xx). |  |  |

### Implementation Phase 3

- GOAL-003: Validate behavior with focused tests and documentation updates.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-009 | Add route tests in `tests/test_tools_pg96.py` (or existing route test module) for `/api/sessions?instance=01` and `/api/sessions?instance=02`, asserting `200` plus presence of `instance_id`, `host`, and `database`. |  |  |
| TASK-010 | Add negative test for `/api/sessions?instance=03` asserting `400` and deterministic error payload shape. |  |  |
| TASK-011 | Add test verifying `sessions-monitor?instance=02` page includes instance-aware fetch target or rendered badge marker for instance routing. |  |  |
| TASK-012 | Update monitor docs in `README.md` section "Real-time Session Monitor" to document query parameter usage and sample response including new instance metadata fields. |  |  |

## 3. Alternatives

- **ALT-001**: Add separate routes (`/api/sessions/01`, `/api/sessions/02`) instead of query params. Rejected because user requirement explicitly requests `?instance=01|02` and query params minimize route proliferation.
- **ALT-002**: Use `_ACTIVE_DB_INSTANCE` implicit default only, without query param parsing. Rejected because it does not provide deterministic user-controlled routing for monitor URLs.
- **ALT-003**: Derive active instance from browser session/local storage only. Rejected because server-side API must remain directly callable and deterministic via URL alone.

## 4. Dependencies

- **DEP-001**: Existing helper `_normalize_instance_id(instance: str | None) -> str` in `server.py`.
- **DEP-002**: Existing helper `_resolve_instance_metadata(instance: str | None) -> dict[str, Any]` in `server.py`.
- **DEP-003**: Existing helper `_run_in_instance_sync(instance_id: str, target: Any, *args: Any, **kwargs: Any) -> Any` in `server.py`.
- **DEP-004**: Existing dual-pool infrastructure (`pool_instance_01`, `pool_instance_02`, `_PoolRouter`) in `server.py`.

## 5. Files

- **FILE-001**: `server.py` - update routes `sessions_monitor` and `api_sessions`, update `SESSION_MONITOR_HTML` header and fetch logic.
- **FILE-002**: `tests/test_tools_pg96.py` - add route tests for valid/invalid instance query handling and payload metadata.
- **FILE-003**: `README.md` - document monitor instance query parameter and response metadata fields.

## 6. Testing

- **TEST-001**: `GET /api/sessions` returns `200` and defaults to `instance_id="01"` when `instance` is omitted.
- **TEST-002**: `GET /api/sessions?instance=01` returns `200` and payload contains `instance_id="01"`, non-empty `host`, and non-empty `database`.
- **TEST-003**: `GET /api/sessions?instance=02` returns `200` and payload contains `instance_id="02"`, non-empty `host`, and non-empty `database`.
- **TEST-004**: `GET /api/sessions?instance=03` returns `400` with deterministic payload keys `ok`, `error`, and `instance`.
- **TEST-005**: `GET /sessions-monitor?instance=02` returns HTML including instance badge element and JS fetch path containing `instance` parameter propagation.
- **TEST-006**: Existing monitor payload fields remain present and numeric: `active`, `idle`, `idle_in_transaction`, `total`, `timestamp`.

## 7. Risks & Assumptions

- **RISK-001**: Route test harness may not currently cover custom HTTP routes and may require lightweight test client setup.
- **RISK-002**: Instance 2 may be unconfigured in some environments, causing runtime error during `instance=02` requests.
- **RISK-003**: Frontend polling error handling may hide API validation errors if not rendered explicitly.
- **ASSUMPTION-001**: `DATABASE_URL_INSTANCE_2` is configured in target environments where `instance=02` is used.
- **ASSUMPTION-002**: `_resolve_instance_metadata("02")` returns non-sensitive, valid host/database values.
- **ASSUMPTION-003**: Existing `SESSION_MONITOR_HTML` string can be updated without introducing template rendering dependencies.

## 8. Related Specifications / Further Reading

- [README.md](../README.md)
- [server.py](../server.py)
- [tests/test_tools_pg96.py](../tests/test_tools_pg96.py)
- [refactor-fastmcp-transforms-alias-routing-1.md](refactor-fastmcp-transforms-alias-routing-1.md)