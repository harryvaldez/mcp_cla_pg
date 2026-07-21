---
goal: Enhance check_db_parameters with MB/GB value display, fix pg_settings unit-multiplier analysis, and add db_n_pg96_check_server tool for OS-level resource retrieval
version: 2.0
date_created: 2026-07-06
last_updated: 2026-07-07
owner: harryvaldez
status: Completed
tags: [feature, bugfix, tool, check_db_parameters, check_server, settings, security, diagnostics, os-metrics]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-planned-blue)

Enhance the `db_n_pg96_check_db_parameters` tool so that numeric `pg_settings` values (memory sizes, time intervals) are converted to human-readable MB/GB units in the output, making findings immediately interpretable. Additionally, add a new MCP tool `db_n_pg96_check_server` that retrieves CPU, memory, and disk utilization for the `/data` filesystem from the EDBAS host via Postgres helper functions. **Phase 7 (bugfix)**: Fix a critical analysis bug where `pg_settings` values are compared against best practices without accounting for the `unit` column multiplier (e.g., `shared_buffers` with `setting="1048576"` and `unit="8kB"` is 8GB, but is incorrectly analyzed as ~1MB).

## 1. Requirements & Constraints

- **REQ-001**: `db_n_pg96_check_db_parameters` output findings must include a `current_value_display` field with converted human-readable values (MB/GB for memory, ms/s/min for time) alongside the raw `current_value`.
- **REQ-002**: Conversion logic must handle all known `pg_settings` unit suffixes (`B`, `kB`, `MB`, `GB`, `TB`, `ms`, `s`, `min`, `h`, `d`) and fall back to raw string for non-numeric/non-temporal settings.
- **REQ-003**: New tool: `db_n_pg96_check_server` — retrieves CPU count/load, total/used/free memory, and disk utilization for `/data` filesystem from the EDBAS host.
- **REQ-004**: `check_server` must use EDBAS 9.6 SQL functions (`pg_read_file`-based OS metrics or available system views) to gather host-level metrics without external agents.
- **REQ-005**: `check_server` logic must be implemented as a reusable async function in `src/tools/settings_security.py` (importable by other tools), with MCP tool registration in `src/tools/pg_tools.py`.
- **REQ-006**: `check_server` and its sub-functions must accept `conn: asyncpg.Connection` as first parameter (reusable module pattern from `table_analysis.py`, `hypopg_tools.py`).
- **REQ-007**: Follow dual-instance closure-binding registration pattern — registered as `db_1_pg96_check_server` and `db_2_pg96_check_server`.
- **REQ-008**: SELECT-only, write guard enforced, input validated, rate limited, audit logged.
- **SEC-001**: Read-only — `readOnlyHint=True` on all tools.
- **SEC-002**: Never expose connection strings, passwords, or host details in output.
- **SEC-003**: Server tool must not execute shell commands — only use Postgres SQL functions and system catalogs.
- **SEC-004**: Validate `filesystem_path` input via existing input validation patterns; default to `/data`.
- **BUG-001**: `check_db_parameters` must compute the **actual** parameter value by multiplying the `setting` column by the `unit` column multiplier before passing to the lambda check. Raw `setting` values from `pg_settings` are in the unit's base blocks (e.g., 8kB pages for `shared_buffers`), not in bytes/kB/MB.
- **PAT-001**: Reusable analysis functions in `src/tools/settings_security.py` (mirroring `table_analysis.py` pattern).
- **PAT-002**: Tool registration helpers mirror `_register_sett_sec_sub_tool` pattern for dual-instance symmetry.
- **CON-001**: All existing tests must continue to pass.
- **CON-002**: No breaking changes to `check_db_parameters` output schema — only additive (`current_value_display` field).

## 2. Implementation Steps

### Implementation Phase 1 — Add Value Display Conversion

- GOAL-001: Add a `_format_pg_value()` helper that converts raw pg_settings values to human-readable display strings, and integrate it into `check_db_parameters()`.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Add `_format_pg_value(setting: str, unit: str | None) -> str` to `src/tools/settings_security.py`. Uses the existing `_parse_mb()`, `_parse_seconds()`, `_parse_ms()` parsers internally. Converts to the most appropriate unit: for byte values, pick GB if >= 1024 MB else MB; for time values, pick min if >= 60s, else s, else ms. Returns raw string for unparseable values. | ✅ | 2026-07-06 |
| TASK-002 | Update the `findings` dict construction in `check_db_parameters()` to add a `"current_value_display"` key. Call `_format_pg_value(current_value, unit)` where `unit` comes from the pg_settings row. | ✅ | 2026-07-06 |
| TASK-003 | Update parameter rules that check non-numeric values — for these, `current_value_display` falls back to raw setting value naturally. | ✅ | 2026-07-06 |

### Implementation Phase 2 — Implement check_server Reusable Functions

- GOAL-002: Add server resource retrieval functions to `src/tools/settings_security.py`.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Add `_get_cpu_info(conn) -> dict` — queries `max_worker_processes` from `pg_settings`, attempts `/proc/cpuinfo` via `pg_read_file()`. | ✅ | 2026-07-06 |
| TASK-005 | Add `_get_memory_info(conn) -> dict` — reads `/proc/meminfo` via `pg_read_file()`; falls back to `shared_buffers` + `effective_cache_size` indicators. | ✅ | 2026-07-06 |
| TASK-006 | Add `_get_disk_info(conn, filesystem_path) -> dict` — reads `/proc/mounts`, `/proc/self/mountinfo`, uses `pg_stat_file()`. | ✅ | 2026-07-06 |
| TASK-007 | Add `check_server(conn, filesystem_path="/data") -> dict` orchestrator combining cpu, memory, disk. | ✅ | 2026-07-06 |

### Implementation Phase 3 — Register db_n_pg96_check_server MCP Tool

- GOAL-003: Wire `check_server` into the dual-instance MCP tool registration loop in `src/tools/pg_tools.py`.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-008 | Import `check_server` from `src.tools.settings_security` in `src/tools/pg_tools.py`. | ✅ | 2026-07-06 |
| TASK-009 | Add `_register_server_tool` helper and register `check_server` in the instance loop. | ✅ | 2026-07-06 |
| TASK-010 | Add `check_server: true` to `tool_enable_flags` in `config/runtime-policy.yaml`. | ✅ | 2026-07-06 |

### Implementation Phase 4 — Integrate check_server into Existing Tools

- GOAL-004: Allow `check_db_parameters` and `analyze_sett_sec` to optionally call `check_server` for correlation.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-011 | Update `check_db_parameters(conn, database_name, check_server_data=None)` — appends `"server_context"` when data provided. | ✅ | 2026-07-06 |
| TASK-012 | Update `analyze_sett_sec` orchestrator — calls `check_server` first, passes to `check_db_parameters`, includes `"Server Context"` in output. | ✅ | 2026-07-06 |

### Implementation Phase 5 — Tests

- GOAL-005: Add automated test coverage.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-013 | Add 13 `_format_pg_value()` tests in `tests/test_settings_security.py`. | ✅ | 2026-07-06 |
| TASK-014 | Add 4 `check_server()` tests with mocked connections. | ✅ | 2026-07-06 |
| TASK-015 | Add 3 `current_value_display` tests in `check_db_parameters` tests. | ✅ | 2026-07-06 |
| TASK-016 | Add `check_server` tool naming test in `tests/test_tool_naming.py`. | ✅ | 2026-07-06 |
| TASK-017 | Tool flag test covered by existing `is_tool_enabled` test pattern. | ✅ | 2026-07-06 |

### Implementation Phase 6 — Documentation

- GOAL-006: Update all affected documentation.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-018 | Update `docs/mcp-tool-catalog.md` — add `check_server` contract, update `check_db_parameters` output schema. | ✅ | 2026-07-06 |
| TASK-019 | Update `README.md` — add `check_server` to Settings & Security tool table. | ✅ | 2026-07-06 |
| TASK-020 | Run `ruff check .` and `pytest -q` — 0 lint errors, 229 tests passing. | ✅ | 2026-07-06 |

### Implementation Phase 7 — Fix pg_settings Unit Analysis Bug

- GOAL-007: Fix `check_db_parameters()` so that raw `pg_settings` values are multiplied by the `unit` column multiplier BEFORE being compared against best-practice lambda checks.

**Bug Analysis:**

`pg_settings` stores parameter values in the unit indicated by the `unit` column. The `setting` column contains a number of *blocks* of that unit, NOT the actual value in bytes/seconds.

Example — `shared_buffers` on a real EDBAS 9.6 instance:
```
SELECT name, setting, unit FROM pg_settings WHERE name = 'shared_buffers';
         name         | setting  | unit
----------------------+----------+------
 shared_buffers       | 1048576  | 8kB
```
`SHOW shared_buffers;` → `8GB`

The actual value: `1048576 × 8 kB = 8,388,608 kB = 8 GB` ✓

Current broken analysis:
1. `current_value = str(row["setting"])` → `"1048576"`  ← unit column IGNORED
2. `rule["check"]("1048576")` calls `_parse_mb("1048576")`
3. `_parse_mb("1048576")`: no suffix match → `float("1048576") / (1024*1024)` ≈ **1.0 MB** ← WRONG
4. `1.0 >= 128.0` → `False` → **false-positive CRITICAL finding** ← BUG

This affects ALL parameters where the `unit` column has a multiplier prefix — including `shared_buffers` (8kB), `effective_cache_size` (8kB), `wal_buffers` (8kB), and any EDBAS-specific units.

**Fix Strategy:** Add `_resolve_setting()` that computes `setting × unit_multiplier` into a string with a standard suffix the existing parsers understand. For `shared_buffers`: `"1048576"` × `"8kB"` → `"8388608kB"` → `_parse_mb("8388608kB")` → `8192 MB` → passes `>= 128` ✓.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-BUG-001 | Add `_resolve_setting(setting: str, unit: str | None) -> str` to `src/tools/settings_security.py`. Parses the `unit` column for a multiplier prefix (e.g., `"8"` from `"8kB"`) and a base unit (`"kB"`). Multiplies the raw `setting` by the multiplier, then formats the result as a string WITH the base unit suffix (e.g., `"8388608kB"`) so the existing `_parse_mb()`, `_parse_seconds()`, `_parse_ms()` parsers can correctly interpret it. For units without a multiplier prefix, returns the setting as-is. For `unit=None`, returns the setting as-is. | ✅ | 2026-07-07 |
| TASK-BUG-002 | Update the `check_db_parameters()` loop (the `for rule in _PARAMETER_RULES:` block) to call `_resolve_setting(current_value, unit)` to compute `resolved_value` before passing to `rule["check"](resolved_value)`. The `unit` is already available from `row["unit"]`. The `current_value` used in the `finding` dict should remain the raw setting (for traceability). | ✅ | 2026-07-07 |
| TASK-BUG-003 | Update the test helper `_make_pg_settings()` in `tests/test_settings_security.py` to include realistic `unit` values for each parameter (e.g., `shared_buffers` → `"8kB"`, `work_mem` → `"kB"`, `effective_cache_size` → `"8kB"`, `maintenance_work_mem` → `"kB"`, `wal_buffers` → `"8kB"`, `max_wal_size` → `"MB"`, `checkpoint_timeout` → `"s"`, `autovacuum_naptime` → `"s"`, `autovacuum_vacuum_cost_delay` → `"ms"`, `tcp_keepalives_idle` → `"s"`, `log_min_duration_statement` → `"ms"`, `log_autovacuum_min_duration` → `"ms"`). Non-unit parameters (ssl, autovacuum, etc.) should remain with `unit=""` or `unit=None`. | ✅ | 2026-07-07 |
| TASK-BUG-004 | Add a new test `test_shared_buffers_8kb_unit_not_false_positive` in `TestCheckDbParameters` — `setting="1048576"`, `unit="8kB"` → actual = 8GB, should pass the `>= 128MB` check (no finding for `shared_buffers`). | ✅ | 2026-07-07 |
| TASK-BUG-005 | Add a new test `test_shared_buffers_8kb_unit_below_threshold` — `setting="16384"`, `unit="8kB"` → actual = 128MB, should pass (boundary). Test with `setting="16383"` → actual = 127.99MB, should FAIL and produce a finding. | ✅ | 2026-07-07 |
| TASK-BUG-006 | Add a new test `test_checkpoint_timeout_unit_parsed` — `setting="5"`, `unit="s"` → actual = 5s, check lambda expects seconds 300-900, should FAIL. `setting="300"`, `unit="s"` → should PASS. | ✅ | 2026-07-07 |
| TASK-BUG-007 | Run `ruff check .` and `pytest -q` — 0 lint errors, 240 tests passing. | ✅ | 2026-07-07 |

## 3. Alternatives

- **ALT-001**: Use a separate shell-script sidecar container for OS metrics. Rejected — adds deployment complexity; Postgres `pg_read_file()` is sufficient for EDBAS 9.6 when the user has necessary privileges.
- **ALT-002**: Only add display conversion or only add check_server. Rejected — both features are requested together for a coherent diagnostics story.
- **ALT-003**: Use an external Python library for unit formatting. Rejected — the existing `_parse_mb()` / `_parse_seconds()` / `_parse_ms()` parsers already handle the reverse direction; the new formatter is a straightforward inverse.

## 4. Dependencies

- **DEP-001**: Existing `_parse_mb()`, `_parse_seconds()`, `_parse_ms()` helpers in `src/tools/settings_security.py`.
- **DEP-002**: Existing `_register_sett_sec_sub_tool` registration pattern in `src/tools/pg_tools.py`.
- **DEP-003**: Existing `is_tool_enabled()` in `src/tools/tool_flags.py` for the new `check_server` flag.

## 5. Files

- **FILE-001**: `src/tools/settings_security.py` — add `_format_pg_value()`, `_get_cpu_info()`, `_get_memory_info()`, `_get_disk_info()`, `check_server()`, update `check_db_parameters()`.
- **FILE-002**: `src/tools/pg_tools.py` — add `_register_server_tool` helper, import `check_server`, register it in the instance loop, wire `check_server` into `analyze_sett_sec`.
- **FILE-003**: `config/runtime-policy.yaml` — add `check_server: true` to `tool_enable_flags`.
- **FILE-004**: `docs/mcp-tool-catalog.md` — add `check_server` tool contract, update `check_db_parameters` output schema.
- **FILE-005**: `README.md` — add `check_server` to tool table.
- **FILE-006**: `tests/test_settings_security.py` — new test file for `_format_pg_value()` and `check_server()`.
- **FILE-007**: `tests/test_tool_naming.py` — add `check_server` naming test.

## 6. Testing

- **TEST-001**: `test_format_pg_value_mb` — verifies `_format_pg_value("16384", "8kB")` → `"16 MB"` (since 16384*8kB = 128MB? Let me recalculate: 16384 * 8 = 131072 kB / 1024 = 128 MB). Actually pg_settings setting is already in the unit specified. So `_format_pg_value("16384", "8kB")` means 16384 * 8kB = 131072 kB = 128 MB. Wait, pg_settings stores the value in the unit given by the `unit` column. For `shared_buffers`, `setting="16384"` and `unit="8kB"`, so it's 16384 * 8kB = 131072 kB = 128 MB. So `_format_pg_value` should compute the actual byte value by multiplying.
- **TEST-002**: `test_format_pg_value_gb` — `_format_pg_value("4096", "MB")` → `"4.00 GB"`.
- **TEST-003**: `test_format_pg_value_seconds` — `_format_pg_value("300", "s")` → `"5 min"`.
- **TEST-004**: `test_format_pg_value_ms` — `_format_pg_value("5000", "ms")` → `"5 s"`.
- **TEST-005**: `test_format_pg_value_fallback` — `_format_pg_value("on", None)` → `"on"`.
- **TEST-006**: `test_check_db_parameters_display_field` — verifies each finding has `current_value_display`.
- **TEST-007**: `test_check_server_cpu` — mocked CPU data returns expected dict keys.
- **TEST-008**: `test_check_server_disk` — mocked disk data with `/data` path.
- **TEST-009**: `test_check_server_tool_name` — verifies `db_1_pg96_check_server` and `db_2_pg96_check_server` naming.

## 7. Risks & Assumptions

- **RISK-001**: `pg_read_file()` may be restricted for non-superusers in EDBAS 9.6, limiting OS-level data retrieval. The implementation must handle `PermissionError`/`InsufficientPrivilege` gracefully, returning `null` indicators with an explanatory `note` field rather than crashing.
- **RISK-002**: EDBAS 9.6 may not have `pg_stat_file()` available. The disk info function must fall back to alternative approaches or return partial data.
- **RISK-003**: The `unit` column in `pg_settings` uses non-standard values like `"8kB"` (not just `"kB"`). The `_format_pg_value()` function must correctly parse multiplier-prefixed unit strings.
- **RISK-004** (BUG — confirmed): `check_db_parameters` passes raw `pg_settings.setting` values directly to lambda checks without accounting for the `unit` column multiplier. This creates false-positive findings for all parameters using multiplier-prefixed units (e.g., `shared_buffers` with `unit="8kB"` where `setting="1048576"` → actual 8GB is incorrectly flagged as 1MB). Fixed in Phase 7 via `_resolve_setting()`.
- **RISK-005**: Changing the value passed to lambda checks may surface previously-hidden findings (parameters that were incorrectly parsing as passing may now correctly parse as failing). These are legitimate findings, not regressions. Tests capture expected behavior changes.

## 8. Related Specifications / Further Reading

- [FastMCP 3 Documentation](https://gofastmcp.com/)
- [EDBAS 9.6 pg_settings Documentation](https://www.enterprisedb.com/docs/)
- [PostgreSQL System Information Functions](https://www.postgresql.org/docs/9.6/functions-admin.html)
- [Existing implementation plan: feature-analyze-sett-sec-tool-1.md](plan/feature-analyze-sett-sec-tool-1.md)
