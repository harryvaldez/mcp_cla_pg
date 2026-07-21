---
goal: Add db_n_pg96_missing_fk tool for detecting tables with missing foreign keys
version: 1.0
date_created: 2026-07-10
last_updated: 2026-07-10
owner: harryvaldez
status: Planned
tags: [feature, tool, data-model, foreign-keys, sql-analysis]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

Add a new MCP tool `db_<n>_pg96_missing_fk` that detects tables and columns where foreign key constraints are likely missing. The tool analyzes column naming conventions (e.g., `*_id` suffix columns that reference other tables) and compares against declared `pg_constraint` entries to identify probable FK omissions. This is a new independent tool in the **Data Model** family (not a sub-tool of `analyze_data_model`, but registered alongside it).

## 1. Requirements & Constraints

- **REQ-001**: Tool name: `db_<n>_pg96_missing_fk`, dual-instance mirrored (`db_1_pg96_missing_fk`, `db_2_pg96_missing_fk`).
- **REQ-002**: Accepts `database_name: str` (required) and `schema_name: str` (required) parameters.
- **REQ-003**: Detects columns ending with `_id` that are NOT backed by a foreign key constraint.
- **REQ-004**: Output must include: `table_name`, `column_name`, `referenced_table` (inferred from column name), and `suggestion` (recommended FK DDL).
- **REQ-005**: SQL logic: query `information_schema.columns` for columns matching `*_id` pattern, then join against `pg_constraint` to exclude columns that already have FK declarations. Infer the referenced table from the column name by stripping the `_id` suffix and pluralizing.
- **REQ-006**: Follow the inline `@mcp.tool()` registration pattern (like `_analyze_constraints_and_fks`), NOT the helper-function pattern.
- **REQ-007**: Read-only (`readOnlyHint=True`), write-guard enforced, input validated, rate limited, audit logged.
- **REQ-008**: Must pass `ruff check .` and `pytest -q` with all existing tests still passing.
- **CON-001**: No breaking changes to existing tools or output schemas.
- **CON-002**: Tool must be enabled by default in `config/runtime-policy.yaml`.
- **PAT-001**: Inline `@mcp.tool()` registration pattern matching `_analyze_constraints_and_fks` in `src/tools/pg_tools.py`.
- **PAT-002**: SQL uses parameterized queries (`$1`, `$2`) -- never f-string concatenation.
- **PAT-003**: Standard lifecycle: `request_id` -> `started` -> `decision`/`error_code`/`row_count`/`_auth_ctx` -> validation -> try/except/finally -> audit log.

## 2. Implementation Steps

### Phase 1 -- Add missing_fk inline tool in pg_tools.py

- GOAL-001: Register `db_<n>_pg96_missing_fk` as an inline tool in the dual-instance registration loop.

| Task | Description | Done |
|------|-------------|------|
| TASK-001 | In `src/tools/pg_tools.py`, inside the instance loop, after the `_analyze_constraints_and_fks` block, add a new `is_tool_enabled` guard for `"missing_fk"`. |:white_large_square: |
| TASK-002 | Add `@mcp.tool()` decorator with `name=f"db_{instance_number}_pg96_missing_fk"`, `readOnlyHint=True`, tags `{"read-only","performance",f"instance-{instance_number}"}`, timeout `30.0`. |:white_large_square: |
| TASK-003 | Implement `async def _missing_fk(database_name, schema_name, ...)` with full Google-style docstring. |:white_large_square: |
| TASK-004 | Write SQL query to detect `*_id` columns without FK constraints, with inferred referenced table. |:white_large_square: |
| TASK-005 | Build DDL suggestion for each candidate. |:white_large_square: |
| TASK-006 | Return result in standard Performance Analysis Schema format. |:white_large_square: |
| TASK-007 | Append tool name to `registered` list. |:white_large_square: |

### Phase 2 -- Enable tool in runtime-policy.yaml

- GOAL-002: Enable the new tool by default.

| Task | Description | Done |
|------|-------------|------|
| TASK-008 | Add `missing_fk: true` to `tool_enable_flags` section in `config/runtime-policy.yaml` (between `list_views` and `list_objects_by_type`). |:white_large_square: |

### Phase 3 -- Tests

- GOAL-003: Add test coverage.

| Task | Description | Done |
|------|-------------|------|
| TASK-009 | Add `test_missing_fk_tool_name` in `tests/test_tool_naming.py`. |:white_large_square: |
| TASK-010 | Verify existing tests still pass. |:white_large_square: |

### Phase 4 -- Documentation

- GOAL-004: Update all affected documentation.

| Task | Description | Done |
|------|-------------|------|
| TASK-011 | Add `db_<n>_pg96_missing_fk` entry to `docs/mcp-tool-catalog.md`. |:white_large_square: |
| TASK-012 | Add entry to the Tool Type Annotations table in catalog. |:white_large_square: |
| TASK-013 | Add `db_n_pg96_missing_fk` row to Data Model Sub-Tools in `README.md`. |:white_large_square: |

### Phase 5 -- Build, Push, Deploy

- GOAL-005: Build, push, recreate container.

| Task | Description | Done |
|------|-------------|------|
| TASK-014 | `ruff check .` + `pytest -q` -- zero errors, all pass. |:white_large_square: |
| TASK-015 | `python -c "from src.server import app"` -- import OK. |:white_large_square: |
| TASK-016 | `docker build --no-cache -t harryvaldez/mcp-edb96-server:latest -f docker/Dockerfile .` |:white_large_square: |
| TASK-017 | `docker push harryvaldez/mcp-edb96-server:latest` |:white_large_square: |
| TASK-018 | `docker compose -f docker/docker-compose.runtime.yml down && docker compose -f docker/docker-compose.runtime.yml up -d` |:white_large_square: |
| TASK-019 | Verify health: `curl -fsS http://localhost:8086/health` -> 200 OK. |:white_large_square: |

### Phase 6 -- Post-Deploy Verification

- GOAL-006: Confirm tool registered.

| Task | Description | Done |
|------|-------------|------|
| TASK-020 | Query MCP `tools/list` -- verify both instances registered. |:white_large_square: |

## 3. Alternatives

- **ALT-001**: Implement as sub-tool called by `analyze_data_model`. Rejected -- standalone tool is cleaner and independently callable.
- **ALT-002**: Use heuristic ML model for FK detection. Rejected -- over-engineering; column naming convention + pg_constraint check is sufficient.
- **ALT-003**: Add to `table_analysis.py` as reusable function. Rejected -- schema-wide SQL makes inline registration more appropriate.

## 4. Dependencies

- **DEP-001**: No new Python packages.
- **DEP-002**: Existing `validate_database_name()`, `validate_schema_name()`.
- **DEP-003**: Existing `is_tool_enabled()`.

## 5. Files

| File | Change |
|------|--------|
| `src/tools/pg_tools.py` | Add inline `_missing_fk` tool. |
| `config/runtime-policy.yaml` | Add `missing_fk: true`. |
| `docs/mcp-tool-catalog.md` | Add tool entry. |
| `README.md` | Add to Data Model Sub-Tools table. |
| `tests/test_tool_naming.py` | Add naming test. |

## 6. Testing

- **TEST-001**: `test_missing_fk_tool_name` -- naming convention.
- **TEST-002**: Full suite re-run -- 240+ tests must pass.

## 7. Risks & Assumptions

- **RISK-001**: Column naming may produce false positives. Output is a candidate list.
- **RISK-002**: Inferred referenced table may not exist. Include `referenced_table_exists` field.
- **ASSUMPTION-001**: EDBAS 9.6 `information_schema.columns` is available.
- **ASSUMPTION-002**: Standard `*_id` naming conventions imply FK relationships.

## 8. Related Specifications / Further Reading

- [analyze_constraints_and_fks catalog entry](docs/mcp-tool-catalog.md)
- [AGENTS.md](AGENTS.md)
- [FastMCP 3 Documentation](https://gofastmcp.com/)
