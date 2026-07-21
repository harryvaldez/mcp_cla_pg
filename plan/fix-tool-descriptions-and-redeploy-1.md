---
goal: Review and Add Accurate Comprehensive Docstrings to All MCP Tools, Force Rebuild Docker Image, Push to Docker Hub, and Recreate Container
version: 2.0
date_created: 2026-07-08
last_updated: 2026-07-08
owner: harryvaldez
status: Planned
tags: [fix, documentation, deploy, docker, tool-descriptions, review]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

Audit every MCP tool for missing or incomplete descriptions/docstrings. Add Google-style docstrings with  + @"" + @"Args: + @"" + @" sections for all 28 tool variants (14 unique tool families × 2 instances). Then force-rebuild the Docker image ( + @"" + @"harryvaldez/mcp-edb96-server:latest + @"" + @"), push to Docker Hub, tear down the running container, and recreate it from the latest pushed image.

## 1. Requirements & Constraints

- **REQ-001**: Every FastMCP  + @"" + @"@mcp.tool() + @"" + @" function must have a docstring.
- **REQ-002**: Every tool docstring must include an  + @"" + @"Args: + @"" + @" section with parameter descriptions in Google-style format.
- **REQ-003**: Docstring format must match the convention established by  + @"" + @"_ping + @"" + @",  + @"" + @"_get_slow_statements + @"" + @",  + @"" + @"_hypopg_create_virtual_indexes + @"" + @", and  + @"" + @"_hypopg_find_optimal_indexes + @"" + @".
- **REQ-004**: No functional or behavioral changes to any tool logic — description-only.
- **REQ-005**: Helper-registered tools must receive descriptions via a new  + @"" + @"description + @"" + @" parameter on helper functions, with  + @"" + @"_impl.__doc__ = description + @"" + @" set *before* the  + @"" + @"@mcp.tool() + @"" + @" decorator.
- **REQ-006**: Docker image force-rebuilt ( + @"" + @"--no-cache + @"" + @"), pushed as  + @"" + @"harryvaldez/mcp-edb96-server:latest + @"" + @", container  + @"" + @"mcp-edb96 + @"" + @" replaced.
- **REQ-007**: Redeployed container must pass health checks.
- **REQ-008**: All existing tests must pass.
- **CON-001**: No breaking changes to tool names, parameter contracts, or output schemas.
- **CON-002**: No new Python dependencies.
- **PAT-001**: Use Google-style docstrings: summary line, optional expanded description,  + @"" + @"Args: + @"" + @" section.

## 2. Docstring Audit Results

### 2.1 Complete (No Changes)

1.  + @"" + @"db_{n}_pg96_ping + @"" + @" ✅
2.  + @"" + @"db_{n}_pg96_get_slow_statements + @"" + @" ✅
3.  + @"" + @"db_{n}_pg96_hypopg_create_virtual_indexes + @"" + @" ✅
4.  + @"" + @"db_{n}_pg96_hypopg_find_optimal_indexes + @"" + @" ✅

### 2.2 Has Docstring But Missing Args (8 tools)

5.  + @"" + @"db_{n}_pg96_blocking_sessions + @"" + @"
6.  + @"" + @"db_{n}_pg96_analyze_data_model + @"" + @"
7.  + @"" + @"db_{n}_pg96_extract_schema_model + @"" + @"
8.  + @"" + @"db_{n}_pg96_analyze_constraints_and_fks + @"" + @"
9.  + @"" + @"db_{n}_pg96_analyze_normalization + @"" + @"
10.  + @"" + @"db_{n}_pg96_analyze_index_statistics + @"" + @"
11.  + @"" + @"db_{n}_pg96_analyze_3nf_and_decomposition + @"" + @"
12.  + @"" + @"db_{n}_pg96_hypopg_explain_with_virtual + @"" + @"

### 2.3 Missing Docstring Entirely (16 tools)

13.  + @"" + @"db_{n}_pg96_exec_query + @"" + @" (inline)
14.  + @"" + @"db_{n}_pg96_analyze_table + @"" + @" (inline)
15.  + @"" + @"db_{n}_pg96_check_table_bloat + @"" + @" (via _register_sub_tool)
16.  + @"" + @"db_{n}_pg96_check_table_wraparound + @"" + @" (via _register_sub_tool)
17.  + @"" + @"db_{n}_pg96_check_table_statistics + @"" + @" (via _register_sub_tool)
18.  + @"" + @"db_{n}_pg96_check_index_health + @"" + @" (via _register_sub_tool)
19.  + @"" + @"db_{n}_pg96_list_objects + @"" + @" (inline)
20.  + @"" + @"db_{n}_pg96_list_tables + @"" + @" (via _register_discovery_tool)
21.  + @"" + @"db_{n}_pg96_list_indexes + @"" + @" (via _register_discovery_tool)
22.  + @"" + @"db_{n}_pg96_list_views + @"" + @" (via _register_discovery_tool)
23.  + @"" + @"db_{n}_pg96_list_objects_by_type + @"" + @" (inline)
24.  + @"" + @"db_{n}_pg96_analyze_sett_sec + @"" + @" (inline)
25.  + @"" + @"db_{n}_pg96_check_db_parameters + @"" + @" (via _register_sett_sec_sub_tool)
26.  + @"" + @"db_{n}_pg96_compute_db_metrics + @"" + @" (via _register_sett_sec_sub_tool)
27.  + @"" + @"db_{n}_pg96_analyze_db_security + @"" + @" (via _register_sett_sec_sub_tool)
28.  + @"" + @"db_{n}_pg96_check_server + @"" + @" (via _register_server_tool)

## 3. Implementation Steps

### Phase 1: Add description Parameter to Helper Functions

- GOAL-001: Modify 4 helper registration functions to accept a  + @"" + @"description + @"" + @" parameter.

| Task | Description | Done |
|------|-------------|------|
| TASK-001 | Add  + @"" + @"description: str = "" + @"" + @" param to  + @"" + @"_register_sub_tool() + @"" + @" signature. After  + @"" + @"sync def _impl(...): + @"" + @" and before  + @"" + @"@mcp.tool(...) + @"" + @", insert  + @"" + @"_impl.__doc__ = description + @"" + @". | ⬜ |
| TASK-002 | Add  + @"" + @"description: str = "" + @"" + @" param to  + @"" + @"_register_discovery_tool() + @"" + @". Insert  + @"" + @"_impl.__doc__ = description + @"" + @" before decorator. | ⬜ |
| TASK-003 | Add  + @"" + @"description: str = "" + @"" + @" param to  + @"" + @"_register_sett_sec_sub_tool() + @"" + @". Insert  + @"" + @"_impl.__doc__ = description + @"" + @" before decorator. | ⬜ |
| TASK-004 | Add  + @"" + @"description: str = "" + @"" + @" param to  + @"" + @"_register_server_tool() + @"" + @". Insert  + @"" + @"_impl.__doc__ = description + @"" + @" before decorator. | ⬜ |

### Phase 2: Pass Description Strings at Call Sites (12 tools)

- GOAL-002: Pass docstrings to all helper-registered tool calls.

| Task | Description | Done |
|------|-------------|------|
| TASK-005 |  + @"" + @"_register_sub_tool("check_table_bloat", ...) + @"" + @": add description about dead tuple ratio, HOT efficiency, vacuum timestamps. | ⬜ |
| TASK-006 |  + @"" + @"_register_sub_tool("check_table_wraparound", ...) + @"" + @": add description about XID age, risk levels, wraparound detection. | ⬜ |
| TASK-007 |  + @"" + @"_register_sub_tool("check_table_statistics", ...) + @"" + @": add description about ANALYZE staleness, 7-day threshold. | ⬜ |
| TASK-008 |  + @"" + @"_register_sub_tool("check_index_health", ...) + @"" + @": add description about invalid/unused/duplicate indexes. | ⬜ |
| TASK-009 |  + @"" + @"_register_discovery_tool("list_tables", ...) + @"" + @": add description about table enumeration with row counts/sizes. | ⬜ |
| TASK-010 |  + @"" + @"_register_discovery_tool("list_indexes", ...) + @"" + @": add description about index enumeration with type/scan stats. | ⬜ |
| TASK-011 |  + @"" + @"_register_discovery_tool("list_views", ...) + @"" + @": add description about view enumeration with definitions. | ⬜ |
| TASK-012 |  + @"" + @"_register_sett_sec_sub_tool("check_db_parameters", ...) + @"" + @": add description about 60+ parameter checks across 7 categories. | ⬜ |
| TASK-013 |  + @"" + @"_register_sett_sec_sub_tool("compute_db_metrics", ...) + @"" + @": add description about cache hit ratio, TXID, dead tuples. | ⬜ |
| TASK-014 |  + @"" + @"_register_sett_sec_sub_tool("analyze_db_security", ...) + @"" + @": add description about SSL, superuser sprawl, audit logging. | ⬜ |
| TASK-015 |  + @"" + @"_register_server_tool("check_server", ...) + @"" + @": add description about CPU/memory/disk resource metrics. | ⬜ |

### Phase 3: Add Docstrings to Inline Tools (5 tools)

- GOAL-003: Add docstrings to inline tools lacking them.

| Task | Description | Done |
|------|-------------|------|
| TASK-016 | Add docstring to  + @"" + @"_exec_query + @"" + @": SELECT-only execution, max_rows cap, returns rows/row_count/truncated. | ⬜ |
| TASK-017 | Add docstring to  + @"" + @"_analyze_table + @"" + @": orchestrates 4 sub-analyses with boolean toggles. | ⬜ |
| TASK-018 | Add docstring to  + @"" + @"_list_objects + @"" + @": enumerates tables/indexes/views with boolean toggles. | ⬜ |
| TASK-019 | Add docstring to  + @"" + @"_list_objects_by_type + @"" + @": generic relkind lister for any pg_class type. | ⬜ |
| TASK-020 | Add docstring to  + @"" + @"_analyze_sett_sec + @"" + @": orchestrates parameter check + metrics + security analysis. | ⬜ |

### Phase 4: Enhance Existing Docstrings with Args (8 tools)

- GOAL-004: Add  + @"" + @"Args: + @"" + @" sections to tools that have summaries but no parameter docs.

| Task | Description | Done |
|------|-------------|------|
| TASK-021 | Add  + @"" + @"Args: + @"" + @" to  + @"" + @"_blocking_sessions + @"" + @" (database_name). | ⬜ |
| TASK-022 | Add  + @"" + @"Args: + @"" + @" to  + @"" + @"_analyze_data_model + @"" + @" (database_name, schema_name). | ⬜ |
| TASK-023 | Enhance  + @"" + @"_extract_schema_model + @"" + @" one-liner with full description + Args. | ⬜ |
| TASK-024 | Enhance  + @"" + @"_analyze_constraints_and_fks + @"" + @" one-liner with full description + Args. | ⬜ |
| TASK-025 | Enhance  + @"" + @"_analyze_normalization + @"" + @" one-liner with full description + Args. | ⬜ |
| TASK-026 | Enhance  + @"" + @"_analyze_index_statistics + @"" + @" one-liner with full description + Args. | ⬜ |
| TASK-027 | Enhance  + @"" + @"_analyze_3nf_and_decomposition + @"" + @" one-liner with full description + Args. | ⬜ |
| TASK-028 | Enhance  + @"" + @"_hypopg_explain_with_virtual + @"" + @" thin docstring with fuller description. | ⬜ |

### Phase 5: Run Tests and Lint

- GOAL-005: Validate all changes.

| Task | Description | Done |
|------|-------------|------|
| TASK-029 |  + @"" + @"uff check . + @"" + @" — zero errors. | ⬜ |
| TASK-030 |  + @"" + @"pytest -q + @"" + @" — all tests pass. | ⬜ |
| TASK-031 | Python import check:  + @"" + @"python -c "from src.server import app" + @"" + @". | ⬜ |

### Phase 6: Update Tool Catalog

- GOAL-006: Sync documentation.

| Task | Description | Done |
|------|-------------|------|
| TASK-032 | Add missing tool entries to  + @"" + @"docs/mcp-tool-catalog.md + @"" + @" for all 18 undocumented tool families. | ⬜ |
| TASK-033 | Add parameter tables to enhanced catalog entries. | ⬜ |

### Phase 7: Force Rebuild Docker Image

- GOAL-007: Build and push fresh image.

| Task | Description | Done |
|------|-------------|------|
| TASK-034 |  + @"" + @"docker build --no-cache -t harryvaldez/mcp-edb96-server:latest -f docker/Dockerfile . + @"" + @" | ⬜ |
| TASK-035 | Verify image:  + @"" + @"docker image inspect harryvaldez/mcp-edb96-server:latest --format "{{.Created}}" + @"" + @" | ⬜ |
| TASK-036 |  + @"" + @"docker push harryvaldez/mcp-edb96-server:latest + @"" + @" | ⬜ |

### Phase 8: Recreate Docker Container

- GOAL-008: Replace running container.

| Task | Description | Done |
|------|-------------|------|
| TASK-037 |  + @"" + @"docker compose -f docker/docker-compose.runtime.yml down + @"" + @" | ⬜ |
| TASK-038 |  + @"" + @"docker compose -f docker/docker-compose.runtime.yml pull + @"" + @" | ⬜ |
| TASK-039 |  + @"" + @"docker compose -f docker/docker-compose.runtime.yml up -d + @"" + @" | ⬜ |
| TASK-040 | Poll  + @"" + @"http://localhost:8087/health + @"" + @" until healthy (max 60s). | ⬜ |
| TASK-041 |  + @"" + @"docker compose -f docker/docker-compose.runtime.yml logs --tail=20 mcp-edb96 + @"" + @" | ⬜ |

### Phase 9: Verify Tool Descriptions

- GOAL-009: Confirm descriptions in deployed server.

| Task | Description | Done |
|------|-------------|------|
| TASK-042 | Query MCP  + @"" + @"	ools/list + @"" + @" to verify all 28 tool variants registered. | ⬜ |
| TASK-043 | Spot-check 3-5 tool descriptions via MCP protocol for completeness. | ⬜ |

## 4. Alternatives

- **ALT-001**: Inline all docstrings without helper changes. Rejected — would require refactoring all helpers to remove shared  + @"" + @"_impl + @"" + @" pattern, increasing duplication and risk.
- **ALT-002**: Use decorator  + @"" + @"description= + @"" + @" param. Rejected — FastMCP 3 reads docstrings from  + @"" + @"__doc__ + @"" + @", not decorator params.
- **ALT-003**: Skip helper-registered tools. Rejected — leaves 12 families undocumented.

## 5. Dependencies

- **DEP-001**: Docker daemon running and authenticated ( + @"" + @"docker login + @"" + @").
- **DEP-002**:  + @"" + @"mcp-net + @"" + @" Docker network exists.
- **DEP-003**:  + @"" + @".env + @"" + @" file with valid EDBAS credentials.
- **DEP-004**: Redis container  + @"" + @"astmcp-redis + @"" + @" accessible on  + @"" + @"mcp-net + @"" + @".
- **DEP-005**: No new packages required.

## 6. Files Modified

| File | Change |
|------|--------|
|  + @"" + @"src/tools/pg_tools.py + @"" + @" | Add  + @"" + @"description + @"" + @" params to 4 helpers; add 5 inline docstrings; enhance 8 existing docstrings; pass descriptions at 12 call sites. |
|  + @"" + @"docs/mcp-tool-catalog.md + @"" + @" | Add 18 undocumented tool entries; add parameter tables for 8 enhanced tools. |

## 7. Testing

- **TEST-001**:  + @"" + @"uff check . + @"" + @" — zero errors.
- **TEST-002**:  + @"" + @"pytest -q + @"" + @" — all pass.
- **TEST-003**:  + @"" + @"docker build --no-cache + @"" + @" — succeeds.
- **TEST-004**:  + @"" + @"curl http://localhost:8087/health + @"" + @" — HTTP 200, status healthy/degraded.
- **TEST-005**: MCP  + @"" + @"	ools/list + @"" + @" — all tools present with descriptions.
- **TEST-006**:  + @"" + @"python -c "from src.server import app" + @"" + @" — succeeds.

## 8. Risks & Assumptions

- **RISK-001**:  + @"" + @"_impl.__doc__ = description + @"" + @" may not propagate to FastMCP 3 introspection. **Mitigation**: Validate via TASK-043; if it fails, inline each helper call into separate  + @"" + @"@mcp.tool() + @"" + @" registrations.
- **RISK-002**: Docker Hub push may fail. **Mitigation**:  + @"" + @"docker login + @"" + @" before TASK-036.
- **RISK-003**: Container recreation causes brief downtime. Acceptable for maintenance.
- **ASSUMPTION-001**:  + @"" + @".env + @"" + @" and config files are correctly configured.
- **ASSUMPTION-002**:  + @"" + @"__doc__ + @"" + @" must be set BEFORE  + @"" + @"@mcp.tool() + @"" + @" decoration. This requires placing  + @"" + @"_impl.__doc__ = description + @"" + @" after  + @"" + @"sync def _impl(...): + @"" + @" but before the  + @"" + @"@mcp.tool(...) + @"" + @" line — which means reordering the helper internals.

## 9. Critical Implementation Detail: __doc__ Assignment Order

For helpers like  + @"" + @"_register_sub_tool + @"" + @", the current code structure is:

`python
@mcp.tool(...)
async def _impl(...):
    ...
`

This MUST be restructured to:

`python
async def _impl(...):
    ...
_impl.__doc__ = description
# THEN decorate:
_impl = mcp.tool(...)(_impl)
`

Or equivalently, set  + @"" + @"__doc__ + @"" + @" immediately after  + @"" + @"def + @"" + @":

`python
async def _impl(...):
    """placeholder"""
    ...
_impl.__doc__ = description
mcp.tool(name=full_name, annotations={...}, ...)(_impl)
`

This is the most invasive change to the helpers but is necessary for FastMCP to pick up the docstring.

## 10. Related Documents

- [Tool catalog](docs/mcp-tool-catalog.md)
- [AGENTS.md](AGENTS.md)
- [Docker runtime guide](docs/run-mcp-server-with-docker.md)
- [FastMCP 3 docs](https://gofastmcp.com/)
