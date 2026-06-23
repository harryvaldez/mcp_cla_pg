# MCP EnterpriseDB Advanced Server 9.6

Dual-instance FastMCP 3 server for EnterpriseDB Advanced Server 9.6 (EDBAS 9.6) with read-only controls, rate limiting, and diagnostics.

## What This Repository Provides

- FastMCP 3 service exposing MCP tools over HTTP at `/mcp`
- Dual-instance EDBAS 9.6 support (primary and secondary with auto-mirrored tools)
- Read-only SQL policy controls with EDBAS-specific DDL blocking
- Local rate limiting with per-actor and global limits
- Structured JSON audit logging for every tool invocation
- Diagnostics endpoints for health, readiness, Prometheus metrics, and security posture
- Docker multi-stage build with hardening (non-root, read-only filesystem)
- Production and development deployment scripts for Windows and Linux

## Repository Structure

- `src/` — Service runtime, tool registration, middleware, diagnostics
- `config/` — Instance config, runtime policy, and rate-limit settings
- `policy/` — SQL blocklist and allowlist definitions
- `docker/` — Dockerfile and compose files
- `tests/` — Unit and integration tests
- `scripts/` — Deployment and operational scripts
- `docs/` — Tool catalog, runbooks, and run instructions
- `plan/` — Implementation plans

## Quick Start

### Prerequisites

- Python 3.11+
- Docker Engine 24+ (for containerized deployment)
- Two EDBAS 9.6 instances accessible via TCP/IP

### Local Development

1. Create and activate a Python 3.11+ virtual environment
2. Install dependencies:

```powershell
pip install -e ".[dev]"
```

3. Configure environment:

```powershell
Copy-Item .env.example .env
# Edit .env with your EDBAS credentials
```

4. Configure instances in `config/instances.yaml`

5. Run the server:

```powershell
python -m src.server
```

6. Health check: `curl http://localhost:8086/health`

### Docker Quick Start

```powershell
docker compose -f docker/docker-compose.yml up -d
```

## Available MCP Tools

| Tool | Description |
|---|---|
| `db_n_pg96_ping` | Check accessibility and identity of an EDBAS 9.6 instance |
| `db_n_pg96_exec_query` | Execute a user-supplied SELECT query |
| `db_n_pg96_get_slow_statements` | Analysis of long-running SQL with index recommendations |
| `db_n_pg96_blocking_sessions` | Identify locking, deadlocks, and wait events |
| `db_n_pg96_analyze_data_model` | Data model health, 3NF compliance, and DB constraints |
| `db_n_pg96_extract_schema_model` | Retrieve table and column definitions |
| `db_n_pg96_analyze_constraints_and_fks` | Check for foreign keys and mapped constraints |
| `db_n_pg96_analyze_normalization` | Statistical anomaly and data type mismatch detection |
| `db_n_pg96_analyze_index_statistics` | Monitor table staleness and index health |
| `db_n_pg96_analyze_3nf_and_decomposition` | Identify row repetition and decomposition targets |
| `db_n_pg96_analyze_table` | Comprehensive single-table maintenance analysis |
| `db_n_pg96_check_table_bloat` | Dead tuple ratio and vacuum staleness |
| `db_n_pg96_check_table_wraparound` | Transaction ID wraparound risk |
| `db_n_pg96_check_table_statistics` | Table statistics staleness |
| `db_n_pg96_check_index_health` | Invalid, unused, and duplicate indexes |
| `db_n_pg96_list_objects` | List database objects (tables, indexes, views) in a schema |
| `db_n_pg96_list_tables` | List tables with row counts and sizes |
| `db_n_pg96_list_indexes` | List indexes with type and scan stats |
| `db_n_pg96_list_views` | List views with definition and owner |
| `db_n_pg96_list_objects_by_type` | List objects by `pg_class.relkind` type |
| `db_n_pg96_hypopg_create_virtual_indexes` | Generate candidate virtual indexes via HypoPG |
| `db_n_pg96_hypopg_explain_with_virtual` | EXPLAIN a query using session's virtual indexes |
| `db_n_pg96_hypopg_find_optimal_indexes` | Find optimal virtual index combination for a query |

## Diagnostics Endpoints

- `GET /health` — Aggregate health across all instances (healthy/degraded/unhealthy)
- `GET /readiness` — Readiness probe (config loaded, pools healthy)
- `GET /metrics` — Prometheus metrics (request counts, latencies, denied requests)
- `GET /security` — Security posture summary (write mode, blocked patterns, checksums)

## Documentation Links

- [Tool catalog](docs/mcp-tool-catalog.md) — Detailed tool contracts
- [Database setup guide](docs/database-setup-guide.md) — Privilege requirements and ROLE configuration
- [Docker runtime guide](docs/run-mcp-server-with-docker.md) — Docker deployment instructions
- [FastMCP 3 Documentation](https://gofastmcp.com/) — FastMCP framework documentation
- [EDBAS Documentation](https://www.enterprisedb.com/docs/) — EnterpriseDB Advanced Server docs
