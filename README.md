# MCP EnterpriseDB Advanced Server 9.6

Dual-instance FastMCP 3 server for EnterpriseDB Advanced Server 9.6 (EDBAS 9.6) with read-only controls, Redis-backed rate limiting, Okta OAuth, table analysis, settings & security diagnostics, and Prometheus metrics.

## What This Repository Provides

- FastMCP 3 service exposing MCP tools over HTTP at `/mcp`
- Dual-instance EDBAS 9.6 support (primary and secondary with auto-mirrored tools via closure binding)
- Read-only SQL policy controls with EDBAS-specific DDL blocking
- **Redis-backed distributed rate limiting** (per-actor + global token buckets; local in-process fallback)
- **Optional Okta OAuth 2.0 / OIDC authentication** via FastMCP `JWTVerifier` with group-based tool authorization (read/write groups, HypoPG/cross-session restrictions for read-level callers)
- **Maintenance analysis**: table bloat, wraparound risk, stale statistics, index health
- **Settings & security diagnostics**: DB parameter audit (EDBAS 9.6 best practices), cache/transaction/TXID metrics, SSL/WAL archiving/backup/authentication vulnerability checks
- **Object discovery**: list tables, indexes, views, and objects by `pg_class.relkind` type
- Structured JSON audit logging for every tool invocation with auth context
- Diagnostics endpoints for health, readiness, Prometheus metrics, and security posture
- Docker multi-stage build with hardening (non-root, read-only filesystem, all capabilities dropped)
- Production and development deployment scripts for Windows and Linux

## Repository Structure

- `src/` — Service runtime, tool registration, middleware, diagnostics
  - `src/tools/` — `pg_tools.py` (registration + auth), `hypopg_tools.py`, `table_analysis.py`, `settings_security.py`, `input_validation.py`, `tool_registry.py`, `tool_flags.py`
  - `src/middleware/` — `write_guard.py`, `rate_limiter.py` (local + Redis backends), `audit_logger.py`
  - `src/security/` — `session_manager.py`
  - `src/diagnostics/` — `routes.py` (health, readiness, metrics, security endpoints)
  - `src/db/` — `connection_manager.py` (asyncpg pool management)
- `config/` — Instance config, runtime policy (with Okta auth section), and rate-limit settings
- `policy/` — SQL blocklist and allowlist definitions (currently empty)
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
- **Redis 7+** (optional — needed only for distributed rate limiting; falls back to local in-process)

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

6. Health check: `curl http://localhost:8080/health`

### Docker Quick Start (with existing Redis)

The MCP server container connects to an existing `fastmcp-redis` container via the `mcp-net` Docker network. To set this up:

```powershell
# Ensure the Redis container is running on the mcp-net network
docker network create mcp-net 2>$null
docker run -d --name fastmcp-redis --network mcp-net redis:7-alpine

# Build and start the MCP server
docker compose -f docker/docker-compose.yml up -d
```

### Docker Quick Start (standalone — no Redis dependency)

Override the rate limit backend to `local` to run without Redis:

```powershell
FASTMCP_RATE_LIMIT_BACKEND=local docker compose -f docker/docker-compose.yml up -d
```

### Verifying

```powershell
curl http://localhost:8086/health
curl http://localhost:8086/readiness
```

## Available MCP Tools

Each tool is auto-mirrored as `db_1_pg96_<name>` and `db_2_pg96_<name>`.

### Core / Diagnostics

| Tool | Description |
|---|---|
| `db_n_pg96_ping` | Check accessibility and identity of an EDBAS 9.6 instance |
| `db_n_pg96_exec_query` | Execute a user-supplied SELECT query (default 100 rows, max 1000) |

### Performance Analysis

| Tool | Description |
|---|---|
| `db_n_pg96_get_slow_statements` | Analysis of long-running SQL with ranked HypoPG index recommendations |
| `db_n_pg96_blocking_sessions` | Identify locking, deadlocks, and wait events (⚠️ restricted for read-group callers) |
| `db_n_pg96_analyze_data_model` | Data model health, 3NF compliance, and DB constraints (aggregates sub-tools) |

### Data Model Sub-Tools

| Tool | Description |
|---|---|
| `db_n_pg96_extract_schema_model` | Retrieve table and column definitions |
| `db_n_pg96_analyze_constraints_and_fks` | Check for foreign keys and mapped constraints |
| `db_n_pg96_missing_fk` | Detect columns lacking foreign keys with inferred target tables and DDL suggestions |
| `db_n_pg96_analyze_normalization` | Statistical anomaly and data type mismatch detection |
| `db_n_pg96_analyze_index_statistics` | Monitor table staleness and index health |
| `db_n_pg96_analyze_3nf_and_decomposition` | Identify row repetition and decomposition targets |

### Single-Table Maintenance (analyze_table family)

| Tool | Description |
|---|---|
| `db_n_pg96_analyze_table` | Orchestrates all 4 sub-tools below against a single table |
| `db_n_pg96_check_table_bloat` | Dead tuple ratio, HOT update%, and vacuum staleness |
| `db_n_pg96_check_table_wraparound` | Transaction ID wraparound risk (LOW/MEDIUM/HIGH/CRITICAL) |
| `db_n_pg96_check_table_statistics` | Stale/missing `last_analyze` and modification counts |
| `db_n_pg96_check_index_health` | Invalid, unused, and duplicate indexes with bloat |

### Object Discovery (list_objects family)

| Tool | Description |
|---|---|
| `db_n_pg96_list_objects` | List tables, indexes, and views in a schema |
| `db_n_pg96_list_tables` | List tables with row counts and sizes |
| `db_n_pg96_list_indexes` | List indexes with type, size, and scan statistics |
| `db_n_pg96_list_views` | List views with definition and owner |
| `db_n_pg96_list_objects_by_type` | List database objects by `pg_class.relkind` type (sequences, materialized views, etc.) |

### HypoPG Virtual Indexing

| Tool | Description |
|---|---|
| `db_n_pg96_hypopg_create_virtual_indexes` | Generate candidate virtual indexes via HypoPG (⚠️ restricted for read-group callers) |
| `db_n_pg96_hypopg_explain_with_virtual` | EXPLAIN a query using session's virtual indexes (⚠️ restricted) |
| `db_n_pg96_hypopg_find_optimal_indexes` | Find optimal virtual index combination for a query (⚠️ restricted) |

### Settings & Security (analyze_sett_sec family)

| Tool | Description |
|---|---|
| `db_n_pg96_analyze_sett_sec` | Orchestrates all 3 sub-tools below for instance-wide analysis |
| `db_n_pg96_check_db_parameters` | Evaluate `pg_settings` against EDBAS 9.6 best practices (Memory, WAL, Autovacuum, Logging, Connections, Security) |
| `db_n_pg96_compute_db_metrics` | Cache hit ratio, transaction commit ratio, tuple metrics, connection utilization, TXID age, database size |
| `db_n_pg96_analyze_db_security` | SSL status, WAL archiving, backup heuristics, auth weaknesses, audit gaps, superuser sprawl |
| `db_n_pg96_check_server` | CPU count/model, memory (via /proc/meminfo), disk utilization for `/data` filesystem |

## Diagnostics Endpoints

| Endpoint | Description |
|---|---|
| `GET /health` | Aggregate health across all instances (healthy/degraded/unhealthy) |
| `GET /readiness` | Readiness probe (config loaded, pools healthy) |
| `GET /metrics` | Prometheus metrics (request counts, latencies, denied requests, pool stats) |
| `GET /security` | Security posture summary (write mode, blocked patterns, checksums) |

> All diagnostics endpoints are unauthenticated by design.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_PG_PRIMARY_USERNAME` | `edb_readonly_user` | Instance 1 database user |
| `SECRET_PG_PRIMARY_PASSWORD` | — | Instance 1 database password |
| `SECRET_PG_SECONDARY_USERNAME` | `edb_readonly_user` | Instance 2 database user |
| `SECRET_PG_SECONDARY_PASSWORD` | — | Instance 2 database password |
| `FASTMCP_CONFIG_PATH` | `config/instances.yaml` | Instance connection config |
| `FASTMCP_POLICY_PATH` | `config/runtime-policy.yaml` | Write guard & tool flags |
| `FASTMCP_RATE_LIMIT_PATH` | `config/rate-limit.yaml` | Rate limits |
| `FASTMCP_RATE_LIMIT_BACKEND` | `local` | `local` or `redis` |
| `FASTMCP_REDIS_URL` | — | Redis connection URL (required when backend=`redis`) |
| `FASTMCP_REDIS_NAMESPACE` | `mcp:ratelimit` | Key prefix for Redis rate limiter |
| `FASTMCP_AUDIT_PATH` | `/var/log/mcp/audit.log` | Audit log file path |
| `FASTMCP_STATELESS_HTTP` | `true` | Stateless mode for horizontal scaling |
| `FASTMCP_MASK_ERROR_DETAILS` | `true` | Mask internal error details in responses |
| `FASTMCP_TOOL_ENABLE_FLAGS_JSON` | — | JSON object of per-tool enable flags (overrides policy) |
| `FASTMCP_INSTANCE_TOOL_ENABLE_FLAGS_JSON` | — | Nested JSON object of per-instance, per-tool enable flags |
| `OKTA_DOMAIN` | — | Okta org domain (required when `auth_mode=okta`) |
| `OKTA_CLIENT_ID` | — | Okta OIDC app client ID (required when `auth_mode=okta`) |
| `OKTA_AUTH_SERVER_ID` | `default` | Okta authorization server ID |

## Documentation Links

- [Agent guidance](AGENTS.md) — Architecture boundaries, tool authoring pattern, middleware reference, common pitfalls
- [Security policy](SECURITY.md) — Security model, container hardening, error masking
- [Tool catalog](docs/mcp-tool-catalog.md) — Detailed tool contracts with parameters, outputs, and annotations
- [Database setup guide](docs/database-setup-guide.md) — Privilege requirements and ROLE configuration
- [Docker runtime guide](docs/run-mcp-server-with-docker.md) — Docker deployment instructions with Redis setup
- [Okta authentication setup guide](docs/okta-authentication-setup.md) — End-to-end Okta OAuth + group setup for MCP access
- [FastMCP 3 Documentation](https://gofastmcp.com/) — FastMCP framework documentation
- [EDBAS Documentation](https://www.enterprisedb.com/docs/) — EnterpriseDB Advanced Server docs
