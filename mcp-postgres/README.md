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

6. Health check: `curl http://localhost:8080/health`

### Docker Quick Start

```powershell
docker compose -f docker/docker-compose.yml up -d
```

## Available MCP Tools

| Tool | Description |
|---|---|
| `db_1_pg96_ping` | Check accessibility and identity of primary EDBAS 9.6 instance |
| `db_2_pg96_ping` | Check accessibility and identity of secondary EDBAS 9.6 instance |

## Diagnostics Endpoints

- `GET /health` — Aggregate health across all instances (healthy/degraded/unhealthy)
- `GET /readiness` — Readiness probe (config loaded, pools healthy)
- `GET /metrics` — Prometheus metrics (request counts, latencies, denied requests)
- `GET /security` — Security posture summary (write mode, blocked patterns, checksums)

## Documentation Links

- [Tool catalog](docs/mcp-tool-catalog.md) — Detailed tool contracts
- [Docker runtime guide](docs/run-mcp-server-with-docker.md) — Docker deployment instructions
- [FastMCP 3 Documentation](https://gofastmcp.com/) — FastMCP framework documentation
- [EDBAS Documentation](https://www.enterprisedb.com/docs/) — EnterpriseDB Advanced Server docs
