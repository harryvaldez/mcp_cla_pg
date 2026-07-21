# Running the MCP Server with Docker

## Prerequisites

- Docker Engine 24+
- Docker Compose plugin
- `.env` file configured with EDBAS credentials
- Network access to both EDBAS 9.6 instances
- **Redis 7+** (optional — required only for distributed rate limiting)

## Architecture Overview

The MCP server container connects to an external Redis container (`fastmcp-redis`) over the `mcp-net` Docker bridge network. The compose file does **not** define a Redis service — it assumes an existing Redis instance on the same network.

```
┌──────────────────┐     mcp-net bridge network     ┌──────────────────┐
│  fastmcp-edb96   │ ─────────────────────────────── │  fastmcp-redis   │
│  (MCP server)    │    redis://fastmcp-redis:6379   │  (Redis 7)       │
│  port 8086:8080  │                                  │  port 6379       │
└──────────────────┘                                  └──────────────────┘
```

## Network Setup

Create the shared Docker network and start Redis **before** the MCP server:

```powershell
# Create the shared network (idempotent)
docker network create mcp-net 2>$null

# Start Redis (if not already running)
docker run -d `
  --name fastmcp-redis `
  --network mcp-net `
  --restart unless-stopped `
  redis:7-alpine redis-server --appendonly yes
```

> **Existing Redis**: If you already have a Redis container (`fastmcp-redis`) on `mcp-net`, skip this step. Verify with `docker ps --filter "name=fastmcp-redis"`.

## Building the Image

```powershell
docker build -t fastmcp-edb96:local -f docker/Dockerfile .
```

## Configuration

### `.env` File

```env
# EDBAS credentials
SECRET_PG_PRIMARY_USERNAME=mcp_readonly
SECRET_PG_PRIMARY_PASSWORD=your_password_here
SECRET_PG_SECONDARY_USERNAME=mcp_readonly
SECRET_PG_SECONDARY_PASSWORD=your_other_password_here

# Rate limiting — Redis backend (distributed)
FASTMCP_RATE_LIMIT_BACKEND=redis
FASTMCP_REDIS_URL=redis://fastmcp-redis:6379
FASTMCP_REDIS_NAMESPACE=mcp:ratelimit

# Runtime
FASTMCP_STATELESS_HTTP=true
FASTMCP_MASK_ERROR_DETAILS=true
```

> **No Redis?** Set `FASTMCP_RATE_LIMIT_BACKEND=local` and leave `FASTMCP_REDIS_URL` empty to use the in-process token bucket.

### `config/instances.yaml`

Update host and port for your EDBAS instances:

```yaml
instances:
  - id: primary
    host: <your-edb-primary-host>
    port: 5444
    # ...
  - id: secondary
    host: <your-edb-secondary-host>
    port: 5444
    # ...
```

## Running

### Development

```powershell
docker compose -f docker/docker-compose.yml up -d
```

### Production

```powershell
docker compose -f docker/docker-compose.runtime.yml up -d
```

### Without Redis (local rate limiting)

```powershell
FASTMCP_RATE_LIMIT_BACKEND=local docker compose -f docker/docker-compose.yml up -d
```

## Verifying

```powershell
# Health check
curl http://localhost:8086/health

# Readiness probe
curl http://localhost:8086/readiness

# Prometheus metrics
curl http://localhost:8086/metrics
```

Expected health response:

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "instances": {
    "primary": {"state": "connected", "instance_number": 1, "error": null},
    "secondary": {"state": "connected", "instance_number": 2, "error": null}
  }
}
```

## Stopping

```powershell
docker compose -f docker/docker-compose.yml down
```

> This does **not** stop the external `fastmcp-redis` container. Stop it separately if needed:
> ```powershell
> docker stop fastmcp-redis && docker rm fastmcp-redis
> ```

## Troubleshooting

### Redis Connection Refused

If the MCP server cannot reach Redis:

1. Verify Redis is running: `docker ps --filter "name=fastmcp-redis"`
2. Verify they share the same network: `docker inspect fastmcp-redis --format '{{json .NetworkSettings.Networks}}'`
3. Check `FASTMCP_REDIS_URL` in `.env` — the hostname must match the Redis container name (`fastmcp-redis`)
4. Test connectivity from inside the MCP container:
   ```powershell
   docker exec fastmcp-edb96 python -c "import redis; r=redis.from_url('redis://fastmcp-redis:6379'); r.ping(); print('OK')"
   ```
5. As a workaround, switch to local rate limiting:
   ```powershell
   FASTMCP_RATE_LIMIT_BACKEND=local docker compose -f docker/docker-compose.yml up -d
   ```

### SSL Errors

If SSL certificate validation fails:
1. Check `sslmode` in `config/instances.yaml`
2. Use `require` for self-signed certificates
3. Use `verify-full` only with trusted CA-signed certificates

### Connection Refused (EDBAS)

1. Verify EDBAS instances are running and accessible
2. Check firewall rules allow traffic on port 5444
3. Verify host addresses in `config/instances.yaml`

### Pool Exhaustion

If connection pool is exhausted:
1. Increase `pool_max` in `config/instances.yaml`
2. Check `/metrics` for pool utilization
3. Verify queries are completing within `command_timeout_sec`
