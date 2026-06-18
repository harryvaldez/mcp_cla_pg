# Running the MCP Server with Docker

## Prerequisites

- Docker Engine 24+
- Docker Compose plugin
- `.env` file configured with EDBAS credentials
- Network access to both EDBAS 9.6 instances

## Building the Image

```powershell
docker build -t fastmcp-edb96 -f docker/Dockerfile .
```

## Configuration

### `.env` File

```env
SECRET_PG_PRIMARY_USERNAME=mcp_readonly
SECRET_PG_PRIMARY_PASSWORD=your_password_here
SECRET_PG_SECONDARY_USERNAME=mcp_readonly
SECRET_PG_SECONDARY_PASSWORD=your_other_password_here
```

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

## Verifying

```powershell
curl http://localhost:8086/health
```

Expected response:

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

## Troubleshooting

### SSL Errors

If SSL certificate validation fails:
1. Check `sslmode` in `config/instances.yaml`
2. Use `require` for self-signed certificates
3. Use `verify-full` only with trusted CA-signed certificates

### Connection Refused

1. Verify EDBAS instances are running and accessible
2. Check firewall rules allow traffic on port 5444
3. Verify host addresses in `config/instances.yaml`

### Pool Exhaustion

If connection pool is exhausted:
1. Increase `pool_max` in `config/instances.yaml`
2. Check `/metrics` for pool utilization
3. Verify queries are completing within `command_timeout_sec`
