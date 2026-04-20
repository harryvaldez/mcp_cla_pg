# mcp-postgres

FastMCP server for PostgreSQL with dual-instance support, operational diagnostics, and safe-by-default runtime controls.
---

## Documentation
- **User Manual:** [docs/users-manual.md](docs/users-manual.md) — End-user setup, configuration, troubleshooting, and all usage examples
- [DEPLOYMENT.md](DEPLOYMENT.md) — Deployment and advanced setup
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution process
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Community expectations
- [SECURITY.md](SECURITY.md) — Security policy
- [LICENSE](LICENSE) — License
---

## Project Overview
mcp-postgres exposes PostgreSQL diagnostics and automation tools via FastMCP, supporting two independently configured database instances. Designed for AI clients, DBAs, and compliance teams seeking a consistent, safe, and extensible interface.

For all setup, quickstart, usage examples, configuration, troubleshooting, and advanced instructions, see the [User Manual](docs/users-manual.md).
---

## License
MIT License. See [LICENSE](LICENSE).

...existing code...


# mcp-postgres

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.13%2B-blue)


**User Manual:** See the new [USER_MANUAL.md](USER_MANUAL.md) for end-user setup, configuration, and troubleshooting instructions.

FastMCP server for PostgreSQL with dual-instance support, operational diagnostics, and safe-by-default runtime controls.

Use this project when you want AI clients or MCP-compatible tools to query and inspect PostgreSQL through a consistent tool interface.

---

## Table of Contents
---

# mcp-postgres

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.13%2B-blue)

FastMCP server for PostgreSQL with dual-instance support, operational diagnostics, and safe-by-default runtime controls.

---

## Documentation

- **User Manual:** [docs/users-manual.md](docs/users-manual.md) — End-user setup, configuration, and troubleshooting
- [DEPLOYMENT.md](DEPLOYMENT.md) — Deployment and advanced setup
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contribution process
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Community expectations
- [SECURITY.md](SECURITY.md) — Security policy
- [LICENSE](LICENSE) — License

---

## Project Overview

mcp-postgres exposes PostgreSQL diagnostics and automation tools via FastMCP, supporting two independently configured database instances. Designed for AI clients, DBAs, and compliance teams seeking a consistent, safe, and extensible interface.

Key features:
- Dual-instance support (`db_01_*` and `db_02_*`)
- Diagnostics endpoints and reporting utilities
- Runtime safety controls (write protection, audit logging, rate limiting)

# mcp-postgres

FastMCP server for PostgreSQL with dual-instance support, operational diagnostics, and safe-by-default runtime controls.

---

## Why This Project Is Useful
- Provides a structured MCP tool surface for PostgreSQL operations
- Supports two independently configured PostgreSQL instances
- Includes diagnostics endpoints and model/report utilities
- Applies runtime safety controls for write mode, rate limiting, and audit behavior

---

## Documentation
- [User Manual](docs/users-manual.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [License](LICENSE)

---

## Features
- PostgreSQL MCP tools exposed through FastMCP
- Support for two configured database instances (`db_01_*` and `db_02_*`)
- Diagnostics endpoints and reporting utilities
- Optional runtime controls for audit logging, rate limiting, and write safety

---


## Quick Start

See [DEPLOYMENT.md](DEPLOYMENT.md) for all setup and deployment instructions, including local, Docker, and cloud deployment.

---

## Prerequisites
- Python 3.13+
- PostgreSQL credentials for at least one instance
- Optional: Docker Desktop for container workflows

---

## Key Environment Variables
- `DATABASE_URL`, `DATABASE_URL_INSTANCE_1`, `DATABASE_URL_INSTANCE_2`: PostgreSQL connection strings
- `MCP_TRANSPORT`, `MCP_HOST`, `MCP_PORT`: server transport and binding
- `MCP_ALLOW_WRITE`, `MCP_CONFIRM_WRITE`: write protection controls
- `MCP_MAX_ROWS`, `MCP_STATEMENT_TIMEOUT_MS`: query guardrails
- `MCP_AUDIT_LOG_FILE`: audit logging controls

---

## Where To Get Help
- Start with the [User Manual](docs/users-manual.md)
- Open a repository issue for bugs or defects
- Use repository discussions for questions and usage patterns (if enabled)

---

## Who Maintains And Contributes
- Maintained by Harry Valdez and community contributors
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

---

## Troubleshooting
- ODBC/connection errors: check driver and credentials in `.env`
- No report output: verify required parameters
- Session monitor errors: check instance configuration

---

## Security Notes
- Do not commit `.env`
- Use least-privilege DB accounts where possible
- Keep `MCP_ALLOW_WRITE=false` unless write operations are required

---

## License

MIT License. See [LICENSE](LICENSE).
- MIME type: `application/json`
- Query args:
  - `pattern`: optional PostgreSQL regex (case-insensitive)
  - `limit`: optional integer, must be `> 0`
- Payload shape:

```json
{
  "pattern": "max_connections|shared_buffers",
  "limit": 50,
  "count": 2,
  "settings": [
    {
      "name": "max_connections",
      "setting": "100",
      "unit": null,
      "category": "Connections and Authentication / Connections and Authentication",
      "short_desc": "Sets the maximum number of concurrent connections.",
      "context": "postmaster",
      "pending_restart": false
    }
  ]
}
```

## 🧪 Testing & Validation

This project has been rigorously tested against **PostgreSQL 9.6** to ensure compatibility with legacy and modern environments.

### Test Results (2026-03-03)
- **Deployment**: Docker, `uv`, `npx` (All Passed)
- **Protocol**: SSE (HTTP/HTTPS), Stdio (All Passed)
- **Database**: PostgreSQL 9.6 (All Tools Verified)
- **Auth**: Token Auth, Azure AD Auth (To be verified)
   > **Verification Status**: **Token Auth** and **Azure AD Auth** have not been tested and are **not production-ready**. End-to-end verification is currently pending setup of a dedicated Azure AD tenant. While the code implements standard FastMCP patterns, these specific providers have not been validated against a live identity provider.
   > 
   > **Limitation**: As noted in [Security Constraints](#security-constraints), **Write Mode** requires mandatory authentication when using HTTP. Until **Token Auth** or **Azure AD Auth** is verified, use `stdio` transport or ensure strict network isolation if testing Write Mode.
  > 
  > **Timeline**: Verification is scheduled for the next minor release. Follow status in [Repository Issues](https://github.com/harryvaldez/mcp_cla_pg/issues).

To run the full test suite locally:
```bash
# Uses pytest discovery scoped to ./tests via pytest.ini
python -m pytest -q
```

On Windows, test runs that import `server.py` should set the startup toggles explicitly so pytest does not trigger the confirmation dialog or install process-wide signal handlers during import:

```powershell
$env:MCP_SKIP_CONFIRMATION='true'
$env:MCP_REGISTER_SIGNAL_HANDLERS='false'
python -m pytest -q
```

To run the primary integration checks used for release validation:
```bash
python -m pytest -q tests/test_security_perf_oltp.py tests/test_tools_pg96.py tests/functional_test.py
```

Windows example:

```powershell
$env:MCP_SKIP_CONFIRMATION='true'
$env:MCP_REGISTER_SIGNAL_HANDLERS='false'
python -m pytest -q tests/test_security_perf_oltp.py tests/test_tools_pg96.py tests/functional_test.py
```

---

## ❓ FAQ & Troubleshooting

### Frequently Asked Questions

**Q: Why is everything prefixed with `db_pg96_`?**
A: This server is explicitly versioned for PostgreSQL 9.6 compatibility to ensure stability in legacy environments. This avoids naming conflicts if you run multiple MCP servers for different database versions.

**Q: Can I use this with newer PostgreSQL versions (13, 14, 15+)?**
A: Yes! Most tools are forward-compatible. The `db_pg96_` prefix just indicates the minimum supported version.

**Q: How do I enable write operations?**
A: By default, the server is read-only. To enable write tools, set `MCP_ALLOW_WRITE=true` and `MCP_CONFIRM_WRITE=true`. If you are using `http` transport, you must also configure authentication through `FASTMCP_AUTH_TYPE` before write mode is allowed.

**Q: What format should `function_args` use for function create/alter/drop operations?**
A: Use a normal PostgreSQL signature fragment such as `arg1 integer, arg2 text` or `integer, text`. The server accepts validated type expressions, but rejects defaults and unsafe raw SQL fragments. For overloaded functions, alter/drop operations resolve the exact `regprocedure` from the validated signature.

### Common Issues

**Browser Error: `Not Acceptable`**
If you visit `http://localhost:8000/mcp` in a browser, you will see a JSON error. This is normal; that endpoint is for MCP clients only. Visit `http://localhost:8000/` for the status page.

**Connection Refused**
Ensure your `DATABASE_URL` is correct. If running in Docker, remember that `localhost` inside the container refers to the container itself. Use `host.docker.internal` to reach the host machine.

**Duplicate Indexes Not Detected**
The `db_pg96_analyze_indexes` tool has been updated to group by the indexed column set. Ensure your indexes have the exact same column order and definition for detection.

---

## ✨ Enhancement Recommendations

We are actively looking for contributions to make this server even better! Here are some recommended areas for enhancement:

- **Cloud Integrations**: Add specialized support for AWS RDS, Azure Database for PostgreSQL, and Google Cloud SQL.
- **Authentication**: Test Azure AD authentication for write mode.
- **Visualization**: Integration with MCP apps or hooks for dashboard tools like Grafana.
- **Deployment**:  Deploy the container image to a more secured container repository like Azure or AWS.

If you have an idea, please submit a feature request!

---

## 📬 Contact & Support

For comments, issues, or feature enhancements, please contact the maintainer or submit an issue to the repository:

- **Repository**: https://github.com/harryvaldez/mcp_cla_pg
- **Maintainer**: Harry Valdez
- **Issues**: https://github.com/harryvaldez/mcp_cla_pg/issues
