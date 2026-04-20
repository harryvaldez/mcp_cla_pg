# User Manual for mcp-postgres

Welcome to the mcp-postgres User Manual. This guide provides end users with clear instructions for setup, usage, troubleshooting, and support. For developer and contributor information, see the README.md and CONTRIBUTING.md.

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Help & Support](#help--support)
- [About](#about)

## Introduction
mcp-postgres is a FastMCP-powered diagnostic and automation toolkit for PostgreSQL, designed for database administrators, engineers, and compliance teams.

## Features
- Automated evidence collection
- Diagnostic tools for PostgreSQL
- Dockerized deployment
- Integration with FastMCP
- Security and compliance reporting

## Quick Start
1. **Clone the repository:**
   ```sh
   git clone https://github.com/harryvaldez/mcp_cla_pg.git
   cd mcp_cla_pg
   ```
2. **Run with Docker Compose:**
   ```sh
   docker-compose up
   ```
3. **Access the service:**
   - Default: http://localhost:8080

## Prerequisites
- Docker and Docker Compose
- Python 3.13+ (for local development)
- PostgreSQL database (local or remote)

## Configuration
Key environment variables:
- `POSTGRES_HOST`: PostgreSQL server address
- `POSTGRES_PORT`: PostgreSQL port (default: 5432)
- `POSTGRES_USER`: Database username
- `POSTGRES_PASSWORD`: Database password
- `POSTGRES_DB`: Database name

## Usage
- Start the service using Docker or Python.
- Use the web interface or API endpoints for diagnostics and evidence collection.
- For advanced usage, see the [README.md](../README.md) and [DEPLOYMENT.md](../DEPLOYMENT.md).

## Troubleshooting
- Check Docker logs: `docker-compose logs`
- Verify environment variables are set correctly
- See the [README.md](../README.md#troubleshooting) for more tips

## Help & Support
- For help, open an issue on GitHub or see the [README.md](../README.md#help--support).

## About
mcp-postgres is maintained by Harry Valdez and contributors. For more details, see the [README.md](../README.md#about).
