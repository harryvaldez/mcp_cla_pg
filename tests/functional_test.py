import asyncio
import os
import json
import subprocess
import time

import pytest
from psycopg_pool import ConnectionPool


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPOSE_FILE = os.path.join(ROOT, "docker-compose.yml")
SERVICE = "postgres96"
HOST = "localhost"
PORT = 15432
DB = "mcp_test"
USER = "postgres"
PASSWORD = "postgres"
DATABASE_URL = f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}"

os.environ["DATABASE_URL"] = DATABASE_URL
os.environ["MCP_ALLOW_WRITE"] = "true"
os.environ["MCP_CONFIRM_WRITE"] = "true"
os.environ["FASTMCP_AUTH_TYPE"] = "none"

import server as server_module

def _run(cmd: list[str], *, check: bool = True, capture: bool = False, env: dict | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=capture,
        env=env,
    )


def _compose(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    # Remove DATABASE_URL from the environment for docker-compose to ensure it uses the default from the yml
    compose_env = os.environ.copy()
    compose_env.pop("DATABASE_URL", None)
    return _run(["docker", "compose", "-f", COMPOSE_FILE, *args], check=check, capture=capture, env=compose_env)


@pytest.fixture(scope="module")
def docker_up_down():
    """A pytest fixture that starts and stops the docker-compose services."""
    _compose("up", "-d", "--wait")
    yield
    _compose("down", "-v")


@pytest.fixture
def db_pool(mocker, docker_up_down):
    """A pytest fixture that sets up a database connection pool."""
    # Wait for the database to be ready
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with ConnectionPool(conninfo=DATABASE_URL, min_size=1, max_size=1, open=True) as pool:
                with pool.connection() as conn:
                    conn.execute("SELECT 1")
                break
        except Exception:
            time.sleep(1)
    else:
        pytest.fail("Database did not become available in time.")

    test_pool = ConnectionPool(conninfo=DATABASE_URL, min_size=1, max_size=2, open=False)
    mocker.patch('server.pool', test_pool)
    return test_pool


@pytest.mark.asyncio
async def test_functional_suite(db_pool):
    print("=== Starting Functional Tests ===")
    db_pool.open()
    try:
        # 1. Test Connection
        print("\n1. Testing db_pg96_ping...")
        tool = await server_module.mcp.get_tool('db_pg96_ping')
        result = tool.fn()
        assert result["ok"] is True
        print(f"Result: {result}")

        # 2. Test Server Info
        print("\n2. Testing db_pg96_server_info...")
        tool = await server_module.mcp.get_tool('db_pg96_server_info')
        result = tool.fn()
        assert "version" in result
        print(f"Result: {result}")

        # 3. Get DB Parameters
        print("\n3. Testing db_pg96_get_db_parameters...")
        tool = await server_module.mcp.get_tool('db_pg96_get_db_parameters')
        result = tool.fn()
        assert isinstance(result, list)
        print(f"Result (first 2): {json.dumps(result[:2], indent=2, default=str)}")

        # 4. List Databases
        print("\n4. Testing db_pg96_list_objects (database)...")
        tool = await server_module.mcp.get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="database")
        assert isinstance(result, list)
        print(f"Result (first 2): {json.dumps(result[:2], indent=2, default=str)}")

        # 5. List Schemas
        print("\n5. Testing db_pg96_list_objects (schema)...")
        tool = await server_module.mcp.get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="schema")
        assert isinstance(result, list)
        print(f"Result (first 5): {[r['name'] for r in result[:5]]}")

        # 6. List Tables
        print("\n6. Testing db_pg96_list_objects (table, schema='public')...")
        tool = await server_module.mcp.get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="table", schema="public")
        assert isinstance(result, list)
        print(f"Result (first 5 tables): {[r['name'] for r in result[:5]]}")

        # 7. Run Query
        print("\n7. Testing db_pg96_run_query...")
        tool = await server_module.mcp.get_tool('db_pg96_run_query')
        result = tool.fn("SELECT current_timestamp as now")
        assert isinstance(result, dict)
        assert "returned_rows" in result
        print(f"Result: {result}")

        # 8b. Describe Table
        print("\n8b. Testing db_pg96_describe_table (pg_catalog.pg_class)...")
        tool = await server_module.mcp.get_tool('db_pg96_describe_table')
        result = tool.fn("pg_catalog", "pg_class")
        assert isinstance(result, list)
        print(f"Result (first 2 cols): {json.dumps(result[:2], indent=2, default=str)}")

        # 8c. List Indexes
        print("\n8c. Testing db_pg96_list_objects (index, pg_catalog)...")
        tool = await server_module.mcp.get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="index", schema="pg_catalog")
        assert isinstance(result, list)
        print(f"Result (first 2 indexes): {json.dumps(result[:2], indent=2, default=str)}")

        # 8d. List Functions
        print("\n8d. Testing db_pg96_list_objects (function, pg_catalog)...")
        tool = await server_module.mcp.get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="function", schema="pg_catalog")
        assert isinstance(result, list)
        print(f"Result (first 2 functions): {json.dumps(result[:2], indent=2, default=str)}")

        # 9. Explain Query
        print("\n9. Testing db_pg96_explain_query...")
        tool = await server_module.mcp.get_tool('db_pg96_explain_query')
        result = tool.fn("SELECT 1")
        assert isinstance(result, list)
        print(f"Result: {json.dumps(result, indent=2)}")

        # 10. Analyze Table Health
        print("\n10. Testing db_pg96_analyze_table_health (pg_catalog.pg_class)...")
        tool = await server_module.mcp.get_tool('db_pg96_analyze_table_health')
        result = tool.fn("pg_catalog", "pg_class")
        assert isinstance(result, dict)
        print(f"Result: {json.dumps(result, indent=2, default=str)}")

        # 11. Kill Session (Should fail in read-only mode)
        print("\n11. Testing db_pg96_kill_session (should fail)...")
        try:
            tool = await server_module.mcp.get_tool('db_pg96_kill_session')
            tool.fn(12345)
            assert False, "db_pg96_kill_session should have raised an exception"
        except Exception as e:
            print(f"Expected Error: {e}")

    finally:
        print("\n=== Functional Tests Complete ===")
        db_pool.close()