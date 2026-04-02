import asyncio
import os
import json
import subprocess
import time
import importlib
import sys
from typing import Any, cast

import pytest
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row


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
os.environ["MCP_SKIP_CONFIRMATION"] = "true"
os.environ["MCP_REGISTER_SIGNAL_HANDLERS"] = "false"

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
    compose_env.pop("MCP_TRANSPORT", None)
    compose_env.pop("MCP_ALLOW_WRITE", None)
    compose_env.pop("MCP_CONFIRM_WRITE", None)
    compose_env["MCP_TRANSPORT"] = "http"
    compose_env["MCP_ALLOW_WRITE"] = "false"
    compose_env["MCP_CONFIRM_WRITE"] = "true"
    compose_env["FASTMCP_AUTH_TYPE"] = "none"
    return _run(["docker", "compose", "-f", COMPOSE_FILE, *args], check=check, capture=capture, env=compose_env)


@pytest.fixture(scope="module")
def docker_up_down():
    """A pytest fixture that starts and stops the docker-compose services."""
    _compose("down", "-v", check=False)
    _compose("up", "-d", "--build", "--wait")
    yield
    _compose("down", "-v")


@pytest.fixture
def db_pool(mocker, docker_up_down):
    """A pytest fixture that sets up a database connection pool."""
    global server_module
    if "server" in sys.modules:
        old_server = sys.modules["server"]
        old_pool = getattr(old_server, "pool", None)
        if old_pool is not None and not getattr(old_pool, "closed", False):
            try:
                try:
                    old_pool.close(timeout=15.0)
                except TypeError:
                    old_pool.close()
            except Exception:
                pass
        server_module = importlib.reload(sys.modules["server"])
    else:
        server_module = importlib.import_module("server")

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

    test_pool = ConnectionPool(
        conninfo=DATABASE_URL,
        min_size=1,
        max_size=2,
        open=False,
        kwargs={"row_factory": dict_row},
    )

    # Reloading `server` creates a real module-level pool. Close it before replacing
    # with the fixture pool to avoid orphaned worker threads during test shutdown.
    original_pool = getattr(server_module, "pool", None)
    if original_pool is not None and not getattr(original_pool, "closed", False):
        try:
            try:
                original_pool.close(timeout=15.0)
            except TypeError:
                original_pool.close()
        except Exception:
            pass

    mocker.patch('server.pool', test_pool)
    try:
        yield test_pool
    finally:
        if not getattr(test_pool, "closed", False):
            try:
                try:
                    test_pool.close(timeout=15.0)
                except TypeError:
                    test_pool.close()
            except Exception:
                pass


def test_functional_suite(db_pool):
    print("=== Starting Functional Tests ===")
    def get_tool(name: str) -> Any:
        tool = asyncio.run(server_module.mcp.get_tool(name))
        assert tool is not None, f"Tool '{name}' not found"
        return cast(Any, tool)

    db_pool.open()
    try:
        # 1. Test Connection
        print("\n1. Testing db_pg96_ping...")
        tool = get_tool('db_pg96_ping')
        result = tool.fn()
        assert result["ok"] is True
        print(f"Result: {result}")

        # 2. Test Server Info
        print("\n2. Testing db_pg96_server_info...")
        tool = get_tool('db_pg96_server_info')
        result = tool.fn()
        assert "version" in result
        assert "database" in result
        print(f"Result: {result}")

        # 3. Get DB Parameters
        print("\n3. Testing db_pg96_get_db_parameters...")
        tool = get_tool('db_pg96_get_db_parameters')
        result = tool.fn()
        assert isinstance(result, list)
        print(f"Result (first 2): {json.dumps(result[:2], indent=2, default=str)}")

        # 4. List Databases
        print("\n4. Testing db_pg96_list_objects (database)...")
        tool = get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="database")
        assert isinstance(result, list)
        print(f"Result (first 2): {json.dumps(result[:2], indent=2, default=str)}")

        # 5. List Schemas
        print("\n5. Testing db_pg96_list_objects (schema)...")
        tool = get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="schema")
        assert isinstance(result, list)
        print(f"Result (first 5): {[r['name'] for r in result[:5]]}")

        # 6. List Tables
        print("\n6. Testing db_pg96_list_objects (table, schema='public')...")
        tool = get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="table", schema="public")
        assert isinstance(result, list)
        print(f"Result (first 5 tables): {[r['name'] for r in result[:5]]}")

        # 7. Run Query
        print("\n7. Testing db_pg96_run_query...")
        tool = get_tool('db_pg96_run_query')
        result = tool.fn("SELECT current_timestamp as now")
        assert isinstance(result, dict)
        assert "returned_rows" in result
        print(f"Result: {result}")

        # 8b. Describe Table
        print("\n8b. Testing db_pg96_describe_table (pg_catalog.pg_class)...")
        tool = get_tool('db_pg96_describe_table')
        result = tool.fn("pg_catalog", "pg_class")
        assert isinstance(result, dict)
        assert "columns" in result and isinstance(result["columns"], list)
        print(f"Result (first 2 cols): {json.dumps(result['columns'][:2], indent=2, default=str)}")

        # 8c. List Indexes
        print("\n8c. Testing db_pg96_list_objects (index, pg_catalog)...")
        tool = get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="index", schema="pg_catalog")
        assert isinstance(result, list)
        print(f"Result (first 2 indexes): {json.dumps(result[:2], indent=2, default=str)}")

        # 8d. List Functions
        print("\n8d. Testing db_pg96_list_objects (function, pg_catalog)...")
        tool = get_tool('db_pg96_list_objects')
        result = tool.fn(object_type="function", schema="pg_catalog")
        assert isinstance(result, list)
        print(f"Result (first 2 functions): {json.dumps(result[:2], indent=2, default=str)}")

        # 9. Explain Query
        print("\n9. Testing db_pg96_explain_query...")
        tool = get_tool('db_pg96_explain_query')
        result = tool.fn("SELECT 1")
        assert isinstance(result, dict)
        assert result.get("format") in {"json", "text"}
        print(f"Result: {json.dumps(result, indent=2)}")

        # 10. Analyze Table Health
        print("\n10. Testing db_pg96_analyze_table_health...")
        tool = get_tool('db_pg96_analyze_table_health')
        result = tool.fn(schema="pg_catalog", min_size_mb=1, limit=5)
        assert isinstance(result, dict)
        assert "summary" in result
        print(f"Result: {json.dumps(result, indent=2, default=str)}")

        # 11. Kill Session (Should fail in read-only mode)
        print("\n11. Testing db_pg96_kill_session (should fail)...")
        try:
            tool = get_tool('db_pg96_kill_session')
            tool.fn(12345)
            assert False, "db_pg96_kill_session should have raised an exception"
        except Exception as e:
            print(f"Expected Error: {e}")

    finally:
        print("\n=== Functional Tests Complete ===")
        try:
            db_pool.close(timeout=15.0)
        except TypeError:
            db_pool.close()


def _parse_resource_payload(raw_content: Any) -> dict[str, Any]:
    """Parse FastMCP resource payloads for both wrapped and direct JSON responses."""
    decoded = json.loads(raw_content)
    if isinstance(decoded, dict) and isinstance(decoded.get("contents"), list):
        first_content = decoded["contents"][0] if decoded["contents"] else {}
        inner = first_content.get("content") if isinstance(first_content, dict) else None
        if isinstance(inner, str):
            return json.loads(inner)
    return decoded if isinstance(decoded, dict) else {}

    def test_startup_rejects_legacy_sse_when_disabled(monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        monkeypatch.setenv("MCP_ALLOW_LEGACY_SSE", "false")
        monkeypatch.delenv("FASTMCP_ALLOW_LEGACY_SSE", raising=False)

        calls: list[dict[str, Any]] = []

        def _fake_run(**kwargs):
            calls.append(kwargs)

        monkeypatch.setattr(server_module.mcp, "run", _fake_run)

        expected_message = "Legacy SSE transport is disabled. Set MCP_TRANSPORT=http or set MCP_ALLOW_LEGACY_SSE=true."
        with pytest.raises(ValueError, match="^" + expected_message.replace(".", r"\\.") + "$"):
            server_module.main()

        assert len(calls) == 0


    def test_startup_allows_legacy_sse_when_enabled(monkeypatch):
        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        monkeypatch.setenv("MCP_ALLOW_LEGACY_SSE", "true")

        calls: list[dict[str, Any]] = []

        def _fake_run(**kwargs):
            calls.append(kwargs)

        monkeypatch.setattr(server_module.mcp, "run", _fake_run)

        server_module.main()

        assert len(calls) == 1
        assert calls[0].get("transport") == "sse"
        assert "host" in calls[0]
        assert "port" in calls[0]


def test_resources_prompts_and_async_context_compat(db_pool):
    db_pool.open()
    try:
        resources = asyncio.run(server_module.mcp.list_resources())
        resource_uris = {str(resource.uri) for resource in resources}
        assert "data://server/status" in resource_uris
        assert "data://server/capabilities" in resource_uris
        assert "data://composed/info" in resource_uris

        resource_templates = asyncio.run(server_module.mcp.list_resource_templates())
        template_uris = {
            str(getattr(template, "uriTemplate", getattr(template, "uri_template", "")))
            for template in resource_templates
        }
        assert "data://db/settings{?pattern,limit}" in template_uris

        status_content = asyncio.run(server_module.mcp.read_resource("data://server/status"))
        if isinstance(status_content, list):
            assert len(status_content) >= 1
            status_data = _parse_resource_payload(status_content[0].content)
        else:
            contents = getattr(status_content, "contents", [])
            assert len(contents) >= 1
            status_data = _parse_resource_payload(contents[0].content)
        assert status_data.get("ok") is True
        assert "transport" in status_data
        assert "allow_write" in status_data
        assert "statement_timeout_ms" in status_data
        assert isinstance(status_data.get("database"), dict)

        capabilities_content = asyncio.run(server_module.mcp.read_resource("data://server/capabilities"))
        if isinstance(capabilities_content, list):
            assert len(capabilities_content) >= 1
            capabilities_data = _parse_resource_payload(capabilities_content[0].content)
        else:
            contents = getattr(capabilities_content, "contents", [])
            assert len(contents) >= 1
            capabilities_data = _parse_resource_payload(contents[0].content)
        assert "resource_count" in capabilities_data
        assert "prompt_count" in capabilities_data

        composed_info_content = asyncio.run(server_module.mcp.read_resource("data://composed/info"))
        if isinstance(composed_info_content, list):
            assert len(composed_info_content) >= 1
            composed_info_data = _parse_resource_payload(composed_info_content[0].content)
        else:
            contents = getattr(composed_info_content, "contents", [])
            assert len(contents) >= 1
            composed_info_data = _parse_resource_payload(contents[0].content)
        assert composed_info_data.get("component") == "composition_demo"

        prompts = asyncio.run(server_module.mcp.list_prompts())
        prompt_names = {prompt.name for prompt in prompts}
        assert "explain_slow_query" in prompt_names
        assert "maintenance_recommendations" in prompt_names
        assert "runtime_context_brief" in prompt_names

        explain_result = asyncio.run(
            server_module.mcp.render_prompt(
                "explain_slow_query",
                {"sql": "select 1", "analyze": "false", "buffers": "false"},
            )
        )
        explain_messages = explain_result.messages
        assert isinstance(explain_messages, list)
        assert len(explain_messages) >= 2

        maintenance_result = asyncio.run(
            server_module.mcp.render_prompt("maintenance_recommendations", {"profile": "oltp"})
        )
        maintenance_messages = maintenance_result.messages
        assert isinstance(maintenance_messages, list)
        assert len(maintenance_messages) >= 1

        runtime_context_result = asyncio.run(
            server_module.mcp.render_prompt("runtime_context_brief", {"topic": "autovacuum tuning"})
        )
        runtime_context_messages = runtime_context_result.messages
        assert isinstance(runtime_context_messages, list)
        assert len(runtime_context_messages) >= 1

        for tool_name in (
            "db_pg96_analyze_logical_data_model_async",
            "db_pg96_analyze_indexes_async",
            "db_pg96_analyze_sessions_async",
        ):
            tool = cast(Any, asyncio.run(server_module.mcp.get_tool(tool_name)))
            assert tool is not None
            schema = json.dumps(tool.parameters)
            assert "\"ctx\"" not in schema

        # Verify async tools are discoverable via MCP runtime API.
        discovered_tools = {tool.name for tool in asyncio.run(server_module.mcp.list_tools())}
        assert "db_pg96_analyze_indexes_async" in discovered_tools
        assert "db_pg96_analyze_sessions_async" in discovered_tools
        assert "task_progress_demo" in discovered_tools
        assert "dependency_injection_snapshot" in discovered_tools
        assert "elicitation_collect_maintenance_window" in discovered_tools
        assert "elicitation_create_maintenance_ticket" in discovered_tools
        assert "session_counter" in discovered_tools
        assert "logging_demo" in discovered_tools
        assert "server_runtime_config_snapshot" in discovered_tools
        assert "composed_composition_ping" in discovered_tools
    finally:
        try:
            db_pool.close(timeout=15.0)
        except TypeError:
            db_pool.close()