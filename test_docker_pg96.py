import json
import os
import subprocess
import sys
import time
import traceback
import urllib.request
from typing import Any, Dict, List

import psycopg

ROOT = os.path.dirname(os.path.abspath(__file__))
COMPOSE_FILE = os.path.join(ROOT, "docker-compose.yml")
DB_SERVICE = "postgres96"
SERVER_SERVICE = "mcp-postgres"
HOST = "localhost"
DB_PORT = 55432
SERVER_PORT = 8000
DB_NAME = "mcp_test"
USER = "postgres"
PASSWORD = "postgres"

def _run(cmd: List[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=capture,
    )

def _compose(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return _run(["docker", "compose", "-f", COMPOSE_FILE, *args], check=check, capture=capture)

def _wait_for_db(timeout_s: int = 60) -> None:
    deadline = time.time() + timeout_s
    last_err: Exception | None = None
    dsn = f"postgresql://{USER}:{PASSWORD}@{HOST}:{DB_PORT}/{DB_NAME}"
    while time.time() < deadline:
        try:
            with psycopg.connect(dsn, autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("select 1")
                    cur.fetchone()
                    return
        except Exception as e:
            last_err = e
            time.sleep(1)
    raise RuntimeError(f"PostgreSQL did not become ready within {timeout_s}s: {last_err}")

def _seed_sample_data() -> None:
    dsn = f"postgresql://{USER}:{PASSWORD}@{HOST}:{DB_PORT}/{DB_NAME}"
    ddl = """
    create table if not exists public.customers (
      id serial primary key,
      email text not null unique,
      created_at timestamptz not null default now()
    );

    create table if not exists public.orders (
      id serial primary key,
      customer_id int not null references public.customers(id),
      status text not null,
      total_cents int not null,
      created_at timestamptz not null default now()
    );

    create index if not exists idx_orders_customer_created_at on public.orders(customer_id, created_at desc);
    """

    dml = """
    insert into public.customers(email)
    select 'user' || g::text || '@example.com'
    from generate_series(1, 50) as g
    on conflict do nothing;

    insert into public.orders(customer_id, status, total_cents, created_at)
    select
      (random() * 49 + 1)::int,
      (array['new','paid','shipped','cancelled'])[1 + (random()*3)::int],
      (random() * 50000 + 100)::int,
      now() - ((random() * 30)::int || ' days')::interval
    from generate_series(1, 200) as g;
    """

    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(ddl)
            cur.execute(dml)

def _wait_for_server(timeout_s: int = 60) -> None:
    deadline = time.time() + timeout_s
    url = f"http://localhost:{SERVER_PORT}/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url) as response:
                if response.getcode() == 200:
                    return
        except:
            time.sleep(1)
    raise RuntimeError(f"Server did not become ready within {timeout_s}s")

def _test_docker_http() -> None:
    # Test tools via Stateless HTTP transport
    url = f"http://localhost:{SERVER_PORT}/mcp"
    
    print(f"Connecting to /mcp at {url}...")
    req = urllib.request.Request(url)
    # FastMCP streamable HTTP often requires a session
    # Let's try to get one or just use the endpoint directly if stateless
    
    def call_tool(method: str, params: Dict[str, Any], is_notification: bool = False) -> Dict[str, Any]:
        req_data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        if not is_notification:
            req_data["id"] = int(time.time() * 1000)
        
        req = urllib.request.Request(
            url,
            data=json.dumps(req_data).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"
            }
        )
        try:
            with urllib.request.urlopen(req) as response:
                if is_notification:
                    return {}
                
                # Read the response. If it's chunked or SSE, we might need to parse it.
                body = response.read().decode("utf-8")
                if not body:
                    return {}
                
                # If it's a stream of events, look for the 'data: ' line
                if "data: " in body:
                    for line in body.splitlines():
                        if line.startswith("data: "):
                            resp_data = json.loads(line[6:])
                            if "error" in resp_data:
                                raise RuntimeError(f"Tool error: {resp_data['error']}")
                            return resp_data.get("result", {})
                
                # Otherwise try direct JSON
                try:
                    resp_data = json.loads(body)
                    if "error" in resp_data:
                        raise RuntimeError(f"Tool error: {resp_data['error']}")
                    return resp_data.get("result", {})
                except:
                    print(f"Failed to parse body as JSON: {body}")
                    raise
        except urllib.error.HTTPError as e:
            print(f"HTTP Error {e.code}: {e.reason}")
            try:
                print(f"Response body: {e.read().decode('utf-8')}")
            except:
                pass
            raise

    # 1. Initialize
    print("Initializing...")
    call_tool("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "1.0.0"}
    })
    
    print("Sending initialized notification...")
    call_tool("notifications/initialized", {}, is_notification=True)

    tools_list = call_tool("tools/list", {})
    tools = tools_list.get("tools", [])
    if not isinstance(tools, list) or not tools:
        raise RuntimeError("tools/list returned no tools")
    tool_names = {t.get("name") for t in tools if isinstance(t, dict)}
    if "db_pg96_ping" not in tool_names:
        raise RuntimeError("tools/list missing db_pg96_ping")

    tools_to_test = [
        ("db_pg96_ping", {}),
        ("db_pg96_server_info", {}),
        ("db_pg96_server_info_mcp", {}),
        ("db_pg96_list_objects", {"object_type": "database"}),
        ("db_pg96_list_objects", {"object_type": "schema"}),
        ("db_pg96_list_objects", {"object_type": "table", "schema": "public"}),
        ("db_pg96_describe_table", {"schema": "public", "table": "customers"}),
        ("db_pg96_run_query", {"sql": "select count(*) from public.orders"}),
        ("db_pg96_explain_query", {"sql": "select * from public.orders", "output_format": "text"}),
        ("db_pg96_db_stats", {"database": DB_NAME, "include_performance": True}),
        ("db_pg96_check_bloat", {"limit": 5}),
        ("db_pg96_get_db_parameters", {"pattern": "max_connections|shared_buffers"}),
        ("db_pg96_list_objects", {"object_type": "schema", "order_by": "size"}),
        ("db_pg96_analyze_sessions", {}),
        ("db_pg96_analyze_table_health", {"schema": "public", "limit": 5, "min_size_mb": 0}),
        ("db_pg96_database_security_performance_metrics", {}),
        ("db_pg96_analyze_indexes", {"schema": "public"}),
        ("db_pg96_analyze_logical_data_model", {"schema": "public", "max_entities": 50}),
        ("db_pg96_list_objects", {"object_type": "table", "schema": "public", "order_by": "size"}),
        ("db_pg96_list_objects", {"object_type": "temp_object"}),
        ("db_pg96_list_objects", {"object_type": "table", "schema": "public", "order_by": "size", "limit": 5}),
        ("db_pg96_list_objects", {"object_type": "index", "schema": "public", "order_by": "scans", "limit": 5}),
        ("db_pg96_list_objects", {"object_type": "table", "schema": "public", "order_by": "dead_tuples", "limit": 5}),
        ("db_pg96_recommend_partitioning", {"min_size_gb": 0.000001, "schema": "public", "limit": 10}),
    ]

    for name, params in tools_to_test:
        print(f"Testing tool: {name}...")
        result = call_tool("tools/call", {"name": name, "arguments": params})
        print(f"  Tool {name} OK")

    # Test write operations
    username = f"test_docker_user_{int(time.time())}"
    print(f"Testing db_pg96_create_db_user: {username}...")
    call_tool("tools/call", {"name": "db_pg96_create_db_user", "arguments": {"username": username, "password": "password123", "privileges": "read", "database": DB_NAME}})
    print(f"Testing db_pg96_drop_db_user: {username}...")
    call_tool("tools/call", {"name": "db_pg96_drop_db_user", "arguments": {"username": username}})

    dsn = f"postgresql://{USER}:{PASSWORD}@{HOST}:{DB_PORT}/{DB_NAME}"
    victim = psycopg.connect(dsn, autocommit=True)
    try:
        with victim.cursor() as cur:
            cur.execute("select pg_backend_pid()")
            pid = cur.fetchone()[0]
        call_tool("tools/call", {"name": "db_pg96_kill_session", "arguments": {"pid": pid}})
    finally:
        try:
            victim.close()
        except Exception:
            pass

    print("PASS: All tools tested successfully via Docker Stateless HTTP transport.")

def main() -> int:
    try:
        print("Starting stack via Docker Compose...")
        # Run the container in HTTP mode with write enabled
        # We explicitly set auth to "none" to pass the new security check for testing
        os.environ["DATABASE_URL"] = f"postgresql://{USER}:{PASSWORD}@{DB_SERVICE}:5432/{DB_NAME}"
        os.environ["MCP_ALLOW_WRITE"] = "true"
        os.environ["MCP_CONFIRM_WRITE"] = "true"
        os.environ["MCP_TRANSPORT"] = "http"
        os.environ["FASTMCP_AUTH_TYPE"] = "none"
        os.environ["MCP_STATELESS"] = "true"
        os.environ["MCP_JSON_RESPONSE"] = "true"
        
        _compose("up", "-d", "--build", check=True)
        
        print("Waiting for database...")
        _wait_for_db(timeout_s=90)
        
        print("Seeding sample data...")
        _seed_sample_data()
        
        print("Waiting for server...")
        _wait_for_server(timeout_s=60)
        
        _test_docker_http()
        return 0
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        print("--- SERVER LOGS ---")
        _compose("logs", SERVER_SERVICE, check=False)
        print("-------------------")
        traceback.print_exc()
        return 1
    finally:
        print("Cleaning up stack...")
        _compose("down", "-v", check=False)

if __name__ == "__main__":
    sys.exit(main())
