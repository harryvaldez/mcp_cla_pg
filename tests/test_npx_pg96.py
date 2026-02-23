import json
import os
import subprocess
import sys
import time
import traceback
from typing import Any, Dict, List

import psycopg

ROOT = os.path.dirname(os.path.abspath(__file__))
COMPOSE_FILE = os.path.join(ROOT, "docker-compose.yml")
SERVICE = "postgres96"
HOST = "localhost"
PORT = 55432
DB = "mcp_test"
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
    dsn = f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}"
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
    dsn = f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}"
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

class MCPClient:
    def __init__(self, cmd: List[str], env: Dict[str, str]):
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr, # Pipe server stderr to our stderr for visibility
            env={**os.environ, **env},
            text=True,
            bufsize=1,
            shell=sys.platform == "win32"
        )
        self.request_id = 1

    def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        req = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }
        self.request_id += 1
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        
        # Read lines until we get a response with the right ID
        deadline = time.time() + 15 # 15 second timeout per request
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"Server process exited prematurely while waiting for response to request {req['id']}")
            try:
                resp = json.loads(line)
                if resp.get("id") == req["id"]:
                    if "error" in resp:
                        raise RuntimeError(f"Tool error: {resp['error']}")
                    return resp.get("result", {})
                # Ignore notifications or other messages for now
            except json.JSONDecodeError:
                continue
        raise TimeoutError(f"Timeout waiting for response to request {req['id']}")

    def send_notification(self, method: str, params: Dict[str, Any] | None = None) -> None:
        notif = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            notif["params"] = params
        self.proc.stdin.write(json.dumps(notif) + "\n")
        self.proc.stdin.flush()

    def close(self):
        self.proc.terminate()
        self.proc.wait()

def _test_npx_stdio() -> None:
    env = {
        "DATABASE_URL": f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}",
        "MCP_ALLOW_WRITE": "true",
        "MCP_CONFIRM_WRITE": "true",
        "MCP_TRANSPORT": "stdio"
    }
    
    # Run npx . which runs bin/mcp-postgres.js
    # We use 'npx' command which should be in PATH
    cmd = ["npx", ".", "--no-banner"] # FastMCP might support --no-banner
    
    print("Starting MCP server via npx...")
    client = MCPClient(cmd, env)
    try:
        # 1. Initialize
        print("Initializing...")
        client.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"}
        })
        client.send_notification("notifications/initialized")

        tools_list = client.send_request("tools/list", {})
        tools = tools_list.get("tools", [])
        if not isinstance(tools, list) or not tools:
            raise RuntimeError("tools/list returned no tools")
        tool_names = {t.get("name") for t in tools if isinstance(t, dict)}
        if "db_pg96_ping" not in tool_names:
            raise RuntimeError("tools/list missing db_pg96_ping")
        
        # 2. Test Tools
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
            ("db_pg96_db_stats", {"database": DB, "include_performance": True}),
            ("db_pg96_check_bloat", {"limit": 5}),
            ("db_pg96_get_db_parameters", {"pattern": "max_connections|shared_buffers"}),
            ("db_pg96_list_objects", {"object_type": "schema", "order_by": "size"}),
            ("db_pg96_list_objects", {"object_type": "table", "schema": "public", "order_by": "size"}),
            ("db_pg96_list_objects", {"object_type": "temp_object"}),
            ("db_pg96_list_objects", {"object_type": "table", "schema": "public", "order_by": "size", "limit": 5}),
            ("db_pg96_list_objects", {"object_type": "index", "schema": "public", "order_by": "scans", "limit": 5}),
            ("db_pg96_list_objects", {"object_type": "table", "schema": "public", "order_by": "dead_tuples", "limit": 5}),
            ("db_pg96_analyze_sessions", {}),
            ("db_pg96_analyze_table_health", {"schema": "public", "limit": 5, "min_size_mb": 0}),
            ("db_pg96_db_sec_perf_metrics", {}),
            ("db_pg96_analyze_indexes", {"schema": "public"}),
            ("db_pg96_analyze_logical_data_model", {"schema": "public", "max_entities": 50, "include_attributes": True}),
            ("db_pg96_recommend_partitioning", {"min_size_gb": 0.000001, "schema": "public", "limit": 10}),
        ]
        
        for name, params in tools_to_test:
            print(f"Testing tool: {name}...")
            result = client.send_request("tools/call", {
                "name": name,
                "arguments": params
            })
            if result is None:
                raise RuntimeError(f"Tool {name} returned null/missing result")
            print(f"  Tool {name} OK")

        # Test kill_session
        print("Testing kill_session...")
        # We need a victim session. Let's create one.
        dsn = f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}"
        victim = psycopg.connect(dsn, autocommit=True)
        try:
            with victim.cursor() as cur:
                cur.execute("select pg_backend_pid()")
                victim_pid = cur.fetchone()[0]
                print(f"  Victim PID: {victim_pid}")
                
            kill_result = client.send_request("tools/call", {
                "name": "db_pg96_kill_session",
                "arguments": {"pid": victim_pid}
            })
            if not kill_result:
                raise RuntimeError("kill_session returned an empty result")
            print("  Tool kill_session OK")
        finally:
            try:
                victim.close()
            except:
                pass

        # Test write operations
        username = f"test_npx_user_{int(time.time())}"
        print(f"Testing db_pg96_create_db_user: {username}...")
        client.send_request("tools/call", {
            "name": "db_pg96_create_db_user",
            "arguments": {"username": username, "password": "password123", "privileges": "read", "database": DB}
        })
        print(f"Testing db_pg96_drop_db_user: {username}...")
        client.send_request("tools/call", {
            "name": "db_pg96_drop_db_user",
            "arguments": {"username": username}
        })
        
        print("PASS: All tools tested successfully via npx stdio transport.")
        
    finally:
        client.close()

def main() -> int:
    try:
        print("Starting PostgreSQL 9.6 container...")
        _compose("up", "-d", SERVICE, check=True)
        _wait_for_db(timeout_s=90)
        print("Seeding sample data...")
        _seed_sample_data()
        _test_npx_stdio()
        return 0
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1
    finally:
        print("Cleaning up container...")
        _compose("down", "-v", check=False)

if __name__ == "__main__":
    sys.exit(main())
