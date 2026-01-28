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
            stderr=subprocess.PIPE,
            env={**os.environ, **env},
            text=True,
            bufsize=1,
            shell=False
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
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()

        start = time.time()
        timeout_s = 60.0
        while True:
            if self.proc.poll() is not None:
                stderr_output = ""
                if self.proc.stderr is not None:
                    try:
                        stderr_output = self.proc.stderr.read()
                    except Exception:
                        stderr_output = ""
                raise RuntimeError(f"Server process exited with code {self.proc.returncode}: {stderr_output}")

            if time.time() - start > timeout_s:
                self.proc.kill()
                raise RuntimeError(f"Timed out waiting for response to method {method}")

            assert self.proc.stdout is not None
            line = self.proc.stdout.readline()
            if not line:
                continue
            try:
                resp = json.loads(line)
                if resp.get("id") == req["id"]:
                    if "error" in resp:
                        raise RuntimeError(f"Tool error: {resp['error']}")
                    return resp.get("result", {})
            except json.JSONDecodeError:
                continue

    def send_notification(self, method: str, params: Dict[str, Any] | None = None) -> None:
        notif = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            notif["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(notif) + "\n")
        self.proc.stdin.flush()

    def close(self):
        self.proc.terminate()
        self.proc.wait()

def _test_uv_stdio() -> None:
    env = {
        "DATABASE_URL": f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}",
        "MCP_ALLOW_WRITE": "true",
        "MCP_CONFIRM_WRITE": "true",
        "MCP_TRANSPORT": "stdio"
    }
    
    cmds = [
        ["uv", "run", "python", "server.py"],
        [sys.executable, "server.py"],
    ]

    last_err: Exception | None = None
    for cmd in cmds:
        print(f"Starting MCP server via: {' '.join(cmd)}")
        client = MCPClient(cmd, env)
        try:
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
        
            tools_to_test = [
                ("db_pg96_ping", {}),
                ("db_pg96_server_info", {}),
                ("db_pg96_server_info_mcp", {}),
                ("db_pg96_list_databases", {}),
                ("db_pg96_list_schemas", {"include_system": False}),
                ("db_pg96_list_tables", {"schema": "public"}),
                ("db_pg96_describe_table", {"schema": "public", "table": "customers"}),
                ("db_pg96_run_query", {"sql": "select count(*) from public.orders"}),
                ("db_pg96_explain_query", {"sql": "select * from public.orders", "output_format": "text"}),
                ("db_pg96_db_stats", {"database": DB, "include_performance": True}),
                ("db_pg96_check_bloat", {"limit": 5}),
                ("db_pg96_get_db_parameters", {"pattern": "max_connections|shared_buffers"}),
                ("db_pg96_list_largest_schemas", {"limit": 5}),
                ("db_pg96_list_largest_tables", {"schema": "public", "limit": 5}),
                ("db_pg96_list_temp_objects", {}),
                ("db_pg96_table_sizes", {"schema": "public", "limit": 5}),
                ("db_pg96_index_usage", {"schema": "public", "limit": 5}),
                ("db_pg96_maintenance_stats", {"schema": "public", "limit": 5}),
                ("db_pg96_analyze_sessions", {}),
                ("db_pg96_analyze_table_health", {"schema": "public", "limit": 5, "min_size_mb": 0}),
                ("db_pg96_database_security_performance_metrics", {}),
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
                    raise RuntimeError(f"Tool {name} returned empty result")
                print(f"  Tool {name} OK")

            dsn = f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}"
            victim = psycopg.connect(dsn, autocommit=True)
            try:
                with victim.cursor() as cur:
                    cur.execute("select pg_backend_pid() as pid")
                    pid = cur.fetchone()[0]
                client.send_request("tools/call", {
                    "name": "db_pg96_kill_session",
                    "arguments": {"pid": pid}
                })
            finally:
                try:
                    victim.close()
                except Exception:
                    pass

            username = f"test_uv_user_{int(time.time())}"
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
        
            print("PASS: All tools tested successfully via stdio transport.")
            return
        except Exception as e:
            last_err = e
        finally:
            try:
                client.close()
            except Exception:
                pass
    raise RuntimeError(f"All stdio launch methods failed. Last error: {last_err}")

def main() -> int:
    try:
        print("Starting PostgreSQL 9.6 container...")
        _compose("up", "-d", SERVICE, check=True)
        _wait_for_db(timeout_s=90)
        print("Seeding sample data...")
        _seed_sample_data()
        _test_uv_stdio()
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
