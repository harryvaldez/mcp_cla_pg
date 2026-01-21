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
        "MCP_TRANSPORT": "stdio"
    }
    
    # Run via uv run python server.py
    cmd = ["uv", "run", "python", "server.py"]
    
    print("Starting MCP server via uv...")
    client = MCPClient(cmd, env)
    try:
        print("Initializing...")
        client.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"}
        })
        client.send_notification("notifications/initialized")
        
        tools_to_test = [
            ("ping", {}),
            ("server_info", {}),
            ("list_databases", {}),
            ("list_schemas", {"include_system": False}),
            ("list_tables", {"schema": "public"}),
            ("describe_table", {"schema": "public", "table": "customers"}),
            ("run_query", {"sql": "select count(*) from public.orders"}),
            ("explain_query", {"sql": "select * from public.orders", "format": "text"}),
            ("db_stats", {"database": DB}),
            ("check_bloat", {"limit": 5}),
            ("list_largest_schemas", {"limit": 5}),
            ("analyze_sessions", {}),
            ("analyze_table_health", {"limit": 5}),
            ("database_security_performance_metrics", {}),
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

        username = f"test_uv_user_{int(time.time())}"
        print(f"Testing create_db_user: {username}...")
        client.send_request("tools/call", {
            "name": "create_db_user",
            "arguments": {"username": username, "password": "password123", "privileges": "read", "database": DB}
        })
        print(f"Testing drop_db_user: {username}...")
        client.send_request("tools/call", {
            "name": "drop_db_user",
            "arguments": {"username": username}
        })
        
        print("PASS: All tools tested successfully via uv stdio transport.")
        
    finally:
        client.close()

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
