import os
import subprocess
import sys
import time
import traceback
import ast
from typing import Any

import pytest
import psycopg


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
COMPOSE_FILE = os.path.join(ROOT, "docker-compose.yml")
SERVER_FILE = os.path.join(ROOT, "server.py")
SERVICE = "postgres96"
HOST = "localhost"
PORT = 15432
DB = "mcp_test"
USER = "postgres"
PASSWORD = "postgres"

EXPECTED_TOOLS = [
    "db_pg96_analyze_indexes",
    "db_pg96_analyze_logical_data_model",
    "db_pg96_analyze_sessions",
    "db_pg96_analyze_table_health",
    "db_pg96_check_bloat",
    "db_pg96_create_db_user",
    "db_pg96_db_sec_perf_metrics",
    "db_pg96_database_security_performance_metrics",
    "db_pg96_alter_object",
    "db_pg96_create_object",
    "db_pg96_drop_object",
    "db_pg96_db_stats",
    "db_pg96_describe_table",
    "db_pg96_drop_db_user",
    "db_pg96_explain_query",
    "db_pg96_get_db_parameters",
    "db_pg96_kill_session",
    "db_pg96_list_objects",
    "db_pg96_monitor_sessions",
    "db_pg96_ping",
    "db_pg96_recommend_partitioning",
    "db_pg96_run_query",
    "db_pg96_server_info",
    "db_pg96_server_info_mcp",
]


def _run(cmd: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=capture,
    )


def _compose(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    compose_env = os.environ.copy()
    compose_env.pop("DATABASE_URL", None)
    compose_env.pop("MCP_TRANSPORT", None)
    compose_env.pop("MCP_ALLOW_WRITE", None)
    compose_env.pop("MCP_CONFIRM_WRITE", None)
    compose_env["MCP_TRANSPORT"] = "http"
    compose_env["MCP_ALLOW_WRITE"] = "false"
    compose_env["MCP_CONFIRM_WRITE"] = "true"
    compose_env["FASTMCP_AUTH_TYPE"] = "none"
    return subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, *args],
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=capture,
        env=compose_env,
    )

def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "info"], cwd=ROOT, check=True, text=True, capture_output=True, timeout=5)
        return True
    except Exception:
        return False

def _scan_server_tools() -> list[str]:
    with open(SERVER_FILE, "r", encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src, filename=SERVER_FILE)
    tools: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        has_tool_decorator = False
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "mcp"
                and target.attr == "tool"
            ):
                has_tool_decorator = True
                break
            if isinstance(target, ast.Name) and target.id == "tool":
                has_tool_decorator = True
                break
        if has_tool_decorator and node.name.startswith("db_pg96_"):
            tools.append(node.name)
    return sorted(set(tools))

def _static_inventory_check() -> None:
    discovered = _scan_server_tools()
    expected = sorted(set(EXPECTED_TOOLS))
    missing = [t for t in expected if t not in discovered]
    extra = [t for t in discovered if t not in expected]
    _assert(not missing, f"Expected tools missing from server.py: {missing}")
    _assert(not extra, f"Unexpected tools found in server.py: {extra}")


def _assert_async_context_injection_contract() -> None:
    with open(SERVER_FILE, "r", encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src, filename=SERVER_FILE)

    expected_positional_prefix: dict[str, list[str]] = {
        "db_pg96_analyze_logical_data_model_async": [
            "schema",
            "include_views",
            "max_entities",
            "include_attributes",
            "detail_level",
            "response_format",
            "progress",
        ],
        "db_pg96_analyze_indexes_async": [
            "schema",
            "detail_level",
            "max_items_per_category",
            "response_format",
            "progress",
        ],
        "db_pg96_analyze_sessions_async": [
            "include_idle",
            "include_active",
            "include_locked",
            "min_duration_seconds",
            "min_idle_seconds",
            "progress",
        ],
    }

    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef)
    }

    for fn_name, prefix in expected_positional_prefix.items():
        fn = functions.get(fn_name)
        _assert(fn is not None, f"Expected async function '{fn_name}' not found")
        args = [arg.arg for arg in fn.args.args]
        _assert(
            args[: len(prefix)] == prefix,
            f"Unexpected leading parameters for {fn_name}: {args}",
        )
        _assert(args[-1] == "ctx", f"Expected trailing ctx parameter for {fn_name}: {args}")

        default = fn.args.defaults[-1] if fn.args.defaults else None
        _assert(
            isinstance(default, ast.Call)
            and isinstance(default.func, ast.Name)
            and default.func.id == "CurrentContext",
            f"Expected CurrentContext() default for {fn_name}.ctx",
        )


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

    create table if not exists public.order_items (
      id serial primary key,
      order_id int not null references public.orders(id),
      sku text not null,
      qty int not null,
      unit_cents int not null
    );

    create index if not exists idx_orders_customer_created_at on public.orders(customer_id, created_at desc);
    create index if not exists idx_order_items_order_id on public.order_items(order_id);

    truncate public.customers, public.orders, public.order_items restart identity cascade;
    """

    dml = """
    insert into public.customers(email)
    select 'user' || g::text || '@example.com'
    from generate_series(1, 200) as g
    on conflict do nothing;

    insert into public.orders(customer_id, status, total_cents, created_at)
    select
      (random() * 199 + 1)::int,
      (array['new','paid','shipped','cancelled'])[1 + (random()*3)::int],
      (random() * 50000 + 100)::int,
      now() - ((random() * 30)::int || ' days')::interval
    from generate_series(1, 5000) as g;

    insert into public.order_items(order_id, sku, qty, unit_cents)
    select
      (random() * 4999 + 1)::int,
      'sku-' || (random() * 50)::int,
      (random() * 5 + 1)::int,
      (random() * 10000 + 50)::int
    from generate_series(1, 20000) as g;

    delete from public.order_items where id in (
      select id from public.order_items order by id desc limit 2000
    );
    """

    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(ddl)
            cur.execute(dml)


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _invoke(server_module: Any, tool_name: str, kwargs: dict[str, Any] | None = None) -> Any:
    kwargs = kwargs or {}
    tool_obj = getattr(server_module, tool_name)
    # Prefer explicit wrapped callables to avoid version-dependent __call__ behavior
    # on FastMCP tool wrapper objects.
    for attr in ("fn", "func", "function", "_fn", "callable"):
        inner = getattr(tool_obj, attr, None)
        if callable(inner):
            return inner(**kwargs)
    if callable(tool_obj):
        return tool_obj(**kwargs)
    run = getattr(tool_obj, "run", None)
    if callable(run):
        try:
            return run(**kwargs)
        except TypeError:
            return run(kwargs)
    raise TypeError(f"Tool {tool_name} is not callable and has no known callable attribute")


def _coerce_rows(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        for key in ("rows", "data", "result", "items"):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
    return []


def _call_all_tools() -> None:
    os.environ["DATABASE_URL"] = f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}"
    os.environ["MCP_ALLOW_WRITE"] = "true"
    os.environ["MCP_CONFIRM_WRITE"] = "true"
    os.environ["MCP_TRANSPORT"] = "stdio"
    os.environ["MCP_SKIP_CONFIRMATION"] = "true"
    os.environ["MCP_REGISTER_SIGNAL_HANDLERS"] = "false"

    if "server" in sys.modules:
        del sys.modules["server"]

    sys.path.insert(0, ROOT)
    import server  # noqa: E402
    sys.path.pop(0)

    missing = [name for name in sorted(set(EXPECTED_TOOLS)) if not hasattr(server, name)]
    _assert(not missing, f"Missing expected tools: {missing}")

    result = _invoke(server, "db_pg96_ping")
    _assert(isinstance(result, dict) and result.get("ok") is True, "ping did not return ok=true")

    info = _invoke(server, "db_pg96_server_info")
    _assert(isinstance(info, dict) and "version" in info, "server_info missing version")

    info_mcp = _invoke(server, "db_pg96_server_info_mcp")
    _assert(isinstance(info_mcp, dict) and info_mcp.get("status") == "healthy", "server_info_mcp returned unexpected shape")

    params = _invoke(server, "db_pg96_get_db_parameters", {"pattern": "max_connections|shared_buffers"})
    param_rows = _coerce_rows(params)
    _assert(
        len(param_rows) >= 1,
        f"get_db_parameters(pattern) returned no rows (type={type(params).__name__})",
    )

    dbs = _invoke(server, "db_pg96_list_objects", {"object_type": "database"})
    _assert(isinstance(dbs, list) and any(r.get("name") == DB for r in dbs), "list_objects(database) did not include test database")

    schemas = _invoke(server, "db_pg96_list_objects", {"object_type": "schema"})
    schema_names = [s.get("name") for s in schemas]
    _assert(isinstance(schemas, list) and "public" in schema_names, "list_objects(schema) did not include public")

    tables = _invoke(server, "db_pg96_list_objects", {"object_type": "table", "schema": "public"})
    table_names = {t.get("name") for t in tables}
    _assert("customers" in table_names and "orders" in table_names, "list_objects(table) missing sample tables")

    desc = _invoke(server, "db_pg96_describe_table", {"schema": "public", "table": "customers"})
    _assert(desc.get("table") == "customers", "describe_table returned wrong table")
    _assert(isinstance(desc.get("columns"), list) and len(desc["columns"]) > 0, "describe_table returned no columns")

    q = _invoke(server, "db_pg96_run_query", {"sql": "select count(*) as n from public.orders"})
    _assert(q.get("returned_rows") == 1, "run_query did not return 1 row for count(*)")

    plan = _invoke(
        server,
        "db_pg96_explain_query",
        {"sql": "select * from public.orders where customer_id = 1 order by created_at desc limit 10", "output_format": "json"},
    )
    _assert(plan.get("format") == "json", "explain_query did not return json format")

    stats = _invoke(server, "db_pg96_db_stats", {"database": DB, "include_performance": True})
    _assert(isinstance(stats, dict) and stats.get("database") == DB, "db_stats returned wrong database")

    bloat = _invoke(server, "db_pg96_check_bloat", {"limit": 10})
    _assert(isinstance(bloat, list), "check_bloat did not return a list")

    largest_schemas = _invoke(server, "db_pg96_list_objects", {"object_type": "schema", "order_by": "size", "limit": 10})
    _assert(isinstance(largest_schemas, list) and len(largest_schemas) > 0, "list_objects(schema, size) failed")

    sessions = _invoke(server, "db_pg96_analyze_sessions", {"min_duration_seconds": 0, "min_idle_seconds": 0})
    _assert(isinstance(sessions, dict) and "summary" in sessions, "analyze_sessions returned unexpected shape")

    health = _invoke(server, "db_pg96_analyze_table_health", {"schema": "public", "min_size_mb": 0, "limit": 10})
    _assert(isinstance(health, dict) and "tables" in health, "analyze_table_health returned unexpected shape")

    secperf = _invoke(server, "db_pg96_db_sec_perf_metrics")
    _assert(isinstance(secperf, dict) and "issues_found" in secperf, "db_sec_perf_metrics returned unexpected shape")

    secperf_full = _invoke(server, "db_pg96_database_security_performance_metrics")
    _assert(
        isinstance(secperf_full, dict) and "issues_found" in secperf_full,
        "database_security_performance_metrics returned unexpected shape",
    )

    username = f"mcp_test_user_{int(time.time())}"
    created = _invoke(
        server,
        "db_pg96_create_db_user",
        {"username": username, "password": "testpass123", "privileges": "read", "database": DB},
    )
    _assert(isinstance(created, str) and username in created, "create_db_user did not return success string")

    dropped = _invoke(server, "db_pg96_drop_db_user", {"username": username})
    _assert(isinstance(dropped, str) and username in dropped, "drop_db_user did not return success string")

    # Test create_db_user with default database (None)
    username_def = f"mcp_test_user_def_{int(time.time())}"
    created_def = _invoke(
        server,
        "db_pg96_create_db_user",
        {"username": username_def, "password": "testpass123", "privileges": "read"},
    )
    _assert(isinstance(created_def, str) and username_def in created_def, "create_db_user (default db) failed")
    
    dropped_def = _invoke(server, "db_pg96_drop_db_user", {"username": username_def})
    _assert(isinstance(dropped_def, str) and username_def in dropped_def, "drop_db_user (default db) failed")

    dsn = f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}"
    victim = psycopg.connect(dsn, autocommit=True)
    try:
        with victim.cursor() as cur:
            cur.execute("select pg_backend_pid() as pid")
            pid = cur.fetchone()[0]
        killed = _invoke(server, "db_pg96_kill_session", {"pid": pid})
        _assert(isinstance(killed, dict) and killed.get("pid") == pid, "kill_session did not echo pid")

        # Additional tools added recently
        idx_stats = _invoke(server, "db_pg96_analyze_indexes", {"schema": "public"})
        _assert(isinstance(idx_stats, dict) and "unused_indexes" in idx_stats, "analyze_indexes failed")

        model = _invoke(server, "db_pg96_analyze_logical_data_model", {"schema": "public", "max_entities": 50, "include_attributes": True})
        _assert(isinstance(model, dict) and "summary" in model, "analyze_logical_data_model failed")

        largest_tables = _invoke(server, "db_pg96_list_objects", {"object_type": "table", "schema": "public", "order_by": "size", "limit": 5})
        _assert(isinstance(largest_tables, list) and len(largest_tables) > 0, "list_objects(table, size) failed")

        temp_objs = _invoke(server, "db_pg96_list_objects", {"object_type": "temp_object"})
        _assert(isinstance(temp_objs, list), "list_objects(temp_object) failed")

        i_usage = _invoke(server, "db_pg96_list_objects", {"object_type": "index", "schema": "public", "order_by": "scans", "limit": 5})
        _assert(isinstance(i_usage, list) and len(i_usage) > 0, "list_objects(index, scans) failed")

        m_stats = _invoke(server, "db_pg96_list_objects", {"object_type": "table", "schema": "public", "order_by": "dead_tuples", "limit": 5})
        _assert(isinstance(m_stats, list) and len(m_stats) > 0, "list_objects(table, dead_tuples) failed")

        p_reco = _invoke(server, "db_pg96_recommend_partitioning", {"min_size_gb": 0.000001, "schema": "public", "limit": 10})
        _assert(isinstance(p_reco, dict) and "candidates" in p_reco, "recommend_partitioning failed")
    finally:
        try:
            victim.close()
        except Exception:
            pass

    try:
        try:
            server.pool.close(timeout=15.0)
        except TypeError:
            server.pool.close()
    except Exception:
        pass


@pytest.mark.skipif(not _docker_available(), reason="Docker is not available")
def test_full_suite():
    _static_inventory_check()
    _assert_async_context_injection_contract()
    print("✅ Static tool inventory matches expected list")

    _compose("down", "-v", "--remove-orphans", check=False)
    _compose("up", "-d", "--build")
    try:
        print("Waiting for database to be ready...")
        _wait_for_db()
        print("✅ Database is ready")

        print("Seeding sample data...")
        _seed_sample_data()
        print("✅ Sample data seeded")

        print("Running tool tests...")
        _call_all_tools()
        print("✅ All tools called successfully")
    finally:
        _compose("down", "-v", "--remove-orphans")

def test_transport_gate_changes_do_not_modify_db_pg96_contract(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "http")

    import importlib
    import server as server_module_local

    server_module_local = importlib.reload(server_module_local)

    ping_result = server_module_local.db_pg96_ping()
    assert "ok" in ping_result
    assert isinstance(ping_result["ok"], bool)

    info_result = server_module_local.db_pg96_server_info()
    assert isinstance(info_result, dict)
    assert "version" in info_result
    assert "database" in info_result
