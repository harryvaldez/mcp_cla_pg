import importlib
import sys
from types import ModuleType
from unittest.mock import MagicMock
import builtins

import pytest


def _build_fake_psycopg_pool(fetch_rows=None):
    pool_instance = MagicMock()
    conn = MagicMock()
    cur = MagicMock()

    pool_instance.connection.return_value.__enter__.return_value = conn
    conn.cursor.return_value.__enter__.return_value = cur

    cur.fetchall.return_value = fetch_rows or []
    return pool_instance


def _import_server_with_fake_pool(monkeypatch, pool_instance):
    monkeypatch.setenv("MCP_SKIP_CONFIRMATION", "true")
    fake_psycopg_pool = ModuleType("psycopg_pool")
    fake_psycopg_pool.ConnectionPool = MagicMock(return_value=pool_instance)
    monkeypatch.setitem(sys.modules, "psycopg_pool", fake_psycopg_pool)

    sys.modules.pop("server", None)
    return importlib.import_module("server")


def test_credential_scope_enforcement_blocks_out_of_scope_tables(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")
    monkeypatch.setenv("MCP_ALLOW_WRITE", "false")
    monkeypatch.setenv("MCP_ENFORCE_TABLE_SCOPE", "true")
    monkeypatch.setenv("MCP_ALLOWED_TABLES", "public.allowed_table")

    fetch_rows = [
        {
            "schema_name": "public",
            "table_name": "allowed_table",
            "can_select": True,
            "can_write": False,
        },
        {
            "schema_name": "public",
            "table_name": "extra_table",
            "can_select": True,
            "can_write": False,
        },
    ]
    pool_instance = _build_fake_psycopg_pool(fetch_rows=fetch_rows)

    with pytest.raises(RuntimeError, match="outside MCP_ALLOWED_TABLES"):
        _import_server_with_fake_pool(monkeypatch, pool_instance)

    sys.modules.pop("server", None)


def test_query_rate_circuit_breaker_opens_after_sustained_rejections(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")
    monkeypatch.setenv("MCP_ALLOW_WRITE", "false")

    pool_instance = _build_fake_psycopg_pool()
    server = _import_server_with_fake_pool(monkeypatch, pool_instance)

    try:
        breaker = server._QueryRateCircuitBreaker(rate_per_minute=1, trip_rejections=2, open_seconds=5)

        breaker.acquire()  # consumes the only token

        with pytest.raises(RuntimeError, match="Rate limit exceeded"):
            breaker.acquire()

        with pytest.raises(RuntimeError, match="Circuit breaker opened"):
            breaker.acquire()

        with pytest.raises(RuntimeError, match="Circuit breaker open"):
            breaker.acquire()
    finally:
        sys.modules.pop("server", None)


def test_audit_policy_requires_source_prompt(monkeypatch, mocker):
    monkeypatch.setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")
    monkeypatch.setenv("MCP_ALLOW_WRITE", "false")
    monkeypatch.setenv("MCP_AUDIT_REQUIRE_PROMPT", "true")

    pool_instance = _build_fake_psycopg_pool()
    server = _import_server_with_fake_pool(monkeypatch, pool_instance)

    try:
        mocker.patch.object(server, "_require_readonly", return_value=True)

        with pytest.raises(ValueError, match="requires source_prompt"):
            server.db_pg96_run_query("SELECT 1")
    finally:
        sys.modules.pop("server", None)


def test_audit_writer_oserror_is_non_fatal(monkeypatch, mocker):
    monkeypatch.setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")
    monkeypatch.setenv("MCP_ALLOW_WRITE", "false")

    pool_instance = _build_fake_psycopg_pool()
    server = _import_server_with_fake_pool(monkeypatch, pool_instance)

    try:
        mock_warning = mocker.patch.object(server.logger, "warning")

        def _raise_oserror(*args, **kwargs):
            raise OSError("disk full")

        mocker.patch.object(builtins, "open", side_effect=_raise_oserror)

        server._write_audit_event(
            tool_name="db_pg96_run_query",
            sql_text="SELECT 1",
            source_prompt="list users",
            params_json=None,
        )

        assert mock_warning.called, "Expected warning log on audit log write failure"
        warning_msg = mock_warning.call_args.args[0]
        assert "Non-fatal audit log write failure" in warning_msg
        assert server.AUDIT_LOG_FILE in warning_msg
    finally:
        sys.modules.pop("server", None)
