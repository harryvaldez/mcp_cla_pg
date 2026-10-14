from types import SimpleNamespace

from src.db.connection_manager import ConnectionManager


def test_build_dsn_quotes_special_credentials():
    manager = ConnectionManager.__new__(ConnectionManager)
    manager._secret_resolver = lambda ref: {"username": "u@x", "password": "p:/@w#"}
    instance = SimpleNamespace(
        auth_secret_ref="ref", host="h", port=5444, database="d", sslmode="require"
    )
    dsn = manager._build_dsn(instance)
    assert dsn == "postgresql://u%40x:p%3A%2F%40w%23@h:5444/d?sslmode=require"
