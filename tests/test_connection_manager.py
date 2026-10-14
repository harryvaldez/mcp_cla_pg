from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import pytest

from src.db.connection_manager import ConnectionManager
from src.models import EdbInstanceConfig


class _FakePool:
    @asynccontextmanager
    async def acquire(self):
        yield object()


def _instance() -> EdbInstanceConfig:
    return EdbInstanceConfig(
        id="primary",
        host="localhost",
        port=5444,
        database="lenexa",
        auth_secret_ref="secret/pg/primary",
        sslmode="require",
        pool_min=1,
        pool_max=2,
        command_timeout_sec=5,
        enabled=True,
    )


def _secret_resolver(_: str) -> dict[str, str]:
    return {"username": "u", "password": "p"}


@pytest.mark.asyncio
async def test_acquire_lazy_init_success(monkeypatch):
    async def _create_pool(**kwargs):
        return _FakePool()

    monkeypatch.setattr("src.db.connection_manager.asyncpg.create_pool", _create_pool)

    manager = ConnectionManager([_instance()], secret_resolver=_secret_resolver)

    async with manager.acquire("primary"):
        pass

    assert "primary" in manager._pools
    assert manager._health["primary"]["state"] == "initialized"


@pytest.mark.asyncio
async def test_acquire_lazy_init_error_does_not_expose_connection_details(monkeypatch):
    async def _create_pool(**kwargs):
        raise RuntimeError("connection refused at secret.example:5444")

    monkeypatch.setattr("src.db.connection_manager.asyncpg.create_pool", _create_pool)

    manager = ConnectionManager([_instance()], secret_resolver=_secret_resolver)

    with pytest.raises(RuntimeError) as exc:
        async with manager.acquire("primary"):
            pass

    assert "Failed to initialize pool for instance 'primary'" in str(exc.value)
    assert "secret.example" not in str(exc.value)
    assert "connection refused" not in str(exc.value)
    assert manager._health["primary"]["state"] == "error"


def test_is_ssl_enforced_requires_tls_for_every_instance():
    primary = _instance()
    secondary = _instance().model_copy(update={"id": "secondary", "sslmode": "verify-full"})
    manager = ConnectionManager([primary, secondary], secret_resolver=_secret_resolver)
    assert manager.is_ssl_enforced() is True

    plaintext = _instance().model_copy(update={"sslmode": "prefer"})
    manager = ConnectionManager([primary, plaintext], secret_resolver=_secret_resolver)
    assert manager.is_ssl_enforced() is False

    manager = ConnectionManager([], secret_resolver=_secret_resolver)
    assert manager.is_ssl_enforced() is False


def test_pool_diagnostics_use_public_pool_api():
    manager = ConnectionManager([_instance()], secret_resolver=_secret_resolver)

    class _Pool:
        def get_min_size(self):
            return 1

        def get_max_size(self):
            return 4

        def get_size(self):
            return 3

        def get_idle_size(self):
            return 2

    manager._pools["primary"] = _Pool()
    assert manager.get_pool_diagnostics() == {
        "primary": {"min_size": 1, "max_size": 4, "size": 3, "free": 2}
    }


@pytest.mark.asyncio
async def test_close_all_pools_closes_every_pool_and_reports_failures(caplog):
    manager = ConnectionManager([_instance()], secret_resolver=_secret_resolver)
    failed_pool = AsyncMock()
    failed_pool.close.side_effect = OSError("secret host detail")
    successful_pool = AsyncMock()
    manager._pools = {"primary": failed_pool, "secondary": successful_pool}

    caplog.set_level("ERROR")
    with pytest.raises(RuntimeError, match="primary"):
        await manager.close_all_pools()

    failed_pool.close.assert_awaited_once()
    successful_pool.close.assert_awaited_once()
    assert manager._pools == {}
    assert "secret host detail" not in caplog.text
