from __future__ import annotations

from contextlib import asynccontextmanager

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
        database="edb",
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
async def test_acquire_lazy_init_error_includes_root_cause(monkeypatch):
    async def _create_pool(**kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr("src.db.connection_manager.asyncpg.create_pool", _create_pool)

    manager = ConnectionManager([_instance()], secret_resolver=_secret_resolver)

    with pytest.raises(RuntimeError) as exc:
        async with manager.acquire("primary"):
            pass

    assert "Failed to initialize pool for instance 'primary': connection refused" in str(exc.value)
    assert manager._health["primary"]["state"] == "error"
