from __future__ import annotations

import asyncio
import contextlib
import ssl
import threading
import time
from collections.abc import Callable
from typing import Any

import asyncpg

from src.models import EdbInstanceConfig


class ConnectionManager:
    """Manages independent asyncpg connection pools for each EDBAS instance."""

    def __init__(
        self,
        instances: list[EdbInstanceConfig],
        secret_resolver: Callable[[str], dict[str, str]],
    ):
        self._instances: dict[str, EdbInstanceConfig] = {
            item.id: item for item in instances if item.enabled
        }
        self._secret_resolver = secret_resolver
        self._lock = threading.RLock()
        self._pools: dict[str, asyncpg.Pool] = {}
        self._health: dict[str, dict[str, Any]] = {
            k: {"state": "unknown", "checked_at": None, "error": None} for k in self._instances
        }

    def _build_dsn(self, instance: EdbInstanceConfig) -> str:
        """Construct asyncpg DSN from instance configuration."""
        creds = self._secret_resolver(instance.auth_secret_ref)
        user = creds.get("username", "")
        password = creds.get("password", "")
        return (
            f"postgresql://{user}:{password}@"
            f"{instance.host}:{instance.port}/"
            f"{instance.database}"
            f"?sslmode={instance.sslmode}"
        )

    def _build_ssl_context(self, instance: EdbInstanceConfig) -> ssl.SSLContext | None:
        """Build SSL context based on sslmode setting."""
        if instance.sslmode in ("disable", "allow", "prefer"):
            return None
        ctx = ssl.create_default_context()
        if instance.sslmode in ("require",):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif instance.sslmode in ("verify-ca",):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
        elif instance.sslmode in ("verify-full",):
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    async def _initialize_pool_for_instance(
        self, instance_id: str, instance: EdbInstanceConfig
    ) -> asyncpg.Pool:
        """Create and store a connection pool for a specific instance."""
        pool = await asyncpg.create_pool(
            dsn=self._build_dsn(instance),
            min_size=instance.pool_min,
            max_size=instance.pool_max,
            command_timeout=instance.command_timeout_sec,
            ssl=self._build_ssl_context(instance),
        )
        self._pools[instance_id] = pool
        self._health[instance_id] = {
            "state": "initialized",
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "error": None,
        }
        return pool

    async def initialize_pools(self) -> None:
        """Create connection pools for all enabled instances."""
        for instance_id, instance in self._instances.items():
            try:
                await self._initialize_pool_for_instance(instance_id, instance)
            except Exception as exc:
                self._health[instance_id] = {
                    "state": "error",
                    "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "error": str(exc),
                }

    @contextlib.asynccontextmanager
    async def acquire(self, instance_id: str):
        """Acquire a connection from the specified instance's pool."""
        pool = self._pools.get(instance_id)
        if pool is None:
            instance = self._instances.get(instance_id)
            if instance is None:
                raise RuntimeError(f"Unknown instance '{instance_id}'")

            try:
                # Lazy init makes tools resilient when startup pool init was skipped/failed.
                pool = await self._initialize_pool_for_instance(instance_id, instance)
            except Exception as exc:
                error_msg = str(exc)
                self._health[instance_id] = {
                    "state": "error",
                    "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "error": error_msg,
                }
                raise RuntimeError(
                    f"Failed to initialize pool for instance '{instance_id}': {error_msg}"
                ) from exc

        async with pool.acquire() as conn:
            yield conn

    async def fetch_single_row(
        self, instance_id: str, database_name: str, sql: str, *args: Any
    ) -> dict[str, Any]:
        """Execute a query and return the first row as a dict."""
        async with self.acquire(instance_id) as conn:
            row = await conn.fetchrow(sql, *args)
            if row is None:
                return {}
            return dict(row)

    async def execute_query(
        self, instance_id: str, database_name: str, sql: str, *args: Any, max_rows: int = 100
    ) -> list[dict[str, Any]]:
        """Execute a query and return all rows as list of dicts."""
        async with self.acquire(instance_id) as conn:
            rows = await conn.fetch(sql, *args)
            return [dict(r) for r in rows[:max_rows]]

    async def healthcheck_instance(self, instance_id: str) -> dict[str, Any]:
        """Check connectivity to a specific instance."""
        try:
            async with self.acquire(instance_id) as conn:
                await conn.fetchval("SELECT 1")
            self._health[instance_id] = {
                "state": "connected",
                "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "error": None,
            }
        except Exception as exc:
            self._health[instance_id] = {
                "state": "disconnected",
                "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "error": str(exc),
            }
        return self._health[instance_id]

    async def healthcheck_all(self) -> dict[str, dict[str, Any]]:
        """Check connectivity for all instances."""
        tasks = {
            instance_id: self.healthcheck_instance(instance_id) for instance_id in self._instances
        }
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        return {
            instance_id: (
                result
                if not isinstance(result, BaseException)
                else {
                    "state": "error",
                    "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "error": str(result),
                }
            )
            for instance_id, result in zip(tasks.keys(), results)
        }

    def get_pool_diagnostics(self) -> dict[str, dict[str, Any]]:
        """Return per-instance pool statistics."""
        diagnostics: dict[str, dict[str, Any]] = {}
        for instance_id, pool in self._pools.items():
            diagnostics[instance_id] = {
                "min_size": pool._minsize,
                "max_size": pool._maxsize,
                "size": len(pool._holders),
                "free": len(getattr(getattr(pool, "_queue", None), "_queue", [])),
            }
        return diagnostics

    def list_enabled_instances(self) -> list[str]:
        """Return list of enabled instance IDs."""
        return list(self._instances.keys())

    async def close_all_pools(self) -> None:
        """Gracefully close all connection pools."""
        for instance_id, pool in self._pools.items():
            try:
                await pool.close()
            except Exception:
                pass
        self._pools.clear()
