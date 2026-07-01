from __future__ import annotations

import threading
import time
from typing import Any

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult


class RateLimitExceededError(Exception):
    """Raised when a request exceeds the configured rate limit."""

    pass


class RateLimiter:
    """Token bucket rate limiter with per-actor and global limits (local/in-process)."""

    def __init__(
        self,
        actor_rpm: int,
        actor_burst: int,
        global_rpm: int,
        global_burst: int,
    ):
        self._actor_rpm = actor_rpm
        self._actor_burst = actor_burst
        self._global_rpm = global_rpm
        self._global_burst = global_burst
        self._lock = threading.RLock()
        self._actor_buckets: dict[str, _TokenBucket] = {}
        self._global_bucket = _TokenBucket(
            rate_per_second=global_rpm / 60.0,
            capacity=global_burst,
        )

    def allow(self, actor_id: str) -> bool:
        """Check if the given actor is allowed to make a request.

        Returns True if allowed, raises RateLimitExceededError otherwise.
        """
        with self._lock:
            # Get or create actor bucket
            if actor_id not in self._actor_buckets:
                self._actor_buckets[actor_id] = _TokenBucket(
                    rate_per_second=self._actor_rpm / 60.0,
                    capacity=self._actor_burst,
                )
            actor_bucket = self._actor_buckets[actor_id]

        # Check actor limit
        if not actor_bucket.consume():
            raise RateLimitExceededError(
                f"RATE_LIMIT_EXCEEDED: actor '{actor_id}' exceeded "
                f"{self._actor_rpm} rpm (burst {self._actor_burst})"
            )

        # Check global limit
        if not self._global_bucket.consume():
            # Refund the actor token since the global limit blocked it
            actor_bucket.refund()
            raise RateLimitExceededError(
                f"RATE_LIMIT_EXCEEDED: global limit of "
                f"{self._global_rpm} rpm (burst {self._global_burst}) exceeded"
            )

        return True

    def get_diagnostics(self) -> dict[str, Any]:
        """Return current rate limiter state for diagnostics."""
        with self._lock:
            return {
                "actor_count": len(self._actor_buckets),
                "global_tokens": round(self._global_bucket.tokens, 2),
                "global_capacity": self._global_bucket.capacity,
                "actor_rpm": self._actor_rpm,
                "actor_burst": self._actor_burst,
                "global_rpm": self._global_rpm,
                "global_burst": self._global_burst,
            }

    # ── FastMCP Middleware integration ────────────────────────────────────

    def as_middleware(self) -> RateLimitingMiddleware:
        """Wrap this rate limiter as a FastMCP Middleware for automatic enforcement.

        Replaces manual ``state.rate_limiter.allow(actor)`` calls in every tool.
        Attach via ``mcp.add_middleware(limiter.as_middleware())``.
        """
        return RateLimitingMiddleware(self)


class _TokenBucket:
    """Simple thread-safe token bucket implementation."""

    def __init__(self, rate_per_second: float, capacity: float):
        self._rate = rate_per_second
        self._capacity = capacity
        self._tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    @property
    def tokens(self) -> float:
        return self._tokens

    @property
    def capacity(self) -> float:
        return self._capacity

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now

    def consume(self) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def refund(self) -> None:
        with self._lock:
            self._tokens = min(self._capacity, self._tokens + 1.0)


class RedisRateLimiter:
    """Redis-backed distributed token-bucket rate limiter.

    Uses a Lua script for atomic token-bucket operations so that multiple
    server replicas share a single rate-limit state via Redis.
    """

    _CONSUME_LUA = """
    local key_tokens = KEYS[1]
    local key_last  = KEYS[2]
    local rate      = tonumber(ARGV[1])
    local capacity  = tonumber(ARGV[2])
    local now       = tonumber(ARGV[3])

    local tokens = tonumber(redis.call('GET', key_tokens))
    if tokens == nil then tokens = capacity end

    local last_refill = tonumber(redis.call('GET', key_last))
    if last_refill == nil then last_refill = now end

    local elapsed = math.max(0, now - last_refill)
    tokens = math.min(capacity, tokens + elapsed * rate)

    if tokens >= 1.0 then
        redis.call('SET', key_tokens, tokens - 1.0, 'EX', 86400)
        redis.call('SET', key_last, now, 'EX', 86400)
        return 1
    end
    redis.call('SET', key_tokens, tokens, 'EX', 86400)
    redis.call('SET', key_last, now, 'EX', 86400)
    return 0
    """

    def __init__(
        self,
        redis_url: str,
        actor_rpm: int,
        actor_burst: int,
        global_rpm: int,
        global_burst: int,
        namespace: str = "mcp:ratelimit",
    ) -> None:
        import redis

        self._redis: redis.Redis = redis.from_url(
            redis_url,
            socket_timeout=3,
            socket_connect_timeout=2,
            decode_responses=True,
        )
        self._actor_rpm = actor_rpm
        self._actor_burst = actor_burst
        self._global_rpm = global_rpm
        self._global_burst = global_burst
        self._ns = namespace
        self._consume = self._redis.register_script(self._CONSUME_LUA)

    # ------------------------------------------------------------------
    # Public API (mirrors RateLimiter)
    # ------------------------------------------------------------------

    def allow(self, actor_id: str) -> bool:
        now = time.time()
        actor_rate = self._actor_rpm / 60.0

        # 1. Check per-actor bucket
        result = self._consume(
            keys=[
                f"{self._ns}:actor:{actor_id}:tokens",
                f"{self._ns}:actor:{actor_id}:last",
            ],
            args=[actor_rate, self._actor_burst, now],
        )
        if not result:
            raise RateLimitExceededError(
                f"RATE_LIMIT_EXCEEDED: actor '{actor_id}' exceeded "
                f"{self._actor_rpm} rpm (burst {self._actor_burst})"
            )

        # 2. Check global bucket
        global_rate = self._global_rpm / 60.0
        result = self._consume(
            keys=[
                f"{self._ns}:global:tokens",
                f"{self._ns}:global:last",
            ],
            args=[global_rate, self._global_burst, now],
        )
        if not result:
            # Refund the actor token since the global limit blocked it
            self._redis.incrbyfloat(
                f"{self._ns}:actor:{actor_id}:tokens", 1.0
            )
            raise RateLimitExceededError(
                f"RATE_LIMIT_EXCEEDED: global limit of "
                f"{self._global_rpm} rpm (burst {self._global_burst}) exceeded"
            )

        return True

    def get_diagnostics(self) -> dict[str, Any]:
        try:
            actor_keys = self._redis.keys(f"{self._ns}:actor:*:tokens")
            global_tokens = self._redis.get(f"{self._ns}:global:tokens")
        except Exception:
            actor_keys = []
            global_tokens = None

        return {
            "actor_count": len(actor_keys),
            "global_tokens": round(float(global_tokens or self._global_burst), 2),
            "global_capacity": self._global_burst,
            "actor_rpm": self._actor_rpm,
            "actor_burst": self._actor_burst,
            "global_rpm": self._global_rpm,
            "global_burst": self._global_burst,
            "backend": "redis",
        }

    # ── FastMCP Middleware integration ────────────────────────────────────

    def as_middleware(self) -> RateLimitingMiddleware:
        """Wrap this Redis rate limiter as a FastMCP Middleware."""
        return RateLimitingMiddleware(self)


class RateLimitingMiddleware(Middleware):
    """FastMCP middleware that enforces per-actor and global rate limits.

    Attach via ``mcp.add_middleware(limiter.as_middleware())``.
    Replaces manual ``state.rate_limiter.allow(actor)`` calls in every tool.
    """

    def __init__(self, limiter: RateLimiter | RedisRateLimiter) -> None:
        self._limiter = limiter

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next,
    ) -> ToolResult:
        fmcp_ctx = context.fastmcp_context
        if fmcp_ctx is not None:
            actor = fmcp_ctx.client_id or "anonymous"
        else:
            actor = "anonymous"
        # Raises RateLimitExceededError if over limit; let it propagate
        self._limiter.allow(actor)
        return await call_next(context)


def build_rate_limiter(
    backend: str = "local",
    actor_rpm: int = 180,
    actor_burst: int = 30,
    global_rpm: int = 1200,
    global_burst: int = 200,
    redis_url: str | None = None,
    redis_namespace: str = "mcp:ratelimit",
) -> RateLimiter | RedisRateLimiter:
    """Factory for creating a rate limiter.

    Args:
        backend: ``"local"`` (in-process) or ``"redis"`` (distributed).
        actor_rpm: Per-actor requests-per-minute.
        actor_burst: Per-actor burst capacity.
        global_rpm: Global requests-per-minute.
        global_burst: Global burst capacity.
        redis_url: Redis connection URL (required when backend is ``"redis"``).
        redis_namespace: Key prefix for Redis keys.
    """
    if backend == "redis":
        if not redis_url:
            raise ValueError(
                "FASTMCP_REDIS_URL must be set when FASTMCP_RATE_LIMIT_BACKEND=redis"
            )
        return RedisRateLimiter(
            redis_url=redis_url,
            actor_rpm=actor_rpm,
            actor_burst=actor_burst,
            global_rpm=global_rpm,
            global_burst=global_burst,
            namespace=redis_namespace,
        )

    if backend == "local":
        return RateLimiter(
            actor_rpm=actor_rpm,
            actor_burst=actor_burst,
            global_rpm=global_rpm,
            global_burst=global_burst,
        )

    raise ValueError(f"Unsupported rate limit backend: {backend}")
