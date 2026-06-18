from __future__ import annotations

import threading
import time
from typing import Any


class RateLimitExceededError(Exception):
    """Raised when a request exceeds the configured rate limit."""

    pass


class RateLimiter:
    """Token bucket rate limiter with per-actor and global limits."""

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


def build_rate_limiter(
    backend: str = "local",
    actor_rpm: int = 180,
    actor_burst: int = 30,
    global_rpm: int = 1200,
    global_burst: int = 200,
    redis_url: str | None = None,
    redis_namespace: str = "mcp:ratelimit",
) -> RateLimiter:
    """Factory for creating a rate limiter.

    Currently only supports 'local' backend. Redis support can be added later.
    """
    if backend != "local":
        raise ValueError(f"Unsupported rate limit backend: {backend}")
    return RateLimiter(
        actor_rpm=actor_rpm,
        actor_burst=actor_burst,
        global_rpm=global_rpm,
        global_burst=global_burst,
    )
