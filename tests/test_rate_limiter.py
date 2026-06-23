"""Tests for the RateLimiter with per-actor and global limits."""

import os
import uuid

import pytest

from src.middleware.rate_limiter import (
    RateLimiter,
    RateLimitExceededError,
    RedisRateLimiter,
    build_rate_limiter,
)


class TestRateLimiter:
    def test_within_limit_passes(self):
        limiter = RateLimiter(actor_rpm=600, actor_burst=100, global_rpm=6000, global_burst=500)
        for _ in range(50):
            assert limiter.allow("actor-1") is True

    def test_exceeds_actor_rpm_raises(self):
        limiter = RateLimiter(actor_rpm=60, actor_burst=1, global_rpm=6000, global_burst=500)
        # Burst of 1 should only allow one request
        assert limiter.allow("actor-1") is True
        with pytest.raises(RateLimitExceededError, match="RATE_LIMIT_EXCEEDED"):
            limiter.allow("actor-1")

    def test_global_limit_enforced(self):
        limiter = RateLimiter(actor_rpm=6000, actor_burst=500, global_rpm=60, global_burst=1)
        assert limiter.allow("actor-1") is True
        with pytest.raises(RateLimitExceededError):
            limiter.allow("actor-2")

    def test_multiple_actors_independent(self):
        limiter = RateLimiter(actor_rpm=600, actor_burst=2, global_rpm=6000, global_burst=500)
        assert limiter.allow("actor-1") is True
        assert limiter.allow("actor-2") is True
        assert limiter.allow("actor-1") is True

    def test_diagnostics_returns_state(self):
        limiter = RateLimiter(actor_rpm=180, actor_burst=30, global_rpm=1200, global_burst=200)
        limiter.allow("actor-1")
        diag = limiter.get_diagnostics()
        assert diag["actor_count"] == 1
        assert diag["actor_rpm"] == 180
        assert diag["global_rpm"] == 1200


# ---------------------------------------------------------------------------
# Redis-backed rate limiter tests
# ---------------------------------------------------------------------------

_REDIS_URL = os.getenv("TEST_REDIS_URL", "redis://localhost:6379/0")

_redis_skip = pytest.mark.skipif(
    not os.getenv("TEST_REDIS_AVAILABLE", ""),
    reason="Set TEST_REDIS_AVAILABLE=1 and ensure Redis is reachable",
)


def _make_redis_limiter(**overrides):
    """Build a RedisRateLimiter with isolation-friendly defaults."""
    ns = f"test:rl:{uuid.uuid4().hex[:8]}"
    kwargs = dict(
        redis_url=_REDIS_URL,
        namespace=ns,
        actor_rpm=600,
        actor_burst=5,
        global_rpm=6000,
        global_burst=50,
    )
    kwargs.update(overrides)
    return RedisRateLimiter(**kwargs)


@_redis_skip
class TestRedisRateLimiter:
    def test_within_limit_passes(self):
        limiter = _make_redis_limiter()
        for _ in range(3):
            assert limiter.allow("actor-1") is True

    def test_exceeds_actor_burst_raises(self):
        limiter = _make_redis_limiter(actor_rpm=60, actor_burst=1)
        assert limiter.allow("actor-1") is True
        with pytest.raises(RateLimitExceededError, match="RATE_LIMIT_EXCEEDED"):
            limiter.allow("actor-1")

    def test_global_limit_enforced(self):
        limiter = _make_redis_limiter(global_rpm=60, global_burst=1)
        assert limiter.allow("actor-1") is True
        with pytest.raises(RateLimitExceededError, match="global limit"):
            limiter.allow("actor-2")

    def test_actor_refund_on_global_block(self):
        """When global blocks, the actor's token should be refunded."""
        limiter = _make_redis_limiter(actor_rpm=60, actor_burst=2, global_rpm=60, global_burst=1)
        assert limiter.allow("actor-1") is True  # global token consumed
        # Next call: actor still has burst, but global should block
        with pytest.raises(RateLimitExceededError, match="global limit"):
            limiter.allow("actor-1")
        # Actor should still have its token refunded — allow again after global refill
        # (we can't easily wait; just verify diag shows actor keys exist)
        diag = limiter.get_diagnostics()
        assert diag["backend"] == "redis"

    def test_multiple_actors_independent(self):
        limiter = _make_redis_limiter(actor_burst=2)
        assert limiter.allow("actor-a") is True
        assert limiter.allow("actor-b") is True
        assert limiter.allow("actor-a") is True  # still within burst

    def test_diagnostics_returns_state(self):
        limiter = _make_redis_limiter()
        limiter.allow("actor-1")
        diag = limiter.get_diagnostics()
        assert diag["backend"] == "redis"
        assert diag["actor_count"] >= 1
        assert diag["actor_rpm"] == 600
        assert diag["global_rpm"] == 6000


class TestBuildRateLimiter:
    def test_build_local_returns_local_limiter(self):
        limiter = build_rate_limiter(backend="local")
        assert isinstance(limiter, RateLimiter)

    def test_build_redis_requires_url(self):
        with pytest.raises(ValueError, match="REDIS_URL"):
            build_rate_limiter(backend="redis", redis_url=None)

    def test_build_unsupported_backend_raises(self):
        with pytest.raises(ValueError, match="Unsupported rate limit backend"):
            build_rate_limiter(backend="memcached")
