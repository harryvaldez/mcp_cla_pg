"""Tests for the RateLimiter with per-actor and global limits."""

import time

import pytest

from src.middleware.rate_limiter import RateLimitExceededError, RateLimiter


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
