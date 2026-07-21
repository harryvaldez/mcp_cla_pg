"""Tests for Pydantic configuration models."""

import pytest
from pydantic import ValidationError

from src.models import EdbInstanceConfig, RateLimitConfig, RuntimePolicy


class TestEdbInstanceConfig:
    def test_valid_primary_config(self):
        cfg = EdbInstanceConfig(
            id="primary",
            host="10.0.0.1",
            auth_secret_ref="secret/pg/primary",
        )
        assert cfg.id == "primary"
        assert cfg.port == 5444
        assert cfg.database == "lenexa"
        assert cfg.sslmode == "require"

    def test_valid_secondary_config(self):
        cfg = EdbInstanceConfig(
            id="secondary",
            host="10.0.0.2",
            auth_secret_ref="secret/pg/secondary",
        )
        assert cfg.id == "secondary"

    def test_invalid_id_pattern(self):
        with pytest.raises(ValidationError):
            EdbInstanceConfig(
                id="tertiary",
                host="10.0.0.1",
                auth_secret_ref="secret/pg/test",
            )

    def test_invalid_sslmode(self):
        with pytest.raises(ValidationError):
            EdbInstanceConfig(
                id="primary",
                host="10.0.0.1",
                auth_secret_ref="secret/pg/primary",
                sslmode="invalid-mode",
            )

    def test_default_values(self):
        cfg = EdbInstanceConfig(
            id="primary",
            host="10.0.0.1",
            auth_secret_ref="secret/pg/primary",
        )
        assert cfg.port == 5444
        assert cfg.database == "lenexa"
        assert cfg.sslmode == "require"
        assert cfg.connect_timeout_sec == 5
        assert cfg.pool_min == 2
        assert cfg.pool_max == 10
        assert cfg.pool_enabled is True
        assert cfg.edb_oracle_compat_mode is False

    def test_edb_oracle_compat_mode_field(self):
        cfg = EdbInstanceConfig(
            id="primary",
            host="10.0.0.1",
            auth_secret_ref="secret/pg/primary",
            edb_oracle_compat_mode=True,
        )
        assert cfg.edb_oracle_compat_mode is True


class TestRuntimePolicy:
    def test_defaults(self):
        policy = RuntimePolicy()
        assert policy.write_mode_default == "deny"
        assert policy.allowed_write_tools == []
        assert policy.max_result_rows == 5000
        assert policy.max_query_duration_ms == 15000

    def test_invalid_write_mode(self):
        with pytest.raises(ValidationError):
            RuntimePolicy(write_mode_default="invalid")


class TestRateLimitConfig:
    def test_valid_config(self):
        raw = {
            "global": {"requests_per_minute": 1200, "burst": 200},
            "actor": {"requests_per_minute": 180, "burst": 30},
            "session": {
                "concurrent_sessions_limit": 10,
                "session_ttl_minutes": 60,
                "inactivity_timeout_minutes": 15,
            },
        }
        cfg = RateLimitConfig(**raw)
        assert cfg.global_.requests_per_minute == 1200
        assert cfg.actor.requests_per_minute == 180
