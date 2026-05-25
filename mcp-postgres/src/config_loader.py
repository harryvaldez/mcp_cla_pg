from __future__ import annotations

import json
import os
import pathlib
from typing import Any

import yaml
from pydantic import BaseModel

from .models import AuthConfig, EdbInstanceConfig, RateLimitConfig, RuntimePolicy


class AppConfig(BaseModel):
    """Top-level application configuration aggregating all config sections."""

    instances: list[EdbInstanceConfig]
    policy: RuntimePolicy
    rate_limit: RateLimitConfig
    auth: AuthConfig


def _parse_bool_map(name: str, raw: str) -> dict[str, bool]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be valid JSON") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"{name} must be a JSON object")

    parsed: dict[str, bool] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not isinstance(value, bool):
            raise ValueError(f"{name} entries must map string keys to boolean values")
        parsed[key] = value
    return parsed


def _parse_nested_bool_map(name: str, raw: str) -> dict[str, dict[str, bool]]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be valid JSON") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"{name} must be a JSON object")

    parsed: dict[str, dict[str, bool]] = {}
    for instance, mapping in payload.items():
        if not isinstance(instance, str) or not isinstance(mapping, dict):
            raise ValueError(f"{name} must map instance names to JSON objects")
        inner: dict[str, bool] = {}
        for tool, enabled in mapping.items():
            if not isinstance(tool, str) or not isinstance(enabled, bool):
                raise ValueError(
                    f"{name} nested entries must map tool names to boolean values"
                )
            inner[tool] = enabled
        parsed[instance] = inner
    return parsed


def apply_policy_env_overrides(
    policy: RuntimePolicy, env: dict[str, str] | None = None
) -> RuntimePolicy:
    """Apply environment variable overrides to tool enable flags in the runtime policy."""
    values = env or dict(os.environ)

    global_overrides = values.get("FASTMCP_TOOL_ENABLE_FLAGS_JSON")
    instance_overrides = values.get("FASTMCP_INSTANCE_TOOL_ENABLE_FLAGS_JSON")

    update_data: dict[str, Any] = {}
    if global_overrides:
        update_data["tool_enable_flags"] = _parse_bool_map(
            "FASTMCP_TOOL_ENABLE_FLAGS_JSON", global_overrides
        )
    if instance_overrides:
        update_data["instance_tool_enable_flags"] = _parse_nested_bool_map(
            "FASTMCP_INSTANCE_TOOL_ENABLE_FLAGS_JSON", instance_overrides
        )

    if not update_data:
        return policy
    return policy.model_copy(update=update_data)


def _load_yaml(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"YAML at {path} must be a mapping")
    return data


def _resolve_path(env_var: str, default: str) -> str:
    raw = os.getenv(env_var, default)
    return str(pathlib.Path(raw).resolve())


def load_config(
    config_path: str | None = None,
    policy_path: str | None = None,
    rate_limit_path: str | None = None,
) -> AppConfig:
    """Load and validate all configuration from YAML files.

    Paths are resolved from environment variables with fallback defaults:
      FASTMCP_CONFIG_PATH -> config/instances.yaml
      FASTMCP_POLICY_PATH -> config/runtime-policy.yaml
      FASTMCP_RATE_LIMIT_PATH -> config/rate-limit.yaml
    """
    cfg_path = config_path or _resolve_path("FASTMCP_CONFIG_PATH", "config/instances.yaml")
    pol_path = policy_path or _resolve_path("FASTMCP_POLICY_PATH", "config/runtime-policy.yaml")
    rl_path = rate_limit_path or _resolve_path("FASTMCP_RATE_LIMIT_PATH", "config/rate-limit.yaml")

    instances_raw = _load_yaml(cfg_path)
    policy_raw = _load_yaml(pol_path)
    rate_limit_raw = _load_yaml(rl_path)

    # Extract auth section from policy if present, else use defaults
    auth_raw = policy_raw.pop("auth", {})
    auth = AuthConfig(**auth_raw)

    instances = [EdbInstanceConfig(**item) for item in instances_raw.get("instances", [])]
    rate_limit = RateLimitConfig(**rate_limit_raw)
    policy = RuntimePolicy(**policy_raw)

    # Apply env overrides for tool enable flags
    policy = apply_policy_env_overrides(policy)

    return AppConfig(
        instances=instances,
        policy=policy,
        rate_limit=rate_limit,
        auth=auth,
    )
