from __future__ import annotations

from src.models import RuntimePolicy


def is_tool_enabled(policy: RuntimePolicy, instance: str, toolname: str) -> bool:
    """Resolve tool enablement using global and per-instance flags.

    Precedence:
    1) instance_tool_enable_flags[instance][toolname]
    2) tool_enable_flags[toolname]
    3) default True
    """
    per_instance = policy.instance_tool_enable_flags.get(instance, {})
    if toolname in per_instance:
        return bool(per_instance[toolname])

    if toolname in policy.tool_enable_flags:
        return bool(policy.tool_enable_flags[toolname])

    return True
