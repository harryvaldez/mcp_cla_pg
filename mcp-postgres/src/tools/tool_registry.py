from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    """Specification for a single MCP tool bound to a database instance."""

    instance: str
    instance_number: int
    toolname: str

    @property
    def full_name(self) -> str:
        """Generate tool name: db_{instance_number}_pg96_{toolname}."""
        return f"db_{self.instance_number}_pg96_{self.toolname}"


def generate_tool_specs(enabled_instances: list[str], toolnames: list[str] | None = None) -> list[ToolSpec]:
    """Generate ToolSpec entries for every combination of instance x toolname.

    Args:
        enabled_instances: List of enabled instance IDs (e.g., ["primary", "secondary"]).
        toolnames: List of tool names to generate specs for. Defaults to ["ping"].

    Returns:
        List of ToolSpec instances, one per instance per toolname.
    """
    if toolnames is None:
        toolnames = ["ping"]

    specs: list[ToolSpec] = []
    for idx, instance in enumerate(enabled_instances, start=1):
        for toolname in toolnames:
            specs.append(ToolSpec(instance=instance, instance_number=idx, toolname=toolname))
    return specs
