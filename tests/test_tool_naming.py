"""Tests for dual-instance tool naming conventions."""

import re

from src.tools.tool_registry import ToolSpec, generate_tool_specs


class TestToolNaming:
    TOOL_NAME_RE = re.compile(r"^db_[12]_pg96_[a-z_]+$")

    def test_ping_tool_name_instance_1(self):
        spec = ToolSpec(instance="primary", instance_number=1, toolname="ping")
        assert spec.full_name == "db_1_pg96_ping"

    def test_ping_tool_name_instance_2(self):
        spec = ToolSpec(instance="secondary", instance_number=2, toolname="ping")
        assert spec.full_name == "db_2_pg96_ping"

    def test_tool_name_regex(self):
        specs = generate_tool_specs(["primary", "secondary"], ["ping"])
        for spec in specs:
            assert self.TOOL_NAME_RE.match(spec.full_name), (
                f"Tool name '{spec.full_name}' does not match regex"
            )

    def test_dual_tool_specs_generated(self):
        specs = generate_tool_specs(["primary", "secondary"], ["ping"])
        assert len(specs) == 2
        names = {s.full_name for s in specs}
        assert "db_1_pg96_ping" in names
        assert "db_2_pg96_ping" in names

    def test_single_instance_single_tool(self):
        specs = generate_tool_specs(["primary"], ["ping"])
        assert len(specs) == 1
        assert specs[0].full_name == "db_1_pg96_ping"

    def test_instance_number_assignment(self):
        specs = generate_tool_specs(["primary", "secondary"], ["ping"])
        primaries = [s for s in specs if s.instance == "primary"]
        secondaries = [s for s in specs if s.instance == "secondary"]
        assert len(primaries) == 1
        assert primaries[0].instance_number == 1
        assert len(secondaries) == 1
        assert secondaries[0].instance_number == 2

    def test_check_server_tool_name(self):
        """check_server tool follows dual-instance naming convention."""
        spec1 = ToolSpec(instance="primary", instance_number=1, toolname="check_server")
        spec2 = ToolSpec(instance="secondary", instance_number=2, toolname="check_server")
        assert spec1.full_name == "db_1_pg96_check_server"
        assert spec2.full_name == "db_2_pg96_check_server"
        assert self.TOOL_NAME_RE.match(spec1.full_name)
        assert self.TOOL_NAME_RE.match(spec2.full_name)

    def test_missing_fk_tool_name(self):
        """missing_fk tool follows dual-instance naming convention."""
        spec1 = ToolSpec(instance="primary", instance_number=1, toolname="missing_fk")
        spec2 = ToolSpec(instance="secondary", instance_number=2, toolname="missing_fk")
        assert spec1.full_name == "db_1_pg96_missing_fk"
        assert spec2.full_name == "db_2_pg96_missing_fk"
        assert self.TOOL_NAME_RE.match(spec1.full_name)
        assert self.TOOL_NAME_RE.match(spec2.full_name)
