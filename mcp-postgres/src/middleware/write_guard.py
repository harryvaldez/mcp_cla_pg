from __future__ import annotations

import re

from src.models import RuntimePolicy

# Recognized non-write SQL verbs
_READ_VERBS = {"SELECT", "EXPLAIN", "SHOW", "SET", "COPY"}
# EDBAS Oracle-compatible verbs that may write
_EDB_WRITE_VERBS = {"MERGE", "EXEC", "EXECUTE", "CALL"}


class WriteGuard:
    """Enforces read-only policy by classifying SQL verbs and checking against
    blocked patterns and allowed write tools."""

    def __init__(self, policy: RuntimePolicy):
        self._policy = policy
        self._blocked_patterns = [re.compile(p) for p in policy.blocked_sql_patterns]

    def enforce(self, tool_name: str, sql_text: str) -> None:
        """Check whether the given SQL is allowed under current policy.

        Raises PermissionError if the SQL is not permitted.
        """
        normalized = sql_text.strip()

        # Check blocked patterns first (always denied regardless of write mode)
        for pattern in self._blocked_patterns:
            if pattern.search(normalized):
                raise PermissionError(f"SQL blocked by policy pattern: {pattern.pattern}")

        # Extract leading verb
        verb = self._extract_verb(normalized).upper()

        # Non-write verbs always pass
        if verb in _READ_VERBS:
            return

        # If write mode is deny, check allowlist
        if self._policy.write_mode_default == "deny":
            if tool_name not in self._policy.allowed_write_tools:
                raise PermissionError(
                    f"Write operation '{verb}' denied for tool '{tool_name}'. "
                    f"Tool is not in allowed_write_tools."
                )

    def _extract_verb(self, sql: str) -> str:
        """Extract the leading SQL verb from a statement."""
        # Handle multi-word verbs like "CREATE OR REPLACE PACKAGE"
        upper = sql.upper().lstrip()
        # Common multi-word patterns
        for multi in [
            "CREATE OR REPLACE PACKAGE",
            "CREATE OR REPLACE TYPE BODY",
            "CREATE OR REPLACE SYNONYM",
            "CREATE OR REPLACE",
            "CREATE TYPE BODY",
            "CREATE SYNONYM",
            "CREATE DIRECTORY",
        ]:
            if upper.startswith(multi):
                return multi

        # Single-word verb
        parts = upper.split()
        return parts[0] if parts else ""
