"""Tests for WriteGuard enforcement including EDBAS-specific DDL."""

import pytest

from src.middleware.write_guard import WriteGuard
from src.models import RuntimePolicy


class TestWriteGuard:
    @pytest.fixture
    def policy_deny(self):
        return RuntimePolicy(
            write_mode_default="deny",
            blocked_sql_patterns=[
                r"(?i)\b(drop|alter|truncate|create)\b",
                r"(?i)\b(pg_read_file|pg_write_file|pg_sleep)\b",
                r"(?i)\b(CREATE\s+(OR\s+REPLACE\s+)?(PACKAGE|TYPE\s+BODY|SYNONYM|DIRECTORY))\b",
            ],
        )

    @pytest.fixture
    def policy_allow(self):
        return RuntimePolicy(
            write_mode_default="allow",
            allowed_write_tools=["db_1_pg96_write"],
        )

    def test_select_passes(self, policy_deny):
        guard = WriteGuard(policy_deny)
        guard.enforce("db_1_pg96_ping", "SELECT * FROM users")

    def test_insert_denied_by_default(self, policy_deny):
        guard = WriteGuard(policy_deny)
        with pytest.raises(PermissionError):
            guard.enforce("db_1_pg96_ping", "INSERT INTO users VALUES (1)")

    def test_drop_table_blocked(self, policy_deny):
        guard = WriteGuard(policy_deny)
        with pytest.raises(PermissionError):
            guard.enforce("db_1_pg96_ping", "DROP TABLE users")

    def test_update_denied(self, policy_deny):
        guard = WriteGuard(policy_deny)
        with pytest.raises(PermissionError):
            guard.enforce("db_1_pg96_ping", "UPDATE users SET name='x'")

    def test_delete_denied(self, policy_deny):
        guard = WriteGuard(policy_deny)
        with pytest.raises(PermissionError):
            guard.enforce("db_1_pg96_ping", "DELETE FROM users")

    def test_create_package_blocked(self, policy_deny):
        guard = WriteGuard(policy_deny)
        with pytest.raises(PermissionError):
            guard.enforce("db_1_pg96_ping", "CREATE OR REPLACE PACKAGE pkg_body AS ...")

    def test_create_type_body_blocked(self, policy_deny):
        guard = WriteGuard(policy_deny)
        with pytest.raises(PermissionError):
            guard.enforce("db_1_pg96_ping", "CREATE TYPE BODY my_type AS ...")

    def test_create_synonym_blocked(self, policy_deny):
        guard = WriteGuard(policy_deny)
        with pytest.raises(PermissionError):
            guard.enforce("db_1_pg96_ping", "CREATE SYNONYM syn FOR tab")

    def test_explain_passes(self, policy_deny):
        guard = WriteGuard(policy_deny)
        guard.enforce("db_1_pg96_ping", "EXPLAIN SELECT * FROM users")

    def test_copy_passes(self, policy_deny):
        guard = WriteGuard(policy_deny)
        guard.enforce("db_1_pg96_ping", "COPY (SELECT 1) TO STDOUT")

    def test_allowlisted_tool_insert_passes(self, policy_allow):
        guard = WriteGuard(policy_allow)
        guard.enforce("db_1_pg96_write", "INSERT INTO users VALUES (1)")
