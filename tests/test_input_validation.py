"""Tests for input validation functions."""

import pytest

from src.tools.input_validation import (
    validate_database_name,
    validate_identifier,
    validate_object_type,
    validate_positive_int,
    validate_query_text,
    validate_schema_name,
    validate_sql_statement,
    validate_table_name,
)


class TestInputValidation:
    def test_valid_database_name(self):
        assert validate_database_name("edb") == "edb"
        assert validate_database_name("  mydb  ") == "mydb"

    def test_empty_database_name(self):
        with pytest.raises(ValueError, match="database_name is required"):
            validate_database_name("")
        with pytest.raises(ValueError, match="database_name is required"):
            validate_database_name("   ")

    def test_sql_injection_rejected(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_database_name("edb; DROP TABLE users;")
        with pytest.raises(ValueError, match="invalid characters"):
            validate_database_name("edb--comment")

    def test_valid_identifier(self):
        assert validate_identifier("my_table", "table_name") == "my_table"

    def test_empty_identifier(self):
        with pytest.raises(ValueError):
            validate_identifier("", "field")

    def test_sql_injection_in_identifier(self):
        with pytest.raises(ValueError):
            validate_identifier("x; DELETE FROM users", "field")

    def test_valid_positive_int(self):
        assert validate_positive_int(50, "limit", 1, 100) == 50

    def test_out_of_range_int(self):
        with pytest.raises(ValueError):
            validate_positive_int(0, "limit", 1, 100)
        with pytest.raises(ValueError):
            validate_positive_int(200, "limit", 1, 100)

    def test_valid_schema_name(self):
        assert validate_schema_name("public") == "public"
        assert validate_schema_name("my_schema") == "my_schema"

    def test_sys_schema_flagged(self):
        with pytest.raises(ValueError, match="sys schema"):
            validate_schema_name("sys")
        with pytest.raises(ValueError, match="sys schema"):
            validate_schema_name("SYS")

    def test_schema_special_chars_rejected(self):
        with pytest.raises(ValueError):
            validate_schema_name("schema-name")
        with pytest.raises(ValueError):
            validate_schema_name("schema name")


class TestValidateQueryText:
    """Tests for validate_query_text() in input validation."""

    def test_accepts_select(self):
        assert validate_query_text("SELECT * FROM users") == "SELECT * FROM users"

    def test_accepts_select_with_whitespace(self):
        assert (
            validate_query_text("  SELECT count(*) FROM orders  ")
            == "SELECT count(*) FROM orders"
        )

    def test_rejects_with_select(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_query_text(
                "WITH recent AS (SELECT * FROM orders) SELECT * FROM recent"
            )

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="query_text is required"):
            validate_query_text("")
        with pytest.raises(ValueError, match="query_text is required"):
            validate_query_text("   ")

    def test_rejects_ddl_create(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_query_text("CREATE TABLE t (id int)")

    def test_rejects_ddl_drop(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_query_text("DROP TABLE users")

    def test_rejects_dml_insert(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_query_text("INSERT INTO users VALUES (1)")

    def test_rejects_dml_update(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_query_text("UPDATE users SET name = 'x'")

    def test_rejects_dml_delete(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_query_text("DELETE FROM users")

    def test_rejects_semicolon_injection(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_query_text("SELECT * FROM users; DROP TABLE users")

    def test_rejects_comment_injection(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_query_text("SELECT * FROM users--comment")


class TestValidateSqlStatement:
    """Tests for validate_sql_statement() used by exec_query tool."""

    def test_accepts_select(self):
        assert (
            validate_sql_statement("SELECT * FROM users")
            == "SELECT * FROM users"
        )

    def test_accepts_select_stripped(self):
        assert (
            validate_sql_statement("  SELECT 1  ")
            == "SELECT 1"
        )

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="sql_statement is required"):
            validate_sql_statement("")
        with pytest.raises(ValueError, match="sql_statement is required"):
            validate_sql_statement("   ")

    def test_rejects_insert(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_sql_statement("INSERT INTO t VALUES (1)")

    def test_rejects_update(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_sql_statement("UPDATE users SET x = 1")

    def test_rejects_delete(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_sql_statement("DELETE FROM users")

    def test_rejects_drop(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_sql_statement("DROP TABLE users")

    def test_rejects_create(self):
        with pytest.raises(ValueError, match="only SELECT"):
            validate_sql_statement("CREATE TABLE t (id int)")

    def test_rejects_semicolon_injection(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_sql_statement("SELECT 1; DROP TABLE users")

    def test_rejects_comment_injection(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_sql_statement("SELECT 1--comment")


class TestValidateTableName:
    """Tests for validate_table_name() used by analyze_table tool."""

    def test_accepts_valid(self):
        assert validate_table_name("orders") == "orders"
        assert validate_table_name("my_table") == "my_table"

    def test_strips_whitespace(self):
        assert validate_table_name("  orders  ") == "orders"

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="table_name is required"):
            validate_table_name("")
        with pytest.raises(ValueError, match="table_name is required"):
            validate_table_name("   ")

    def test_rejects_special_chars(self):
        with pytest.raises(ValueError, match="alphanumeric"):
            validate_table_name("my-table")
        with pytest.raises(ValueError, match="alphanumeric"):
            validate_table_name("table name")

    def test_rejects_injection(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_table_name("orders; DROP TABLE users")
        with pytest.raises(ValueError, match="invalid characters"):
            validate_table_name("orders--comment")


class TestValidateObjectType:
    """Tests for validate_object_type() used by list_objects tool."""

    def test_accepts_table(self):
        assert validate_object_type("table") == "r"

    def test_accepts_index(self):
        assert validate_object_type("index") == "i"

    def test_accepts_view(self):
        assert validate_object_type("view") == "v"

    def test_accepts_sequence(self):
        assert validate_object_type("sequence") == "S"

    def test_accepts_case_insensitive(self):
        assert validate_object_type("TABLE") == "r"
        assert validate_object_type("  View  ") == "v"

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="object_type is required"):
            validate_object_type("")
        with pytest.raises(ValueError, match="object_type is required"):
            validate_object_type("   ")

    def test_rejects_unknown_type(self):
        with pytest.raises(ValueError, match="unknown object_type"):
            validate_object_type("function")

    def test_rejects_injection(self):
        with pytest.raises(ValueError, match="invalid characters"):
            validate_object_type("table; DROP TABLE users")
