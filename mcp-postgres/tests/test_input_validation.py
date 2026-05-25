"""Tests for input validation functions."""

import pytest

from src.tools.input_validation import (
    validate_database_name,
    validate_identifier,
    validate_positive_int,
    validate_schema_name,
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
