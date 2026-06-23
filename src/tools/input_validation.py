from __future__ import annotations


def validate_database_name(database_name: str) -> str:
    value = database_name.strip()
    if not value:
        raise ValueError("INVALID_INPUT: database_name is required")
    if ";" in value or "--" in value:
        raise ValueError("INVALID_INPUT: database_name contains invalid characters")
    return value


def validate_positive_int(value: int, field_name: str, minimum: int, maximum: int) -> int:
    if value < minimum or value > maximum:
        raise ValueError(f"INVALID_INPUT: {field_name} must be between {minimum} and {maximum}")
    return value


def validate_schema_name(name: str) -> str:
    value = name.strip()
    if not value:
        raise ValueError("INVALID_INPUT: schema_name is required")
    if ";" in value or "--" in value:
        raise ValueError("INVALID_INPUT: schema_name contains invalid characters")
    if value.lower() == "sys":
        raise ValueError("INVALID_INPUT: direct access to EDBAS sys schema is restricted")
    if not value.replace("_", "").isalnum():
        raise ValueError("INVALID_INPUT: schema_name must be alphanumeric with underscores")
    return value


def validate_query_text(query_text: str) -> str:
    """Validate SQL query text for HypoPG sub-tools.

    Strips leading/trailing whitespace, strips SQL comments (/* */, --),
    rejects DDL/DML statements, and rejects input containing SQL injection
    vectors (;, -- inside the query body). Only SELECT statements (including
    CTE-prefixed WITH ... SELECT ...) are permitted for HypoPG analysis.
    """
    import re

    value = query_text.strip()
    if not value:
        raise ValueError("INVALID_INPUT: query_text is required")
    if ";" in value or "--" in value:
        raise ValueError("INVALID_INPUT: query_text contains invalid characters")

    # Strip SQL block comments /* ... */ before checking the verb
    stripped = re.sub(r"/\*.*?\*/", "", value, flags=re.DOTALL)
    stripped = stripped.strip()

    # Check for valid SQL verb: SELECT or WITH (CTE-prefixed SELECT)
    upper = stripped.upper().lstrip()
    if upper.startswith("SELECT") or upper.startswith("WITH"):
        return value

    raise ValueError("INVALID_INPUT: only SELECT queries can be analyzed by HypoPG tools")


def validate_sql_statement(sql_statement: str) -> str:
    """Validate a user-supplied SQL statement for the exec_query tool.

    Only SELECT statements are permitted. Rejects SQL injection vectors.
    """
    value = sql_statement.strip()
    if not value:
        raise ValueError("INVALID_INPUT: sql_statement is required")
    if ";" in value or "--" in value:
        raise ValueError("INVALID_INPUT: sql_statement contains invalid characters")
    if not value.upper().lstrip().startswith("SELECT"):
        raise ValueError("INVALID_INPUT: only SELECT queries are allowed")
    return value


def validate_table_name(name: str) -> str:
    """Validate a table name for analyze_table and related tools.

    Strips whitespace, rejects SQL injection vectors, enforces
    alphanumeric+underscore pattern (same as validate_schema_name).
    """
    value = name.strip()
    if not value:
        raise ValueError("INVALID_INPUT: table_name is required")
    if ";" in value or "--" in value:
        raise ValueError("INVALID_INPUT: table_name contains invalid characters")
    if not value.replace("_", "").isalnum():
        raise ValueError("INVALID_INPUT: table_name must be alphanumeric with underscores")
    return value


# Mapping from user-friendly object_type strings to pg_class.relkind values
OBJECT_TYPE_MAP: dict[str, str] = {
    "table": "r",
    "index": "i",
    "view": "v",
    "sequence": "S",
    "materialized_view": "m",
    "composite_type": "c",
    "foreign_table": "f",
}


def validate_object_type(object_type: str) -> str:
    """Validate and map an object_type string to a pg_class.relkind value.

    Accepts user-friendly names (table, index, view, etc.) and returns
    the corresponding pg_class.relkind character. Rejects unknown types.
    """
    value = object_type.strip().lower()
    if not value:
        raise ValueError("INVALID_INPUT: object_type is required")
    if ";" in value or "--" in value:
        raise ValueError("INVALID_INPUT: object_type contains invalid characters")
    if value not in OBJECT_TYPE_MAP:
        allowed = ", ".join(sorted(OBJECT_TYPE_MAP.keys()))
        raise ValueError(
            f"INVALID_INPUT: unknown object_type '{object_type}'. "
            f"Allowed types: {allowed}"
        )
    return OBJECT_TYPE_MAP[value]
