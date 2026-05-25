from __future__ import annotations


def validate_database_name(database_name: str) -> str:
    value = database_name.strip()
    if not value:
        raise ValueError("INVALID_INPUT: database_name is required")
    if ";" in value or "--" in value:
        raise ValueError("INVALID_INPUT: database_name contains invalid characters")
    return value


def validate_identifier(name: str, field_name: str) -> str:
    value = name.strip()
    if not value:
        raise ValueError(f"INVALID_INPUT: {field_name} cannot be blank")
    if ";" in value or "--" in value:
        raise ValueError(f"INVALID_INPUT: {field_name} contains invalid characters")
    return value


def validate_positive_int(value: int, field_name: str, minimum: int, maximum: int) -> int:
    if value < minimum or value > maximum:
        raise ValueError(
            f"INVALID_INPUT: {field_name} must be between {minimum} and {maximum}"
        )
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
