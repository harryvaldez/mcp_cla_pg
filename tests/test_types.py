import os
import psycopg
from psycopg.rows import dict_row
import json
import decimal
import uuid
from datetime import datetime
from dotenv import load_dotenv
import pytest

# Load environment variables from .env file
load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")

@pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL environment variable not set.")
def test_types():
    """Connects to the DB and asserts that common types are JSON serializable."""
    try:
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    select
                      table_name, column_name, ordinal_position, is_nullable,
                      data_type, character_maximum_length, numeric_precision,
                      numeric_scale, column_default
                    from information_schema.columns
                    where table_schema = 'smsadmin'
                    limit 100
                """)
                rows = cur.fetchall()
                
                assert isinstance(rows, list), "fetchall() should return a list"
                assert len(rows) > 0, "information_schema.columns should not be empty"

                for row in rows:
                    assert isinstance(row, dict), "row should be a dict"
                    for key, value in row.items():
                        try:
                            json.dumps({key: value})
                        except TypeError as e:
                            pytest.fail(f"Failed to serialize column '{key}' with value '{value}' (type: {type(value)}): {e}")

                # Also check generated_at
                cur.execute("select now() at time zone 'utc' as generated_at_utc")
                gen_row = cur.fetchone()
                assert isinstance(gen_row, dict)
                gen_at = gen_row.get('generated_at_utc')
                assert isinstance(gen_at, datetime), "generated_at_utc should be a datetime object"

    except psycopg.Error as e:
        pytest.fail(f"Database connection or query failed: {e}")

if __name__ == "__main__":
    test_types()
