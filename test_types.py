import os
import psycopg
from psycopg.rows import dict_row
import json
import decimal
import uuid
from datetime import datetime

# Connection string
dsn = "postgresql://mcp_readonly:R0_mcp@10.100.2.20:5444/lenexa"

def test_types():
    try:
        with psycopg.connect(dsn, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                # Test query similar to the one in server.py
                cur.execute("""
                    select
                      table_name,
                      column_name,
                      ordinal_position,
                      is_nullable,
                      data_type,
                      character_maximum_length,
                      numeric_precision,
                      numeric_scale,
                      column_default
                    from information_schema.columns
                    where table_schema = 'smsadmin'
                    limit 5
                """)
                rows = cur.fetchall()
                
                print(f"Fetched {len(rows)} rows.")
                
                for row in rows:
                    print(f"Row: {row}")
                    for k, v in row.items():
                        print(f"  {k}: {type(v)} = {v}")
                        
                        # Test serialization
                        try:
                            json.dumps(v)
                        except TypeError as e:
                            print(f"  !!! Serialization failed for {k}: {e}")

                # Also check generated_at
                cur.execute("select now() at time zone 'utc' as generated_at_utc")
                gen_row = cur.fetchone()
                gen_at = gen_row['generated_at_utc']
                print(f"generated_at_utc type: {type(gen_at)}")

    except Exception as e:
        print(f"Database error: {e}")

if __name__ == "__main__":
    test_types()
