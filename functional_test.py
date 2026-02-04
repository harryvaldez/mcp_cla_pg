import asyncio
import os
import json
from server import (
    db_pg96_test_connection,
    db_pg96_server_info,
    db_pg96_get_version,
    db_pg96_get_db_parameters,
    db_pg96_list_objects,
    db_pg96_describe_table,
    db_pg96_run_query,
    db_pg96_explain_query,
    db_pg96_analyze_table_health,
    db_pg96_kill_session,
    pool
)

async def run_functional_tests():
    print("=== Starting Functional Tests ===")
    
    # Open pool manually since we're not running via FastMCP lifespan
    await pool.open()
    print("Connection pool opened.")
    # 1. Test Connection
    print("\n1. Testing db_pg96_test_connection...")
    try:
        result = await db_pg96_test_connection.fn()
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")

    # 2. Server Info
    print("\n2. Testing db_pg96_server_info...")
    try:
        result = await db_pg96_server_info.fn()
        print(f"Result: {json.dumps(result, indent=2, default=str)}")
    except Exception as e:
        print(f"Error: {e}")

    # 3. Get Version
    print("\n3. Testing db_pg96_get_version...")
    try:
        result = await db_pg96_get_version.fn()
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")

    # 4. Get DB Parameters
    print("\n4. Testing db_pg96_get_db_parameters...")
    try:
        result = await db_pg96_get_db_parameters.fn(name="max_connections")
        print(f"Result (first 2): {json.dumps(result[:2], indent=2, default=str)}")
    except Exception as e:
        print(f"Error: {e}")

    # 5. List Databases
    print("\n5. Testing db_pg96_list_objects (database)...")
    try:
        result = await db_pg96_list_objects.fn(object_type="database")
        print(f"Result (first 2): {json.dumps(result[:2], indent=2, default=str)}")
    except Exception as e:
        print(f"Error: {e}")

    # 6. List Schemas
    print("\n6. Testing db_pg96_list_objects (schema)...")
    try:
        result = await db_pg96_list_objects.fn(object_type="schema")
        print(f"Result (first 5): {[r['name'] for r in result[:5]]}")
    except Exception as e:
        print(f"Error: {e}")

    # 7. List Tables
    print("\n7. Testing db_pg96_list_objects (table, schema='public')...")
    try:
        result = await db_pg96_list_objects.fn(object_type="table", schema="public")
        print(f"Result (first 5 tables): {[r['name'] for r in result[:5]]}")
    except Exception as e:
        print(f"Error: {e}")

    # 8. Run Query
    print("\n8. Testing db_pg96_run_query...")
    try:
        result = await db_pg96_run_query.fn(sql_query="SELECT current_timestamp as now")
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")

    # 8b. Describe Table
    print("\n8b. Testing db_pg96_describe_table (pg_catalog.pg_class)...")
    try:
        result = await db_pg96_describe_table.fn(schema_name="pg_catalog", table_name="pg_class")
        print(f"Result (first 2 cols): {json.dumps(result[:2], indent=2, default=str)}")
    except Exception as e:
        print(f"Error: {e}")

    # 8c. List Indexes
    print("\n8c. Testing db_pg96_list_objects (index, pg_catalog)...")
    try:
        result = await db_pg96_list_objects.fn(object_type="index", schema="pg_catalog")
        print(f"Result (first 2 indexes): {json.dumps(result[:2], indent=2, default=str)}")
    except Exception as e:
        print(f"Error: {e}")

    # 8d. List Functions
    print("\n8d. Testing db_pg96_list_objects (function, pg_catalog)...")
    try:
        result = await db_pg96_list_objects.fn(object_type="function", schema="pg_catalog")
        print(f"Result (first 2 functions): {json.dumps(result[:2], indent=2, default=str)}")
    except Exception as e:
        print(f"Error: {e}")

    # 9. Explain Query
    print("\n9. Testing db_pg96_explain_query...")
    try:
        result = await db_pg96_explain_query.fn(sql_query="SELECT 1")
        print(f"Result: {json.dumps(result, indent=2)}")
    except Exception as e:
        print(f"Error: {e}")

    # 10. Analyze Table Health
    print("\n10. Testing db_pg96_analyze_table_health (public.pg_class)...")
    try:
        # Using a system table that's guaranteed to exist
        result = await db_pg96_analyze_table_health.fn(schema_name="pg_catalog", table_name="pg_class")
        print(f"Result: {json.dumps(result, indent=2, default=str)}")
    except Exception as e:
        print(f"Error: {e}")

    # 11. Kill Session (Should fail in read-only mode)
    print("\n11. Testing db_pg96_kill_session (should fail)...")
    try:
        result = await db_pg96_kill_session.fn(pid=12345)
        print(f"Result: {result}")
    except Exception as e:
        print(f"Expected Error: {e}")

    print("\n=== Functional Tests Completed ===")
    
    if pool:
        print("\nClosing connection pool...")
        await pool.close()

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_functional_tests())
