
import os
import time
import json
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Any
import sys
import psycopg
from psycopg_pool import ConnectionPool
from dotenv import load_dotenv
from urllib.parse import urlparse

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
# Get DATABASE_URL from environment
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set. Please configure it in your environment or a .env file.")

os.environ["MCP_ALLOW_WRITE"] = "false"
# Explicitly set pool size to default to match server behavior
os.environ["MCP_POOL_MAX_SIZE"] = "5"
os.environ["MCP_POOL_TIMEOUT"] = "10.0" 

def invoke_tool(tool_obj, **kwargs):
    """Helper to invoke a FastMCP tool object."""
    # Try calling it directly (some versions)
    if callable(tool_obj):
        try:
            return tool_obj(**kwargs)
        except TypeError:
            pass
    
    # Try finding the underlying function
    for attr in ("fn", "func", "function", "_fn"):
        inner = getattr(tool_obj, attr, None)
        if callable(inner):
            return inner(**kwargs)
            
    raise TypeError(f"Could not find callable for tool {tool_obj}")

def test_connection_pooling_remote():
    """Test connection pooling behavior against remote DB."""
    print("Testing connection pooling...")
    
    try:
        # Test with configured pool settings
        pool = ConnectionPool(
            conninfo=os.environ["DATABASE_URL"],
            min_size=1,
            max_size=5,
            timeout=10,
            kwargs={"row_factory": psycopg.rows.dict_row}
        )
        
        # Test basic connectivity
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_backend_pid(), current_user")
                result = cur.fetchone()
                print(f"Pool connection successful: PID={result['pg_backend_pid']}, User={result['current_user']}")
        
        # Test concurrent connections to exhaust pool
        print("Testing pool exhaustion (max_size=5)...")
        
        def hold_connection(conn_id, duration):
            try:
                with pool.connection(timeout=5) as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT pg_sleep(%s)", (duration,))
                        return {
                            "connection_id": conn_id,
                            "success": True,
                            "msg": "slept"
                        }
            except Exception as e:
                return {
                    "connection_id": conn_id,
                    "success": False,
                    "error": str(e)
                }
        
        # Launch 10 threads (more than max_size 5)
        # 5 should succeed immediately, others should wait or timeout
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Sleep for 2 seconds, timeout is 5 seconds.
            futures = [executor.submit(hold_connection, i, 1.0) for i in range(8)]
            
            results = []
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        
        pool.close()
        
        success_count = sum(1 for r in results if r["success"])
        print(f"Concurrent stress test: {success_count}/{len(results)} successful")
        for r in results:
            if not r["success"]:
                print(f"  Failed: {r['error']}")
                
        return results
        
    except Exception as e:
        print(f"Connection pooling test failed: {e}")
        return {"error": str(e)}

def test_mcp_tools_sequential():
    """Test MCP tools sequentially to check for leaks."""
    print("\nTesting MCP tools sequential soak test (50 iterations)...")
    
    try:
        # Import server to use its pool
        import server
        
        success_count = 0
        total_iterations = 50
        
        start_time = time.time()
        for i in range(total_iterations):
            try:
                # Check server info
                invoke_tool(server.db_pg96_server_info)
                
                # Check simple query
                invoke_tool(server.db_pg96_list_objects, object_type="schema")
                
                success_count += 1
                if i % 10 == 0:
                    print(f"  Iteration {i}: OK")
                    
            except Exception as e:
                print(f"  Iteration {i}: FAILED - {e}")
                # If we fail, it might be permanent
                break
                
        duration = time.time() - start_time
        print(f"Sequential test completed: {success_count}/{total_iterations} in {duration:.2f}s")
        
    except Exception as e:
        print(f"Sequential test error: {e}")

def get_safe_target_display(url: str) -> str:
    """Safely parse the DATABASE_URL to get a display string without credentials."""
    if not url:
        return "<DATABASE_URL not set>"
    try:
        parsed = urlparse(url)
        # Return hostname and port if available, otherwise the full URL minus password
        return parsed.hostname + (":" + str(parsed.port) if parsed.port else "")
    except Exception:
        # Fallback for malformed URLs
        return "<unable to parse DATABASE_URL>"

def main():
    print("PostgreSQL MCP Server Remote Stress Test")
    print("=" * 60)
    print(f"Target: {get_safe_target_display(DATABASE_URL)}")
    
    # Test 1: Connection Pool Stress
    test_connection_pooling_remote()
    
    # Test 2: MCP Tool Sequential Soak
    test_mcp_tools_sequential()

if __name__ == "__main__":
    main()
