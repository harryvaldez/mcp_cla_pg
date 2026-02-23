
import os
import time
import json
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Any
import sys
import psycopg
from dotenv import load_dotenv
from urllib.parse import urlparse, urlunparse

# Load environment variables
load_dotenv()

def get_sanitized_url(url: str) -> str:
    """Removes the password from a database URL for safe logging."""
    try:
        parsed_url = urlparse(url)
        if parsed_url.password:
            netloc = f"{parsed_url.username}:****@{parsed_url.hostname}"
            if parsed_url.port:
                netloc += f":{parsed_url.port}"
            sanitized_parts = parsed_url._replace(netloc=netloc)
            return urlunparse(sanitized_parts)
        return url
    except Exception:
        return "<unparseable_url>"

def test_direct_connection():
    """Test direct database connection using environment variables."""
    print("Testing direct database connection...")

    # Build connection strings from environment variables
    db_host = os.environ.get("POSTGRES_HOST", "localhost")
    db_port = os.environ.get("POSTGRES_PORT", 5432)
    db_name = os.environ.get("POSTGRES_DB", "mcp_db")
    
    # Read-only user
    ro_user = os.environ.get("POSTGRES_READONLY_USER", "postgres_readonly")
    ro_pass = os.environ.get("POSTGRES_READONLY_PASSWORD", "readonly123")
    
    # Superuser
    su_user = os.environ.get("POSTGRES_USER", "postgres")
    su_pass = os.environ.get("POSTGRES_PASSWORD", "password123")

    conn_strings = [
        f"postgresql://{ro_user}:{ro_pass}@{db_host}:{db_port}/{db_name}",
        f"postgresql://{su_user}:{su_pass}@{db_host}:{db_port}/{db_name}",
        f"postgresql://{su_user}:{su_pass}@127.0.0.1:{db_port}/{db_name}"
    ]

    results = []
    for conn_str in conn_strings:
        try:
            start_time = time.time()
            # Use a with statement to ensure the connection is closed
            with psycopg.connect(conn_str, connect_timeout=5) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT version(), current_user, pg_backend_pid()")
                    result = cur.fetchone()
                    end_time = time.time()

                    results.append({
                        "connection_string": conn_str,
                        "success": True,
                        "execution_time": end_time - start_time,
                        "version": result[0][:50] + "..." if result and result[0] else "N/A",
                        "user": result[1] if result else "N/A",
                        "backend_pid": result[2] if result else "N/A"
                    })

        except Exception as e:
            results.append({
                "connection_string": conn_str,
                "success": False,
                "error": str(e)
            })
    return results

def test_connection_pooling():
    """Test connection pooling behavior, ensuring resources are cleaned up."""
    print("Testing connection pooling...")
    pool = None
    try:
        from psycopg_pool import ConnectionPool

        # Build connection string from environment variables
        db_host = os.environ.get("POSTGRES_HOST", "localhost")
        db_port = os.environ.get("POSTGRES_PORT", 5432)
        db_name = os.environ.get("POSTGRES_DB", "mcp_db")
        su_user = os.environ.get("POSTGRES_USER", "postgres")
        su_pass = os.environ.get("POSTGRES_PASSWORD", "password123")
        conninfo = f"postgresql://{su_user}:{su_pass}@{db_host}:{db_port}/{db_name}"

        pool = ConnectionPool(
            conninfo=conninfo,
            min_size=1,
            max_size=5,
            max_idle=30,
            timeout=5
        )

        # Test basic connectivity
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_backend_pid(), current_user")
                result = cur.fetchone()
                print(f"Pool connection successful: PID={result[0]}, User={result[1]}")

        # Test concurrent connections
        def test_concurrent_connection(conn_id):
            try:
                with pool.connection(timeout=3) as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT pg_backend_pid(), now()")
                        result = cur.fetchone()
                        return {"connection_id": conn_id, "success": True, "backend_pid": result[0], "timestamp": str(result[1])}
            except Exception as e:
                return {"connection_id": conn_id, "success": False, "error": str(e)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_concurrent_connection, i) for i in range(5)]
            concurrent_results = [future.result() for future in concurrent.futures.as_completed(futures, timeout=10)]

        return {
            "basic_connection": True,
            "concurrent_results": concurrent_results,
            "success_rate": sum(1 for r in concurrent_results if r.get("success")) / len(concurrent_results) if concurrent_results else 0
        }

    except Exception as e:
        print(f"Connection pooling test failed: {e}")
        return {"error": str(e)}
    finally:
        # Ensure the pool is closed even if errors occur
        if pool is not None:
            pool.close()
            print("Connection pool closed.")

def test_mcp_tools():
    """Test MCP tools with error handling in an isolated environment."""
    print("Testing MCP tools...")

    # Preserve original environment variables
    original_db_url = os.environ.get("DATABASE_URL")
    original_allow_write = os.environ.get("MCP_ALLOW_WRITE")

    try:
        # Set environment for readonly user for the scope of this test
        ro_user = os.environ.get("POSTGRES_READONLY_USER", "postgres_readonly")
        ro_pass = os.environ.get("POSTGRES_READONLY_PASSWORD", "readonly123")
        db_host = os.environ.get("POSTGRES_HOST", "localhost")
        db_port = os.environ.get("POSTGRES_PORT", 5432)
        db_name = os.environ.get("POSTGRES_DB", "mcp_db")
        
        os.environ["DATABASE_URL"] = f"postgresql://{ro_user}:{ro_pass}@{db_host}:{db_port}/{db_name}"
        os.environ["MCP_ALLOW_WRITE"] = "false"

        # Dynamically import server to use the temporary environment
        import server

        def invoke_tool_safe(tool_obj, **kwargs):
            # Simplified and safer invocation
            if callable(tool_obj):
                return tool_obj(**kwargs)
            for attr in ("fn", "func", "function", "_fn"):
                inner = getattr(tool_obj, attr, None)
                if callable(inner):
                    return inner(**kwargs)
            raise TypeError(f"Could not find callable for tool {tool_obj}")

        def test_single_tool(tool_name: str, tool_obj, **kwargs) -> Dict[str, Any]:
            start_time = time.time()
            try:
                result = invoke_tool_safe(tool_obj, **kwargs)
                end_time = time.time()
                return {
                    "tool": tool_name,
                    "success": True,
                    "execution_time": end_time - start_time,
                    "result_size": len(str(result)) if result else 0
                }
            except Exception as e:
                end_time = time.time()
                return {
                    "tool": tool_name,
                    "success": False,
                    "execution_time": end_time - start_time,
                    "error": str(e)
                }

        tools_to_test = [
            ("ping", server.db_pg96_ping),
            ("server_info", server.db_pg96_server_info),
            ("list_schemas", server.db_pg96_list_objects, {"object_type": "schema"}),
            ("list_tables", server.db_pg96_list_objects, {"object_type": "table", "schema": "smsadmin"})
        ]

        tool_results = []
        for tool_name, tool_obj, *args in tools_to_test:
            kwargs = args[0] if args else {}
            result = test_single_tool(tool_name, tool_obj, **kwargs)
            tool_results.append(result)

        return tool_results

    except Exception as e:
        return [{"tool": "import_error", "success": False, "error": str(e)}]
    finally:
        # Restore original environment
        if original_db_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = original_db_url
        
        if original_allow_write is None:
            os.environ.pop("MCP_ALLOW_WRITE", None)
        else:
            os.environ["MCP_ALLOW_WRITE"] = original_allow_write

def analyze_connection_issues(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze connection issues and provide structured recommendations."""
    recommendations = []
    timeout_errors, connection_errors, auth_errors = 0, 0, 0

    for category, data in results.items():
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not item or not isinstance(item, dict):
                continue
            error = item.get("error", "").lower()
            if "timeout" in error:
                timeout_errors += 1
            elif "connection" in error:
                connection_errors += 1
            elif "authentication" in error or "permission" in error:
                auth_errors += 1

    if timeout_errors > 0:
        recommendations.append({
            "title": "Connection timeouts detected",
            "bullets": [
                "Increase connection timeout values in your application.",
                "Check network latency and stability between the client and the PostgreSQL server.",
                "Verify the PostgreSQL server isn't overloaded and is accepting connections promptly.",
                "Review firewall rules on the client, server, and any intermediary network devices."
            ]
        })

    if connection_errors > 0:
        recommendations.append({
            "title": "Connection establishment errors detected",
            "bullets": [
                "Verify the PostgreSQL server is running and accessible from the client machine.",
                "Check that the connection string (host, port, dbname) is correct.",
                "Ensure the specified port (e.g., 5432) is open and not blocked by a firewall.",
                "Check the PostgreSQL `max_connections` setting and current connection count."
            ]
        })

    if auth_errors > 0:
        recommendations.append({
            "title": "Authentication or permission errors detected",
            "bullets": [
                "Verify the username and password are correct for the target database.",
                "Check the `pg_hba.conf` file on the PostgreSQL server to ensure the connection method is allowed.",
                "Ensure the user has the necessary privileges on the database and its objects."
            ]
        })

    return recommendations


def main():
    print("PostgreSQL MCP Server Connection Issues Analysis")
    print("=" * 60)

    results = {}

    # Test 1: Direct Connection
    print("\n1. Testing Direct Database Connections...")
    direct_results = test_direct_connection()
    results["direct_connection"] = direct_results

    print("Direct Connection Results:")
    for result in direct_results:
        status = "✓ SUCCESS" if result["success"] else "✗ FAILED"
        # Sanitize URL before printing
        sanitized_url = get_sanitized_url(result['connection_string'])
        print(f"  {sanitized_url}: {status}")
        if result["success"]:
            print(f"    Execution time: {result['execution_time']:.3f}s")
            print(f"    User: {result['user']}, PID: {result['backend_pid']}")
        else:
            print(f"    Error: {result['error']}")

    # Test 2: Connection Pooling
    print("\n2. Testing Connection Pooling...")
    pool_results = test_connection_pooling()
    results["connection_pooling"] = pool_results

    if "error" in pool_results:
        print(f"Connection pooling failed: {pool_results['error']}")
    else:
        print(f"Basic connection: {'✓ SUCCESS' if pool_results.get('basic_connection') else '✗ FAILED'}")
        print(f"Concurrent connections success rate: {pool_results.get('success_rate', 0)*100:.1f}%")
        concurrent_results = pool_results.get("concurrent_results", [])
        if concurrent_results:
            successful = sum(1 for r in concurrent_results if r.get("success"))
            print(f"Successful concurrent connections: {successful}/{len(concurrent_results)}")

    # Test 3: MCP Tools
    print("\n3. Testing MCP Tools...")
    tool_results = test_mcp_tools()
    results["mcp_tools"] = tool_results

    print("MCP Tool Results:")
    for result in tool_results:
        status = "✓ SUCCESS" if result["success"] else "✗ FAILED"
        print(f"  {result['tool']}: {status}")
        if result["success"]:
            print(f"    Execution time: {result['execution_time']:.3f}s")
            print(f"    Result size: {result['result_size']} bytes")
        else:
            print(f"    Error: {result.get('error', 'Unknown error')}")

    # Analysis and Recommendations
    print("\n" + "=" * 60)
    print("CONNECTION ISSUES ANALYSIS & RECOMMENDATIONS")
    print("=" * 60)

    recommendations = analyze_connection_issues(results)

    print("\nRecommendations:")
    if not recommendations:
        print("  ✓ All tests passed and no common connection issues were detected.")
    else:
        for i, rec in enumerate(recommendations, 1):
            print(f"\n{i}. {rec['title']}")
            for bullet in rec['bullets']:
                print(f"    - {bullet}")

    # Summary statistics
    print("\nTest Summary:")
    total_direct_tests = len(results.get("direct_connection", []))
    successful_direct = sum(1 for r in results.get("direct_connection", []) if r.get("success", False))
    
    total_tool_tests = len(results.get("mcp_tools", []))
    successful_tools = sum(1 for r in results.get("mcp_tools", []) if r.get("success", False))
    
    pool_success = results.get("connection_pooling", {}).get("success_rate", 0) > 0
    
    print(f"Direct connections: {successful_direct}/{total_direct_tests} successful")
    print(f"MCP tools: {successful_tools}/{total_tool_tests} successful")
    print(f"Connection pooling: {'✓ SUCCESS' if pool_success else '✗ FAILED'}")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"connection_analysis_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {output_file}")
    
    return results

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
