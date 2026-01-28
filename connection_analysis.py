
import os
import time
import json
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Any
import sys
import psycopg

def test_direct_connection():
    """Test direct database connection."""
    print("Testing direct database connection...")
    
    try:
        # Test with different connection strings
        conn_strings = [
            "postgresql://postgres_readonly:readonly123@localhost:5432/mcp_db",
            "postgresql://postgres:password123@localhost:5432/mcp_db",
            "postgresql://postgres:password123@127.0.0.1:5432/mcp_db"
        ]
        
        results = []
        for conn_str in conn_strings:
            try:
                start_time = time.time()
                conn = psycopg.connect(conn_str, connect_timeout=5)
                
                with conn.cursor() as cur:
                    cur.execute("SELECT version(), current_user, pg_backend_pid()")
                    result = cur.fetchone()
                    
                    end_time = time.time()
                    
                    results.append({
                        "connection_string": conn_str,
                        "success": True,
                        "execution_time": end_time - start_time,
                        "version": result[0][:50] + "...",
                        "user": result[1],
                        "backend_pid": result[2]
                    })
                
                conn.close()
                
            except Exception as e:
                results.append({
                    "connection_string": conn_str,
                    "success": False,
                    "error": str(e)
                })
        
        return results
        
    except Exception as e:
        print(f"Direct connection test failed: {e}")
        return []

def test_connection_pooling():
    """Test connection pooling behavior."""
    print("Testing connection pooling...")
    
    try:
        from psycopg_pool import ConnectionPool
        
        # Test with superuser first
        pool = ConnectionPool(
            conninfo="postgresql://postgres:password123@localhost:5432/mcp_db",
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
                        return {
                            "connection_id": conn_id,
                            "success": True,
                            "backend_pid": result[0],
                            "timestamp": str(result[1])
                        }
            except Exception as e:
                return {
                    "connection_id": conn_id,
                    "success": False,
                    "error": str(e)
                }
        
        # Test multiple concurrent connections
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_concurrent_connection, i) for i in range(5)]
            
            concurrent_results = []
            for future in concurrent.futures.as_completed(futures, timeout=10):
                try:
                    result = future.result(timeout=2)
                    concurrent_results.append(result)
                except Exception as e:
                    concurrent_results.append({
                        "connection_id": "timeout",
                        "success": False,
                        "error": str(e)
                    })
        
        pool.close()
        
        return {
            "basic_connection": True,
            "concurrent_results": concurrent_results,
            "success_rate": sum(1 for r in concurrent_results if r.get("success", False)) / len(concurrent_results) if concurrent_results else 0
        }
        
    except Exception as e:
        print(f"Connection pooling test failed: {e}")
        return {"error": str(e)}

def test_mcp_tools():
    """Test MCP tools with error handling."""
    print("Testing MCP tools...")
    
    # Set environment for readonly user
    os.environ["DATABASE_URL"] = "postgresql://postgres_readonly:readonly123@localhost:5432/mcp_db"
    os.environ["MCP_ALLOW_WRITE"] = "false"
    
    def invoke_tool_safe(tool_obj, **kwargs):
        """Safely invoke a FastMCP tool object."""
        try:
            # Try calling it directly
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
        except Exception as e:
            raise e
    
    def test_single_tool(tool_name: str, tool_obj, **kwargs) -> Dict[str, Any]:
        """Test a single tool."""
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
    
    try:
        import server
        
        tools_to_test = [
            ("ping", server.db_pg96_ping),
            ("server_info", server.db_pg96_server_info),
            ("list_schemas", server.db_pg96_list_schemas, {"include_system": False}),
            ("list_tables", server.db_pg96_list_tables, {"schema": "smsadmin"})
        ]
        
        tool_results = []
        for tool_name, tool_obj, *args in tools_to_test:
            kwargs = args[0] if args else {}
            result = test_single_tool(tool_name, tool_obj, **kwargs)
            tool_results.append(result)
        
        return tool_results
        
    except Exception as e:
        return [{"tool": "import_error", "success": False, "error": str(e)}]

def analyze_connection_issues(results: Dict[str, Any]) -> List[str]:
    """Analyze connection issues and provide recommendations."""
    recommendations = []
    
    # Check for timeout errors
    timeout_errors = 0
    connection_errors = 0
    auth_errors = 0
    
    for category, data in results.items():
        if isinstance(data, list):
            for item in data:
                error = item.get("error", "")
                if "timeout" in error.lower():
                    timeout_errors += 1
                elif "connection" in error.lower():
                    connection_errors += 1
                elif "authentication" in error.lower() or "permission" in error.lower():
                    auth_errors += 1
        elif isinstance(data, dict) and "error" in data:
            error = data["error"]
            if "timeout" in error.lower():
                timeout_errors += 1
            elif "connection" in error.lower():
                connection_errors += 1
            elif "authentication" in error.lower() or "permission" in error.lower():
                auth_errors += 1
    
    if timeout_errors > 0:
        recommendations.append("Connection timeouts detected. Consider:")
        recommendations.append("  - Increasing connection timeout values")
        recommendations.append("  - Checking network connectivity to PostgreSQL")
        recommendations.append("  - Verifying PostgreSQL is accepting connections")
        recommendations.append("  - Checking firewall rules")
    
    if connection_errors > 0:
        recommendations.append("Connection establishment errors detected. Consider:")
        recommendations.append("  - Verifying PostgreSQL is running and accessible")
        recommendations.append("  - Checking connection string format")
        recommendations.append("  - Verifying port 5432 is open and accessible")
        recommendations.append("  - Checking PostgreSQL max_connections setting")
    
    if auth_errors > 0:
        recommendations.append("Authentication/permission errors detected. Consider:")
        recommendations.append("  - Verifying user credentials and permissions")
        recommendations.append("  - Checking pg_hba.conf authentication settings")
        recommendations.append("  - Ensuring user has necessary database privileges")
    
    if not recommendations:
        recommendations.append("No specific connection issues detected in the test results.")
    
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
        print(f"  {result['connection_string']}: {status}")
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
        print(f"Basic connection: {'✓ SUCCESS' if pool_results['basic_connection'] else '✗ FAILED'}")
        print(f"Concurrent connections success rate: {pool_results['success_rate']*100:.1f}%")
        concurrent_results = pool_results.get("concurrent_results", [])
        if concurrent_results:
            successful = sum(1 for r in concurrent_results if r.get("success", False))
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
            print(f"    Error: {result['error']}")
    
    # Analysis and Recommendations
    print("\n" + "=" * 60)
    print("CONNECTION ISSUES ANALYSIS & RECOMMENDATIONS")
    print("=" * 60)
    
    recommendations = analyze_connection_issues(results)
    
    print("\nRecommendations:")
    for i, recommendation in enumerate(recommendations, 1):
        print(f"{i}. {recommendation}")
    
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
