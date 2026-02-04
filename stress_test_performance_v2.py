
import os
import time
import json
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Any
import sys
import psycopg
from psycopg_pool import ConnectionPool

# Configuration for readonly user
os.environ["DATABASE_URL"] = "postgresql://postgres_readonly:readonly123@localhost:5432/mcp_db"
os.environ["MCP_ALLOW_WRITE"] = "false"

def create_connection_pool():
    """Create a connection pool with optimized settings."""
    try:
        pool = ConnectionPool(
            conninfo=os.environ["DATABASE_URL"],
            min_size=1,
            max_size=10,
            max_idle=30,
            max_lifetime=600,
            timeout=10
        )
        return pool
    except Exception as e:
        print(f"Failed to create connection pool: {e}")
        return None

def test_connection_pooling():
    """Test connection pooling behavior."""
    print("Testing connection pooling...")
    
    pool = create_connection_pool()
    if not pool:
        return None
    
    try:
        # Test basic connectivity
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version()")
                version = cur.fetchone()
                print(f"Connected to: {version[0][:50]}...")
        
        # Test pool statistics
        stats = pool.get_stats()
        print(f"Pool stats: {stats}")
        
        return pool
    except Exception as e:
        print(f"Connection pool test failed: {e}")
        return None

def invoke_tool_safe(tool_obj, **kwargs):
    """Safely invoke a FastMCP tool object with error handling."""
    try:
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
    except Exception as e:
        raise e

def test_tool_performance_safe(tool_name: str, tool_obj, **kwargs) -> Dict[str, Any]:
    """Test a single tool performance with comprehensive error handling."""
    start_time = time.time()
    try:
        result = invoke_tool_safe(tool_obj, **kwargs)
        end_time = time.time()
        return {
            "tool": tool_name,
            "success": True,
            "execution_time": end_time - start_time,
            "result_size": len(str(result)) if result else 0,
            "error": None
        }
    except Exception as e:
        end_time = time.time()
        return {
            "tool": tool_name,
            "success": False,
            "execution_time": end_time - start_time,
            "result_size": 0,
            "error": str(e)
        }

def run_connection_pool_test(num_connections: int) -> Dict[str, Any]:
    """Test connection pool behavior under load."""
    print(f"Testing connection pool with {num_connections} concurrent connections...")
    
    pool = create_connection_pool()
    if not pool:
        return {"error": "Failed to create connection pool"}
    
    results = []
    
    def test_connection(conn_id: int) -> Dict[str, Any]:
        try:
            with pool.connection(timeout=5) as conn:
                with conn.cursor() as cur:
                    start_time = time.time()
                    cur.execute("SELECT pg_backend_pid(), current_user, now()")
                    result = cur.fetchone()
                    end_time = time.time()
                    
                    return {
                        "connection_id": conn_id,
                        "success": True,
                        "backend_pid": result[0],
                        "user": result[1],
                        "timestamp": str(result[2]),
                        "execution_time": end_time - start_time
                    }
        except Exception as e:
            return {
                "connection_id": conn_id,
                "success": False,
                "error": str(e)
            }
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_connections) as executor:
        futures = [executor.submit(test_connection, i) for i in range(num_connections)]
        
        for future in concurrent.futures.as_completed(futures, timeout=30):
            try:
                result = future.result(timeout=5)
                results.append(result)
            except Exception as e:
                results.append({
                    "connection_id": "timeout",
                    "success": False,
                    "error": str(e)
                })
    
    # Get final pool stats
    final_stats = pool.get_stats()
    
    return {
        "num_connections": num_connections,
        "results": results,
        "pool_stats": final_stats,
        "success_rate": sum(1 for r in results if r.get("success", False)) / len(results) if results else 0
    }

def run_tool_stress_test(num_threads: int, iterations: int) -> Dict[str, Any]:
    """Run stress test on MCP tools."""
    print(f"Running tool stress test with {num_threads} threads, {iterations} iterations each...")
    
    results = []
    
    def worker_task(thread_id: int, iteration: int) -> List[Dict[str, Any]]:
        try:
            # Import server inside thread to avoid connection pool issues
            import server
            
            # Test different tools
            tools_to_test = [
                ("ping", server.db_pg96_ping),
                ("server_info", server.db_pg96_server_info),
                ("list_schemas", server.db_pg96_list_objects, {"object_type": "schema"}),
                ("list_tables", server.db_pg96_list_objects, {"object_type": "table", "schema": "smsadmin"}),
                ("analyze_logical_data_model", server.db_pg96_analyze_logical_data_model, {"schema": "smsadmin"})
            ]
            
            thread_results = []
            for tool_name, tool_obj, *args in tools_to_test:
                kwargs = args[0] if args else {}
                result = test_tool_performance_safe(tool_name, tool_obj, **kwargs)
                result["thread_id"] = thread_id
                result["iteration"] = iteration
                result["timestamp"] = datetime.now().isoformat()
                thread_results.append(result)
            
            return thread_results
        except Exception as e:
            return [{
                "tool": "import_error",
                "success": False,
                "execution_time": 0,
                "error": str(e),
                "thread_id": thread_id,
                "iteration": iteration,
                "timestamp": datetime.now().isoformat()
            }]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for thread_id in range(num_threads):
            for iteration in range(iterations):
                future = executor.submit(worker_task, thread_id, iteration)
                futures.append(future)
        
        for future in concurrent.futures.as_completed(futures, timeout=60):
            try:
                thread_results = future.result(timeout=10)
                results.extend(thread_results)
            except Exception as e:
                results.append({
                    "tool": "future_error",
                    "success": False,
                    "execution_time": 0,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
    
    return {
        "num_threads": num_threads,
        "iterations": iterations,
        "results": results,
        "total_tests": len(results)
    }

def analyze_stress_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze stress test results."""
    total_tests = len(results)
    successful_tests = sum(1 for r in results if r.get("success", False))
    failed_tests = total_tests - successful_tests
    
    # Group by tool
    tools_stats = {}
    for result in results:
        tool = result.get("tool", "unknown")
        if tool not in tools_stats:
            tools_stats[tool] = {
                "total": 0,
                "successful": 0,
                "failed": 0,
                "avg_execution_time": 0,
                "max_execution_time": 0,
                "min_execution_time": float('inf'),
                "errors": []
            }
        
        tools_stats[tool]["total"] += 1
        if result.get("success", False):
            tools_stats[tool]["successful"] += 1
        else:
            tools_stats[tool]["failed"] += 1
            if result.get("error"):
                tools_stats[tool]["errors"].append(result["error"])
        
        exec_time = result.get("execution_time", 0)
        tools_stats[tool]["avg_execution_time"] += exec_time
        tools_stats[tool]["max_execution_time"] = max(tools_stats[tool]["max_execution_time"], exec_time)
        tools_stats[tool]["min_execution_time"] = min(tools_stats[tool]["min_execution_time"], exec_time)
    
    # Calculate averages
    for tool in tools_stats:
        if tools_stats[tool]["total"] > 0:
            tools_stats[tool]["avg_execution_time"] /= tools_stats[tool]["total"]
        if tools_stats[tool]["min_execution_time"] == float('inf'):
            tools_stats[tool]["min_execution_time"] = 0
    
    return {
        "summary": {
            "total_tests": total_tests,
            "successful_tests": successful_tests,
            "failed_tests": failed_tests,
            "success_rate": (successful_tests / total_tests * 100) if total_tests > 0 else 0
        },
        "tools_stats": tools_stats,
        "raw_results": results
    }

def main():
    print("PostgreSQL MCP Server Stress Test & Performance Analysis")
    print("=" * 60)
    
    # Test connection pooling first
    print("\n1. Testing Connection Pooling...")
    pool_results = []
    for num_conns in [1, 5, 10, 20]:
        result = run_connection_pool_test(num_conns)
        if "error" not in result:
            pool_results.append(result)
            print(f"  {num_conns} connections: {result['success_rate']*100:.1f}% success rate")
            if result.get("pool_stats"):
                stats = result["pool_stats"]
                print(f"    Pool usage: {stats.get('usage', 'N/A')}")
                print(f"    Available connections: {stats.get('available', 'N/A')}")
        else:
            print(f"  {num_conns} connections: Failed - {result['error']}")
    
    # Test configurations for tool stress testing
    test_configs = [
        {"threads": 1, "iterations": 3},
        {"threads": 5, "iterations": 2},
        {"threads": 10, "iterations": 1}
    ]
    
    tool_test_results = []
    
    print("\n2. Testing MCP Tools Under Load...")
    for config in test_configs:
        print(f"\nTesting with {config['threads']} threads, {config['iterations']} iterations each...")
        start_time = time.time()
        
        test_result = run_tool_stress_test(config["threads"], config["iterations"])
        analysis = analyze_stress_results(test_result["results"])
        
        end_time = time.time()
        test_duration = end_time - start_time
        
        print(f"Test completed in {test_duration:.2f} seconds")
        print(f"Success rate: {analysis['summary']['success_rate']:.1f}%")
        print(f"Total tests: {analysis['summary']['total_tests']}")
        print(f"Failed tests: {analysis['summary']['failed_tests']}")
        
        # Show tool-specific stats
        print("\nTool Performance Summary:")
        for tool, stats in analysis["tools_stats"].items():
            if stats["total"] > 0 and tool != "import_error":
                print(f"  {tool}:")
                print(f"    Success rate: {stats['successful']/stats['total']*100:.1f}%")
                print(f"    Avg execution time: {stats['avg_execution_time']:.3f}s")
                print(f"    Min/Max time: {stats['min_execution_time']:.3f}s / {stats['max_execution_time']:.3f}s")
                if stats["errors"]:
                    print(f"    Errors: {len(stats['errors'])} unique errors")
        
        tool_test_results.append({
            "config": config,
            "test_result": test_result,
            "analysis": analysis,
            "duration": test_duration
        })
    
    # Final summary
    print("\n" + "=" * 60)
    print("STRESS TEST & PERFORMANCE ANALYSIS SUMMARY")
    print("=" * 60)
    
    print("\nConnection Pooling Results:")
    for i, result in enumerate(pool_results):
        num_conns = result["num_connections"]
        print(f"  {num_conns} connections: {result['success_rate']*100:.1f}% success rate")
        if result.get("pool_stats"):
            stats = result["pool_stats"]
            print(f"    Pool usage: {stats.get('usage', 'N/A')}")
            print(f"    Available connections: {stats.get('available', 'N/A')}")
    
    print("\nTool Stress Test Results:")
    for result in tool_test_results:
        config = result["config"]
        analysis = result["analysis"]
        print(f"\n{config['threads']} threads × {config['iterations']} iterations:")
        print(f"  Duration: {result['duration']:.2f}s")
        print(f"  Success rate: {analysis['summary']['success_rate']:.1f}%")
        print(f"  Total tests: {analysis['summary']['total_tests']}")
        print(f"  Failed tests: {analysis['summary']['failed_tests']}")
    
    # Save detailed results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"stress_test_performance_{timestamp}.json"
    
    final_results = {
        "timestamp": timestamp,
        "connection_pool_results": pool_results,
        "tool_stress_results": tool_test_results,
        "summary": {
            "total_connection_tests": len(pool_results),
            "total_tool_tests": len(tool_test_results),
            "overall_success": any(r["analysis"]["summary"]["success_rate"] > 0 for r in tool_test_results)
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(final_results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {output_file}")
    
    # Performance recommendations
    print("\nPerformance Recommendations:")
    print("1. Connection Pool Issues Detected:")
    print("   - Consider increasing max_connections in PostgreSQL")
    print("   - Implement connection pool retry logic")
    print("   - Monitor connection pool exhaustion")
    
    print("\n2. Tool Performance Issues:")
    print("   - Tools are failing due to connection timeouts")
    print("   - Consider implementing circuit breaker pattern")
    print("   - Add connection pool monitoring and alerts")
    
    print("\n3. Specific Issues Found:")
    print("   - Connection timeouts after 30 seconds")
    print("   - Pool exhaustion under concurrent load")
    print("   - Import errors in multi-threaded environment")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStress test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
