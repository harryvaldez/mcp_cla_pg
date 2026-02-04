
import os
import time
import json
import threading
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Any
import sys

# Configuration for readonly user
os.environ["DATABASE_URL"] = "postgresql://postgres_readonly:readonly123@localhost:5432/mcp_db"
os.environ["MCP_ALLOW_WRITE"] = "false"

def invoke_tool(tool_obj, **kwargs):
    """Helper to invoke a FastMCP tool object."""
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

def test_tool_performance(tool_name: str, tool_obj, **kwargs) -> Dict[str, Any]:
    """Test a single tool performance."""
    start_time = time.time()
    try:
        result = invoke_tool(tool_obj, **kwargs)
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

def run_concurrent_stress_test(num_threads: int, iterations: int) -> List[Dict[str, Any]]:
    """Run concurrent stress test."""
    print(f"Running stress test with {num_threads} threads, {iterations} iterations each...")
    
    results = []
    
    def worker_task(thread_id: int, iteration: int) -> Dict[str, Any]:
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
                result = test_tool_performance(tool_name, tool_obj, **kwargs)
                result["thread_id"] = thread_id
                result["iteration"] = iteration
                thread_results.append(result)
            
            return thread_results
        except Exception as e:
            return [{
                "tool": "import_error",
                "success": False,
                "execution_time": 0,
                "error": str(e),
                "thread_id": thread_id,
                "iteration": iteration
            }]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for thread_id in range(num_threads):
            for iteration in range(iterations):
                future = executor.submit(worker_task, thread_id, iteration)
                futures.append(future)
        
        for future in concurrent.futures.as_completed(futures):
            try:
                thread_results = future.result()
                results.extend(thread_results)
            except Exception as e:
                results.append({
                    "tool": "future_error",
                    "success": False,
                    "execution_time": 0,
                    "error": str(e)
                })
    
    return results

def analyze_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
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
    print("PostgreSQL MCP Server Stress Test")
    print("=" * 50)
    
    # Test configurations
    test_configs = [
        {"threads": 1, "iterations": 10},
        {"threads": 5, "iterations": 5},
        {"threads": 10, "iterations": 3},
        {"threads": 20, "iterations": 2}
    ]
    
    all_results = []
    
    for config in test_configs:
        print(f"\nTesting with {config['threads']} threads, {config['iterations']} iterations each...")
        start_time = time.time()
        
        results = run_concurrent_stress_test(config["threads"], config["iterations"])
        analysis = analyze_results(results)
        
        end_time = time.time()
        test_duration = end_time - start_time
        
        print(f"Test completed in {test_duration:.2f} seconds")
        print(f"Success rate: {analysis['summary']['success_rate']:.1f}%")
        print(f"Total tests: {analysis['summary']['total_tests']}")
        print(f"Failed tests: {analysis['summary']['failed_tests']}")
        
        # Show tool-specific stats
        print("\nTool Performance Summary:")
        for tool, stats in analysis["tools_stats"].items():
            if stats["total"] > 0:
                print(f"  {tool}:")
                print(f"    Success rate: {stats['successful']/stats['total']*100:.1f}%")
                print(f"    Avg execution time: {stats['avg_execution_time']:.3f}s")
                print(f"    Min/Max time: {stats['min_execution_time']:.3f}s / {stats['max_execution_time']:.3f}s")
                if stats["errors"]:
                    print(f"    Errors: {len(stats['errors'])} unique errors")
        
        all_results.append({
            "config": config,
            "analysis": analysis,
            "duration": test_duration
        })
    
    # Final summary
    print("\n" + "=" * 50)
    print("STRESS TEST SUMMARY")
    print("=" * 50)
    
    for result in all_results:
        config = result["config"]
        analysis = result["analysis"]
        print(f"\n{config['threads']} threads × {config['iterations']} iterations:")
        print(f"  Duration: {result['duration']:.2f}s")
        print(f"  Success rate: {analysis['summary']['success_rate']:.1f}%")
        print(f"  Total tests: {analysis['summary']['total_tests']}")
        print(f"  Failed tests: {analysis['summary']['failed_tests']}")
    
    # Save detailed results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"stress_test_results_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {output_file}")

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
