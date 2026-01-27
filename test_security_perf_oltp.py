#!/usr/bin/env python
"""
Test script to call db_pg96_database_security_performance_metrics with profile=oltp
and analyze the results with recommendations.
"""

import json
import os
import sys
from server import server, pool

# Get database connection parameters from environment
HOST = os.environ.get("POSTGRES_HOST", "localhost")
PORT = int(os.environ.get("POSTGRES_PORT", "5432"))
USER = os.environ.get("POSTGRES_USER", "postgres")
PASSWORD = os.environ.get("POSTGRES_PASSWORD", "")
DB = os.environ.get("POSTGRES_DB", "postgres")

def _invoke(server_instance, tool_name, arguments=None):
    """Invoke a tool on the server."""
    if arguments is None:
        arguments = {}
    # Get the tool function
    for tool in server_instance._tools.values():
        if tool.name == tool_name:
            return tool.fn(**arguments)
    raise ValueError(f"Tool {tool_name} not found")

def main():
    print("=" * 80)
    print("DATABASE SECURITY & PERFORMANCE METRICS ANALYSIS")
    print("Profile: OLTP (Online Transaction Processing)")
    print("=" * 80)
    print()
    
    try:
        # Initialize the database connection pool
        print("[1/3] Initializing database connection pool...")
        print(f"      Connecting to {HOST}:{PORT}/{DB} as {USER}")
        print()
        
        # Call the function with profile=oltp
        print("[2/3] Calling db_pg96_database_security_performance_metrics(profile='oltp')...")
        results = _invoke(
            server,
            "db_pg96_database_security_performance_metrics",
            {"profile": "oltp"}
        )
        print("      ✓ Results retrieved successfully")
        print()
        
        # Display results
        print("[3/3] Analyzing results and generating recommendations...")
        print()
        
        # Pretty print JSON results
        print("FULL RESULTS:")
        print("-" * 80)
        print(json.dumps(results, indent=2, default=str))
        print()
        
        # Summary analysis
        print("=" * 80)
        print("EXECUTIVE SUMMARY (OLTP Profile)")
        print("=" * 80)
        print()
        
        profile = results.get("profile_applied", "unknown")
        print(f"Profile Applied: {profile.upper()}")
        print()
        
        # Security Metrics Summary
        print("SECURITY METRICS:")
        print("-" * 80)
        security = results.get("security_metrics", {})
        
        ssl_settings = security.get("ssl_settings", [])
        ssl_enabled = any(s["setting"] == "on" for s in ssl_settings if s.get("name") == "ssl")
        print(f"SSL/TLS Enabled: {'✓ YES' if ssl_enabled else '✗ NO'}")
        
        user_summary = security.get("user_accounts_summary", {})
        print(f"Total Users: {user_summary.get('total_users', 0)}")
        print(f"Superusers: {user_summary.get('superuser_count', 0)}")
        if user_summary.get('superuser_count', 0) > 1:
            print(f"  ⚠ Multiple superusers: {user_summary.get('superusers', [])}")
        
        no_pwd_count = user_summary.get('no_password_count', 0)
        if no_pwd_count > 0:
            print(f"  ⚠ Users without passwords: {no_pwd_count}")
        
        extensions = security.get("installed_extensions", [])
        risky = ["dblink", "postgres_fdw", "file_fdw", "plpython3u", "plperlu"]
        installed_risky = [e for e in extensions if e.get("extension") in risky]
        if installed_risky:
            print(f"  ⚠ Risky extensions: {[e['extension'] for e in installed_risky]}")
        else:
            print(f"Risky Extensions: ✓ None detected")
        
        print()
        
        # Performance Metrics Summary
        print("PERFORMANCE METRICS:")
        print("-" * 80)
        perf = results.get("performance_metrics", {})
        
        cache_metrics = perf.get("cache_hit_ratios", [])
        if cache_metrics:
            min_cache = min((m.get("cache_hit_ratio", 0) for m in cache_metrics), default=0)
            avg_cache = sum((m.get("cache_hit_ratio", 0) for m in cache_metrics)) / len(cache_metrics)
            print(f"Cache Hit Ratio: {avg_cache:.1f}% (avg) | min: {min_cache:.1f}%")
            print(f"  OLTP Threshold: ≥95%")
        
        conn_usage = perf.get("connection_usage", {})
        if conn_usage:
            active = conn_usage.get("active_connections", 0)
            max_conn = conn_usage.get("max_connections", 0)
            usage_pct = (active / max_conn * 100) if max_conn > 0 else 0
            print(f"Connection Usage: {active}/{max_conn} ({usage_pct:.1f}%)")
            print(f"  OLTP Threshold: ≤70%")
        
        checkpoint = perf.get("checkpoint_stats", {})
        if checkpoint:
            req_ratio = checkpoint.get("checkpoint_request_ratio", 0)
            print(f"Checkpoint Request Ratio: {req_ratio}%")
            print(f"  OLTP Threshold: ≤20%")
        
        lock_stats = perf.get("lock_stats", {})
        if lock_stats:
            deadlocks = lock_stats.get("deadlocks", 0)
            if deadlocks > 0:
                print(f"  ⚠ Deadlocks detected: {deadlocks}")
            temp_files = lock_stats.get("temp_files", 0)
            if temp_files > 50:  # OLTP threshold
                print(f"  ⚠ High temp file usage: {temp_files} files")
        
        print()
        
        # Issues Found
        issues = results.get("issues_found", [])
        if issues:
            print("ISSUES IDENTIFIED:")
            print("-" * 80)
            for i, issue in enumerate(issues, 1):
                print(f"{i}. {issue}")
            print()
        
        # Recommended Fixes
        fixes = results.get("recommended_fixes", [])
        if fixes:
            print("RECOMMENDED FIXES:")
            print("-" * 80)
            fix_num = 1
            for fix in fixes:
                if fix.startswith("#"):
                    print(fix)
                else:
                    print(f"{fix_num}. {fix}")
                    fix_num += 1
            print()
        
        if not issues:
            print("✓ NO ISSUES DETECTED - Database is well-configured for OLTP workloads")
            print()
        
        print("=" * 80)
        return 0
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
