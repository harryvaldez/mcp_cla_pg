#!/usr/bin/env python
"""
Test script to call db_pg96_db_sec_perf_metrics with profile=oltp
and analyze the results with recommendations.
"""

import os
os.environ["DATABASE_URL"] = "postgres://test:test@localhost:5432/testdb"
os.environ["MCP_ALLOW_WRITE"] = "true"
os.environ["MCP_CONFIRM_WRITE"] = "true"
os.environ["FASTMCP_AUTH_TYPE"] = "none"

import json
import os
import sys
import server as server_module



import pytest

def test_security_perf_oltp(mocker):
    """
    Tests the analysis and recommendation logic of the security and performance
    metrics tool for the OLTP profile.
    """
    # 1. Mock the tool's output
    mock_results = {
        "profile_applied": "oltp",
        "security_metrics": {
            "ssl_settings": [{"name": "ssl", "setting": "on"}],
            "user_accounts_summary": {
                "total_users": 10,
                "superuser_count": 2,
                "superusers": ["postgres", "admin"],
                "no_password_count": 1,
            },
            "installed_extensions": [
                {"extension": "plpgsql"},
                {"extension": "dblink"},
            ],
        },
        "performance_metrics": {
            "cache_hit_ratios": [
                {"type": "index", "cache_hit_ratio": 99.5},
                {"type": "table", "cache_hit_ratio": 98.9},
            ],
            "connection_usage": {
                "active_connections": 50,
                "max_connections": 100,
            },
            "checkpoint_stats": {"checkpoint_request_ratio": 15},
            "lock_stats": {"deadlocks": 2, "temp_files": 60},
        },
        "issues_found": [
            "High number of superusers.",
            "User account without a password.",
            "Risky extension 'dblink' is installed.",
            "High deadlock count.",
            "High temporary file usage.",
        ],
        "recommended_fixes": [
            "# Security Recommendations",
            "Review and reduce the number of superuser roles.",
        ],
    }
    mocker.patch(
        "server.db_pg96_database_security_performance_metrics.fn",
        return_value=mock_results,
    )

    # 2. Call the tool
    results = server_module.server.db_pg96_database_security_performance_metrics.fn(profile="oltp")
    assert results == mock_results

    # 3. Analyze results and assert conditions
    profile = results.get("profile_applied", "unknown")
    assert profile == "oltp"

    # Security Metrics
    security = results.get("security_metrics", {})
    ssl_settings = security.get("ssl_settings", [])
    ssl_enabled = any(s.get("setting") == "on" for s in ssl_settings if s.get("name") == "ssl")
    assert ssl_enabled, "SSL/TLS should be enabled"

    user_summary = security.get("user_accounts_summary", {})
    assert user_summary.get("total_users", 0) == 10
    assert user_summary.get("superuser_count", 0) > 1
    assert user_summary.get("no_password_count", 0) > 0

    extensions = security.get("installed_extensions", [])
    risky = ["dblink", "postgres_fdw", "file_fdw", "plpython3u", "plperlu"]
    installed_risky = [e for e in extensions if e.get("extension") in risky]
    assert installed_risky, "Risky extensions should be detected"

    # Performance Metrics
    perf = results.get("performance_metrics", {})
    cache_metrics = perf.get("cache_hit_ratios", [])
    assert cache_metrics
    min_cache = min((m.get("cache_hit_ratio", 0) for m in cache_metrics), default=0)
    assert min_cache >= 95, "Cache hit ratio should meet OLTP threshold"

    conn_usage = perf.get("connection_usage", {})
    assert conn_usage
    active = conn_usage.get("active_connections", 0)
    max_conn = conn_usage.get("max_connections", 0)
    usage_pct = (active / max_conn * 100) if max_conn > 0 else 0
    assert usage_pct <= 70, "Connection usage should be within OLTP threshold"

    checkpoint = perf.get("checkpoint_stats", {})
    assert checkpoint
    req_ratio = checkpoint.get("checkpoint_request_ratio", 0)
    assert req_ratio <= 20, "Checkpoint request ratio should meet OLTP threshold"

    lock_stats = perf.get("lock_stats", {})
    assert lock_stats
    assert lock_stats.get("deadlocks", 0) > 0
    assert lock_stats.get("temp_files", 0) > 50

    # Issues and Fixes
    issues = results.get("issues_found", [])
    assert len(issues) > 0, "There should be issues found"

    fixes = results.get("recommended_fixes", [])
    assert len(fixes) > 0, "There should be recommended fixes"


