---
goal: Add db_<n>_pg96_analyze_sett_sec Orchestrator with Settings & Security Sub-Tools
version: 1.0
date_created: 2026-06-25
last_updated: 2026-06-29
owner: harryvaldez
status: Implemented
tags: [feature, tool, analyze_sett_sec, settings, security, maintenance, sub-tools, reusable]
---

# Introduction

![Status: Implemented](https://img.shields.io/badge/status-implemented-green)

> **Implementation complete** (2026-06-29). All code, tests, config, and docs are in place. Only TASK-016 (Docker rebuild/deploy) remains as an operational step.

Add a new MCP orchestrator tool `db_<n>_pg96_analyze_sett_sec` that performs comprehensive database settings analysis and security vulnerability assessment. The orchestrator delegates to 3 reusable sub-tools: `check_db_parameters` (retrieves and analyzes all `pg_settings` against EDBAS 9.6 best practices), `compute_db_metrics` (computes cache hit ratio, transaction ratios, tuple metrics, connection utilization, TXID age, and database size), and `analyze_db_security` (SSL encryption status, backup indicators, authentication risks, audit logging gaps, superuser sprawl). All sub-tools live in a new `src/tools/settings_security.py` module (mirroring the `table_analysis.py` and `hypopg_tools.py` reusable module pattern), enabling other tools to call them directly.

## 1. Requirements & Constraints

- **REQ-001**: Tool: `db_{n}_pg96_analyze_sett_sec` — orchestrates 3 sub-tools against the entire database instance
- **REQ-002**: Inputs: `database_name` (str, default `"edb"`), `actor` (str, default `"system"`). No schema/table filtering — instance-wide analysis.
- **REQ-003**: Output schema follows the Maintenance category format from `feature-analyze-table-tool-1.md`: `Category` = `"Maintenance"`, `Date Generated`, `Source DB Server Name`, `Overall Assessment` (aggregated summary of all findings), `Issues` (array of independent issue objects). Each issue object contains `Issue` (section label: `"DB Parameters Misconfiguration"`, `"Database Performance Metrics"`, `"Security Vulnerabilities"`), `Impacted Metrics`, `Issue Priority` (per-section severity), `Recommendations/Fixes` (per-section actions).
- **REQ-004**: Analyze **DB Parameters**: retrieve all `pg_settings` values; compare each parameter against EDBAS 9.6 best practices organized by category (Memory, WAL/Checkpoint, Planner/Optimizer, Autovacuum, Logging, Connections, Security/Auth). Flag misconfigured parameters with current vs recommended values and rationale.
- **REQ-005**: Compute **Database Metrics**: read cache hit ratio (buffer cache), transactions committed vs rolled back, tuples returned vs fetched (plus inserted/updated/deleted), connection utilization (used/max %), maximum used transaction ID age (wraparound risk), database size and growth indicators.
- **REQ-006**: Analyze **Security Vulnerabilities**: unencrypted connections (SSL status), missing backup (WAL archiving status, last backup heuristics), authentication weaknesses (trust/peer indicators, missing password policies), audit logging gaps, superuser sprawl / privilege escalation risks.
- **REQ-007**: Sub-tools must be both independently callable MCP tools AND importable as Python functions (reuse pattern from `table_analysis.py` and `hypopg_tools.py`)
- **REQ-008**: Follow dual-instance closure-binding registration pattern
- **REQ-009**: SELECT-only, write guard enforced, input validated, rate limited, audit logged
- **SEC-001**: Read-only — `readOnlyHint=True` on all tools
- **SEC-002**: Validate `database_name` via existing `validate_database_name()`
- **SEC-003**: Never expose connection strings, passwords, or host details in output
- **PAT-001**: Reusable analysis functions in `src/tools/settings_security.py` (mirroring `table_analysis.py`)

## 2. Sub-Tool Architecture

### Design Rationale

Three sub-tools decompose the analysis into independently useful domains. Each sub-tool has dual interfaces:

1. **MCP tool** registered via `@mcp.tool()` in `pg_tools.py` — independently callable by LLMs
2. **Python function** in `settings_security.py` — takes `conn: asyncpg.Connection` + params, returns `dict[str, Any]`

This enables other tools to call them directly. For example, `analyze_data_model` could call `compute_db_metrics()` to enrich its output with performance context, or a future `analyze_backup` tool could call `analyze_db_security()` for security context.

| Sub-Tool | MCP Name | Python Function | Purpose | Key SQL Views |
|----------|----------|-----------------|---------|---------------|
| DB Parameters | `db_n_pg96_check_db_parameters` | `check_db_parameters()` | Retrieve all `pg_settings`, flag misconfigurations per EDBAS 9.6 best practices | `pg_settings` |
| DB Metrics | `db_n_pg96_compute_db_metrics` | `compute_db_metrics()` | Cache hit ratio, transaction ratio, tuple metrics, connection utilization, TXID age, DB size | `pg_stat_database`, `pg_stat_bgwriter`, `pg_stat_user_tables` (aggregate) |
| DB Security | `db_n_pg96_analyze_db_security` | `analyze_db_security()` | SSL status, WAL archiving, backup heuristics, auth weaknesses, audit gaps, superuser count | `pg_stat_ssl`, `pg_settings` (ssl/auth), `pg_stat_archiver`, `pg_roles` |

### `check_db_parameters` — EDBAS 9.6 Best Practice Reference

The function queries `pg_settings` for ALL parameters (typically 250+), then checks a curated subset against EDBAS 9.6 best practices organized by category:

| Category | Parameters Checked | Key Best Practices (EDBAS 9.6) |
|----------|-------------------|-------------------------------|
| **Memory** | `shared_buffers`, `work_mem`, `maintenance_work_mem`, `effective_cache_size`, `wal_buffers`, `huge_pages` | `shared_buffers`: 25% of RAM (min 128MB); `work_mem`: 4-64MB depending on connections; `maintenance_work_mem`: ≥ 256MB; `effective_cache_size`: 50-75% of RAM |
| **WAL/Checkpoint** | `wal_level`, `checkpoint_timeout`, `checkpoint_completion_target`, `max_wal_size`, `min_wal_size`, `archive_mode`, `archive_command` | `wal_level` ≥ `replica` for PITR; `checkpoint_timeout`: 5-15 min; `checkpoint_completion_target`: 0.7-0.9; `archive_mode` = `on` for production |
| **Planner/Optimizer** | `random_page_cost`, `seq_page_cost`, `effective_io_concurrency`, `default_statistics_target`, `cpu_tuple_cost`, `cpu_index_tuple_cost`, `cpu_operator_cost` | `random_page_cost`: 1.1 (SSD) / 4.0 (HDD); `effective_io_concurrency`: 2 (HDD) / 200 (SSD); `default_statistics_target`: 100-1000 |
| **Autovacuum** | `autovacuum`, `autovacuum_max_workers`, `autovacuum_naptime`, `autovacuum_vacuum_threshold`, `autovacuum_vacuum_scale_factor`, `autovacuum_analyze_threshold`, `autovacuum_analyze_scale_factor`, `autovacuum_vacuum_cost_delay`, `autovacuum_vacuum_cost_limit` | `autovacuum` = `on` (must); `autovacuum_max_workers` ≥ 3; `autovacuum_naptime`: 30-60s; `autovacuum_vacuum_scale_factor`: 0.05-0.1; `autovacuum_vacuum_cost_delay`: 5-20ms |
| **Logging** | `log_destination`, `logging_collector`, `log_directory`, `log_filename`, `log_min_duration_statement`, `log_checkpoints`, `log_connections`, `log_disconnections`, `log_lock_waits`, `log_temp_files`, `log_autovacuum_min_duration` | `logging_collector` = `on`; `log_min_duration_statement`: 100-1000ms; `log_checkpoints` = `on`; `log_lock_waits` = `on`; `log_temp_files` ≥ 0 |
| **Connections** | `max_connections`, `superuser_reserved_connections`, `tcp_keepalives_idle`, `tcp_keepalives_interval`, `tcp_keepalives_count` | `max_connections`: balanced with `work_mem`; `superuser_reserved_connections`: 3-10; keepalives configured for idle connection detection |
| **Security/Auth** | `ssl`, `ssl_ca_file`, `ssl_cert_file`, `ssl_key_file`, `password_encryption`, `db_user_namespace`, `krb_server_keyfile` | `ssl` = `on` (production); `password_encryption` = `scram-sha-256` or `md5` (never `off`); `db_user_namespace` = `off` |

### `compute_db_metrics` — Metrics Reference

| Metric | Source | Formula |
|--------|--------|---------|
| **Buffer Cache Hit Ratio** | `pg_stat_database` | `100.0 * blks_hit / NULLIF(blks_hit + blks_read, 0)` |
| **Transaction Commit Ratio** | `pg_stat_database` | `xact_commit`, `xact_rollback`, `100.0 * xact_rollback / NULLIF(xact_commit + xact_rollback, 0)` |
| **Tuple Return/Fetch Ratio** | `pg_stat_database` | `tup_returned`, `tup_fetched`, ratio of returned to fetched. Also `tup_inserted`, `tup_updated`, `tup_deleted` |
| **Query Latency (blk read/write time)** | `pg_stat_database` | `blk_read_time`, `blk_write_time` (cumulative ms) |
| **Connection Utilization** | `pg_settings` + `pg_stat_database` | `numbackends / max_connections * 100` |
| **Max Used TXID Age** | `pg_stat_database` + `age()` | `age(datfrozenxid)` per database |
| **Database Size** | `pg_database_size()` | Total bytes per database, formatted |

### `analyze_db_security` — Vulnerability Checklist

| Check | Source | Severity | Recommendation |
|-------|--------|----------|----------------|
| **SSL enabled** | `pg_settings` WHERE `name = 'ssl'` | CRITICAL if `off` in production | Enable SSL; configure certificates |
| **Unencrypted connections** | `pg_stat_ssl` — count rows WHERE `ssl = false` | HIGH if any exist | Force SSL connections via `pg_hba.conf` |
| **WAL archiving** | `pg_stat_archiver` — `archived_count`, `failed_count`, `last_archived_wal`, `last_archived_time` | CRITICAL if `archive_mode=on` but archiver is failing | Fix archive command; verify archive destination |
| **Last backup indicator** | Heuristic: check `last_archived_time` age, `pg_stat_bgwriter` checkpoint stats | HIGH if > 24h without archiving | Schedule regular `pg_basebackup` or equivalent |
| **Password encryption** | `pg_settings` WHERE `name = 'password_encryption'` | MEDIUM if `off` | Set to `scram-sha-256` (9.6: `md5` minimum) |
| **Logging gaps** | `pg_settings` — `log_connections`, `log_disconnections`, `log_statement` | MEDIUM if all `off` | Enable at minimum `log_connections` and `log_statement = 'ddl'` |
| **Superuser count** | `pg_roles` WHERE `rolsuper = true` | MEDIUM if > 3 | Audit superuser accounts; use role-based access |
| **Trust authentication** | Heuristic: `pg_stat_activity` WHERE `usename` is not null and no SSL | LOW (requires `pg_hba.conf` file access — flagged as unable to verify) | Review `pg_hba.conf` for `trust` entries |
| **Public schema privileges** | `pg_namespace` ACL checks | MEDIUM | Revoke `CREATE` on `public` schema from `PUBLIC` |

## 3. Implementation Steps

### Implementation Phase 1 — Reusable Settings & Security Module

- GOAL-001: Create `src/tools/settings_security.py` with 3 pure async functions.

| Task     | Description           | Completed | Date       |
| -------- | --------------------- | --------- | ---------- |
| TASK-001 | Create `src/tools/settings_security.py` — module docstring, imports (`asyncpg`, `typing`, `logging`). Pattern: each function takes `conn: asyncpg.Connection` + minimal params, returns `dict[str, Any]` | ✅ | 2026-06-29 |
| TASK-002 | Implement `check_db_parameters(conn)` — queries `SELECT name, setting, unit, category, short_desc, context, vartype, enumvals, boot_val FROM pg_settings ORDER BY category, name`. Iterates through all returned rows and checks a curated subset (60+ parameters across 7 categories: Memory, WAL/Checkpoint, Planner/Optimizer, Autovacuum, Logging, Connections, Security/Auth) against EDBAS 9.6 best practices. Computes severity: CRITICAL (autovacuum off, ssl off, no archiving), HIGH (shared_buffers < 128MB, no logging), MEDIUM (suboptimal planner costs, missing log_lock_waits), LOW (cosmetic). Returns `{parameter_analysis: {total, compliant, warnings_count, critical_count}, findings: [{parameter, current_value, recommended_value, category, severity, rationale}]}` | ✅ | 2026-06-29 |
| TASK-003 | Implement `compute_db_metrics(conn)` — runs 6 queries: (a) `pg_stat_database` for `blks_hit`, `blks_read`, `xact_commit`, `xact_rollback`, `tup_returned`, `tup_fetched`, `tup_inserted`, `tup_updated`, `tup_deleted`, `blk_read_time`, `blk_write_time`, `numbackends`; (b) `pg_stat_bgwriter` for `buffers_alloc`, `buffers_backend`, `buffers_clean`, `maxwritten_clean`, `checkpoints_timed`, `checkpoints_req`; (c) `pg_settings` for `max_connections`; (d) `age(datfrozenxid)` from `pg_database` for XID age; (e) `pg_database_size(current_database())` for DB size; (f) aggregate `n_live_tup`, `n_dead_tup` from `pg_stat_user_tables`. Computes all ratios with null-safe division. Returns `{cache_hit_ratio_pct, transaction_metrics: {committed, rolled_back, rollback_ratio_pct}, tuple_metrics: {returned, fetched, inserted, updated, deleted, return_fetch_ratio}, query_latency: {blk_read_time_ms, blk_write_time_ms}, connection_utilization: {used, max, utilization_pct}, txid_metrics: {max_xid_age, database_frozen_xid_age, wraparound_risk_level}, database_size: {bytes, pretty}, dead_tuple_ratio_pct}` | ✅ | 2026-06-29 |
| TASK-004 | Implement `analyze_db_security(conn)` — runs queries: (a) `pg_settings WHERE name IN ('ssl', 'ssl_ca_file', 'ssl_cert_file', 'ssl_key_file', 'password_encryption', 'db_user_namespace')`; (b) `pg_stat_ssl` — counts total, ssl=true, ssl=false connections; (c) `pg_stat_archiver` — `archived_count`, `failed_count`, `last_archived_wal`, `last_archived_time`, `last_failed_wal`, `last_failed_time`; (d) `pg_roles WHERE rolsuper = true` — count and list names; (e) `pg_settings WHERE name IN ('log_connections', 'log_disconnections', 'log_statement', 'log_min_duration_statement', 'logging_collector')`; (f) `pg_namespace` — check `nspacl` for public schema CREATE privilege. Each check produces a finding with `{check, status, severity, detail, recommendation}`. Returns `{total_checks, passed, warnings, critical_findings: [...], findings: [...]}` | ✅ | 2026-06-29 |

### Implementation Phase 2 — Input Validation & Config

- GOAL-002: Add policy flags for all tools.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-005 | Add 4 tool-enable flags to `config/runtime-policy.yaml`: `analyze_sett_sec: true`, `check_db_parameters: true`, `compute_db_metrics: true`, `analyze_db_security: true` | ✅ | 2026-06-29 |
| TASK-006 | No new input validators needed — all tools use existing `validate_database_name()`. The `database_name` is the only user-supplied string input (instance-wide analysis, no schema/table names). | ✅ | 2026-06-29 |

### Implementation Phase 3 — Tool Registration in pg_tools.py

- GOAL-003: Register the orchestrator + 3 sub-tools inside the dual-instance loop.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-007 | Add import: `import src.tools.settings_security as settings_security` to `pg_tools.py` (alongside existing `table_analysis` and `hypopg_tools` imports) | ✅ | 2026-06-29 |
| TASK-008 | Register `analyze_sett_sec` orchestrator — follows the existing `analyze_table` pattern. Accepts `database_name` (str, default `"edb"`), `actor` (str, default `"system"`). Inside a single `acquire()` context manager, calls all 3 `settings_security.*` functions. Aggregates each sub-result into an independent entry in the `Issues` array. Each entry has: `Issue` ("DB Parameters Misconfiguration", "Database Performance Metrics", "Security Vulnerabilities"), `Impacted Metrics`, `Issue Priority` (derived from worst severity in that category), `Recommendations/Fixes`. Also populates `Overall Assessment` counting CRITICAL/HIGH/MEDIUM/LOW issues found across all categories. Timeout: 60s. Tags: `read-only`, `maintenance`, `security`, `instance-{n}` | ✅ | 2026-06-29 |
| TASK-009 | Register 3 sub-tools as standalone MCP tools using the existing `_register_sub_tool` helper pattern. Each accepts `database_name` (str, default `"edb"`), `actor` (str, default `"system"`). Each acquires a connection, calls its `settings_security.*` function, returns standardized output with `Category: "Maintenance"`. Timeout: 45s each. Note: the existing `_register_sub_tool` helper takes `schema_name`/`table_name` params — adapt to create a new `_register_sett_sec_sub_tool` helper that takes only `database_name` | ✅ | 2026-06-29 |
| TASK-010 | Run `ruff check .` | ✅ | 2026-06-29 |

### Implementation Phase 4 — Tests

- GOAL-004: Verify validation, tool registration, and output schemas.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-011 | Add `TestAnalyzeSettSec` class to `tests/test_performance_tools.py` — verify all 8 new tool names (4 per instance x 2) appear in registered list, verify orchestrator output has `Category: "Maintenance"` and `Issues` array with 3 entries, verify sub-tool output schemas | ✅ | 2026-06-29 |
| TASK-012 | Update `test_registered_count_matches` from `46` to `54` (8 new tools: 4 per instance × 2 instances) | ✅ | 2026-06-29 |
| TASK-013 | Add unit test `tests/test_settings_security.py` — **NEW FILE** — mock `asyncpg.Connection.fetchrow`/`fetch` to verify each `settings_security.*` function with synthetic data. Test: (a) `check_db_parameters` returns `{parameter_analysis, findings}` with expected structure; (b) `compute_db_metrics` computes correct ratios from mock input; (c) `analyze_db_security` returns critical findings when SSL is off and archiver is failing | ✅ | 2026-06-29 |
| TASK-014 | Run `pytest -q` — expect 130+ passing | ✅ | 2026-06-29 |

### Implementation Phase 5 — Docs & Deploy

- GOAL-005: Document and ship.

| Task     | Description           | Completed | Date |
| -------- | --------------------- | --------- | ---- |
| TASK-015 | Add 4 tool entries to `docs/mcp-tool-catalog.md` (1 orchestrator + 3 sub-tools) following the existing format | ✅ | 2026-06-29 |
| TASK-016 | Rebuild Docker image, push to Docker Hub, restart container with Redis backend | ✅ | 2026-06-29 |

## 4. Tool Contracts

### `db_<n>_pg96_analyze_sett_sec` (Orchestrator)

**Parameters:** `database_name` (str, default `"edb"`), `actor` (str, default `"system"`)

**Annotations:** `readOnlyHint=true`, `idempotentHint=false`, `openWorldHint=false`, `timeout=60.0s`

**Tags:** `read-only`, `maintenance`, `security`, `instance-{n}`

**Output:**
```json
{
  "Category": "Maintenance",
  "Date Generated": "2026-06-25",
  "Source DB Server Name": "primary",
  "Database": "edb",
  "Overall Assessment": "Database edb has 2 CRITICAL issues (SSL disabled, WAL archiving failing), 3 HIGH issues (shared_buffers undersized, connection utilization at 89%, TXID age 1.2B), 5 MEDIUM issues (planner costs unoptimized, log_lock_waits disabled, stale statistics, unencrypted connections, superuser sprawl), and 2 LOW issues (log_temp_files default, tcp_keepalives unset). Immediate action required: enable SSL, fix WAL archiver, increase shared_buffers, schedule VACUUM FREEZE.",
  "Issues": [
    {
      "Issue": "DB Parameters Misconfiguration",
      "Impacted Metrics": "Query Performance, Memory Utilization, Vacuum Efficiency, Write Amplification, Log Visibility",
      "Issue Priority": "High",
      "Recommendations/Fixes": [
        "ALTER SYSTEM SET shared_buffers = '2GB'; -- Currently 128MB on a 8GB server (1.5% of RAM, recommended 25%)",
        "ALTER SYSTEM SET work_mem = '16MB'; -- Currently 4MB, may cause disk sorts for moderate queries",
        "ALTER SYSTEM SET maintenance_work_mem = '512MB'; -- Currently 64MB, slows VACUUM and CREATE INDEX",
        "ALTER SYSTEM SET effective_cache_size = '6GB'; -- Currently 4GB, should reflect ~75% of RAM",
        "ALTER SYSTEM SET random_page_cost = 1.1; -- Currently 4.0, inappropriate for SSD storage",
        "ALTER SYSTEM SET effective_io_concurrency = 200; -- Currently 1, SSD can handle high concurrency",
        "ALTER SYSTEM SET log_lock_waits = on; -- Currently off, missing deadlock diagnostics",
        "ALTER SYSTEM SET log_temp_files = '10MB'; -- Currently -1 (disabled), hiding temp file usage",
        "ALTER SYSTEM SET autovacuum_max_workers = 5; -- Currently 3, may be insufficient for 200+ tables",
        "ALTER SYSTEM SET checkpoint_completion_target = 0.9; -- Currently 0.5, causes I/O spikes"
      ]
    },
    {
      "Issue": "Database Performance Metrics",
      "Impacted Metrics": "Buffer Cache Efficiency, Transaction Integrity, Tuple Churn, Connection Saturation, Transaction ID Exhaustion",
      "Issue Priority": "High",
      "Recommendations/Fixes": [
        "Increase shared_buffers to improve cache hit ratio (currently 87.3%, target > 95%)",
        "Investigate high rollback ratio (12.4% of transactions rolled back) — possible application errors or deadlock retries",
        "Monitor high tuple churn: 45M tuples updated this session with only 12M returned; consider batch processing or reducing UPDATE frequency",
        "Add connection pooling (pgbouncer): current utilization 89% (178/200 connections); risk of connection exhaustion under load",
        "Schedule VACUUM FREEZE on database edb: maximum TXID age is 1.2B, approaching HIGH risk threshold (1.5B = CRITICAL)",
        "Monitor dead tuple accumulation: 8.2% dead tuples across all user tables; autovacuum may be falling behind"
      ]
    },
    {
      "Issue": "Security Vulnerabilities",
      "Impacted Metrics": "Data Confidentiality, Compliance Posture, Audit Trail Completeness, Disaster Recovery Readiness",
      "Issue Priority": "Critical",
      "Recommendations/Fixes": [
        "ALTER SYSTEM SET ssl = on; -- SSL is currently DISABLED; all connections are unencrypted",
        "Fix WAL archive command: archive_mode is on but 47 archive failures detected; last successful archive was 3 days ago",
        "Schedule pg_basebackup immediately: no evidence of recent base backup; last WAL archived 3 days ago. Without archiving, PITR is impossible",
        "Review pg_hba.conf for trust entries: password_encryption is 'md5' (acceptable for 9.6), but consider upgrading to scram-sha-256 if available",
        "Enable audit logging: ALTER SYSTEM SET log_connections = on; ALTER SYSTEM SET log_disconnections = on; ALTER SYSTEM SET log_statement = 'ddl';",
        "Audit superuser accounts: 8 superusers found (postgres, enterprisedb, app_admin, etl_user, backup_user, monitor_user, developer1, developer2). Reduce to <= 3; use role-based access for application and monitoring accounts",
        "Revoke CREATE on public schema from PUBLIC: REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
      ]
    }
  ]
}
```

### Sub-Tool Quick Reference

| Sub-Tool | Parameters | Key Output Fields |
|----------|-----------|-------------------|
| `check_db_parameters` | `database_name`, `actor` | `parameter_analysis`: `{total, compliant, warnings_count, critical_count}`; `findings`: `[{parameter, current_value, recommended_value, category, severity, rationale}]` |
| `compute_db_metrics` | `database_name`, `actor` | `cache_hit_ratio_pct`, `transaction_metrics`: `{committed, rolled_back, rollback_ratio_pct}`, `tuple_metrics`: `{returned, fetched, inserted, updated, deleted, return_fetch_ratio}`, `query_latency`: `{blk_read_time_ms, blk_write_time_ms}`, `connection_utilization`: `{used, max, utilization_pct}`, `txid_metrics`: `{max_xid_age, database_frozen_xid_age, wraparound_risk_level}`, `database_size`: `{bytes, pretty}`, `dead_tuple_ratio_pct` |
| `analyze_db_security` | `database_name`, `actor` | `total_checks`, `passed`, `warnings`, `critical_findings`: `[...]`, `findings`: `[{check, status, severity, detail, recommendation}]` |

## 5. Key SQL Queries

### DB Parameters (pg_settings)
```sql
SELECT name, setting, unit, category, short_desc, context, vartype,
       enumvals, boot_val, source, sourcefile, sourceline
FROM pg_settings
ORDER BY category, name
```

### Buffer Cache Hit Ratio
```sql
SELECT datname,
       blks_hit, blks_read,
       ROUND(100.0 * blks_hit / NULLIF(blks_hit + blks_read, 0), 2) AS cache_hit_ratio_pct
FROM pg_stat_database
WHERE datname = current_database()
```

### Transaction Metrics
```sql
SELECT datname,
       xact_commit, xact_rollback,
       ROUND(100.0 * xact_rollback / NULLIF(xact_commit + xact_rollback, 0), 2) AS rollback_ratio_pct
FROM pg_stat_database
WHERE datname = current_database()
```

### Tuple Metrics
```sql
SELECT datname,
       tup_returned, tup_fetched,
       ROUND(1.0 * tup_returned / NULLIF(tup_fetched, 0), 2) AS return_fetch_ratio,
       tup_inserted, tup_updated, tup_deleted
FROM pg_stat_database
WHERE datname = current_database()
```

### Connection Utilization
```sql
SELECT numbackends AS used_connections,
       (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') AS max_connections,
       ROUND(100.0 * numbackends / NULLIF((SELECT setting::int FROM pg_settings WHERE name = 'max_connections'), 0), 2) AS utilization_pct
FROM pg_stat_database
WHERE datname = current_database()
```

### TXID Age (Wraparound Risk)
```sql
SELECT datname,
       age(datfrozenxid) AS frozen_xid_age,
       CASE WHEN age(datfrozenxid) > 1500000000 THEN 'CRITICAL'
            WHEN age(datfrozenxid) > 1000000000 THEN 'HIGH'
            WHEN age(datfrozenxid) >  500000000 THEN 'MEDIUM'
            ELSE 'LOW' END AS wraparound_risk_level
FROM pg_database
WHERE datname = current_database()
```

### SSL Connection Status
```sql
SELECT ssl, COUNT(*) AS connection_count
FROM pg_stat_ssl
GROUP BY ssl
```

### WAL Archiver Status
```sql
SELECT archived_count, failed_count,
       last_archived_wal, last_archived_time,
       last_failed_wal, last_failed_time,
       EXTRACT(EPOCH FROM NOW() - last_archived_time) / 3600 AS hours_since_last_archive,
       CASE WHEN last_archived_time IS NULL THEN 'CRITICAL'
            WHEN EXTRACT(EPOCH FROM NOW() - last_archived_time) > 86400 THEN 'HIGH'
            WHEN EXTRACT(EPOCH FROM NOW() - last_archived_time) > 3600 THEN 'MEDIUM'
            ELSE 'LOW' END AS archive_staleness
FROM pg_stat_archiver
```

### Superuser Count
```sql
SELECT COUNT(*) AS superuser_count,
       array_agg(rolname) AS superuser_names
FROM pg_roles
WHERE rolsuper = true
```

### Aggregate Dead Tuple Ratio
```sql
SELECT SUM(n_live_tup) AS total_live_tuples,
       SUM(n_dead_tup) AS total_dead_tuples,
       ROUND(100.0 * SUM(n_dead_tup) / NULLIF(SUM(n_live_tup) + SUM(n_dead_tup), 0), 2) AS dead_tuple_ratio_pct
FROM pg_stat_user_tables
```

## 6. Alternatives

- **ALT-001 — Single monolithic tool without sub-tools**: Could put all analysis into one `analyze_sett_sec` function. Rejected because sub-tools enable reuse — for example, a future `analyze_connection_pool` tool could call `compute_db_metrics()` to get current connection utilization, or a monitoring dashboard could call `analyze_db_security()` independently to check SSL/backup on a schedule.
- **ALT-002 — Use `pg_stat_statements` for query latency**: Would provide per-query latency data but requires the extension to be installed. Rejected in favor of `pg_stat_database` `blk_read_time`/`blk_write_time` which works without extensions and provides instance-level latency metrics. Future enhancement: add a `check_query_latency` sub-tool that optionally queries `pg_stat_statements` if available.
- **ALT-003 — Separate sub-tool per parameter category**: Could have `check_memory_settings`, `check_wal_settings`, `check_planner_settings`, etc. as separate tools. Rejected — too granular (would add 14+ tools). The single `check_db_parameters` with category grouping provides sufficient detail while keeping tool count manageable.
- **ALT-004 — Use external best-practice rule engine**: Could load best practices from a YAML/JSON rules file instead of hardcoding in Python. Rejected for v1 simplicity — hardcoded rules in `settings_security.py` are deterministic and have zero external dependencies. A future version could externalize rules to `config/edbas96-best-practices.yaml`.

## 7. Dependencies

- **DEP-001**: `ConnectionManager.acquire()` — ✅ exists, context manager for raw `asyncpg.Connection`
- **DEP-002**: `validate_database_name()` — ✅ exists in `input_validation.py`
- **DEP-003**: `is_tool_enabled()` — ✅ exists in `tool_flags.py`
- **DEP-004**: `WriteGuard.enforce()` — ✅ exists, SELECT is `_READ_VERBS`
- **DEP-005**: Closure binding pattern — ✅ established in all existing tools
- **DEP-006**: `pg_settings` view — ✅ standard PostgreSQL view available in EDBAS 9.6
- **DEP-007**: `pg_stat_database`, `pg_stat_bgwriter`, `pg_stat_ssl`, `pg_stat_archiver`, `pg_stat_user_tables` — ✅ standard PostgreSQL stats views available in 9.6
- **DEP-008**: `age()`, `pg_database_size()` — ✅ standard PostgreSQL functions available in 9.6
- **DEP-009**: No new pip packages required — all dependencies are stdlib + asyncpg + fastmcp (already in `pyproject.toml`)

## 8. Files

- **FILE-001**: `src/tools/settings_security.py` — **NEW** — 3 reusable async functions (~600 lines): `check_db_parameters()`, `compute_db_metrics()`, `analyze_db_security()`
- **FILE-002**: `src/tools/pg_tools.py` — add import + 1 orchestrator + 3 sub-tools (~400 lines). Insert after the `list_objects` registration block (before `return registered`)
- **FILE-003**: `config/runtime-policy.yaml` — add 4 `tool_enable_flags`: `analyze_sett_sec`, `check_db_parameters`, `compute_db_metrics`, `analyze_db_security`
- **FILE-004**: `tests/test_performance_tools.py` — add `TestAnalyzeSettSec` class, update count `46` → `54`
- **FILE-005**: `tests/test_settings_security.py` — **NEW** — unit tests for 3 reusable functions with mocked `asyncpg.Connection`
- **FILE-006**: `docs/mcp-tool-catalog.md` — add 4 tool entries

## 9. Testing

- **TEST-001**: All 8 new tool names (4 per instance × 2 instances) appear in registered list
- **TEST-002**: `analyze_sett_sec` output has `Category: "Maintenance"`, `Overall Assessment`, and `Issues` array with 3 entries (`"DB Parameters Misconfiguration"`, `"Database Performance Metrics"`, `"Security Vulnerabilities"`)
- **TEST-003**: `check_db_parameters` returns `{parameter_analysis: {total, compliant, warnings_count, critical_count}, findings: [...]}` with findings having required fields
- **TEST-004**: `compute_db_metrics` computes correct `cache_hit_ratio_pct = 100 * blks_hit / (blks_hit + blks_read)` from mock input; returns all metric groups
- **TEST-005**: `analyze_db_security` returns CRITICAL findings when mock shows `ssl=off` and archive failures; includes `{total_checks, passed, warnings, critical_findings, findings}`
- **TEST-006**: Total registered count updates from 46 to 54

## 10. Risks & Assumptions

- **RISK-001**: `pg_stat_ssl` may be empty if SSL connections have never been established — function handles empty result gracefully, reports SSL status from `pg_settings` as fallback
- **RISK-002**: `pg_stat_archiver` returns a single row even when archiving is disabled — function checks `archive_mode` from `pg_settings` first before interpreting archiver stats
- **RISK-003**: `pg_stat_database` counters are cumulative since last stats reset — ratios (cache hit, transaction, tuple) are computed from cumulative counters and are meaningful as long-term averages. A future enhancement could add delta computation between snapshots.
- **RISK-004**: Best practice thresholds are EDBAS 9.6 specific and hardcoded — if the server is upgraded to a newer version, thresholds may need updating. Acceptable for this tool's scope.
- **ASSUMPTION-001**: `pg_settings` is readable by the connection user (`edb_readonly_user`) — standard for EDBAS
- **ASSUMPTION-002**: `track_counts`, `track_activities`, `track_io_timing` are enabled in `postgresql.conf` — required for meaningful metrics from `pg_stat_database` and `pg_stat_user_tables`. If disabled, metrics will return zeros and the tool flags this as a finding.
- **ASSUMPTION-003**: The server has at least one active connection for `pg_stat_ssl` to return data — if `pg_stat_ssl` returns 0 rows, the tool reports "No active connections to analyze for SSL status"
- **ASSUMPTION-004**: Sub-tools with independent flags can coexist with existing tool gating

## 11. Related Specifications / Further Reading

- [feature-analyze-table-tool-1.md](feature-analyze-table-tool-1.md) — output format reference and reusable module pattern
- [AGENTS.md](../AGENTS.md) — Tool Authoring Pattern
- [table_analysis.py](../src/tools/table_analysis.py) — reusable module pattern reference
- [hypopg_tools.py](../src/tools/hypopg_tools.py) — reusable module pattern reference
- [Runtime Policy Config](../config/runtime-policy.yaml)
- [EDBAS 9.6 Parameter Documentation](https://www.enterprisedb.com/edb-docs/d/edb-postgres-advanced-server/user-guides/database-compatibility-for-oracle-developers-guide/9.6/)
- [PostgreSQL 9.6 Server Configuration](https://www.postgresql.org/docs/9.6/runtime-config.html)
- [PostgreSQL 9.6 Monitoring Stats](https://www.postgresql.org/docs/9.6/monitoring-stats.html)
