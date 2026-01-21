## What I’ll Change
- Update `explain_query` logging to never include raw SQL at INFO; log only safe metadata and optionally a SHA-256 fingerprint.
- Update `run_query` logging so INFO contains only safe metadata (row limit, SQL length, optional SQL fingerprint) and DEBUG contains only non-reversible fingerprints (no raw SQL/params).

## Implementation Details
- **server.py**
  - Update `explain_query` and `run_query` so INFO logs **never** include raw SQL or params.
  - In `explain_query`, replace the INFO log with one that logs only safe metadata: `analyze`, `buffers`, `verbose`, `settings`, `format`, `sql_len`, and `sql_sha256`.
  - In `run_query`, replace the INFO log with only safe metadata: `{max_rows_effective, sql_len, sql_sha256, params_sha256}`.
  - Compute `sql_sha256` via `hashlib.sha256(sql.encode()).hexdigest()`.
  - If `params` is provided:
    - Serialize `params` to JSON: `params_json = json.dumps(params, separators=(",", ":"), sort_keys=True)`.
    - Compute `params_sha256` via `hashlib.sha256(params_json.encode()).hexdigest()`.
    - If serialization fails, catch the exception, log `{max_rows_effective, sql_len, sql_sha256}`, and optionally record a safe flag (do not raise).
  - Ensure `logger.debug` (if kept) contains only non-reversible fingerprints (SHA-256 values) and **never** raw SQL or raw params.

- **test_logging.py**
  - Remove the module-level `addHandler(...)` call entirely.
  - Replace prints/try-except with real assertions and allow exceptions to fail the test.
  - Fix `mock_cursor.description` to be PEP 249 compliant (either `None` or a list of 7-item tuples).
  - Keep the same patching strategy (`server._require_readonly`, `server.pool`) and add assertions like:
    - `server.logger.info` called
    - `server.logger.info` message does **not** contain the SQL text
    - `mock_cursor.fetchmany` called once (test_logging.py uses fetchmany)
  - Because `pytest` is not available in this environment, rewrite the test to use the stdlib `unittest` framework with `setUp/tearDown` to provide fixture-like isolation.
  - Prevent real DB connection attempts during `import server` by setting required env vars and mocking `psycopg_pool` in `sys.modules` before importing `server`.

## Cleanup
- Remove the temporary debug helper file that was created during investigation (`debug_import.py`) to avoid repository clutter.

## Verification
- **Run `python test_logging.py`** and confirm it passes. This test script includes specific security assertions:
  1.  **No Raw SQL in INFO**: Verifies `assertNotIn("SELECT * FROM users", info_msg)`.
  2.  **Fingerprints Present**: Verifies `assertIn("sql_sha256=", info_msg)` and `assertIn("params_sha256=", debug_msg)`.
  3.  **Debug Output**: Verifies `logger.debug` is called with the safe `params_sha256` fingerprint, ensuring debugging capability without data leaks.
- **Manual Verification (Optional)**:
  - Run the server locally.
  - Execute a query (e.g., `SELECT 1`).
  - Check standard output/logs to confirm the INFO log looks like: `run_query called. sql_len=8 max_rows=100 sql_sha256=...` and does NOT contain `SELECT 1`.

If you confirm, I’ll apply these edits and run the verification steps.