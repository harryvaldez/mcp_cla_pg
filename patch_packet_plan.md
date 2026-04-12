# Patch-Packet Plan (Exact Edit Blocks)

Each block below is the exact applied diff for mapped findings.

## Finding Coverage
- FIND-001 to FIND-016: Covered by code patch blocks in this document.
- FIND-017 (`description_empty`): No patch required in this wave because `server.py` currently contains non-empty descriptions for `db_pg96_create_db_user`, `db_pg96_drop_db_user`, and `db_pg96_alter_object`.
- FIND-018 to FIND-020: Covered by disposition artifact patch block in `SECURITY_FINDINGS_DISPOSITIONS.md`.

## File: bin/mcp-postgres.js
```diff
diff --git a/bin/mcp-postgres.js b/bin/mcp-postgres.js
index 7e25fc8..5ec90b1 100644
--- a/bin/mcp-postgres.js
+++ b/bin/mcp-postgres.js
@@ -1,34 +1,47 @@
 #!/usr/bin/env node
 
 const { spawn } = require('child_process');
+const { spawnSync } = require('child_process');
 const path = require('path');
-const fs = require('fs');
 
 const serverPath = path.join(__dirname, '..', 'server.py');
 
-// Try to find python
-const pythonCmds = ['python3', 'python'];
-let pythonCmd = null;
-
-for (const cmd of pythonCmds) {
-    try {
-        require('child_process').execSync(`${cmd} --version`, { stdio: 'ignore' });
-        pythonCmd = cmd;
-        break;
-    } catch (e) {
-        // continue
+function resolvePythonCommand() {
+    const candidates = [];
+    if (process.env.PYTHON && process.env.PYTHON.trim()) {
+        candidates.push({ cmd: process.env.PYTHON.trim(), versionArgs: ['--version'], runPrefix: [] });
     }
+    candidates.push({ cmd: 'python3', versionArgs: ['--version'], runPrefix: [] });
+    candidates.push({ cmd: 'python', versionArgs: ['--version'], runPrefix: [] });
+    candidates.push({ cmd: 'py', versionArgs: ['-3', '--version'], runPrefix: ['-3'] });
+
+    for (const candidate of candidates) {
+        try {
+            const probe = spawnSync(candidate.cmd, candidate.versionArgs, {
+                stdio: 'ignore',
+                shell: false,
+            });
+            if (probe.status === 0) {
+                return candidate;
+            }
+        } catch (_err) {
+            // Continue to next candidate.
+        }
+    }
+    return null;
 }
 
-if (!pythonCmd) {
+const pythonRuntime = resolvePythonCommand();
+if (!pythonRuntime) {
     console.error('Error: Python not found. Please install Python 3.12 or later.');
     process.exit(1);
 }
 
-const args = [serverPath, ...process.argv.slice(2)];
-const pythonProcess = spawn(pythonCmd, args, {
+const args = [...pythonRuntime.runPrefix, serverPath, ...process.argv.slice(2)];
+const pythonProcess = spawn(pythonRuntime.cmd, args, {
     stdio: 'inherit',
-    env: process.env
+    env: process.env,
+    shell: false,
 });
 
 pythonProcess.on('close', (code) => {
```

## File: scripts/connection_analysis.py
```diff
diff --git a/scripts/connection_analysis.py b/scripts/connection_analysis.py
index 6615015..593c624 100644
--- a/scripts/connection_analysis.py
+++ b/scripts/connection_analysis.py
@@ -27,6 +27,13 @@ def get_sanitized_url(url: str) -> str:
     except Exception:
         return "<unparseable_url>"
 
+
+def _build_dsn(host: str, port: Any, db_name: str, username: str | None, password: str | None) -> str | None:
+    """Build a DSN only when both username and password are provided."""
+    if not username or not password:
+        return None
+    return f"postgresql://{username}:{password}@{host}:{port}/{db_name}"
+
 def test_direct_connection():
     """Test direct database connection using environment variables."""
     print("Testing direct database connection...")
@@ -36,19 +43,29 @@ def test_direct_connection():
     db_port = os.environ.get("POSTGRES_PORT", 5432)
     db_name = os.environ.get("POSTGRES_DB", "mcp_db")
     
-    # Read-only user
-    ro_user = os.environ.get("POSTGRES_READONLY_USER", "postgres_readonly")
-    ro_pass = os.environ.get("POSTGRES_READONLY_PASSWORD", "readonly123")
-    
-    # Superuser
-    su_user = os.environ.get("POSTGRES_USER", "postgres")
-    su_pass = os.environ.get("POSTGRES_PASSWORD", "password123")
-
-    conn_strings = [
-        f"postgresql://{ro_user}:{ro_pass}@{db_host}:{db_port}/{db_name}",
-        f"postgresql://{su_user}:{su_pass}@{db_host}:{db_port}/{db_name}",
-        f"postgresql://{su_user}:{su_pass}@127.0.0.1:{db_port}/{db_name}"
-    ]
+    ro_user = os.environ.get("POSTGRES_READONLY_USER")
+    ro_pass = os.environ.get("POSTGRES_READONLY_PASSWORD")
+    su_user = os.environ.get("POSTGRES_USER")
+    su_pass = os.environ.get("POSTGRES_PASSWORD")
+
+    conn_strings = []
+    ro_dsn = _build_dsn(db_host, db_port, db_name, ro_user, ro_pass)
+    if ro_dsn:
+        conn_strings.append(ro_dsn)
+
+    su_dsn = _build_dsn(db_host, db_port, db_name, su_user, su_pass)
+    if su_dsn:
+        conn_strings.append(su_dsn)
+
+    su_loopback_dsn = _build_dsn("127.0.0.1", db_port, db_name, su_user, su_pass)
+    if su_loopback_dsn:
+        conn_strings.append(su_loopback_dsn)
+
+    if not conn_strings:
+        return [{
+            "success": False,
+            "error": "No connection credentials available. Set POSTGRES_READONLY_USER/POSTGRES_READONLY_PASSWORD or POSTGRES_USER/POSTGRES_PASSWORD."
+        }]
 
     results = []
     for conn_str in conn_strings:
@@ -62,7 +79,7 @@ def test_direct_connection():
                     end_time = time.time()
 
                     results.append({
-                        "connection_string": conn_str,
+                        "connection_string": get_sanitized_url(conn_str),
                         "success": True,
                         "execution_time": end_time - start_time,
                         "version": result[0][:50] + "..." if result and result[0] else "N/A",
@@ -72,7 +89,7 @@ def test_direct_connection():
 
         except Exception as e:
             results.append({
-                "connection_string": conn_str,
+                "connection_string": get_sanitized_url(conn_str),
                 "success": False,
                 "error": str(e)
             })
@@ -85,13 +102,14 @@ def test_connection_pooling():
     try:
         from psycopg_pool import ConnectionPool
 
-        # Build connection string from environment variables
         db_host = os.environ.get("POSTGRES_HOST", "localhost")
         db_port = os.environ.get("POSTGRES_PORT", 5432)
         db_name = os.environ.get("POSTGRES_DB", "mcp_db")
-        su_user = os.environ.get("POSTGRES_USER", "postgres")
-        su_pass = os.environ.get("POSTGRES_PASSWORD", "password123")
-        conninfo = f"postgresql://{su_user}:{su_pass}@{db_host}:{db_port}/{db_name}"
+        su_user = os.environ.get("POSTGRES_USER")
+        su_pass = os.environ.get("POSTGRES_PASSWORD")
+        conninfo = _build_dsn(db_host, db_port, db_name, su_user, su_pass)
+        if not conninfo:
+            return {"error": "POSTGRES_USER and POSTGRES_PASSWORD are required for connection pooling test."}
 
         pool = ConnectionPool(
             conninfo=conninfo,
@@ -147,14 +165,16 @@ def test_mcp_tools():
     original_allow_write = os.environ.get("MCP_ALLOW_WRITE")
 
     try:
-        # Set environment for readonly user for the scope of this test
-        ro_user = os.environ.get("POSTGRES_READONLY_USER", "postgres_readonly")
-        ro_pass = os.environ.get("POSTGRES_READONLY_PASSWORD", "readonly123")
+        ro_user = os.environ.get("POSTGRES_READONLY_USER")
+        ro_pass = os.environ.get("POSTGRES_READONLY_PASSWORD")
         db_host = os.environ.get("POSTGRES_HOST", "localhost")
         db_port = os.environ.get("POSTGRES_PORT", 5432)
         db_name = os.environ.get("POSTGRES_DB", "mcp_db")
-        
-        os.environ["DATABASE_URL"] = f"postgresql://{ro_user}:{ro_pass}@{db_host}:{db_port}/{db_name}"
+        readonly_dsn = _build_dsn(db_host, db_port, db_name, ro_user, ro_pass)
+        if not readonly_dsn:
+            return [{"tool": "import_error", "success": False, "error": "POSTGRES_READONLY_USER and POSTGRES_READONLY_PASSWORD are required for MCP tool tests."}]
+
+        os.environ["DATABASE_URL"] = readonly_dsn
         os.environ["MCP_ALLOW_WRITE"] = "false"
 
         # Dynamically import server to use the temporary environment
```

## File: scripts/validate_n8n_json.py
```diff
diff --git a/scripts/validate_n8n_json.py b/scripts/validate_n8n_json.py
index 6335238..3af9d0c 100644
--- a/scripts/validate_n8n_json.py
+++ b/scripts/validate_n8n_json.py
@@ -1,12 +1,35 @@
 import json
 import sys
 import os
+from pathlib import Path
+
+
+BASE_DIR = Path(__file__).resolve().parent.parent
+
+
+def _resolve_safe_json_path(file_path: str) -> Path:
+    candidate = Path(file_path)
+    resolved = candidate.resolve() if candidate.is_absolute() else (BASE_DIR / candidate).resolve()
+
+    if not resolved.is_file():
+        raise FileNotFoundError(f"File {resolved} not found.")
+
+    if not str(resolved).lower().endswith(".json"):
+        raise ValueError("Only .json files are allowed.")
+
+    try:
+        resolved.relative_to(BASE_DIR)
+    except ValueError as exc:
+        raise ValueError("Path traversal detected: file must remain inside repository base directory.") from exc
+
+    return resolved
 
 def validate_workflow(file_path):
     print(f"Validating workflow file: {file_path}")
     is_valid = True
     try:
-        with open(file_path, 'r') as f:
+        safe_path = _resolve_safe_json_path(file_path)
+        with safe_path.open('r', encoding='utf-8') as f:
             workflow = json.load(f)
 
         # 1. Structure Validation
@@ -84,9 +107,6 @@ def validate_workflow(file_path):
 
 if __name__ == "__main__":
     file_path = "n8n-mcp-workflow.json"
-    if not os.path.exists(file_path):
-        print(f"File {file_path} not found.")
-        sys.exit(1)
 
     if validate_workflow(file_path):
         print("\n≡ƒÄë Workflow validation successful.")
```

## File: scripts/validate_remote_workflow.py
```diff
diff --git a/scripts/validate_remote_workflow.py b/scripts/validate_remote_workflow.py
index 68af176..73d056a 100644
--- a/scripts/validate_remote_workflow.py
+++ b/scripts/validate_remote_workflow.py
@@ -4,6 +4,8 @@ import os
 import urllib.request
 import urllib.error
 import socket
+import ipaddress
+from urllib.parse import urlparse
 
 # --- Configuration ---
 # Load from environment variables
@@ -12,6 +14,50 @@ API_KEY = os.environ.get("N8N_API_KEY")
 WORKFLOW_ID_RAW = os.environ.get("N8N_WORKFLOW_ID", "/MyYz15IkOxsSZL82pBIkO")
 REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 10))
 
+
+def _load_allowlist() -> set[str]:
+    configured = os.environ.get("OUTBOUND_URL_ALLOWLIST", "")
+    defaults = "claritasllc.app.n8n.cloud,github.com,login.microsoftonline.com"
+    raw = configured if configured.strip() else defaults
+    return {part.strip().lower() for part in raw.split(",") if part.strip()}
+
+
+def _host_allowed(hostname: str, allowlist: set[str]) -> bool:
+    host = hostname.lower()
+    for allowed in allowlist:
+        if host == allowed or host.endswith(f".{allowed}"):
+            return True
+    return False
+
+
+def validate_outbound_url(url: str) -> str:
+    parsed = urlparse(url)
+    if parsed.scheme not in {"http", "https"}:
+        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
+    if not parsed.hostname:
+        raise ValueError("URL is missing hostname")
+
+    allowlist = _load_allowlist()
+    host = parsed.hostname
+    allow_local = os.environ.get("ALLOW_PRIVATE_OUTBOUND", "false").lower() == "true"
+
+    try:
+        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
+    except socket.gaierror as exc:
+        raise ValueError(f"Unable to resolve host '{host}'") from exc
+
+    for info in infos:
+        ip_str = info[4][0]
+        ip_obj = ipaddress.ip_address(ip_str)
+        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast) and not allow_local:
+            if not _host_allowed(host, allowlist):
+                raise ValueError(f"Blocked private/internal destination for host '{host}' ({ip_obj})")
+
+    if not _host_allowed(host, allowlist):
+        raise ValueError(f"Host '{host}' is not in outbound allowlist")
+
+    return url
+
 # Validate essential configuration
 if not API_KEY:
     print("Γ¥î Error: N8N_API_KEY environment variable not set.")
@@ -22,6 +68,7 @@ WORKFLOW_ID = WORKFLOW_ID_RAW.strip("/")
 
 def fetch_workflow(workflow_id):
     url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/workflows/{workflow_id}"
+    validate_outbound_url(url)
     print(f"Fetching workflow from: {url}")
     
     req = urllib.request.Request(url)
```

## File: tests/test_docker_pg96.py
```diff
diff --git a/tests/test_docker_pg96.py b/tests/test_docker_pg96.py
index 95ee27a..058b054 100644
--- a/tests/test_docker_pg96.py
+++ b/tests/test_docker_pg96.py
@@ -5,6 +5,7 @@ import sys
 import time
 import traceback
 import urllib.request
+import urllib.parse
 from typing import Any, Dict, List
 
 import psycopg
@@ -20,6 +21,15 @@ DB_NAME = "mcp_test"
 USER = "postgres"
 PASSWORD = "postgres"
 
+
+def _validate_local_http_url(url: str) -> str:
+    parsed = urllib.parse.urlparse(url)
+    if parsed.scheme not in {"http", "https"}:
+        raise ValueError(f"Unsupported URL scheme for test target: {parsed.scheme}")
+    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
+        raise ValueError(f"Blocked non-local test URL host: {parsed.hostname}")
+    return url
+
 def _run(cmd: List[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
     return subprocess.run(
         cmd,
@@ -90,10 +100,10 @@ def _seed_sample_data() -> None:
 
 def _wait_for_server(timeout_s: int = 60) -> None:
     deadline = time.time() + timeout_s
-    url = f"http://localhost:{SERVER_PORT}/health"
+    url = _validate_local_http_url(f"http://localhost:{SERVER_PORT}/health")
     while time.time() < deadline:
         try:
-            with urllib.request.urlopen(url) as response:
+            with urllib.request.urlopen(url, timeout=5) as response:
                 if response.getcode() == 200:
                     return
         except:
@@ -102,7 +112,7 @@ def _wait_for_server(timeout_s: int = 60) -> None:
 
 def _test_docker_http() -> None:
     # Test tools via Stateless HTTP transport
-    url = f"http://localhost:{SERVER_PORT}/mcp"
+    url = _validate_local_http_url(f"http://localhost:{SERVER_PORT}/mcp")
     
     print(f"Connecting to /mcp at {url}...")
     req = urllib.request.Request(url)
@@ -127,7 +137,7 @@ def _test_docker_http() -> None:
             }
         )
         try:
-            with urllib.request.urlopen(req) as response:
+            with urllib.request.urlopen(req, timeout=15) as response:
                 if is_notification:
                     return {}
                 
@@ -216,7 +226,10 @@ def _test_docker_http() -> None:
     # Test write operations
     username = f"test_docker_user_{int(time.time())}"
     print(f"Testing db_pg96_create_db_user: {username}...")
-    call_tool("tools/call", {"name": "db_pg96_create_db_user", "arguments": {"username": username, "password": "password123", "privileges": "read", "database": DB_NAME}})
+    new_user_password = os.environ.get("TEST_NEW_USER_PASSWORD")
+    if not new_user_password:
+        raise RuntimeError("TEST_NEW_USER_PASSWORD environment variable is required for db_pg96_create_db_user test.")
+    call_tool("tools/call", {"name": "db_pg96_create_db_user", "arguments": {"username": username, "password": new_user_password, "privileges": "read", "database": DB_NAME}})
     print(f"Testing db_pg96_drop_db_user: {username}...")
     call_tool("tools/call", {"name": "db_pg96_drop_db_user", "arguments": {"username": username}})
 
```

## File: tests/test_remote_workflow.py
```diff
diff --git a/tests/test_remote_workflow.py b/tests/test_remote_workflow.py
index bb3782e..c4fd160 100644
--- a/tests/test_remote_workflow.py
+++ b/tests/test_remote_workflow.py
@@ -3,6 +3,9 @@ import json
 import time
 import urllib.request
 import urllib.error
+import socket
+import ipaddress
+from urllib.parse import urlparse
 
 # --- Configuration ---
 # These must be set as environment variables
@@ -12,8 +15,46 @@ WORKFLOW_ID = os.environ.get("N8N_WORKFLOW_ID", "MyYz15IkOxsSZL82pBIkO")
 
 import pytest
 
+
+def _load_allowlist() -> set[str]:
+    configured = os.environ.get("OUTBOUND_URL_ALLOWLIST", "")
+    defaults = "claritasllc.app.n8n.cloud,github.com,login.microsoftonline.com"
+    raw = configured if configured.strip() else defaults
+    return {part.strip().lower() for part in raw.split(",") if part.strip()}
+
+
+def _host_allowed(hostname: str, allowlist: set[str]) -> bool:
+    host = hostname.lower()
+    for allowed in allowlist:
+        if host == allowed or host.endswith(f".{allowed}"):
+            return True
+    return False
+
+
+def _validate_outbound_url(url: str) -> str:
+    parsed = urlparse(url)
+    if parsed.scheme not in {"http", "https"}:
+        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
+    if not parsed.hostname:
+        raise ValueError("URL is missing hostname")
+
+    host = parsed.hostname
+    allowlist = _load_allowlist()
+    allow_local = os.environ.get("ALLOW_PRIVATE_OUTBOUND", "false").lower() == "true"
+
+    infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
+    for info in infos:
+        ip_obj = ipaddress.ip_address(info[4][0])
+        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast) and not allow_local:
+            if not _host_allowed(host, allowlist):
+                raise ValueError(f"Blocked private/internal destination for host '{host}' ({ip_obj})")
+
+    if not _host_allowed(host, allowlist):
+        raise ValueError(f"Host '{host}' is not in outbound allowlist")
+    return url
+
 def trigger_workflow():
-    url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/executions"
+    url = _validate_outbound_url(f"{N8N_BASE_URL.rstrip('/')}/api/v1/executions")
     print(f"Triggering workflow execution: {url}")
     
     # Payload to execute the workflow
@@ -41,7 +82,7 @@ def trigger_workflow():
         return None
 
 def get_execution_status(execution_id):
-    url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/executions/{execution_id}"
+    url = _validate_outbound_url(f"{N8N_BASE_URL.rstrip('/')}/api/v1/executions/{execution_id}")
     print(f"Checking execution status: {execution_id}...", end="\r")
     
     req = urllib.request.Request(url)
```

## File: tests/test_npx_pg96.py
```diff
diff --git a/tests/test_npx_pg96.py b/tests/test_npx_pg96.py
index 6fc3f87..0e936b9 100644
--- a/tests/test_npx_pg96.py
+++ b/tests/test_npx_pg96.py
@@ -95,7 +95,7 @@ class MCPClient:
             env={**os.environ, **env},
             text=True,
             bufsize=1,
-            shell=sys.platform == "win32"
+            shell=False
         )
         self.request_id = 1
 
@@ -151,7 +151,8 @@ def _test_npx_stdio() -> None:
     
     # Run npx . which runs bin/mcp-postgres.js
     # We use 'npx' command which should be in PATH
-    cmd = ["npx", ".", "--no-banner"] # FastMCP might support --no-banner
+    npx_cmd = "npx.cmd" if sys.platform == "win32" else "npx"
+    cmd = [npx_cmd, ".", "--no-banner"]
     
     print("Starting MCP server via npx...")
     client = MCPClient(cmd, env)
@@ -238,9 +239,12 @@ def _test_npx_stdio() -> None:
         # Test write operations
         username = f"test_npx_user_{int(time.time())}"
         print(f"Testing db_pg96_create_db_user: {username}...")
+        new_user_password = os.environ.get("TEST_NEW_USER_PASSWORD")
+        if not new_user_password:
+            raise RuntimeError("TEST_NEW_USER_PASSWORD environment variable is required for db_pg96_create_db_user test.")
         client.send_request("tools/call", {
             "name": "db_pg96_create_db_user",
-            "arguments": {"username": username, "password": "password123", "privileges": "read", "database": DB}
+            "arguments": {"username": username, "password": new_user_password, "privileges": "read", "database": DB}
         })
         print(f"Testing db_pg96_drop_db_user: {username}...")
         client.send_request("tools/call", {
```

## File: tests/test_uv_pg96.py
```diff
diff --git a/tests/test_uv_pg96.py b/tests/test_uv_pg96.py
index 1c6d97f..ce46e6d 100644
--- a/tests/test_uv_pg96.py
+++ b/tests/test_uv_pg96.py
@@ -244,9 +244,12 @@ def _test_uv_stdio() -> None:
 
             username = f"test_uv_user_{int(time.time())}"
             print(f"Testing db_pg96_create_db_user: {username}...")
+            new_user_password = os.environ.get("TEST_NEW_USER_PASSWORD")
+            if not new_user_password:
+                raise RuntimeError("TEST_NEW_USER_PASSWORD environment variable is required for db_pg96_create_db_user test.")
             client.send_request("tools/call", {
                 "name": "db_pg96_create_db_user",
-                "arguments": {"username": username, "password": "password123", "privileges": "read", "database": DB}
+                "arguments": {"username": username, "password": new_user_password, "privileges": "read", "database": DB}
             })
             print(f"Testing db_pg96_drop_db_user: {username}...")
             client.send_request("tools/call", {
```

## File: tests/stress_test_mcp.py
```diff
diff --git a/tests/stress_test_mcp.py b/tests/stress_test_mcp.py
index 2b0da4c..98e806f 100644
--- a/tests/stress_test_mcp.py
+++ b/tests/stress_test_mcp.py
@@ -15,11 +15,14 @@ load_dotenv()
 # --- Configuration ---
 # Construct DATABASE_URL from environment variables for security
 DB_USER = os.environ.get("MCP_DB_USER", "postgres_readonly")
-DB_PASSWORD = os.environ.get("MCP_DB_PASSWORD", "readonly123")
+DB_PASSWORD = os.environ.get("MCP_DB_PASSWORD")
 DB_HOST = os.environ.get("MCP_DB_HOST", "localhost")
 DB_PORT = os.environ.get("MCP_DB_PORT", "5432")
 DB_NAME = os.environ.get("MCP_DB_NAME", "mcp_db")
 
+if not DB_PASSWORD:
+    raise RuntimeError("MCP_DB_PASSWORD must be set for stress tests.")
+
 os.environ["DATABASE_URL"] = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
 os.environ["MCP_ALLOW_WRITE"] = "false"
 
```

## File: tests/stress_test_performance.py
```diff
diff --git a/tests/stress_test_performance.py b/tests/stress_test_performance.py
index 28b39e1..ad998c6 100644
--- a/tests/stress_test_performance.py
+++ b/tests/stress_test_performance.py
@@ -17,11 +17,14 @@ load_dotenv()
 # --- Configuration ---
 # Construct DATABASE_URL from environment variables for security
 DB_USER = os.environ.get("MCP_DB_USER", "postgres_readonly")
-DB_PASSWORD = os.environ.get("MCP_DB_PASSWORD", "readonly123")
+DB_PASSWORD = os.environ.get("MCP_DB_PASSWORD")
 DB_HOST = os.environ.get("MCP_DB_HOST", "localhost")
 DB_PORT = os.environ.get("MCP_DB_PORT", "5432")
 DB_NAME = os.environ.get("MCP_DB_NAME", "mcp_db")
 
+if not DB_PASSWORD:
+    raise RuntimeError("MCP_DB_PASSWORD must be set for stress tests.")
+
 os.environ["DATABASE_URL"] = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
 os.environ["MCP_ALLOW_WRITE"] = "false"
 
```

## File: tests/stress_test_performance_v2.py
```diff
diff --git a/tests/stress_test_performance_v2.py b/tests/stress_test_performance_v2.py
index fe8cc15..3483523 100644
--- a/tests/stress_test_performance_v2.py
+++ b/tests/stress_test_performance_v2.py
@@ -9,15 +9,32 @@ import sys
 import psycopg
 from psycopg_pool import ConnectionPool
 
-# Configuration for readonly user
-os.environ["DATABASE_URL"] = "postgresql://postgres_readonly:readonly123@localhost:5432/mcp_db"
-os.environ["MCP_ALLOW_WRITE"] = "false"
+# Configuration for readonly user is loaded from environment.
+os.environ.setdefault("MCP_ALLOW_WRITE", "false")
+
+
+def _get_database_url() -> str:
+    explicit = os.environ.get("DATABASE_URL")
+    if explicit and explicit.strip():
+        return explicit
+
+    host = os.environ.get("POSTGRES_HOST", "localhost")
+    port = os.environ.get("POSTGRES_PORT", "5432")
+    db = os.environ.get("POSTGRES_DB", "mcp_db")
+    user = os.environ.get("POSTGRES_READONLY_USER")
+    password = os.environ.get("POSTGRES_READONLY_PASSWORD")
+    if not user or not password:
+        raise RuntimeError(
+            "Set DATABASE_URL or both POSTGRES_READONLY_USER and POSTGRES_READONLY_PASSWORD for stress tests."
+        )
+    return f"postgresql://{user}:{password}@{host}:{port}/{db}"
 
 def create_connection_pool():
     """Create a connection pool with optimized settings."""
     try:
+        database_url = _get_database_url()
         pool = ConnectionPool(
-            conninfo=os.environ["DATABASE_URL"],
+            conninfo=database_url,
             min_size=1,
             max_size=10,
             max_idle=30,
```

## File: tests/functional_test.py
```diff
diff --git a/tests/functional_test.py b/tests/functional_test.py
index d0671ab..f1294bb 100644
--- a/tests/functional_test.py
+++ b/tests/functional_test.py
@@ -19,7 +19,9 @@ HOST = "localhost"
 PORT = 15432
 DB = "mcp_test"
 USER = "postgres"
-PASSWORD = "postgres"
+PASSWORD = os.environ.get("POSTGRES_PASSWORD")
+if not PASSWORD:
+    pytest.skip("POSTGRES_PASSWORD must be set for functional tests.", allow_module_level=True)
 DATABASE_URL = f"postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB}"
 
 os.environ["DATABASE_URL"] = DATABASE_URL
```

