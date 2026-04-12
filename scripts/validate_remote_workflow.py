import json
import sys
import os
import socket
import ipaddress
import http.client
from urllib.parse import urlparse

# --- Configuration ---
# Load from environment variables
N8N_BASE_URL = os.environ.get("N8N_BASE_URL", "https://claritasllc.app.n8n.cloud/")
API_KEY = os.environ.get("N8N_API_KEY")
WORKFLOW_ID_RAW = os.environ.get("N8N_WORKFLOW_ID", "/MyYz15IkOxsSZL82pBIkO")
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 10))


def _load_allowlist() -> set[str]:
    configured = os.environ.get("OUTBOUND_URL_ALLOWLIST", "")
    defaults = "claritasllc.app.n8n.cloud,github.com,login.microsoftonline.com"
    raw = configured if configured.strip() else defaults
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def _host_allowed(hostname: str, allowlist: set[str]) -> bool:
    host = hostname.lower()
    for allowed in allowlist:
        if host == allowed or host.endswith(f".{allowed}"):
            return True
    return False


def validate_outbound_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("URL is missing hostname")

    allowlist = _load_allowlist()
    host = parsed.hostname
    allow_local = os.environ.get("ALLOW_PRIVATE_OUTBOUND", "false").lower() == "true"

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve host '{host}'") from exc

    for info in infos:
        ip_str = info[4][0]
        ip_obj = ipaddress.ip_address(ip_str)
        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast) and not allow_local:
            if not _host_allowed(host, allowlist):
                raise ValueError(f"Blocked private/internal destination for host '{host}' ({ip_obj})")

    if not _host_allowed(host, allowlist):
        raise ValueError(f"Host '{host}' is not in outbound allowlist")

    return url


def _http_json_request(method: str, url: str, headers: dict[str, str], timeout: int, body: bytes | None = None) -> dict | None:
    safe_url = validate_outbound_url(url)
    parsed = urlparse(safe_url)
    connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    connection = connection_cls(parsed.netloc, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read().decode()
        if response.status >= 400:
            print(f"❌ HTTP Error: {response.status} {response.reason}")
            if payload:
                print(f"Response: {payload}")
            return None
        return json.loads(payload) if payload else {}
    except (socket.timeout, OSError) as e:
        print(f"❌ Error: Request timed out or failed: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON response: {e}")
        return None
    finally:
        connection.close()

# Validate essential configuration
if not API_KEY:
    print("❌ Error: N8N_API_KEY environment variable not set.")
    sys.exit(1)

# Clean ID
WORKFLOW_ID = WORKFLOW_ID_RAW.strip("/")

def fetch_workflow(workflow_id):
    url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/workflows/{workflow_id}"
    print(f"Fetching workflow from: {url}")
    return _http_json_request(
        "GET",
        url,
        {"X-N8N-API-KEY": API_KEY},
        REQUEST_TIMEOUT,
    )

def validate_workflow(workflow_data):
    print("\nValidating Workflow...")
    valid = True
    
    if not isinstance(workflow_data, dict):
        print(f"❌ Error: Expected workflow data to be a dictionary, but got {type(workflow_data)}")
        return False

    workflow = workflow_data
    
    # 1. Structure Validation
    if 'nodes' not in workflow:
        print("❌ Error: 'nodes' array missing.")
        return False # Fatal error
    if 'connections' not in workflow:
        print("❌ Error: 'connections' object missing.")
        return False # Fatal error
        
    print(f"✅ Structure valid. Name: '{workflow.get('name', '[Untitled]')}'")
    print(f"✅ Found {len(workflow['nodes'])} nodes.")
    
    # 2. Node Validation
    # Safely create a dictionary of nodes by name, skipping any without a 'name' key
    nodes_by_name = {node.get('name'): node for node in workflow['nodes'] if node.get('name')}

    for node in workflow['nodes']:
        node_name = node.get('name', '[Unnamed]')
        if 'type' not in node:
            print(f"❌ Error: Node '{node_name}' is missing the 'type' key.")
            valid = False
        if 'parameters' not in node:
            print(f"⚠️ Warning: Node '{node_name}' is missing 'parameters'.")
            
    # 3. Connection Validation
    for source_node_name, outputs in workflow.get('connections', {}).items():
        if source_node_name not in nodes_by_name:
            print(f"❌ Error: Connection source node '{source_node_name}' not found.")
            valid = False
            continue
        
        for output_type, output_connections in outputs.items():
            for connection_list in output_connections:
                for conn in connection_list:
                    # Safely get the target node name
                    target_node_name = conn.get('node')
                    if not target_node_name:
                        print(f"❌ Error: Malformed connection from '{source_node_name}'. Missing target 'node' key.")
                        valid = False
                        continue

                    if target_node_name not in nodes_by_name:
                        print(f"❌ Error: Connection target '{target_node_name}' (from '{source_node_name}') not found.")
                        valid = False
                    
    if valid:
        print("\n🎉 Workflow validation passed successfully.")
    else:
        print("\n💔 Workflow validation failed.")
        
    return valid

if __name__ == "__main__":
    data = fetch_workflow(WORKFLOW_ID)
    if not data:
        print("\nAborting validation due to fetch failure.")
        sys.exit(1)
    
    # Exit with status code based on validation result
    if validate_workflow(data):
        sys.exit(0)
    else:
        sys.exit(1)
