import json
import sys
import os
import urllib.request
import urllib.error
import socket

# --- Configuration ---
# Load from environment variables
N8N_BASE_URL = os.environ.get("N8N_BASE_URL", "https://claritasllc.app.n8n.cloud/")
API_KEY = os.environ.get("N8N_API_KEY")
WORKFLOW_ID_RAW = os.environ.get("N8N_WORKFLOW_ID", "/MyYz15IkOxsSZL82pBIkO")
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 10))

# Validate essential configuration
if not API_KEY:
    print("❌ Error: N8N_API_KEY environment variable not set.")
    sys.exit(1)

# Clean ID
WORKFLOW_ID = WORKFLOW_ID_RAW.strip("/")

def fetch_workflow(workflow_id):
    url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/workflows/{workflow_id}"
    print(f"Fetching workflow from: {url}")
    
    req = urllib.request.Request(url)
    req.add_header('X-N8N-API-KEY', API_KEY)
    
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            data = json.loads(response.read().decode())
            return data
    except urllib.error.HTTPError as e:
        print(f"❌ HTTP Error: {e.code} {e.reason}")
        try:
            print(f"Response: {e.read().decode()}")
        except Exception:
            pass # Can fail if response body is empty
        return None
    except (socket.timeout, urllib.error.URLError) as e:
        print(f"❌ Error: Request timed out or failed: {e}")
        return None
    except Exception as e:
        print(f"❌ An unexpected error occurred while fetching workflow: {e}")
        return None

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
