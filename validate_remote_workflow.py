import json
import sys
import urllib.request
import urllib.error

# Configuration
N8N_BASE_URL = "https://claritasllc.app.n8n.cloud/"
API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzMTQzYmQwNi1mZGZjLTRlYjMtYTMxYi0xZmZjZmU2Mzk3Y2YiLCJpc3MiOiJuOG4iLCJhdWQiOiJwdWJsaWMtYXBpIiwiaWF0IjoxNzY3OTMxODk5fQ.a7SwDJx6Q1_xa9KsxCLDHJqJf-hm4EHBVVM8l4KX5Is"
WORKFLOW_ID_RAW = "/MyYz15IkOxsSZL82pBIkO"

# Clean ID
WORKFLOW_ID = WORKFLOW_ID_RAW.strip("/")

def fetch_workflow(workflow_id):
    url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/workflows/{workflow_id}"
    print(f"Fetching workflow from: {url}")
    
    req = urllib.request.Request(url)
    req.add_header('X-N8N-API-KEY', API_KEY)
    
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            return data
    except urllib.error.HTTPError as e:
        print(f"❌ HTTP Error: {e.code} {e.reason}")
        print(f"Response: {e.read().decode()}")
        return None
    except Exception as e:
        print(f"❌ Error fetching workflow: {e}")
        return None

def validate_workflow(workflow_data):
    print("\nValidating Workflow...")
    
    # n8n API returns the workflow object directly or inside 'data'?
    # Usually GET /workflows/{id} returns the workflow object directly.
    
    workflow = workflow_data
    
    # 1. Structure Validation
    if 'nodes' not in workflow:
        print("❌ Error: 'nodes' array missing.")
        return False
    if 'connections' not in workflow:
        print("❌ Error: 'connections' object missing.")
        return False
        
    print(f"✅ Structure valid. Name: '{workflow.get('name', 'Untitled')}'")
    print(f"✅ Found {len(workflow['nodes'])} nodes.")
    
    # 2. Node Validation
    nodes_by_name = {node['name']: node for node in workflow['nodes']}
    valid = True
    
    for node in workflow['nodes']:
        node_name = node.get('name', 'Unknown')
        if 'type' not in node:
            print(f"❌ Error: Node '{node_name}' missing 'type'.")
            valid = False
        if 'parameters' not in node:
            print(f"⚠️ Warning: Node '{node_name}' missing 'parameters'.")
            
    # 3. Connection Validation
    for source_node_name, outputs in workflow['connections'].items():
        if source_node_name not in nodes_by_name:
            print(f"❌ Error: Connection source node '{source_node_name}' not found in nodes.")
            valid = False
            continue
        
        for output_type, output_connections in outputs.items():
            # n8n connections format: list of lists (multiplexing)
            for connection_list in output_connections:
                for conn in connection_list:
                    target_node_name = conn['node']
                    if target_node_name not in nodes_by_name:
                        print(f"❌ Error: Connection target node '{target_node_name}' not found.")
                        valid = False
                    
    if valid:
        print("✅ Workflow validation passed successfully.")
    else:
        print("❌ Workflow validation failed.")
        
    return valid

if __name__ == "__main__":
    data = fetch_workflow(WORKFLOW_ID)
    if data:
        validate_workflow(data)
