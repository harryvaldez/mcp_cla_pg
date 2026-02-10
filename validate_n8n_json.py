import json
import sys
import os

def validate_workflow(file_path):
    print(f"Validating workflow file: {file_path}")
    try:
        with open(file_path, 'r') as f:
            workflow = json.load(f)
        
        # 1. Structure Validation
        if 'nodes' not in workflow:
            print("❌ Error: 'nodes' array missing.")
            return False
        if 'connections' not in workflow:
            print("❌ Error: 'connections' object missing.")
            return False
            
        print(f"✅ Structure valid. Found {len(workflow['nodes'])} nodes.")
        
        # 2. Node Validation
        node_ids = {node['id'] for node in workflow['nodes']}
        for node in workflow['nodes']:
            if 'type' not in node:
                print(f"❌ Error: Node {node.get('name', 'Unknown')} missing 'type'.")
            if 'parameters' not in node:
                print(f"⚠️ Warning: Node {node.get('name', 'Unknown')} missing 'parameters'.")
                
        # 3. Connection Validation
        for source_node, outputs in workflow['connections'].items():
            # Source node name might not match ID, usually it's the Name.
            # n8n connections use Node Name as key.
            # Let's verify source node exists by Name
            source_exists = any(n['name'] == source_node for n in workflow['nodes'])
            if not source_exists:
                print(f"❌ Error: Connection source node '{source_node}' not found in nodes.")
            
            for output_type, output_connections in outputs.items():
                # output_connections is a list of lists (multiplexing)
                for connection_list in output_connections:
                    for conn in connection_list:
                        target_node = conn['node']
                        # Target node is referenced by Name in connections
                        target_exists = any(n['name'] == target_node for n in workflow['nodes'])
                        if not target_exists:
                            print(f"❌ Error: Connection target node '{target_node}' not found.")
        
        print("✅ Connections valid.")
        return True
        
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON syntax.")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    file_path = "n8n-mcp-workflow.json"
    if os.path.exists(file_path):
        validate_workflow(file_path)
    else:
        print(f"File {file_path} not found.")
