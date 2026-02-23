import json
import sys
import os

def validate_workflow(file_path):
    print(f"Validating workflow file: {file_path}")
    is_valid = True
    try:
        with open(file_path, 'r') as f:
            workflow = json.load(f)

        # 1. Structure Validation
        if 'nodes' not in workflow:
            print("❌ Error: 'nodes' array missing.")
            return False # Fatal error
        if 'connections' not in workflow:
            print("❌ Error: 'connections' object missing.")
            return False # Fatal error

        print(f"✅ Basic structure valid. Found {len(workflow['nodes'])} nodes.")

        # 2. Node Validation
        node_ids = set()
        node_names = set()
        for node in workflow['nodes']:
            # Validate ID presence and uniqueness
            node_id = node.get('id')
            if not node_id:
                print(f"❌ Error: Node missing 'id'. Name: {node.get('name', '[Unnamed]')}")
                is_valid = False
            elif node_id in node_ids:
                print(f"❌ Error: Duplicate node ID '{node_id}' found.")
                is_valid = False
            else:
                node_ids.add(node_id)

            # Validate name
            node_names.add(node.get('name'))

            # Validate type
            if 'type' not in node:
                print(f"❌ Error: Node {node.get('name', '[Unnamed]')} (ID: {node_id}) missing 'type'.")
                is_valid = False
            
            if 'parameters' not in node:
                print(f"⚠️ Warning: Node {node.get('name', '[Unnamed]')} (ID: {node_id}) missing 'parameters'.")

        if is_valid:
            print("✅ All nodes have a unique ID and a type.")

        # 3. Connection Validation
        connections_valid = True
        for source_node_name, outputs in workflow['connections'].items():
            if source_node_name not in node_names:
                print(f"❌ Error: Connection source node '{source_node_name}' not found in any node's 'name' field.")
                connections_valid = False

            for output_type, output_connections in outputs.items():
                for connection_list in output_connections:
                    for conn in connection_list:
                        target_node_name = conn.get('node')
                        if not target_node_name:
                            print(f"❌ Error: A connection from '{source_node_name}' is missing the target 'node' key.")
                            connections_valid = False
                            continue
                        
                        if target_node_name not in node_names:
                            print(f"❌ Error: Connection target node '{target_node_name}' (from source '{source_node_name}') not found.")
                            connections_valid = False
        
        if connections_valid:
            print("✅ All connections are valid.")
        else:
            is_valid = False

        return is_valid

    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON syntax.")
        return False
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
        return False

if __name__ == "__main__":
    file_path = "n8n-mcp-workflow.json"
    if not os.path.exists(file_path):
        print(f"File {file_path} not found.")
        sys.exit(1)

    if validate_workflow(file_path):
        print("\n🎉 Workflow validation successful.")
        sys.exit(0)
    else:
        print("\n💔 Workflow validation failed.")
        sys.exit(1)
