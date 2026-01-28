import os
import json
import sys
import datetime

# Set environment variables BEFORE importing server
# Use the robust remote connection string
os.environ["DATABASE_URL"] = "postgresql://enterprisedb:ClaRitAs02@10.100.2.20:5444/lenexa"
os.environ["MCP_ALLOW_WRITE"] = "false"
os.environ["MCP_POOL_MAX_SIZE"] = "20"
os.environ["MCP_POOL_TIMEOUT"] = "60.0"

# Import the mcp object and the function directly
sys.path.append(os.getcwd())
try:
    from server import db_pg96_analyze_logical_data_model
except ImportError:
    print("Could not import db_pg96_analyze_logical_data_model directly.", file=sys.stderr)
    sys.exit(1)

def invoke_tool(tool_obj, **kwargs):
    """Helper to invoke a FastMCP tool object."""
    # Try calling it directly (some versions)
    if callable(tool_obj):
        try:
            return tool_obj(**kwargs)
        except TypeError:
            pass
    
    # Try finding the underlying function
    for attr in ("fn", "func", "function", "_fn"):
        inner = getattr(tool_obj, attr, None)
        if callable(inner):
            return inner(**kwargs)
            
    raise TypeError(f"Could not find callable for tool {tool_obj}")

def main():
    try:
        print(f"Connecting to {os.environ['DATABASE_URL']}...", file=sys.stderr)
        print("Invoking db_pg96_analyze_logical_data_model(schema='smsadmin')...", file=sys.stderr)
        
        # Use helper to invoke the tool
        result = invoke_tool(db_pg96_analyze_logical_data_model, schema="smsadmin")
        
        # Print JSON to stdout for capture
        print(json.dumps(result, indent=2, default=str))
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
