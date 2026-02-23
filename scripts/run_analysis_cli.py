import os
import sys
import json
import threading
import time

import os
import sys
import json
import threading
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Environment Configuration ---
# Validate DATABASE_URL
if not os.environ.get("DATABASE_URL"):
    raise ValueError("DATABASE_URL environment variable not set. Please create a .env file or set it manually.")

# Set other MCP environment variables
os.environ.setdefault("MCP_ALLOW_WRITE", "false")
os.environ.setdefault("MCP_PORT", "8085")

try:
    import server
except Exception as e:
    print(f"Failed to import server: {e}")
    sys.exit(1)

def run_analysis_and_serve():
    print("Invoking db_pg96_analyze_logical_data_model for schema 'smsadmin'...")
    tool = server.db_pg96_analyze_logical_data_model
    
    # Check if it's a FunctionTool and has 'fn'
    if hasattr(tool, 'fn'):
        func = tool.fn
    else:
        print("Cannot find underlying function, aborting.")
        return

    try:
        # The tool returns a dict with 'report_url'
        result = func(schema="smsadmin")
        
        print("\n--- Tool Result (JSON) ---")
        print(json.dumps(result, indent=2, default=str))
        print("--------------------------")
        
        print("\nStarting HTTP server to serve the report...")
        print("Press Ctrl+C to stop.")
        sys.stdout.flush()
        
        # Start the server in HTTP mode to serve the content
        # We use the same mcp object from server.py which has the cache populated
        server.mcp.run(transport="http", port=8085, show_banner=False, log_level="error")
        
    except Exception as e:
        print(f"Error executing analysis: {e}")
    except KeyboardInterrupt:
        print("\nStopping server...")

if __name__ == "__main__":
    run_analysis_and_serve()
