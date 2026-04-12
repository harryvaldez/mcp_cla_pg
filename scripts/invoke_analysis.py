import os
import sys
import threading
import time

# Set environment variable BEFORE importing server, as server.py initializes pool on import
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    db_user = os.environ.get("MCP_DB_USER")
    db_password = os.environ.get("MCP_DB_PASSWORD")
    db_host = os.environ.get("MCP_DB_HOST", "localhost")
    db_port = os.environ.get("MCP_DB_PORT", "5432")
    db_name = os.environ.get("MCP_DB_NAME", "lenexa")
    if not db_user or not db_password:
        print("DATABASE_URL or MCP_DB_USER/MCP_DB_PASSWORD must be set before running invoke_analysis.py")
        sys.exit(1)
    database_url = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

os.environ["DATABASE_URL"] = database_url
os.environ["MCP_ALLOW_WRITE"] = "false"  # Required by server.py
os.environ["MCP_PORT"] = "8085" # Explicitly set port

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
        print("\n--- Analysis Completed ---")
        print(f"Message: {result.get('message')}")
        print(f"Report URL: {result.get('report_url')}")
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
