import os
import sys
import json
import time
import subprocess
import traceback
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add project root to sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# --- Environment Configuration ---
# Validate DATABASE_URL
if not os.environ.get("DATABASE_URL"):
    raise ValueError("DATABASE_URL environment variable not set. Please create a .env file or set it manually.")

# Configure Environment for the Server (MUST BE DONE BEFORE IMPORTING server)
os.environ["MCP_ALLOW_WRITE"] = "false"
os.environ["MCP_LOG_LEVEL"] = "WARNING"
os.environ["MCP_TRANSPORT"] = "stdio"

# Import the server module
try:
    import server
except ImportError:
    print("Error: Could not import server.py. Make sure you are in the project root.")
    sys.exit(1)

def invoke_tool(tool_obj, **kwargs):
    """Helper to invoke a FastMCP tool object"""
    if callable(tool_obj):
        return tool_obj(**kwargs)
    
    # Check for common underlying function attributes
    for attr in ("fn", "func", "function", "_fn"):
        inner = getattr(tool_obj, attr, None)
        if callable(inner):
            return inner(**kwargs)
            
    raise TypeError(f"Could not find callable for tool {tool_obj}")

def main():
    print("Starting PostgreSQL 9.6 container...")
    compose_file = os.path.join(project_root, "docker-compose.yml")
    try:
        subprocess.run(["docker", "compose", "-f", compose_file, "up", "-d", "postgres96"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to start docker containers: {e}")
        sys.exit(1)
    
    # Wait for DB to be ready using a real connection check
    print("Waiting for database to be ready...")
    
    from psycopg_pool import ConnectionPool
    from psycopg.rows import dict_row

    max_retries = 15
    retry_delay = 2
    check_pool = None  # Initialize to None
    
    try:
        check_pool = ConnectionPool(os.environ["DATABASE_URL"], kwargs={"row_factory": dict_row}, timeout=5)
        for i in range(max_retries):
            try:
                with check_pool.connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1")
                        print("Database is ready!")
                        break
            except Exception as e:
                if i < max_retries - 1:
                    print(f"Database not ready ({e}), retrying in {retry_delay}s... ({i+1}/{max_retries})")
                    time.sleep(retry_delay)
                else:
                    print("Error: Database failed to become ready after multiple attempts.")
                    sys.exit(1) # Exit here, finally will still run
    finally:
        # Safely close the pool
        if check_pool is not None:
            check_pool.close()
            print("Connectivity check pool closed.")

    try:
        # Check if we can connect to the DB
        
        # We don't want to mess with server.pool if it's already working, 
        # but since we imported server after setting env vars, it should be fine.
        
        print("\nExecuting db_pg96_database_security_performance_metrics(profile='oltp')...\n")
        
        result = invoke_tool(server.db_pg96_database_security_performance_metrics, profile="oltp")
        
        print(json.dumps(result, indent=2, default=str))

    except Exception as e:
        print(f"Error running tool: {e}")
        traceback.print_exc()
    finally:
        print("\nStopping containers...")
        subprocess.run(["docker", "compose", "-f", "docker-compose.yml", "down", "-v"], check=False)

if __name__ == "__main__":
    main()
