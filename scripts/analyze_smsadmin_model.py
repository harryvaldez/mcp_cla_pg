import os
import json
import sys
import datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from dotenv import load_dotenv

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Load environment variables from .env file
load_dotenv(dotenv_path=project_root / ".env")

# --- Environment Configuration ---
# Get and validate DATABASE_URL
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set. Please create a .env file or set it manually.")

# Sanitize URL for logging
def get_sanitized_url(url: str) -> str:
    parsed_url = urlparse(url)
    # Rebuild netloc without password
    if parsed_url.password:
        netloc = f"{parsed_url.username}:****@{parsed_url.hostname}"
        if parsed_url.port:
            netloc += f":{parsed_url.port}"
        # Create a new tuple for replacement
        sanitized_parts = parsed_url._replace(netloc=netloc)
        return urlunparse(sanitized_parts)
    return url # Return original if no password

SANITIZED_DB_URL = get_sanitized_url(DATABASE_URL)

# Set other MCP environment variables
os.environ["MCP_ALLOW_WRITE"] = "false"
os.environ["MCP_POOL_MAX_SIZE"] = "20"
os.environ["MCP_POOL_TIMEOUT"] = "60.0"
try:
    from server import db_pg96_analyze_logical_data_model
except ImportError:
    print("Could not import db_pg96_analyze_logical_data_model directly.", file=sys.stderr)
    sys.exit(1)

def invoke_tool(tool_obj, tool_name: str, **kwargs):
    """Helper to invoke a FastMCP tool object."""
    # First, check if the primary object is callable
    if callable(tool_obj):
        return tool_obj(**kwargs)
    
    # If not, try finding the underlying function for compatibility
    for attr in ("fn", "func", "function", "_fn"):
        inner = getattr(tool_obj, attr, None)
        if callable(inner):
            return inner(**kwargs)
            
    # If no callable is found, raise a clear error
    raise TypeError(f"Error: Tool '{tool_name}' is not a callable function and no underlying function could be found.")

def main():
    try:
        print(f"Connecting to {SANITIZED_DB_URL}...", file=sys.stderr)
        print("Invoking db_pg96_analyze_logical_data_model(schema='smsadmin')...", file=sys.stderr)
        
        # Use helper to invoke the tool
        result = invoke_tool(
            db_pg96_analyze_logical_data_model, 
            tool_name="db_pg96_analyze_logical_data_model",
            schema="smsadmin"
        )
        
        # Print JSON to stdout for capture
        print(json.dumps(result, indent=2, default=str))
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
