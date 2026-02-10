
import os
import sys

# Mock env vars to avoid errors
os.environ["DATABASE_URL"] = "postgres://user:pass@localhost:5432/db"
os.environ["MCP_ALLOW_WRITE"] = "true"
os.environ["MCP_CONFIRM_WRITE"] = "true"
os.environ["FASTMCP_AUTH_TYPE"] = "apikey"
os.environ["FASTMCP_API_KEY"] = "test"

try:
    from server import mcp
    print(f"Type: {type(mcp)}")
    print(f"Dir: {dir(mcp)}")
    if hasattr(mcp, 'router'):
        print("Has router")
        print(f"Routes: {len(mcp.router.routes) if hasattr(mcp.router, 'routes') else '?'}")
    
    if hasattr(mcp, 'http_app'):
        app = mcp.http_app()
        print(f"Http App: {type(app)}")
        print(f"App Routes: {[r.path for r in app.routes]}")
        # print(f"App Middleware: {len(app.middleware_stack) if hasattr(app, 'middleware_stack') else '?'}")

except Exception as e:
    print(f"Error: {e}")
