
import os
import sys
import psycopg
import time
from psycopg_pool import ConnectionPool
from urllib.parse import urlparse

# --- Configuration ---
# Load from environment variables
DB_URL = os.environ.get("DATABASE_URL")

# Validate essential configuration
if not DB_URL:
    print("❌ Error: DATABASE_URL environment variable not set.")
    sys.exit(1)

def get_sanitized_host(url):
    """Safely parse the URL to get a displayable host, without credentials."""
    if not url:
        return "<invalid URL>"
    try:
        parsed = urlparse(url)
        # Reconstruct without userinfo
        return parsed.hostname or "<no host>"
    except Exception:
        return "<unparseable URL>"

def check_connection():
    print(f"Attempting to connect to: {get_sanitized_host(DB_URL)} ...")
    try:
        start = time.time()
        with psycopg.connect(DB_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version(), current_user, pg_backend_pid()")
                res = cur.fetchone()
                duration = time.time() - start
                print(f"✅ SUCCESS ({duration:.3f}s)")
                if res:
                    print(f"   Version: {res[0]}")
                    print(f"   User: {res[1]}")
                    print(f"   PID: {res[2]}")
    except psycopg.Error as e:
        print(f"❌ FAILED: A database error occurred: {e.pgcode} - {e.pgerror}")
    except Exception as e:
        print(f"❌ FAILED: An unexpected error occurred: {e}")

if __name__ == "__main__":
    check_connection()
