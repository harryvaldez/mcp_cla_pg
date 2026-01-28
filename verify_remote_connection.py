
import os
import psycopg
import time
from psycopg_pool import ConnectionPool

# Configuration
DB_URL = "postgresql://enterprisedb:ClaRitAs02@10.100.2.20:5444/lenexa"

def check_connection():
    print(f"Attempting to connect to: {DB_URL.split('@')[1]} ...")
    try:
        start = time.time()
        with psycopg.connect(DB_URL, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version(), current_user, pg_backend_pid()")
                res = cur.fetchone()
                duration = time.time() - start
                print(f"✅ SUCCESS ({duration:.3f}s)")
                print(f"   Version: {res[0]}")
                print(f"   User: {res[1]}")
                print(f"   PID: {res[2]}")
    except Exception as e:
        print(f"❌ FAILED: {e}")

if __name__ == "__main__":
    check_connection()
