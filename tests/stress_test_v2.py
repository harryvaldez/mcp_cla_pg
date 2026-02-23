import os
import sys
import time
import json
import threading
import subprocess
import logging
from queue import Queue, Empty

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
TOTAL_CLIENTS = 20
CLIENTS_PER_BATCH = 2
RAMP_UP_THRESHOLD = 10  # requests completed before next batch
PARALLEL_PROMPTS = 10   # Window size of pending requests
RAMP_UP_TIMEOUT = 60 # seconds for a batch to meet ramp up criteria
FINAL_PHASE_TIMEOUT = 120 # seconds for all clients to complete final phase
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable must be set")

# Messages
INITIALIZE_MSG = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "stress-tester", "version": "2.0"}
    }
}

INITIALIZED_MSG = {
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
    "params": {}
}

PING_TOOL_CALL = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
        "name": "db_pg96_ping",
        "arguments": {}
    }
}

DESCRIBE_TABLE_CALL = {
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
        "name": "db_pg96_describe_table",
        "arguments": {
            "schema": "information_schema",
            "table": "tables"
        }
    }
}

class ClientThread(threading.Thread):
    def __init__(self, client_id):
        super().__init__(name=f"Client-{client_id}")
        self.client_id = client_id
        self.request_count = 0
        self.stop_event = threading.Event()
        self.error_occurred = False
        self.started_event = threading.Event()
        self.process = None

    def run(self):
        logger.info(f"Client {self.client_id} starting...")
        
        env = os.environ.copy()
        env["DATABASE_URL"] = DATABASE_URL
        env["MCP_TRANSPORT"] = "stdio"
        env["MCP_ALLOW_WRITE"] = "false"
        # Limit pool size per process to avoid DB exhaustion (20 processes * 5 = 100 conns)
        env["MCP_POOL_MAX_SIZE"] = "5" 
        
        try:
            self.process = subprocess.Popen(
                [sys.executable, "server.py"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                bufsize=1
            )
            
            # Handshake
            self._send(INITIALIZE_MSG)
            init_resp = self.process.stdout.readline()
            if not init_resp:
                raise Exception("No initialize response")
            
            self._send(INITIALIZED_MSG)
            self.started_event.set()
            
            # Continuous Load Loop
            req_id_base = 100
            while not self.stop_event.is_set():
                # Send batch of PARALLEL_PROMPTS
                current_batch_ids = []
                for i in range(PARALLEL_PROMPTS):
                    req = PING_TOOL_CALL.copy() if i % 2 == 0 else DESCRIBE_TABLE_CALL.copy()
                    req_id = req_id_base + i
                    req["id"] = req_id
                    current_batch_ids.append(req_id)
                    self._send(req)
                
                req_id_base += PARALLEL_PROMPTS
                
                # Read responses for this batch
                for _ in range(PARALLEL_PROMPTS):
                    resp = self.process.stdout.readline()
                    if not resp:
                        raise Exception("Stream ended unexpectedly")
                    
                    resp_json = json.loads(resp)
                    if "error" in resp_json:
                        logger.error(f"Client {self.client_id} error: {resp_json['error']}")
                        self.error_occurred = True
                    else:
                        self.request_count += 1
                
                # Small sleep to prevent tight loop burning CPU too hard
                time.sleep(0.05)
                
        except Exception as e:
            logger.error(f"Client {self.client_id} crashed: {e}")
            self.error_occurred = True
        finally:
            if self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=1)
                except:
                    self.process.kill()
            logger.info(f"Client {self.client_id} stopped. Total reqs: {self.request_count}")

    def _send(self, msg):
        self.process.stdin.write(json.dumps(msg) + "\n")
        self.process.stdin.flush()

    def stop(self):
        self.stop_event.set()

def main():
    logger.info("Starting Stress Test V2")
    active_clients = []
    
    try:
        # Ramp Up Phase
        for batch_idx in range(0, TOTAL_CLIENTS, CLIENTS_PER_BATCH):
            new_clients = []
            logger.info(f"Starting batch {batch_idx // CLIENTS_PER_BATCH + 1} (Clients {batch_idx}-{batch_idx + CLIENTS_PER_BATCH - 1})")
            
            for i in range(CLIENTS_PER_BATCH):
                client_id = batch_idx + i
                if client_id >= TOTAL_CLIENTS:
                    break
                c = ClientThread(client_id)
                c.start()
                if c.started_event.wait(timeout=10):
                    new_clients.append(c)
                    active_clients.append(c)
                else:
                    logger.error(f"Client {client_id} failed to start in time! Aborting.")
                    raise RuntimeError(f"Client {client_id} failed to start.")
            
            # Condition: Each NEW client must process RAMP_UP_THRESHOLD requests
            # Existing clients keep running in background
            logger.info(f"Waiting for new clients to reach {RAMP_UP_THRESHOLD} requests...")
            start_time = time.time()
            while True:
                if time.time() - start_time > RAMP_UP_TIMEOUT:
                    raise RuntimeError(f"Ramp-up phase timed out after {RAMP_UP_TIMEOUT} seconds.")

                # Check for errors in any client
                if any(c.error_occurred for c in active_clients):
                    logger.error("Error detected in a client! Aborting test.")
                    raise RuntimeError("Stress test failed due to client error")
                
                # Check condition
                if all(c.request_count >= RAMP_UP_THRESHOLD for c in new_clients):
                    logger.info("Ramp-up condition met.")
                    break
                
                time.sleep(0.5)
        
        logger.info("All 20 clients running. Entering final phase...")
        
        # Final Phase: Run all 20 clients for a bit longer to prove stability
        # "At the last phase... 20 clients running 10 prompts each in parallel"
        # We verify they can ALL do another 10 prompts
        
        # Snapshot current counts
        start_counts = {c.client_id: c.request_count for c in active_clients}
        target_increment = 10
        
        logger.info(f"Verifying all 20 clients can process {target_increment} more requests...")
        start_time = time.time()
        while True:
            if time.time() - start_time > FINAL_PHASE_TIMEOUT:
                raise RuntimeError(f"Final phase timed out after {FINAL_PHASE_TIMEOUT} seconds.")

            if any(c.error_occurred for c in active_clients):
                logger.error("Error detected in a client! Aborting test.")
                raise RuntimeError("Stress test failed due to client error")
            
            if all(c.request_count >= start_counts[c.client_id] + target_increment for c in active_clients):
                logger.info("Final phase verification successful!")
                break
            
            time.sleep(1)
            
        logger.info("Success! All clients demonstrated sustained load.")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        sys.exit(1)
    finally:
        logger.info("Stopping all clients...")
        for c in active_clients:
            c.stop()
        for c in active_clients:
            c.join()
        logger.info("Test finished.")

if __name__ == "__main__":
    main()
