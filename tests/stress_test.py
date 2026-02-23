import asyncio
import json
import os
import sys
import logging
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
TOTAL_CLIENTS = 20
PROMPTS_PER_PARALLEL_BATCH = 10
RAMP_UP_INCREMENT = 2
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")
HANDSHAKE_TIMEOUT = 30  # seconds
REQUEST_TIMEOUT = 60 # seconds

# MCP JSON-RPC Messages
INITIALIZE_MSG = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "stress-tester-v3", "version": "3.0"}
    }
}

INITIALIZED_MSG = {
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
    "params": {}
}

PING_TOOL_CALL = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "db_pg96_ping",
        "arguments": {}
    }
}

DESCRIBE_TABLE_CALL = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "db_pg96_describe_table",
        "arguments": {
            "schema": "information_schema",
            "table": "tables"
        }
    }
}

class VirtualClient:
    def __init__(self, client_id, trigger_event=None):
        self.client_id = client_id
        self.trigger_event = trigger_event
        self.process = None
        self.stop_event = asyncio.Event()
        self.prompts_completed = 0
        self.pending_requests = {}  # id -> asyncio.Future
        self.reader_task = None
        self.write_lock = asyncio.Lock()

    async def run(self):
        logger.info(f"Client {self.client_id} starting...")
        
        env = os.environ.copy()
        env["DATABASE_URL"] = DATABASE_URL
        env["MCP_TRANSPORT"] = "stdio"
        env["MCP_ALLOW_WRITE"] = "false"
        
        try:
            self.process = await asyncio.create_subprocess_exec(
                sys.executable, "server.py",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, # Redirect stderr to prevent deadlocks
                env=env
            )
            
            self.reader_task = asyncio.create_task(self.read_responses())

            # Handshake
            handshake_id = 1
            fut = asyncio.get_running_loop().create_future()
            self.pending_requests[handshake_id] = fut
            
            async with self.write_lock:
                self.process.stdin.write((json.dumps(INITIALIZE_MSG) + "\n").encode())
                await self.process.stdin.drain()
            
            await asyncio.wait_for(fut, timeout=HANDSHAKE_TIMEOUT)
            
            async with self.write_lock:
                self.process.stdin.write((json.dumps(INITIALIZED_MSG) + "\n").encode())
                await self.process.stdin.drain()

            # Start sending prompts
            while not self.stop_event.is_set():
                batch_tasks = []
                for i in range(PROMPTS_PER_PARALLEL_BATCH):
                    req_id = (self.client_id * 10000) + self.prompts_completed + i + 100
                    batch_tasks.append(self.send_request(req_id))
                
                results = await asyncio.gather(*batch_tasks)
                self.prompts_completed += PROMPTS_PER_PARALLEL_BATCH
                
                if self.trigger_event and not self.trigger_event.is_set() and self.prompts_completed >= 10:
                    logger.info(f"Client {self.client_id} completed 10 prompts. Signaling next batch.")
                    self.trigger_event.set()
                
                if any(r is False for r in results):
                    logger.error(f"Client {self.client_id} encountered errors in batch")
                
                await asyncio.sleep(0.5)

        except Exception as e:
            logger.error(f"Client {self.client_id} exception: {e}")
        finally:
            self.stop_event.set()
            if self.reader_task:
                self.reader_task.cancel()
            if self.process:
                try:
                    self.process.terminate()
                    await self.process.wait()
                except Exception:
                    pass
            logger.info(f"Client {self.client_id} finished. Total prompts: {self.prompts_completed}")

    async def read_responses(self):
        try:
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    logger.warning(f"Client {self.client_id} reader: EOF received.")
                    break
                try:
                    resp_json = json.loads(line.decode())
                    req_id = resp_json.get("id")
                    if req_id in self.pending_requests:
                        fut = self.pending_requests.pop(req_id)
                        if not fut.done():
                            fut.set_result(resp_json)
                except Exception as e:
                    logger.error(f"Client {self.client_id} reader error: {e} on line: {line.decode()}")
        except asyncio.CancelledError:
            pass
        finally:
            # Fail any remaining requests to prevent hangs
            remaining_ids = list(self.pending_requests.keys())
            if remaining_ids:
                logger.warning(f"Client {self.client_id} reader exiting. Failing {len(remaining_ids)} pending requests.")
                for req_id in remaining_ids:
                    fut = self.pending_requests.pop(req_id)
                    if not fut.done():
                        fut.set_exception(RuntimeError(f"Reader for client {self.client_id} exited prematurely."))

    async def send_request(self, req_id):
        try:
            req = PING_TOOL_CALL.copy() if req_id % 2 == 0 else DESCRIBE_TABLE_CALL.copy()
            req["id"] = req_id
            
            fut = asyncio.get_running_loop().create_future()
            self.pending_requests[req_id] = fut
            
            async with self.write_lock:
                self.process.stdin.write((json.dumps(req) + "\n").encode())
                await self.process.stdin.drain()
            
            resp_json = await asyncio.wait_for(fut, timeout=REQUEST_TIMEOUT)
            if "error" in resp_json:
                logger.error(f"Client {self.client_id} req {req_id} error: {resp_json['error']}")
                return False
            return True
        except Exception as e:
            logger.error(f"Client {self.client_id} req {req_id} exception: {e}")
            if req_id in self.pending_requests:
                self.pending_requests.pop(req_id)
            return False

async def main():
    logger.info("Starting Corrected Stress Test (v3)")
    clients = []
    client_tasks = []
    
    for i in range(0, TOTAL_CLIENTS, RAMP_UP_INCREMENT):
        batch_trigger = asyncio.Event()
        
        for j in range(RAMP_UP_INCREMENT):
            client_id = i + j
            client = VirtualClient(client_id, trigger_event=batch_trigger if j == 0 else None)
            clients.append(client)
            client_tasks.append(asyncio.create_task(client.run()))
        
        logger.info(f"Started batch ending with client {i+1}. Waiting for 10 prompts...")
        
        if i + RAMP_UP_INCREMENT < TOTAL_CLIENTS:
            try:
                await asyncio.wait_for(batch_trigger.wait(), timeout=60)
            except asyncio.TimeoutError:
                logger.error(f"Timeout waiting for batch {i} to complete 10 prompts. Continuing anyway.")
        else:
            logger.info("Last batch reached. Running for 60 seconds...")
            await asyncio.sleep(60)
            for c in clients:
                c.stop_event.set()

    await asyncio.gather(*client_tasks)
    logger.info("Stress Test Completed")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
