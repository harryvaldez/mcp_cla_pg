import os
import json
import time
import socket
import ipaddress
import http.client
from urllib.parse import urlparse

# --- Configuration ---
# These must be set as environment variables
N8N_BASE_URL = os.environ.get("N8N_BASE_URL", "https://claritasllc.app.n8n.cloud/")
API_KEY = os.environ.get("N8N_API_KEY")
WORKFLOW_ID = os.environ.get("N8N_WORKFLOW_ID", "MyYz15IkOxsSZL82pBIkO")

import pytest


def _load_allowlist() -> set[str]:
    configured = os.environ.get("OUTBOUND_URL_ALLOWLIST", "")
    defaults = "claritasllc.app.n8n.cloud,github.com,login.microsoftonline.com"
    raw = configured if configured.strip() else defaults
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def _host_allowed(hostname: str, allowlist: set[str]) -> bool:
    host = hostname.lower()
    for allowed in allowlist:
        if host == allowed or host.endswith(f".{allowed}"):
            return True
    return False


def _validate_outbound_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("URL is missing hostname")

    host = parsed.hostname
    allowlist = _load_allowlist()
    allow_local = os.environ.get("ALLOW_PRIVATE_OUTBOUND", "false").lower() == "true"

    infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    for info in infos:
        ip_obj = ipaddress.ip_address(info[4][0])
        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast) and not allow_local:
            if not _host_allowed(host, allowlist):
                raise ValueError(f"Blocked private/internal destination for host '{host}' ({ip_obj})")

    if not _host_allowed(host, allowlist):
        raise ValueError(f"Host '{host}' is not in outbound allowlist")
    return url


def _http_json_request(method: str, url: str, headers: dict[str, str], timeout: int, body: bytes | None = None):
    safe_url = _validate_outbound_url(url)
    parsed = urlparse(safe_url)
    connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    connection = connection_cls(parsed.netloc, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(f"HTTP Error {response.status} {response.reason}: {payload}")
        return json.loads(payload) if payload else {}
    finally:
        connection.close()

def trigger_workflow():
    url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/executions"
    print(f"Triggering workflow execution: {url}")
    
    # Payload to execute the workflow
    payload = {
        "workflowId": WORKFLOW_ID,
        "mode": "manual"
    }
    
    data = json.dumps(payload).encode('utf-8')
    
    try:
        result = _http_json_request(
            "POST",
            url,
            {
                "X-N8N-API-KEY": API_KEY,
                "Content-Type": "application/json",
            },
            timeout=30,
            body=data,
        )
        print("✅ Workflow execution started.")
        return result
    except Exception as e:
        print(f"❌ Error triggering workflow: {e}")
        return None

def get_execution_status(execution_id):
    url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/executions/{execution_id}"
    print(f"Checking execution status: {execution_id}...", end="\r")
    
    try:
        return _http_json_request(
            "GET",
            url,
            {"X-N8N-API-KEY": API_KEY},
            timeout=10,
        )
    except Exception as e:
        print(f"\n❌ Error fetching execution: {e}")
        return None

@pytest.mark.skipif(not API_KEY, reason="N8N_API_KEY environment variable not set.")
def test_remote_workflow():
    # 1. Trigger Execution
    execution_data = trigger_workflow()
    assert execution_data, "Failed to trigger workflow execution."

    execution_id = execution_data.get('id')
    assert execution_id, "No execution ID returned from workflow trigger."

    print(f"Execution ID: {execution_id}")

    # 2. Poll for Completion
    max_retries = 10
    for i in range(max_retries):
        status_data = get_execution_status(execution_id)
        if status_data:
            finished = status_data.get('finished', False)
            stopped_at = status_data.get('stoppedAt')

            if finished or stopped_at:
                print(f"\n✅ Execution finished. Status: {'completed' if finished else 'stopped'}")

                # Analyze result
                data = status_data.get('data', {})
                result_data = data.get('resultData', {})
                run_data = result_data.get('runData', {})

                # Check for errors in specific nodes
                errors = []
                for node_name, node_runs in run_data.items():
                    for run in node_runs:
                        if 'error' in run:
                            error_detail = run['error']
                            errors.append(f"Node '{node_name}': {error_detail}")
                            print(f"❌ Error in node '{node_name}': {error_detail}")
                        if 'data' in run:
                            # Try to extract output
                            try:
                                output = run['data']['main'][0][0]['json']
                                print(f"📄 Output from '{node_name}': {json.dumps(output, indent=2)}")
                            except (KeyError, IndexError, TypeError) as e:
                                print(f"⚠️ Could not parse output from node '{node_name}': {e}")

                assert not errors, f"Workflow finished with errors: {'; '.join(errors)}"
                print("🎉 Workflow executed successfully without errors.")
                return

        time.sleep(2)

    pytest.fail(f"Timed out after {max_retries * 2} seconds waiting for execution {execution_id} to finish.")

if __name__ == "__main__":
    main()
