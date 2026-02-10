import json
import time
import urllib.request
import urllib.error

# Configuration
N8N_BASE_URL = "https://claritasllc.app.n8n.cloud/"
API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzMTQzYmQwNi1mZGZjLTRlYjMtYTMxYi0xZmZjZmU2Mzk3Y2YiLCJpc3MiOiJuOG4iLCJhdWQiOiJwdWJsaWMtYXBpIiwiaWF0IjoxNzY3OTMxODk5fQ.a7SwDJx6Q1_xa9KsxCLDHJqJf-hm4EHBVVM8l4KX5Is"
WORKFLOW_ID = "MyYz15IkOxsSZL82pBIkO"

def trigger_workflow():
    url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/executions"
    print(f"Triggering workflow execution: {url}")
    
    # Payload to execute the workflow
    payload = {
        "workflowId": WORKFLOW_ID,
        "mode": "manual"
    }
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('X-N8N-API-KEY', API_KEY)
    req.add_header('Content-Type', 'application/json')
    
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            print("✅ Workflow execution started.")
            return result
    except urllib.error.HTTPError as e:
        print(f"❌ HTTP Error: {e.code} {e.reason}")
        print(f"Response: {e.read().decode()}")
        return None
    except Exception as e:
        print(f"❌ Error triggering workflow: {e}")
        return None

def get_execution_status(execution_id):
    url = f"{N8N_BASE_URL.rstrip('/')}/api/v1/executions/{execution_id}"
    print(f"Checking execution status: {execution_id}...", end="\r")
    
    req = urllib.request.Request(url)
    req.add_header('X-N8N-API-KEY', API_KEY)
    
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"\n❌ Error fetching execution: {e}")
        return None

def main():
    # 1. Trigger Execution
    execution_data = trigger_workflow()
    
    if not execution_data:
        # Fallback: Maybe /webhook-test/{id} if it was a webhook?
        # But for manual trigger, we rely on /executions
        print("Could not trigger workflow. Ensure the n8n instance supports 'POST /executions'.")
        return

    execution_id = execution_data.get('id')
    if not execution_id:
        print("No execution ID returned.")
        return

    print(f"Execution ID: {execution_id}")
    
    # 2. Poll for Completion
    max_retries = 10
    for i in range(max_retries):
        status_data = get_execution_status(execution_id)
        if status_data:
            finished = status_data.get('finished', False)
            mode = status_data.get('mode')
            stopped_at = status_data.get('stoppedAt')
            
            if finished or stopped_at:
                print(f"\n✅ Execution finished. Mode: {mode}")
                
                # Analyze result
                data = status_data.get('data', {})
                result_data = data.get('resultData', {})
                run_data = result_data.get('runData', {})
                
                # Check for errors in specific nodes
                error = False
                for node_name, node_runs in run_data.items():
                    for run in node_runs:
                        if 'error' in run:
                            print(f"❌ Error in node '{node_name}': {run['error']}")
                            error = True
                        if 'data' in run:
                             # Try to extract output
                             try:
                                 output = run['data']['main'][0][0]['json']
                                 print(f"📄 Output from '{node_name}': {json.dumps(output, indent=2)}")
                             except:
                                 pass
                
                if not error:
                    print("🎉 Workflow executed successfully without errors.")
                else:
                    print("⚠️ Workflow finished with errors.")
                    
                return
        
        time.sleep(2)
    
    print("\n⏳ Timed out waiting for execution to finish.")

if __name__ == "__main__":
    main()
