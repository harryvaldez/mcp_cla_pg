# Azure VM Disk Usage Monitoring System

## Overview

This automated monitoring system tracks disk space usage on Azure virtual machines (Windows Server 2016 and Red Hat 7) without public IP addresses. The system collects disk usage data securely and generates alerts in Jira when usage exceeds predefined thresholds.

## Architecture

```
Azure VMs (No Public IP) → Python/Bash Scripts (JWT) → n8n Webhook → Jira Integration
```

### Components
1. **Monitoring Scripts (Python/Bash)** - Run on each VM to collect disk usage data
2. **n8n Workflow** - Processes incoming data and creates Jira tickets
3. **Jira Integration** - Automated ticket creation with priority-based alerts

## Prerequisites

### Software Requirements
- Python 3.6+ for Windows monitoring script
- n8n instance (self-hosted or cloud)
- Jira instance with API access
- Required Python packages:
  ```bash
  pip install psutil requests
  ```

  ```bash
  # Linux JWT dependency
  pip install PyJWT==1.7.1
  ```

### Network Requirements
- Outbound HTTPS access from Azure VMs to n8n instance
- n8n instance accessible via HTTPS
- Jira API accessible from n8n instance

## Installation & Deployment

### 1. Python Script Deployment

#### Windows Server 2016
```powershell
# Copy script to VM
Copy-Item windows_disk_monitor.py C:\Monitoring\disk_monitor

# Install dependencies
pip install psutil requests

# Create scheduled task (runs every hour)
Create a scheduled task named N8N_DiskMon, with:
          Run whether user is logged on or not 
          Run with highest privileges
Runs Daily and repeat every 30 minutes
Actions:  Start a program
          Program Script: "C:\Program Files\Python313\python.exe" 
          Add arguments:  C:\Monitoring\disk_monitor\windows_disk_monitor.py
```

#### Red Hat 7 Linux (Bash Version with JWT)
```bash
# Copy script to VM
sudo cp linux_disk_monitor.sh /opt/edb/as9.6/scripts

# Make script executable
sudo chmod +x /opt/edb/as9.6/scripts/linux_disk_monitor.sh

# Install dependencies (calculations, webhook, JWT)
sudo yum install bc curl
sudo yum install python3-pip
sudo pip3 install PyJWT==1.7.1

# Create cron job (runs every 30 minutes)
log in as enterprisedb and issue crontab -e
# Add line:
*/30 * * * * /opt/edb/as9.6/scripts/linux_disk_monitor.sh
# Note: The script reports only the /data mount; ensure /data exists
```
### 2. Script Configuration

Update the following variables in the scripts:

```python
# windows_disk_monitor.py
WEBHOOK_URL = "https://claritasllc.app.n8n.cloud/webhook/disk-monitor"
JWT_SECRET = "a-claritas-dba-secret-string-for-n8n-authentication"
```

```bash
# linux_disk_monitor.sh
WEBHOOK_URL="https://claritasllc.app.n8n.cloud/webhook/disk-monitor"
JWT_SECRET="a-claritas-dba-secret-string-for-n8n-authentication"
```
## Workflow Components

### n8n Workflow Nodes

1. **Disk Monitor Webhook** - Receives POST requests from monitoring scripts
2. **Parse Disk Data** - Extracts and processes disk usage information
3. **Check Usage Threshold** - Routes data based on 75% threshold
4. **Format Jira Ticket** - Creates detailed ticket content
5. **Call Create Jira ** - Subworkflow that checks for duplicate Jira Tasks and sends email if new ticket is created
6. **Logging Nodes** - For monitoring and debugging
7. **Webhook Response** - Returns HTTP response

### Alert Thresholds

- **High**: 76-90% disk usage
- **Highest**: >90% disk usage

## Monitoring Scripts

### Windows Script Features
- Uses psutil for disk information
- Handles permission errors
- Comprehensive logging
- Error handling
 - Sends Authorization: Bearer JWT (HS256) with service claims
 - Includes os_type and os_version in payload
 - Excludes drives `C:` and `D:` from monitoring

### Linux Script Features (Bash Version - linux_disk_monitor.sh)
- Pure bash implementation for environments without Python
- Uses df command for disk and inode information
- Filters out Windows/WSL filesystems and special filesystems
- Proper JSON formatting with numeric values (not strings)
- Comprehensive error handling and logging
- Validates usage percentages (0-100 range)
- Converts disk blocks to GB
- Handles permission issues with log files
- Environment detection and compatibility handling
 - Generates JWT via Python/PyJWT and sends Authorization header
 - Includes os_type and os_version in payload
 - Monitors only the `/data` filesystem (other mounts are ignored)

## Jira Integration

### Ticket Format
Each Jira ticket includes:
- Server name and IP address
- Mount point/device information
- Current usage percentage
- Total/used/free space
- Priority based on usage
- Timestamp and alert details

### Custom Fields
- Labels: `disk-space`, `azure-vm`, `automated-alert`
- Components: `infrastructure`, `monitoring`
- Custom timestamp field

## Security Considerations

### Azure Environment
- VMs operate without public IP addresses
- Outbound HTTPS only to n8n instance
- Use Azure Private Link if required

### n8n Security
- Secure webhook endpoints
- HTTPS encryption
- Authentication for Jira API
- Regular n8n updates

### Script Security
- Scripts run with minimal privileges
- No sensitive data in logs
- Secure credential management

## Troubleshooting

### Common Issues

1. **Webhook Connection Failed**
   ```bash
   # Test connectivity from VM
   curl -X POST https://claritasllc.app.n8n.cloud/webhook/disk-monitor -d '{"test": "connection"}'
   ```

   JWT test (Linux/macOS):
   ```bash
   # Generate a short‑lived token and call webhook with Authorization header
   TOKEN=$(python3 jwt_helper.py generate "a-claritas-dba-secret-string-for-n8n-authentication" '{"sub":"python-script","name":"Monitoring Service for Disk Util","role":"service","service_id":"monitor-test","server_name":"test","server_ip":"127.0.0.1","timestamp":"'"$(date -Iseconds)"'"}')
   curl -X POST https://claritasllc.app.n8n.cloud/webhook/disk-monitor \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"test":"jwt"}'
   ```

   JWT test (Windows PowerShell):
   ```powershell
   $payload = '{"sub":"python-script","name":"Monitoring Service for Disk Util","role":"service","service_id":"monitor-test","server_name":"test","server_ip":"127.0.0.1","timestamp":"' + (Get-Date).ToString('s') + '"}'
   $token = python .\jwt_helper.py generate "a-claritas-dba-secret-string-for-n8n-authentication" $payload
   Invoke-RestMethod -Method Post -Uri https://claritasllc.app.n8n.cloud/webhook/disk-monitor -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body '{"test":"jwt"}'
   ```

   Notes:
   - Tokens expire based on `expires_in` (default 300s); generate a fresh token before calling.
   - Ensure the n8n workflow verifies the `Authorization` header.

2. **Python Dependencies Missing in Windows**
   ```bash
   # Check installed packages
   pip list | grep psutil
   pip list | grep requests
   ```

3. **Permission Errors**
   - Ensure scripts have appropriate execution permissions
   - Check user context for scheduled tasks/cron jobs

4. **Jira API Errors**
   - Verify Jira credentials in n8n
   - Check project key and issue type permissions

5. **JWT/Authorization Issues**
   - Ensure `JWT_SECRET` matches n8n validator configuration
   - Confirm `Authorization: Bearer <token>` is present at the webhook
   - Check system time; tokens use `exp`/`iat`
   - On Linux, verify PyJWT: `python3 -c "import jwt"`

6. **No Disk Data on Linux**
   - The script monitors only `/data`. Create/mount `/data` or adjust the script if a different mount is required.

### Log Files

- **Windows**: `C:\Monitoring\disk_monitor\disk_monitor.log` (falls back to `disk_monitor.log` in current directory if directory creation fails)
- **Linux (Bash)**: `/opt/edb/as9.6/scripts/disk_monitor.log` (falls back to that directory if `/var/log` is denied)
- **n8n**: Check n8n execution logs

## Authentication

- Both scripts authenticate to the n8n webhook using JWT (HS256) in `Authorization: Bearer <token>`.
- Shared secret: `JWT_SECRET` configured in each script.
- Claims:
  - `sub`: `python-script`
  - `name`: `Monitoring Service for Disk Util`
  - `role`: `service`
  - `service_id`: `monitor-<server_name>`
  - `server_name`, `server_ip`, `timestamp` (and standard `iat`/`exp`)

### Debug Mode
Enable debug logging in Python scripts:
```python
logging.basicConfig(level=logging.DEBUG)
```

## Performance Considerations

- Scripts run every 30 minutes (modify as needed)
- Lightweight disk monitoring using native tools
- Efficient data transmission to n8n
- Batch processing in n8n workflow

## Maintenance

### Regular Tasks
1. Monitor script execution logs
2. Review n8n workflow executions
3. Check Jira ticket creation success
4. Update Python dependencies periodically

### Updates
1. Test script updates in development environment
2. Update n8n workflow as needed
3. Maintain compatibility with Azure VM images

## FAQ

### Q: How often does the monitoring run?
A: Scripts run every 30 minutes by default. Adjust cron/scheduled task intervals as needed.

### Q: Can I modify the alert thresholds?
A: Yes, update the threshold values in the n8n workflow (See Alert Thresholds above.  To change, modify "Parse Disk Data" node).

### Q: What Jira permissions are required?
A: The API user needs permissions to create issues in the target project.

### Q: How do I add more VMs to monitor?
A: Deploy the appropriate script (Windows Python or Linux Bash) to each new VM.

### Q: Can I use this with other cloud providers?
A: Yes, the scripts are cloud-agnostic. Only the deployment instructions are Azure-specific.

### Q: How do I handle SSL certificates?
A: The scripts use the system's certificate store. For self-signed certificates, add them to the trust store.

## Support

For issues with:
- **Python scripts**: Check logs and verify dependencies
- **n8n workflow**: Review execution details and node configurations
- **Jira integration**: Verify API credentials and permissions
- **Azure connectivity**: Check network security groups and routing

## License

This solution is provided as-is for monitoring purposes. Ensure compliance with your organization's policies and Azure/Jira licensing requirements.

## Version History

- **v1.2** - Documented JWT authentication (HS256) and claims, added Authentication section, included os_type/os_version in payloads, and added Linux PyJWT dependency with updated log path behavior
- **v1.1** - Updated documentation to reflect Windows Python (psutil-based) and Linux Bash monitor; corrected log paths; added Linux dependencies (bc, curl)
- **v1.0** - Initial release with Windows Server 2016 and Red Hat 7 support; basic disk monitoring and Jira integration; comprehensive logging and error handling
