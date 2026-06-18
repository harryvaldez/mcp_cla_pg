#!/usr/bin/env pwsh
# Production deployment for FastMCP EDB96 Dual-Instance Server
param(
    [string]$ImageTag = "latest",
    [string]$ComposeFile = "docker/docker-compose.runtime.yml"
)

$ErrorActionPreference = "Stop"

Write-Host "=== FastMCP EDB96 Production Deployment ===" -ForegroundColor Green

# Validate prerequisites
if (-not (Test-Path ".env")) {
    Write-Error ".env file required for production deployment"
    exit 1
}

# Pull latest image
Write-Host "Pulling image digests..." -ForegroundColor Yellow
docker compose -f $ComposeFile pull --quiet 2>$null

# Deploy
Write-Host "Deploying containers..." -ForegroundColor Yellow
docker compose -f $ComposeFile up -d --remove-orphans

# Wait for healthy
Write-Host "Waiting for health check..." -ForegroundColor Cyan
$maxWait = 60
$waited = 0
while ($waited -lt $maxWait) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8085/health" -TimeoutSec 2 -UseBasicParsing
        $body = $response.Content | ConvertFrom-Json
        if ($body.status -eq "healthy" -or $body.status -eq "degraded") {
            Write-Host "Deployment successful! Status: $($body.status)" -ForegroundColor Green
            Write-Host "Instances: $($body.instances | ConvertTo-Json -Compress)" -ForegroundColor Cyan
            exit 0
        }
    } catch {
        # Still waiting
    }
    Start-Sleep -Seconds 2
    $waited += 2
}

Write-Error "Deployment may have failed. Check 'docker compose logs' for details."
exit 1
