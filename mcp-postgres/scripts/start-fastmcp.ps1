#!/usr/bin/env pwsh
# Start FastMCP EDB96 server in Docker
param(
    [switch]$Build,
    [switch]$Detached = $true,
    [string]$ComposeFile = "docker/docker-compose.yml"
)

$ErrorActionPreference = "Stop"

# Validate .env exists
if (-not (Test-Path ".env")) {
    Write-Error ".env file not found. Copy .env.example to .env and configure credentials."
    exit 1
}

# Validate YAML configs
$configFiles = @(
    "config/instances.yaml",
    "config/runtime-policy.yaml",
    "config/rate-limit.yaml"
)
foreach ($file in $configFiles) {
    if (-not (Test-Path $file)) {
        Write-Error "Config file not found: $file"
        exit 1
    }
}

Write-Host "Starting FastMCP EDB96 Dual-Instance Server..." -ForegroundColor Green

if ($Build) {
    Write-Host "Building Docker image..." -ForegroundColor Yellow
    docker compose -f $ComposeFile build
}

$detachArg = if ($Detached) { "-d" } else { "" }
Invoke-Expression "docker compose -f $ComposeFile up $detachArg"

Write-Host "Server starting. Health check available at http://localhost:8080/health" -ForegroundColor Cyan
