$ErrorActionPreference = "Stop"

$command = "npx"
$commandArgs = @("@smithery/cli@latest", "skill", "add", "sickn33/postgresql")

Write-Host "Installing Smithery skill sickn33/postgresql..."
& $command @commandArgs

if ($LASTEXITCODE -ne 0) {
    throw "Smithery skill install failed with exit code $LASTEXITCODE"
}

Write-Host "Smithery skill install completed successfully."
