$ErrorActionPreference = "Stop"

function Resolve-SkillRoots {
    $raw = $env:MCP_SKILLS_DIRS
    if ([string]::IsNullOrWhiteSpace($raw)) {
        $raw = $env:FASTMCP_SKILLS_DIRS
    }

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $candidates = ($raw -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } else {
        $candidates += (Join-Path (Get-Location) ".trae\skills")
        $candidates += (Join-Path $HOME ".copilot\skills")
    }

    $resolved = @()
    foreach ($candidate in $candidates) {
        $full = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($candidate))
        if ((Test-Path -LiteralPath $full -PathType Container) -and -not ($resolved -contains $full)) {
            $resolved += $full
        }
    }

    return $resolved
}

$roots = Resolve-SkillRoots
if ($roots.Count -eq 0) {
    throw "No valid skills roots found. Configure MCP_SKILLS_DIRS/FASTMCP_SKILLS_DIRS or create .trae/skills or ~/.copilot/skills."
}

$skillIds = @()
foreach ($root in $roots) {
    Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $skillFile = Join-Path $_.FullName "SKILL.md"
        if (Test-Path -LiteralPath $skillFile -PathType Leaf) {
            $id = $_.Name
            $skillIds += $id
        }
    }
}

$skillIds = $skillIds | Sort-Object -Unique
if ($skillIds.Count -eq 0) {
    throw "No SKILL.md files found under resolved roots: $($roots -join ', ')"
}

$postgresMatches = $skillIds | Where-Object { $_ -match 'postgres|pg' }
if ($postgresMatches.Count -eq 0) {
    throw "Skill discovery succeeded but no PostgreSQL-like skill id was found. Visible ids: $($skillIds -join ', ')"
}

Write-Host "Resolved roots:"
$roots | ForEach-Object { Write-Host "- $_" }
Write-Host "Resolved skill ids:"
$skillIds | ForEach-Object { Write-Host "- $_" }
Write-Host "PostgreSQL-like skill ids:"
$postgresMatches | ForEach-Object { Write-Host "- $_" }
