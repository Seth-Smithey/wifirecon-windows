<#
.SYNOPSIS
    Pull the latest wifirecon-win and restart it.
.DESCRIPTION
    Stops any running instance, fast-forwards the checkout, reinstalls
    dependencies if they changed, and starts the app again. Safe to run from the
    Diagnostics tab, which calls it detached so the restart does not kill itself.
#>
[CmdletBinding()]
param(
    [string]$Channel = 'main',
    [switch]$Restart,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$logFile = Join-Path $env:LOCALAPPDATA 'wifirecon-win\update.log'
New-Item -ItemType Directory -Force -Path (Split-Path $logFile) | Out-Null

function Log($text) {
    $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $text
    Add-Content -Path $logFile -Value $line
    Write-Host $text
}

Log "Update starting on channel '$Channel'"

if (-not (Test-Path (Join-Path $root '.git'))) {
    Log "This copy was not installed with git, so it cannot update itself."
    exit 1
}

# --- stop the running instance -------------------------------------------
$stopped = $false
$rootPattern = [regex]::Escape($root)
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
    Where-Object {
        $_.CommandLine -match '-m\s+app' -and
        ($_.CommandLine -match $rootPattern -or $_.ExecutablePath -match $rootPattern)
    } |
    ForEach-Object {
        Log "Stopping process $($_.ProcessId)"
        try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $stopped = $true }
        catch { Log "Could not stop $($_.ProcessId): $_" }
    }
if ($stopped) { Start-Sleep -Seconds 2 }

# --- pull -----------------------------------------------------------------
$before = (git rev-parse --short HEAD 2>$null)

if ($Force) {
    Log "Force requested: discarding local changes"
    git reset --hard HEAD | Out-Null
}

git fetch origin $Channel 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Log "Could not reach the update server."; exit 1 }

git merge --ff-only "origin/$Channel" 2>&1 | ForEach-Object { Log $_ }
if ($LASTEXITCODE -ne 0) {
    Log "Fast-forward failed. There are local commits or changes in the way."
    Log "Run: .\update.ps1 -Force   to discard them, or resolve by hand."
    exit 1
}

$after = (git rev-parse --short HEAD 2>$null)
if ($before -eq $after) { Log "Already up to date at $after" }
else { Log "Updated $before -> $after" }

# --- dependencies ---------------------------------------------------------
$venvPython = Join-Path $root '.venv\Scripts\python.exe'
if (Test-Path $venvPython) {
    Log "Refreshing dependencies"
    & $venvPython -m pip install -r (Join-Path $root 'requirements.txt') --quiet --upgrade
    if ($LASTEXITCODE -ne 0) { Log "Dependency refresh reported a problem." }
} else {
    Log "No virtual environment found; run install.ps1"
}

# Stale bytecode from a root-owned or older run can shadow updated modules.
Get-ChildItem -Path $root -Include '__pycache__' -Recurse -Directory -ErrorAction SilentlyContinue |
    ForEach-Object {
        try { Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop }
        catch { Log "Could not clear $($_.FullName)" }
    }

# --- restart --------------------------------------------------------------
if ($Restart) {
    $pythonw = Join-Path $root '.venv\Scripts\pythonw.exe'
    if (Test-Path $pythonw) {
        Log "Restarting"
        Start-Process -FilePath $pythonw -ArgumentList @('-m','app','--no-browser') `
            -WorkingDirectory $root -WindowStyle Hidden
    } else {
        Log "pythonw.exe not found; start the app manually with .\run.ps1"
    }
}

Log "Update finished"
