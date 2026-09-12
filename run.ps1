<#
.SYNOPSIS
    Start wifirecon-win.
#>
[CmdletBinding()]
param(
    [int]$Port,
    [switch]$NoBrowser,
    [switch]$Mock,
    [switch]$Doctor,
    [switch]$ScanOnce,
    [switch]$Background
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$venvPython = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    Write-Host "No virtual environment found. Run .\install.ps1 first." -ForegroundColor Red
    exit 1
}

$arguments = @('-m', 'app')
if ($Port)      { $arguments += @('--port', $Port) }
if ($NoBrowser) { $arguments += '--no-browser' }
if ($Mock)      { $arguments += '--mock' }
if ($Doctor)    { $arguments += '--doctor' }
if ($ScanOnce)  { $arguments += '--scan-once' }

if ($Background) {
    $pythonw = Join-Path $root '.venv\Scripts\pythonw.exe'
    Start-Process -FilePath $pythonw -ArgumentList $arguments -WorkingDirectory $root `
        -WindowStyle Hidden
    Write-Host "Started the desktop application." -ForegroundColor Green
} else {
    & $venvPython @arguments
    exit $LASTEXITCODE
}
