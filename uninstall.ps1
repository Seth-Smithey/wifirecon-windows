<#
.SYNOPSIS
    Remove wifirecon-win's shortcut, scheduled task and (optionally) its data.
#>
param([switch]$KeepData)

$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$rootPattern = [regex]::Escape($root)
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
    Where-Object {
        $_.CommandLine -match '-m\s+app' -and
        ($_.CommandLine -match $rootPattern -or $_.ExecutablePath -match $rootPattern)
    } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

Unregister-ScheduledTask -TaskName 'wifirecon' -Confirm:$false
Remove-Item (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\wifirecon.lnk') -Force

if (-not $KeepData) {
    $dataDir = Join-Path $env:LOCALAPPDATA 'wifirecon-win'
    Write-Host "Removing $dataDir"
    Remove-Item $dataDir -Recurse -Force
} else {
    Write-Host "Data kept at $(Join-Path $env:LOCALAPPDATA 'wifirecon-win')"
}

Write-Host "Done. Delete $root yourself if you want the code gone too."
