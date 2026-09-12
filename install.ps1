<#
.SYNOPSIS
    First-time setup for wifirecon-win.
.DESCRIPTION
    Creates a virtual environment, installs dependencies, registers a Start Menu
    shortcut, and optionally sets the app to start at logon.
#>
[CmdletBinding()]
param(
    [switch]$Autostart,
    [switch]$WithGps,
    [switch]$NoShortcut
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Say($text, $colour = 'Gray') { Write-Host $text -ForegroundColor $colour }

Say "`nwifirecon-win setup" 'Cyan'
Say ("-" * 40)

# --- Python ---------------------------------------------------------------
$python = $null
$pythonArgs = @()
$candidates = @(
    @{ exe = 'py';      args = @('-3') },
    @{ exe = 'python';  args = @() },
    @{ exe = 'python3'; args = @() }
)
foreach ($candidate in $candidates) {
    if (-not (Get-Command $candidate.exe -ErrorAction SilentlyContinue)) { continue }
    try {
        $version = & $candidate.exe @($candidate.args + '--version') 2>&1 | Out-String
        if ($version -match 'Python (\d+)\.(\d+)') {
            if ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -ge 10) {
                $python = $candidate.exe
                $pythonArgs = $candidate.args
                Say ("Found " + $version.Trim()) 'Green'
                break
            } else {
                Say ("Skipping " + $version.Trim() + " - too old") 'Yellow'
            }
        }
    } catch { }
}
if (-not $python) {
    Say "Python 3.10 or newer is required." 'Red'
    Say "Install it from https://www.python.org/downloads/ and tick 'Add python.exe to PATH'."
    exit 1
}

# --- virtual environment --------------------------------------------------
$venv = Join-Path $root '.venv'
if (-not (Test-Path (Join-Path $venv 'Scripts\python.exe'))) {
    Say "Creating the virtual environment..."
    & $python @($pythonArgs + @('-m', 'venv', $venv))
    if ($LASTEXITCODE -ne 0) { Say "Could not create the virtual environment." 'Red'; exit 1 }
}
$venvPython = Join-Path $venv 'Scripts\python.exe'

Say "Installing dependencies..."
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r (Join-Path $root 'requirements.txt') --quiet
if ($LASTEXITCODE -ne 0) { Say "Dependency install failed." 'Red'; exit 1 }
if ($WithGps) {
    Say "Installing pyserial for GPS support..."
    & $venvPython -m pip install pyserial --quiet
}
Say "Dependencies installed." 'Green'

# --- vendor database ------------------------------------------------------
$dataDir = Join-Path $env:LOCALAPPDATA 'wifirecon-win'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$manuf = Join-Path $dataDir 'manuf'
if (-not (Test-Path $manuf)) {
    Say "Fetching the vendor database (optional, skipped on failure)..."
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 `
            -Uri 'https://www.wireshark.org/download/automated/data/manuf' `
            -OutFile $manuf
        Say "Vendor database saved to $manuf" 'Green'
    } catch {
        Say "Could not download it. The built-in vendor list will be used instead." 'Yellow'
    }
}

# --- shortcut -------------------------------------------------------------
if (-not $NoShortcut) {
    try {
        $startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
        $shortcut = Join-Path $startMenu 'wifirecon.lnk'
        $shell = New-Object -ComObject WScript.Shell
        $link = $shell.CreateShortcut($shortcut)
        $link.TargetPath = Join-Path $venv 'Scripts\pythonw.exe'
        $link.Arguments = '-m app'
        $link.WorkingDirectory = $root
        $link.Description = 'Passive wireless recon'
        $link.Save()
        Say "Start Menu shortcut created." 'Green'
    } catch {
        Say "Could not create the shortcut: $_" 'Yellow'
    }
}

# --- autostart ------------------------------------------------------------
if ($Autostart) {
    try {
        $action  = New-ScheduledTaskAction -Execute (Join-Path $venv 'Scripts\pythonw.exe') `
                        -Argument '-m app --no-browser' -WorkingDirectory $root
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                        -DontStopIfGoingOnBatteries -StartWhenAvailable `
                        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName 'wifirecon' -Action $action -Trigger $trigger `
            -Settings $settings -Description 'wifirecon passive wireless survey' -Force | Out-Null
        Say "Registered to start at logon (Task Scheduler task 'wifirecon')." 'Green'
    } catch {
        Say "Could not register the scheduled task: $_" 'Yellow'
        Say "Run this script from an elevated prompt if you want autostart."
    }
}

# --- diagnostics ----------------------------------------------------------
Say "`nRunning diagnostics..." 'Cyan'
& $venvPython -m app --doctor

Say "`nSetup finished." 'Green'
Say "Start it with:  .\run.ps1"
Say "Then open:      http://127.0.0.1:8722`n"
