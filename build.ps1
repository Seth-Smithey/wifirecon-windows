<#
.SYNOPSIS
    Build wifirecon.exe.
.DESCRIPTION
    Produces a folder build in dist\wifirecon\ plus a zip you can hand to
    someone, and a SHA-256 checksum file in the format the updater verifies
    against.

    The interface is Qt, so a folder build is the default: a single-file
    executable has to unpack the whole Qt runtime on every launch, which is
    slow and is the shape antivirus heuristics dislike most. Use -OneFile if
    you want the single portable executable anyway.
.EXAMPLE
    .\build.ps1
    .\build.ps1 -OneFile
    .\build.ps1 -Version 1.1.0 -Release
#>
[CmdletBinding()]
param(
    [string]$PythonExecutable,
    [string]$Version,
    [switch]$OneFile,
    [switch]$OneDir,          # accepted and ignored; folder builds are the default
    [switch]$WithGps,
    [switch]$Clean,
    [switch]$Release,
    [switch]$SkipTest
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Say($text, $colour = 'Gray') { Write-Host $text -ForegroundColor $colour }

Say "`nwifirecon build" 'Cyan'
Say ("-" * 46)

# --- version ---------------------------------------------------------------
if ($Version) {
    if ($Version -notmatch '^\d+\.\d+\.\d+$') {
        Say "Version must look like 1.2.3" 'Red'; exit 1
    }
    Set-Content -Path (Join-Path $root 'VERSION') -Value $Version -NoNewline
    Say "Version set to $Version" 'Green'
}
$currentVersion = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
Say "Building version $currentVersion"

# --- python ----------------------------------------------------------------
$python = $null
$pythonArgs = @()
if ($PythonExecutable) {
    $python = (Get-Command $PythonExecutable -ErrorAction Stop).Source
}
foreach ($candidate in @(
    @{ exe = 'py';      args = @('-3') },
    @{ exe = 'python';  args = @() },
    @{ exe = 'python3'; args = @() })) {
    if ($python) { break }
    if (-not (Get-Command $candidate.exe -ErrorAction SilentlyContinue)) { continue }
    $v = & $candidate.exe @($candidate.args + '--version') 2>&1 | Out-String
    if ($v -match 'Python (\d+)\.(\d+)' -and [int]$Matches[1] -eq 3 -and [int]$Matches[2] -ge 10) {
        $python = $candidate.exe; $pythonArgs = $candidate.args
        Say ("Using " + $v.Trim()) 'Green'; break
    }
}
if (-not $python) { Say "Python 3.10 or newer is required." 'Red'; exit 1 }

# --- build environment -----------------------------------------------------
$venv = Join-Path $root '.buildenv'
if ($Clean -and (Test-Path $venv)) {
    Say "Removing the old build environment"
    Remove-Item $venv -Recurse -Force
}
if (-not (Test-Path (Join-Path $venv 'Scripts\python.exe'))) {
    Say "Creating the build environment..."
    & $python @($pythonArgs + @('-m', 'venv', $venv))
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the build environment.' }
}
$venvPython = Join-Path $venv 'Scripts\python.exe'

Say "Installing build dependencies..."
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r (Join-Path $root 'requirements.txt') --quiet
if ($LASTEXITCODE -ne 0) { Say "Dependency install failed." 'Red'; exit 1 }
& $venvPython -m pip install pyinstaller --quiet
if ($LASTEXITCODE -ne 0) { Say "PyInstaller install failed." 'Red'; exit 1 }
if ($WithGps) { & $venvPython -m pip install pyserial --quiet; Say "GPS support included" }
if ($LASTEXITCODE -ne 0) { Say "Dependency install failed." 'Red'; exit 1 }

# --- version resource ------------------------------------------------------
$parts = ($currentVersion -split '[.-]')[0..2]
while ($parts.Count -lt 3) { $parts += '0' }
$fileVersion = "$($parts[0]), $($parts[1]), $($parts[2]), 0"
@"
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=($fileVersion), prodvers=($fileVersion),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([StringTable('040904B0', [
        StringStruct('CompanyName', 'wifirecon'),
        StringStruct('FileDescription', 'Passive wireless reconnaissance for Windows'),
        StringStruct('FileVersion', '$currentVersion'),
        StringStruct('InternalName', 'wifirecon'),
        StringStruct('OriginalFilename', 'wifirecon.exe'),
        StringStruct('ProductName', 'wifirecon'),
        StringStruct('ProductVersion', '$currentVersion')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"@ | Set-Content -Path (Join-Path $root 'version_info.txt') -Encoding UTF8

# --- clean previous output -------------------------------------------------
foreach ($dir in @('build', 'dist')) {
    $path = Join-Path $root $dir
    if (Test-Path $path) { Remove-Item $path -Recurse -Force }
}

# --- build -----------------------------------------------------------------
Say "`nRunning PyInstaller (this takes a minute or two)..." 'Cyan'
$pyiArgs = @('-m', 'PyInstaller', 'wifirecon.spec', '--noconfirm', '--clean')
if ($OneFile) { $pyiArgs += @('--', '--onefile') }
& $venvPython @pyiArgs
if ($LASTEXITCODE -ne 0) { Say "`nBuild failed." 'Red'; exit 1 }

$exe = if ($OneFile) { Join-Path $root 'dist\wifirecon.exe' }
       else { Join-Path $root 'dist\wifirecon\wifirecon.exe' }
if (-not (Test-Path $exe)) { Say "Expected output missing: $exe" 'Red'; exit 1 }

$sizeMb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Say "`nBuilt $exe ($sizeMb MB)" 'Green'

# --- smoke test ------------------------------------------------------------
if (-not $SkipTest) {
    $previousDataDir = $env:WIFIRECON_DATA_DIR
    $env:WIFIRECON_DATA_DIR = Join-Path $root 'build\smoke-data'
    try {
    Say "`nSmoke testing the binary..." 'Cyan'
    $reported = (& $exe --version 2>&1 | Out-String).Trim()
    if ($reported -ne $currentVersion) {
        Say "Version check failed: binary reports '$reported', expected '$currentVersion'" 'Red'
        exit 1
    }
    Say "  --version   $reported" 'Green'

    $scan = (& $exe --scan-once --mock 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $scan -notmatch 'Scanned \d+ networks') {
        Say "Scan test failed: $scan" 'Red'; exit 1
    }
    Say "  --scan-once $scan" 'Green'
    } finally {
        $env:WIFIRECON_DATA_DIR = $previousDataDir
    }
}

# --- checksums -------------------------------------------------------------
$hash = (Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLower()
$checksumFile = Join-Path (Split-Path $exe) 'SHA256SUMS.txt'
"$hash  $(Split-Path $exe -Leaf)" | Set-Content -Path $checksumFile -Encoding ASCII
Say "`nSHA-256  $hash"
Say "Written to $checksumFile"

if (-not $OneFile) {
    $zip = Join-Path $root "dist\wifirecon-$currentVersion-win64.zip"
    Compress-Archive -Path (Join-Path $root 'dist\wifirecon\*') -DestinationPath $zip -Force
    Say "Zipped to $zip" 'Green'
    $zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
    $checksumFile = Join-Path $root 'dist\SHA256SUMS.txt'
    "$zipHash  $(Split-Path $zip -Leaf)" | Set-Content -LiteralPath $checksumFile -Encoding ASCII
}

# --- release ---------------------------------------------------------------
if ($Release) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        Say "`nThe GitHub CLI (gh) is not installed, so the release was not published." 'Yellow'
        Say "Install it from https://cli.github.com/ or upload dist\ by hand."
        exit 1
    } else {
        $tag = "v$currentVersion"
        Say "`nPublishing release $tag..." 'Cyan'
        $releaseAsset = if ($OneFile) { $exe } else { $zip }
        $releaseHash = if ($OneFile) { $hash } else { $zipHash }
        $notes = "Automated build of wifirecon $currentVersion.`n`nSHA-256: $releaseHash"
        & gh release create $tag $releaseAsset $checksumFile --verify-tag --title $tag --notes $notes
        if ($LASTEXITCODE -eq 0) {
            Say "Published. Download and extract the complete folder package to update a folder install." 'Green'
        } else {
            Say "gh release failed. Upload dist\ manually." 'Yellow'
            exit 1
        }
    }
}

Say "`nDone.`n" 'Green'
$shipped = if ($OneFile) { '.\dist\wifirecon.exe' } else { '.\dist\wifirecon\wifirecon.exe' }
Say "Install it with:  $shipped --install"
Say "Or just run it:   $shipped"
if (-not $OneFile) {
    Say "To give it to someone, send them dist\wifirecon-$currentVersion-win64.zip"
}
Say ""
