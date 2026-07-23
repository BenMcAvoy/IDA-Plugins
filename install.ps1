<#
.SYNOPSIS
  Builds every plugin in this repo and installs it into the local IDA
  Professional installation's plugins directory.

.DESCRIPTION
  Configures + builds each plugin with CMake (Release, x64), then copies
  the built DLL and ida-plugin.json into
  "<IDA install dir>\plugins\<target>\". Copying into the IDA install
  directory (under Program Files) requires administrator rights, so this
  script re-launches itself elevated (a UAC prompt) if it isn't already
  running as Administrator -- the whole build+install runs in that
  elevated process.

.PARAMETER IdaSdk
  Path to a HexRaysSA/ida-sdk checkout (a tag with CMake support, e.g.
  v9.3.1-release -- not the classic hex-rays SDK zip). Defaults to the
  IDASDK environment variable, or C:\Users\Ben\ida-sdk-src if that's unset.

.PARAMETER IdaInstallDir
  IDA installation directory to install into. If omitted, the newest
  "C:\Program Files\IDA Professional *" / "IDA Pro *" / "IDA *" directory
  is auto-detected, matching each plugin's own CMakeLists.txt logic.
#>

[CmdletBinding()]
param(
  [string]$IdaSdk = $(if ($env:IDASDK) { $env:IDASDK } else { "C:\Users\Ben\ida-sdk-src" }),
  [string]$IdaInstallDir
)

$ErrorActionPreference = "Stop"

# --- Self-elevate (UAC prompt) if not already running as Administrator ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
  [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Host "Elevation required to install into Program Files -- relaunching with UAC prompt..."
  $scriptArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
  foreach ($key in $PSBoundParameters.Keys) {
    $scriptArgs += "-$key"
    $scriptArgs += "$($PSBoundParameters[$key])"
  }
  Start-Process powershell -Verb RunAs -ArgumentList $scriptArgs
  exit
}

$repoRoot = $PSScriptRoot

if (-not (Test-Path (Join-Path $IdaSdk "src\cmake\bootstrap.cmake"))) {
  throw "IDASDK ('$IdaSdk') doesn't look like a CMake-enabled ida-sdk checkout (missing src\cmake\bootstrap.cmake). See each plugin's README for setup."
}
$env:IDASDK = $IdaSdk
Write-Host "Using IDASDK: $IdaSdk"

if (-not $IdaInstallDir) {
  $candidates = Get-ChildItem "C:\Program Files" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "IDA Professional *" -or $_.Name -like "IDA Pro *" -or $_.Name -like "IDA *" } |
    Sort-Object Name -Descending
  if (-not $candidates) {
    throw "No IDA installation found under C:\Program Files. Pass -IdaInstallDir explicitly."
  }
  $IdaInstallDir = $candidates[0].FullName
}
Write-Host "Installing into: $IdaInstallDir"

$plugins = @(
  @{ Dir = "vtable-utility";   Target = "pseudocode_xrefs" }
  @{ Dir = "stl-utility";      Target = "stl_retype" }
  @{ Dir = "xxhash-utility";   Target = "xxhash_collapse" }
  @{ Dir = "sm-global-finder"; Target = "sm_global_finder" }
)

$results = @()

foreach ($plugin in $plugins) {
  $pluginDir = Join-Path $repoRoot $plugin.Dir
  $buildDir = Join-Path $pluginDir "build"
  $target = $plugin.Target

  Write-Host ""
  Write-Host "=== $($plugin.Dir) ($target) ===" -ForegroundColor Cyan

  if (-not (Test-Path $pluginDir)) {
    Write-Warning "Skipping $($plugin.Dir): directory not found."
    $results += [pscustomobject]@{ Plugin = $plugin.Dir; Status = "missing directory" }
    continue
  }

  try {
    & cmake -S $pluginDir -B $buildDir -G "Visual Studio 17 2022" -A x64
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed (exit $LASTEXITCODE)" }

    & cmake --build $buildDir --config Release
    if ($LASTEXITCODE -ne 0) { throw "cmake build failed (exit $LASTEXITCODE)" }

    $builtDll = Join-Path $IdaSdk "src\bin\plugins\$target\$target.dll"
    $builtJson = Join-Path $IdaSdk "src\bin\plugins\$target\ida-plugin.json"
    if (-not (Test-Path $builtDll)) {
      throw "Built DLL not found at expected path: $builtDll"
    }

    $destDir = Join-Path $IdaInstallDir "plugins\$target"
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    Copy-Item $builtDll $destDir -Force
    if (Test-Path $builtJson) {
      Copy-Item $builtJson $destDir -Force
    }

    Write-Host "Installed $target -> $destDir" -ForegroundColor Green
    $results += [pscustomobject]@{ Plugin = $plugin.Dir; Status = "installed" }
  }
  catch {
    Write-Warning "Failed to build/install $($plugin.Dir): $_"
    $results += [pscustomobject]@{ Plugin = $plugin.Dir; Status = "FAILED: $_" }
  }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

Write-Host ""
Write-Host "Restart IDA (if running) to pick up the installed/updated plugins."
Read-Host "Press Enter to close"
