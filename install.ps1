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

.PARAMETER Only
  Directory name(s) of specific plugin(s) to build/install (e.g.
  "xxhash-utility"), instead of all of them. Useful when other plugins
  have in-progress edits you don't want to rebuild yet.
#>

[CmdletBinding()]
param(
  [string]$IdaSdk = $(if ($env:IDASDK) { $env:IDASDK } else { "C:\Users\Ben\ida-sdk-src" }),
  [string]$IdaInstallDir,
  # Comma-separated list (e.g. "stl-utility,xxhash-utility"), not string[] --
  # when this script re-launches itself elevated via `-File`, PowerShell
  # does NOT apply its interactive "a,b splits into an array" parsing to
  # passed-through arguments (that only happens for arguments typed directly
  # in a PowerShell expression, not raw argv passed via -File), so a
  # string[] parameter arrives as a single unsplit string anyway -- a plain
  # string split manually below avoids that mismatch entirely.
  [string]$Only
)

$ErrorActionPreference = "Stop"

# --- Self-elevate (UAC prompt) if not already running as Administrator ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
  [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Host "Elevation required to install into Program Files -- relaunching with UAC prompt..."
  $scriptArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
  foreach ($key in $PSBoundParameters.Keys) {
    $value = $PSBoundParameters[$key]
    $scriptArgs += "-$key"
    if ($value -is [array]) {
      # Comma-join (not space-join, which is PowerShell's default array
      # ToString() and gets mis-split back into separate positional tokens
      # by the child process's command-line parsing) so string[] params
      # round-trip correctly through the elevated relaunch.
      $scriptArgs += ($value -join ",")
    } else {
      $scriptArgs += "$value"
    }
  }
  Start-Process powershell -Verb RunAs -ArgumentList $scriptArgs
  exit
}

$repoRoot = $PSScriptRoot

# --- Log everything to a file so results are inspectable even if this
#     elevated window closes/crashes before anyone reads it interactively. ---
$logPath = Join-Path $repoRoot "install.log"
$transcribing = $false
try {
  Start-Transcript -Path $logPath -Append -ErrorAction Stop | Out-Null
  $transcribing = $true
} catch {
  Write-Warning "Could not start transcript logging to $logPath -- continuing without it: $_"
}

try {
  Write-Host ""
  Write-Host "===== install.ps1 run started: $(Get-Date -Format o) =====" -ForegroundColor DarkGray

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
    @{ Dir = "crt-idioms-utility"; Target = "crt_idioms_collapse" }
    @{ Dir = "sm-lua-func-finder"; Target = "sm_lua_func_finder" }
  )

  if ($Only) {
    $onlyList = $Only.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $plugins = $plugins | Where-Object { $onlyList -contains $_.Dir }
    if (-not $plugins) {
      throw "No plugins matched -Only $($onlyList -join ', ')"
    }
  }

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
  $results | Format-Table -AutoSize | Out-String | Write-Host

  Write-Host ""
  Write-Host "Restart IDA (if running) to pick up the installed/updated plugins."
  Write-Host "===== install.ps1 run finished: $(Get-Date -Format o) =====" -ForegroundColor DarkGray
}
catch {
  # Catch-all so a top-level/unexpected exception still gets written to the
  # log before the window (and transcript) closes, instead of vanishing.
  Write-Host ""
  Write-Host "===== UNHANDLED ERROR =====" -ForegroundColor Red
  Write-Host "$_" -ForegroundColor Red
  Write-Host ($_.ScriptStackTrace) -ForegroundColor Red
  Write-Host "===== install.ps1 run FAILED: $(Get-Date -Format o) =====" -ForegroundColor DarkGray
}
finally {
  if ($transcribing) {
    try { Stop-Transcript | Out-Null } catch {}
  }
}

Read-Host "Press Enter to close"
