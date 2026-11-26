<#
.SYNOPSIS
Universal installer for rship on Windows (x86_64).

.EXAMPLE
irm https://hua0512.github.io/rship/install.ps1 | iex
#>
[CmdletBinding()]
param(
  [string]$Version = $env:RSHIP_VERSION,
  [string]$InstallDir = $env:RSHIP_INSTALL_DIR,
  [switch]$NoVerify = ($env:RSHIP_NO_VERIFY -eq '1'),
  [switch]$NoModifyPath = ($env:RSHIP_NO_MODIFY_PATH -eq '1')
)

$ErrorActionPreference = 'Stop'

# Enable TLS 1.2 on older Windows PowerShell 5.1 hosts
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
  # Ignore if platform restricts manual protocol flags
}

$Repo = 'hua0512/rship'

function Write-Info([string]$Message) {
  Write-Host "[rship] $Message"
}

function Resolve-WindowsArch {
  $arch = $null
  try {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
  } catch {
    # Fallback for older .NET Framework runtimes
  }

  if (-not $arch) {
    if ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -or $env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
      $arch = 'X64'
    } else {
      $arch = $env:PROCESSOR_ARCHITECTURE
    }
  }

  switch ($arch.ToUpperInvariant()) {
    'X64' { return 'x86_64-pc-windows-msvc' }
    'AMD64' { return 'x86_64-pc-windows-msvc' }
    default {
      throw "Unsupported Windows architecture '$arch'. Prebuilt archives are published at https://github.com/$Repo/releases/latest"
    }
  }
}

function Resolve-LatestTag {
  try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{
      'User-Agent' = 'rship-installer'
      'Accept'     = 'application/vnd.github+json'
    }
    if ($release.tag_name) {
      return [string]$release.tag_name
    }
  } catch {
    # Fallback via redirect URL if GitHub API is rate-limited
  }

  $req = [System.Net.HttpWebRequest]::Create("https://github.com/$Repo/releases/latest")
  $req.Method = 'HEAD'
  $req.AllowAutoRedirect = $true
  $req.UserAgent = 'rship-installer'
  $resp = $req.GetResponse()
  try {
    $finalUri = $resp.ResponseUri.AbsolutePath
    $tag = ($finalUri.TrimEnd('/') -split '/')[-1]
    if ($tag -and $tag -ne 'latest') {
      return $tag
    }
  } finally {
    $resp.Close()
  }

  throw "Could not resolve latest release tag from https://github.com/$Repo/releases/latest"
}

$Target = Resolve-WindowsArch

if ([string]::IsNullOrWhiteSpace($Version)) {
  Write-Info 'Resolving latest release...'
  $Version = Resolve-LatestTag
} else {
  $trimmed = $Version.Trim()
  $Version = if ($trimmed.StartsWith('v')) { $trimmed } else { "v$trimmed" }
}

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
  $InstallDir = Join-Path $env:LOCALAPPDATA 'rship\bin'
}

$Stem = "rship-$Version-$Target"
$Archive = "$Stem.zip"
$BaseUrl = "https://github.com/$Repo/releases/download/$Version"

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("rship-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
  $ArchivePath = Join-Path $TempDir $Archive
  $ExtractDir = Join-Path $TempDir 'extract'

  Write-Info "Downloading $Archive..."
  Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile $ArchivePath -UseBasicParsing

  if (-not $NoVerify) {
    Write-Info 'Verifying SHA-256 checksum...'
    $SumsPath = Join-Path $TempDir 'SHA256SUMS.txt'
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $SumsPath -UseBasicParsing
    $SumsContent = Get-Content -Path $SumsPath -Raw
    $Match = [regex]::Match($SumsContent, '(?m)^([a-fA-F0-9]{64})\s+\*?' + [regex]::Escape($Archive) + '\r?$')
    if (-not $Match.Success) {
      throw "Checksum entry for $Archive not found in SHA256SUMS.txt"
    }
    $ExpectedSha = $Match.Groups[1].Value.ToLowerInvariant()
    $ActualSha = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualSha -ne $ExpectedSha) {
      throw "Checksum mismatch for $Archive (expected $ExpectedSha, got $ActualSha)"
    }
  }

  Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir -Force

  $SourceExe = Join-Path $ExtractDir "$Stem\rship.exe"
  if (-not (Test-Path $SourceExe)) {
    $Found = Get-ChildItem -Path $ExtractDir -Filter 'rship.exe' -Recurse | Select-Object -First 1
    if (-not $Found) {
      throw "rship.exe not found inside $Archive"
    }
    $SourceExe = $Found.FullName
  }

  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  $DestExe = Join-Path $InstallDir 'rship.exe'
  Copy-Item -Path $SourceExe -Destination $DestExe -Force

  if (-not $NoModifyPath) {
    $NormalizedInstallDir = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $PathEntries = if ($UserPath) { $UserPath -split ';' | Where-Object { $_.Trim() -ne '' } } else { @() }
    $AlreadyInPath = $false
    foreach ($entry in $PathEntries) {
      try {
        if ([System.IO.Path]::GetFullPath($entry.Trim()).TrimEnd('\').Equals($NormalizedInstallDir, [System.StringComparison]::OrdinalIgnoreCase)) {
          $AlreadyInPath = $true
          break
        }
      } catch {
        # Ignore malformed existing PATH entries
      }
    }

    if (-not $AlreadyInPath) {
      $NewUserPath = if ($UserPath) { "$($UserPath.TrimEnd(';'));$InstallDir" } else { $InstallDir }
      [Environment]::SetEnvironmentVariable('Path', $NewUserPath, 'User')
      Write-Info "Added $InstallDir to your user PATH (open a new terminal if needed)."
    }

    if (-not (($env:Path -split ';') -contains $InstallDir)) {
      $env:Path = "$InstallDir;$env:Path"
    }
  }

  $InstalledVer = (& $DestExe --version) -join ''
  Write-Info "Installed $InstalledVer to $DestExe"
} finally {
  if (Test-Path $TempDir) {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}
