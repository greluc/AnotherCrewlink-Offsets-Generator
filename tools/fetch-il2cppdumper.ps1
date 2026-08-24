<#
.SYNOPSIS
  Downloads the Il2CppDumper release pinned in tools.lock.json and verifies it.

.DESCRIPTION
  This is the only part of the project that touches the network. It is a script,
  not Rust code, on purpose: keeping HTTP, TLS and zip out of the generator's
  dependency tree removes the largest block of third-party code from the build,
  and leaves the one network operation we do need in ~100 reviewable lines.

  The archive digest is checked before extraction and each extracted binary is
  checked afterwards. Any mismatch aborts and leaves nothing behind.

.PARAMETER Update
  Download, print the observed digests, and stop without installing. Use this
  when moving to a new upstream release: review the numbers, then paste them
  into tools.lock.json by hand and re-run without -Update.

.EXAMPLE
  pwsh tools/fetch-il2cppdumper.ps1
#>
[CmdletBinding()]
param(
    [switch]$Update
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$lockPath = Join-Path $repoRoot 'tools.lock.json'
$installDir = Join-Path $PSScriptRoot 'il2cppdumper'

if (-not (Test-Path $lockPath)) {
    throw "tools.lock.json not found at $lockPath"
}

$lock = (Get-Content -Raw -Path $lockPath | ConvertFrom-Json).il2cppdumper
$archive = $lock.archive

Write-Host "Il2CppDumper $($lock.tag) ($($archive.asset), $([math]::Round($archive.size/1MB,1)) MB)"
Write-Host "  from $($archive.url)"

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("acl-offsetgen-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging | Out-Null

try {
    $zipPath = Join-Path $staging $archive.asset

    # TLS 1.2 is the floor; older PowerShell hosts still default lower.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    Invoke-WebRequest -Uri $archive.url -OutFile $zipPath -MaximumRedirection 5 -UseBasicParsing

    $actualSize = (Get-Item $zipPath).Length
    $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($Update) {
        Write-Host ''
        Write-Host 'Observed values -- review these against the upstream release page,'
        Write-Host 'then paste them into tools.lock.json:'
        Write-Host ("  size:   {0}" -f $actualSize)
        Write-Host ("  sha256: {0}" -f $actualHash)
        Write-Host ''
        $probe = Join-Path $staging 'probe'
        Expand-Archive -Path $zipPath -DestinationPath $probe -Force
        Get-ChildItem -Path $probe -Filter '*.exe' | ForEach-Object {
            $h = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            Write-Host ("  {0}: size {1}, sha256 {2}" -f $_.Name, $_.Length, $h)
        }
        return
    }

    if ($actualSize -ne $archive.size) {
        throw "size mismatch: expected $($archive.size) bytes, got $actualSize. Refusing to install."
    }
    if ($actualHash -ne $archive.sha256.ToLowerInvariant()) {
        throw "SHA-256 mismatch.`n  expected $($archive.sha256)`n  actual   $actualHash`nRefusing to install."
    }
    Write-Host '  archive digest ok'

    $extracted = Join-Path $staging 'extracted'
    Expand-Archive -Path $zipPath -DestinationPath $extracted -Force

    foreach ($binary in $lock.binaries) {
        $binPath = Join-Path $extracted $binary.path
        if (-not (Test-Path $binPath)) {
            throw "archive does not contain $($binary.path)"
        }
        $binSize = (Get-Item $binPath).Length
        $binHash = (Get-FileHash -Path $binPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($binSize -ne $binary.size -or $binHash -ne $binary.sha256.ToLowerInvariant()) {
            throw "digest mismatch for $($binary.path).`n  expected $($binary.sha256) ($($binary.size) bytes)`n  actual   $binHash ($binSize bytes)"
        }
        Write-Host "  $($binary.path) digest ok"
    }

    if (Test-Path $installDir) {
        Remove-Item -Recurse -Force $installDir
    }
    New-Item -ItemType Directory -Path $installDir | Out-Null
    Copy-Item -Path (Join-Path $extracted '*') -Destination $installDir -Recurse -Force

    # The dumper reads config.json from its own directory. The shipped one sets
    # RequireAnyKey, which would block forever with no console, and turns on the
    # dummy-DLL export we never read. acl-offsetgen rewrites this before each run
    # anyway; writing it here means a manual dumper run behaves the same.
    $config = [ordered]@{
        DumpMethod          = $true
        DumpField           = $true
        DumpProperty        = $true
        DumpAttribute       = $false
        DumpFieldOffset     = $true
        DumpMethodOffset    = $true
        DumpTypeDefIndex    = $true
        GenerateDummyDll    = $false
        GenerateStruct      = $true
        DummyDllAddToken    = $false
        RequireAnyKey       = $false
        ForceIl2CppVersion  = $false
        ForceVersion        = 16
        ForceDump           = $false
        NoRedirectedPointer = $false
    }
    $config | ConvertTo-Json | Set-Content -Path (Join-Path $installDir 'config.json') -Encoding utf8

    Write-Host "Installed to $installDir"
}
finally {
    if (Test-Path $staging) {
        Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
    }
}
