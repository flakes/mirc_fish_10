[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$PackageUrl = 'https://download.firedaemon.com/FireDaemon-OpenSSL/openssl-3.5.9.zip',
    [string]$Sha256 = '76DA391395BE029B44794857B9FF380255E02A0960A98314CD3F6A6816D82696',
    [ValidateSet('x86')]
    [string]$Platform = 'x86',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = Split-Path -Parent $scriptDir
$libDir = Join-Path $repoRoot 'lib'
$includeDir = Join-Path $repoRoot 'include'
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'mirc_fish_10'
$archiveName = [System.IO.Path]::GetFileName([Uri]$PackageUrl)
$archivePath = Join-Path $tempRoot $archiveName
$extractRoot = Join-Path $tempRoot ([System.IO.Path]::GetFileNameWithoutExtension($archiveName))

function Get-PlatformRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SearchRoot,
        [Parameter(Mandatory = $true)]
        [string]$PlatformName
    )

    $candidate = Get-ChildItem -LiteralPath $SearchRoot -Directory -Recurse |
        Where-Object { $_.Name -eq $PlatformName } |
        Select-Object -First 1

    if (-not $candidate) {
        throw "Could not find platform directory '$PlatformName' under $SearchRoot."
    }

    return $candidate.FullName
}

function Copy-Tree {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        throw "Missing source path: $Source"
    }

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    Get-ChildItem -LiteralPath $Source -Recurse -File | ForEach-Object {
        $relativePath = $_.FullName.Substring($Source.Length).TrimStart('\')
        $targetPath = Join-Path $Destination $relativePath
        $targetDir = Split-Path -Parent $targetPath

        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $targetPath -Force
    }
}

function Copy-FilesFlat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Filter,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        throw "Missing source path: $Source"
    }

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    Get-ChildItem -LiteralPath $Source -File -Filter $Filter | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name) -Force
    }
}

function Copy-OptionalFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }

    $targetDir = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

if ($Force -and (Test-Path -LiteralPath $archivePath)) {
    Remove-Item -LiteralPath $archivePath -Force
}

if ($Force -and (Test-Path -LiteralPath $extractRoot)) {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

if (-not (Test-Path -LiteralPath $archivePath)) {
    if ($PSCmdlet.ShouldProcess($PackageUrl, "Download OpenSSL archive to $archivePath")) {
        Invoke-WebRequest -Uri $PackageUrl -OutFile $archivePath
    }
}

if (-not (Test-Path -LiteralPath $archivePath)) {
    Write-Host "OpenSSL archive not present at $archivePath."
    Write-Host 'No changes were applied.'
    return
}

$actualSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
if ($actualSha256 -ne $Sha256) {
    throw "SHA-256 mismatch for $archiveName. Expected $Sha256 but got $actualSha256."
}

if (-not (Test-Path -LiteralPath $extractRoot)) {
    if ($PSCmdlet.ShouldProcess($archivePath, "Extract archive to $extractRoot")) {
        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot -Force
    }
}

$platformRoot = Get-PlatformRoot -SearchRoot $extractRoot -PlatformName $Platform
$binSource = Join-Path $platformRoot 'bin'
$libSource = Join-Path $platformRoot 'lib'
$includeSource = Join-Path $platformRoot 'include'
$legacyModuleSource = Join-Path $libSource 'ossl-modules\legacy.dll'
$legacyModuleDestination = Join-Path $libDir 'libcrypto-legacy.dll'

if ($PSCmdlet.ShouldProcess($repoRoot, 'Populate lib and include folders with OpenSSL artifacts')) {
    Copy-FilesFlat -Source $binSource -Filter '*.dll' -Destination $libDir
    Copy-FilesFlat -Source $libSource -Filter '*.lib' -Destination $libDir
    Copy-OptionalFile -Source $legacyModuleSource -Destination $legacyModuleDestination
    Copy-Tree -Source $includeSource -Destination $includeDir
}

Write-Host "OpenSSL bootstrap completed."
Write-Host "  Package : $archiveName"
Write-Host "  SHA-256 : $actualSha256"
Write-Host "  DLLs    : $libDir"
Write-Host "  LIBs    : $libDir"
Write-Host "  Headers : $includeDir"
