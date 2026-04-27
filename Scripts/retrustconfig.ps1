#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Erstellt das TrustedConfig.cat im Programmverzeichnis neu und signiert es.

.BESCHREIBUNG
    Das Skript ist als Hilfsskript für den Release-/Betriebspfad gedacht.
    Es löscht das bestehende catalog\TrustedConfig.cat, erzeugt einen neuen
    File Catalog für den Ordner TrustedConfig und signiert die .cat-Datei.

    Optional wird am Ende geprüft, ob der Signer der .cat-Datei mit dem
    Signer der EXE im Programmverzeichnis übereinstimmt.

.HINWEIS
    Standardmäßig arbeitet das Skript relativ zu seinem eigenen Speicherort.
    Liegt es im Unterordner Scripts, verwendet es automatisch den übergeordneten
    Ordner als Programmverzeichnis. Liegt es direkt im Programmverzeichnis,
    verwendet es weiterhin diesen Ordner.

    Beispielstruktur:
      <ProgramDir>\
        IntuneSupportSuite.exe
        TrustedConfig\TrustedConfig.json
        catalog\TrustedConfig.cat
        Scripts\retrustconfig.ps1
#>

# =========================
# KONFIGURATION ANPASSEN
# =========================

# Standard: wenn das Skript im Unterordner "Scripts" liegt, ist das Programmverzeichnis der übergeordnete Ordner.
# Wenn es direkt neben der EXE liegt, bleibt das Programmverzeichnis der Ordner des Skripts.
$ProgramRoot = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "TrustedConfig")) {
    $PSScriptRoot
}
elseif ((Split-Path -Path $PSScriptRoot -Leaf) -ieq "Scripts" -and (Test-Path -LiteralPath (Join-Path (Split-Path -Path $PSScriptRoot -Parent) "TrustedConfig"))) {
    Split-Path -Path $PSScriptRoot -Parent
}
else {
    $PSScriptRoot
}

# Optional: EXE-Name für Signer-Vergleich am Ende
$ExeName = "IntuneSupportSuite.exe"

# Optional: expliziten Zertifikat-Thumbprint setzen.
# Leer lassen = erstes passendes CodeSigning-Zertifikat im gewählten Store verwenden.
$CertThumbprint = ""

# Zertifikatsspeicher: CurrentUser oder LocalMachine
$CertStoreLocation = "CurrentUser"

# Timestamp-Server
$TimestampServer = "http://timestamp.digicert.com"

# Falls SignTool.exe nicht im PATH ist, hier fest eintragen.
# Sonst leer lassen.
$SignToolOverride = ""

# =========================
# ABGELEITETE PFADE
# =========================

$TrustedConfigDir  = Join-Path $ProgramRoot "TrustedConfig"
$TrustedConfigJson = Join-Path $TrustedConfigDir "TrustedConfig.json"

$CatalogDir        = Join-Path $ProgramRoot "catalog"
$CatalogFile       = Join-Path $CatalogDir "TrustedConfig.cat"

$ExePath           = Join-Path $ProgramRoot $ExeName

# =========================
# HILFSFUNKTIONEN
# =========================

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Ensure-PathExists {
    param([string]$Path, [string]$Description)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Description nicht gefunden: $Path"
    }
}

function Get-CodeSigningCertificate {
    param(
        [string]$Thumbprint,
        [ValidateSet('CurrentUser','LocalMachine')]
        [string]$StoreLocation = 'CurrentUser'
    )

    $storePath = "Cert:\$StoreLocation\My"

    if ($Thumbprint) {
        $normalized = ($Thumbprint -replace '\s','').ToUpperInvariant()
        $cert = Get-ChildItem -Path $storePath | Where-Object {
            $_.Thumbprint.ToUpperInvariant() -eq $normalized
        } | Select-Object -First 1

        if (-not $cert) {
            throw "Kein Zertifikat mit Thumbprint $normalized im Store $storePath gefunden."
        }

        if (-not $cert.HasPrivateKey) {
            throw "Das Zertifikat $normalized hat keinen privaten Schlüssel."
        }

        return $cert
    }

    $candidates = Get-ChildItem -Path $storePath -CodeSigningCert |
        Where-Object { $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending

    if (-not $candidates) {
        throw "Kein CodeSigning-Zertifikat mit privatem Schlüssel im Store $storePath gefunden."
    }

    return $candidates[0]
}

function Get-SignToolPath {
    param([string]$OverridePath)

    if ($OverridePath) {
        Ensure-PathExists -Path $OverridePath -Description "SignTool"
        return $OverridePath
    }

    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    ) | Where-Object { $_ -and (Test-Path $_) }

    $candidates = foreach ($root in $roots) {
        Get-ChildItem -Path $root -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue
    }

    $best = $candidates |
        Sort-Object FullName -Descending |
        Select-Object -First 1

    if (-not $best) {
        throw "SignTool.exe wurde nicht gefunden. Installiere das Windows SDK oder setze `$SignToolOverride."
    }

    return $best.FullName
}

function Get-NormalizedThumbprint {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    return ($Certificate.Thumbprint -replace '\s','').ToUpperInvariant()
}

function Get-PublicKeyHex {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    return ([System.BitConverter]::ToString($Certificate.PublicKey.EncodedKeyValue.RawData)).Replace("-","")
}

function Get-SignatureInfo {
    param([string]$Path)

    Ensure-PathExists -Path $Path -Description "Datei"

    $sig = Get-AuthenticodeSignature -FilePath $Path
    [pscustomobject]@{
        Path          = $Path
        Status        = $sig.Status
        StatusMessage = $sig.StatusMessage
        Thumbprint    = if ($sig.SignerCertificate) { Get-NormalizedThumbprint $sig.SignerCertificate } else { $null }
        PublicKeyHex  = if ($sig.SignerCertificate) { Get-PublicKeyHex $sig.SignerCertificate } else { $null }
        Subject       = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
    }
}

function Compare-SignerEquality {
    param(
        [string]$PathA,
        [string]$PathB
    )

    $a = Get-SignatureInfo -Path $PathA
    $b = Get-SignatureInfo -Path $PathB

    if ($a.Status -ne 'Valid') {
        throw "Signatur von '$PathA' ist nicht gültig. Status: $($a.Status) / $($a.StatusMessage)"
    }

    if ($b.Status -ne 'Valid') {
        throw "Signatur von '$PathB' ist nicht gültig. Status: $($b.Status) / $($b.StatusMessage)"
    }

    if ($a.Thumbprint -ne $b.Thumbprint -or $a.PublicKeyHex -ne $b.PublicKeyHex) {
        throw @"
Signer stimmt nicht überein.
A: $PathA
   Thumbprint: $($a.Thumbprint)
   Subject   : $($a.Subject)

B: $PathB
   Thumbprint: $($b.Thumbprint)
   Subject   : $($b.Subject)
"@
    }

    Write-Host "Signer identisch:" -ForegroundColor Green
    Write-Host "  A: $PathA"
    Write-Host "  B: $PathB"
    Write-Host "  Thumbprint: $($a.Thumbprint)"
}

function Sign-BinaryWithSignTool {
    param(
        [string]$Path,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$TimestampUrl,
        [string]$SignToolPath,
        [ValidateSet('CurrentUser','LocalMachine')]
        [string]$StoreLocation = 'CurrentUser'
    )

    $certThumb = Get-NormalizedThumbprint $Certificate

    Write-Host "Signiere CAT: $Path" -ForegroundColor Yellow

    $args = @(
        'sign',
        '/fd', 'SHA256',
        '/td', 'SHA256',
        '/tr', $TimestampUrl,
        '/sha1', $certThumb
    )

    if ($StoreLocation -eq 'LocalMachine') {
        $args += '/sm'
    }

    $args += $Path

    & $SignToolPath @args
    if ($LASTEXITCODE -ne 0) {
        throw "SignTool-Signierung fehlgeschlagen ($LASTEXITCODE): $Path"
    }

    $check = Get-AuthenticodeSignature -FilePath $Path
    if ($check.Status -ne 'Valid') {
        throw "Datei nach SignTool-Signierung nicht gültig signiert: $Path / Status: $($check.Status)"
    }
}

function New-SignedCatalogForTrustedConfigFolder {
    param(
        [string]$TrustedConfigFolder,
        [string]$TrustedConfigJson,
        [string]$CatalogFile,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$TimestampUrl,
        [string]$SignToolPath,
        [ValidateSet('CurrentUser','LocalMachine')]
        [string]$StoreLocation = 'CurrentUser'
    )

    Ensure-PathExists -Path $TrustedConfigFolder -Description "TrustedConfig-Ordner"
    Ensure-PathExists -Path $TrustedConfigJson -Description "TrustedConfig.json"

    $catalogDir = Split-Path -Path $CatalogFile -Parent
    if (-not (Test-Path -LiteralPath $catalogDir)) {
        New-Item -ItemType Directory -Path $catalogDir -Force | Out-Null
    }

    if (Test-Path -LiteralPath $CatalogFile) {
        Write-Host "Lösche bestehendes Catalog: $CatalogFile" -ForegroundColor Yellow
        Remove-Item -LiteralPath $CatalogFile -Force
    }

    Write-Host "Erzeuge neues Catalog für Ordner: $TrustedConfigFolder" -ForegroundColor Yellow
    New-FileCatalog -Path $TrustedConfigFolder -CatalogFilePath $CatalogFile -CatalogVersion 2.0 | Out-Null

    Sign-BinaryWithSignTool -Path $CatalogFile -Certificate $Certificate -TimestampUrl $TimestampUrl -SignToolPath $SignToolPath -StoreLocation $StoreLocation
}

function Verify-CatalogMatchesTrustedConfigFolder {
    param(
        [string]$TrustedConfigFolder,
        [string]$CatalogFile
    )

    Ensure-PathExists -Path $TrustedConfigFolder -Description "TrustedConfig-Ordner"
    Ensure-PathExists -Path $CatalogFile -Description "Catalog-Datei"

    Write-Host "Prüfe Catalog gegen TrustedConfig-Ordner ..." -ForegroundColor Yellow
    $result = Test-FileCatalog -CatalogFilePath $CatalogFile -Path $TrustedConfigFolder -Detailed

    if ($result.Status -ne 'Valid') {
        $catalogItems = @()
        $pathItems = @()

        if ($result.CatalogItems) { $catalogItems = @($result.CatalogItems) }
        if ($result.PathItems)    { $pathItems = @($result.PathItems) }

        throw "Catalog-Prüfung fehlgeschlagen. Status=$($result.Status); CatalogItems=$($catalogItems -join ','); PathItems=$($pathItems -join ',')"
    }

    $hasTrustedConfig = $false
    if ($result.CatalogItems -and (@($result.CatalogItems) -contains 'TrustedConfig.json')) {
        $hasTrustedConfig = $true
    }

    if (-not $hasTrustedConfig) {
        throw "Catalog enthält TrustedConfig.json nicht."
    }

    Write-Host "Catalog passt zum TrustedConfig-Ordner." -ForegroundColor Green
}

# =========================
# AUSFÜHRUNG
# =========================

Write-Step "Vorbereitung"
Ensure-PathExists -Path $ProgramRoot -Description "Programmverzeichnis"
Ensure-PathExists -Path $TrustedConfigDir -Description "TrustedConfig-Ordner"
Ensure-PathExists -Path $TrustedConfigJson -Description "TrustedConfig.json"

$cert = Get-CodeSigningCertificate -Thumbprint $CertThumbprint -StoreLocation $CertStoreLocation
$signTool = Get-SignToolPath -OverridePath $SignToolOverride

Write-Host "Programmverzeichnis:" -ForegroundColor Green
Write-Host "  $ProgramRoot"

Write-Host "Verwendetes Zertifikat:" -ForegroundColor Green
Write-Host "  Subject    : $($cert.Subject)"
Write-Host "  Thumbprint : $(Get-NormalizedThumbprint $cert)"
Write-Host "  Store      : Cert:\$CertStoreLocation\My"

Write-Host "Verwendetes SignTool:" -ForegroundColor Green
Write-Host "  $signTool"

Write-Step "TrustedConfig Catalog neu erzeugen"
New-SignedCatalogForTrustedConfigFolder `
    -TrustedConfigFolder $TrustedConfigDir `
    -TrustedConfigJson $TrustedConfigJson `
    -CatalogFile $CatalogFile `
    -Certificate $cert `
    -TimestampUrl $TimestampServer `
    -SignToolPath $signTool `
    -StoreLocation $CertStoreLocation

Write-Step "Catalog prüfen"
Verify-CatalogMatchesTrustedConfigFolder `
    -TrustedConfigFolder $TrustedConfigDir `
    -CatalogFile $CatalogFile

Write-Step "Optionaler Signer-Vergleich mit EXE"
if (Test-Path -LiteralPath $ExePath) {
    Compare-SignerEquality -PathA $ExePath -PathB $CatalogFile
}
else {
    Write-Warning "EXE nicht gefunden. Signer-Vergleich übersprungen: $ExePath"
}

Write-Step "Fertig"
Write-Host "TrustedConfig.cat wurde erfolgreich neu erzeugt und signiert." -ForegroundColor Green
Write-Host "TrustedConfig.json : $TrustedConfigJson" -ForegroundColor Green
Write-Host "Catalog-Datei      : $CatalogFile" -ForegroundColor Green
