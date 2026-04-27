#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =========================
# custompacker.ps1
# Externes Build-/Release-Hilfsskript für DAP Intune Support Suite
# =========================
# Zweck:
# - PS1-Quellscripte signieren
# - dotnet publish ausführen
# - Release-Artefakte in RID-Root und publish konsistent bereitstellen
# - EXE im RID-Root und im publish signieren
# - Catalog für TrustedConfig.json im RID-Root und im publish erzeugen + signieren
# - Signer-Gleichheit zwischen EXE und Catalog prüfen
#
# Wichtige Realität:
# - Dieses Skript ist ein externes Hilfsmittel. Es ändert nicht die App-Logik.
# - v0.8.1 prüft in der App noch direkt auf TrustedConfig.json. Das ist getrennt von diesem Pack-Skript.
# =========================

# =========================
# KONFIGURATION ANPASSEN
# =========================

# Projektwurzel (Ordner mit .csproj)
$ProjectRoot = "Path to Project with csproj in it"

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

# Build-/Publish-Parameter
# ReleaseName steuert den Ordner unter \bin\ sowie standardmäßig auch den Wert für dotnet -c.
# Beispiel: "Release", "Release-v0.8.1", "Release-hotfix"
# Wichtige Realität: Ein eigener Name für -c ist ein eigener MSBuild-Configuration-Wert.
# Wenn dein .csproj/Build explizit nur auf "Release" konditionierte Einstellungen hat,
# müssen diese ggf. zusätzlich auf den neuen Namen erweitert werden.
$ReleaseName       = "Release"
$DotnetConfiguration = $ReleaseName
$TargetFramework   = "net8.0-windows"
$RuntimeIdentifier = "win-x64"
$AssemblyName      = "IntuneSupportSuite"

# Optional: Publish-Ausgabe vor dem Publish löschen
$CleanPublishOutput = $true

# Standardmäßig Build-Artefakte und IDE-Ordner auslassen
$ExcludeDirectories = @(
    "bin",
    "obj",
    ".vs",
    ".git"
)

# =========================
# ABGELEITETE PFADE
# =========================

$ProjectFile = Join-Path $ProjectRoot "$AssemblyName.csproj"

$SourceConfigDir         = Join-Path $ProjectRoot "Config"
$SourceConfigJson        = Join-Path $SourceConfigDir "config.json"
$SourceScriptsDir        = Join-Path $ProjectRoot "Scripts"
$SourceTrustedConfigDir  = Join-Path $ProjectRoot "TrustedConfig"
$SourceTrustedConfigJson = Join-Path $SourceTrustedConfigDir "TrustedConfig.json"
$SourceCatalogDir        = Join-Path $ProjectRoot "catalog"
$SourceCatalogFile       = Join-Path $SourceCatalogDir "TrustedConfig.cat"

$RidRoot                 = Join-Path $ProjectRoot ("bin\{0}\{1}\{2}" -f $ReleaseName, $TargetFramework, $RuntimeIdentifier)
$PublishDir              = Join-Path $RidRoot "publish"

$RidRootExe              = Join-Path $RidRoot "$AssemblyName.exe"
$PublishExe              = Join-Path $PublishDir "$AssemblyName.exe"

$RidRootConfigDir         = Join-Path $RidRoot "Config"
$RidRootConfigJson        = Join-Path $RidRootConfigDir "config.json"
$RidRootScriptsDir        = Join-Path $RidRoot "Scripts"
$RidRootTrustedConfigDir  = Join-Path $RidRoot "TrustedConfig"
$RidRootTrustedConfigJson = Join-Path $RidRootTrustedConfigDir "TrustedConfig.json"
$RidRootCatalogDir        = Join-Path $RidRoot "catalog"
$RidRootCatalogFile       = Join-Path $RidRootCatalogDir "TrustedConfig.cat"

$PublishConfigDir         = Join-Path $PublishDir "Config"
$PublishConfigJson        = Join-Path $PublishConfigDir "config.json"
$PublishScriptsDir        = Join-Path $PublishDir "Scripts"
$PublishTrustedConfigDir  = Join-Path $PublishDir "TrustedConfig"
$PublishTrustedConfigJson = Join-Path $PublishTrustedConfigDir "TrustedConfig.json"
$PublishCatalogDir        = Join-Path $PublishDir "catalog"
$PublishCatalogFile       = Join-Path $PublishCatalogDir "TrustedConfig.cat"

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

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Assert-SafePathSegment {
    param(
        [string]$Value,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name darf nicht leer sein."
    }

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($char in $invalidChars) {
        if ($Value.Contains([string]$char)) {
            throw "$Name enthält ungültige Zeichen: '$char'"
        }
    }
}

function Ensure-DotnetAvailable {
    $cmd = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "dotnet wurde nicht gefunden. Installiere das .NET SDK oder stelle sicher, dass dotnet.exe im PATH liegt."
    }
    return $cmd.Source
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

function Sign-ScriptFile {
    param(
        [string]$Path,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$TimestampUrl
    )

    $existing = Get-AuthenticodeSignature -FilePath $Path
    $certThumb = Get-NormalizedThumbprint $Certificate

    $needsSigning = $true
    if ($existing.Status -eq 'Valid' -and $existing.SignerCertificate) {
        $existingThumb = Get-NormalizedThumbprint $existing.SignerCertificate
        if ($existingThumb -eq $certThumb) {
            $needsSigning = $false
        }
    }

    if (-not $needsSigning) {
        Write-Host "PS1 bereits gültig signiert: $Path" -ForegroundColor Green
        return
    }

    Write-Host "Signiere PS1: $Path" -ForegroundColor Yellow
    $result = Set-AuthenticodeSignature -FilePath $Path -Certificate $Certificate -TimestampServer $TimestampUrl

    if ($result.Status -ne 'Valid') {
        throw "Signieren von PS1 fehlgeschlagen: $Path / Status: $($result.Status)"
    }
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

    $existing = Get-AuthenticodeSignature -FilePath $Path
    $certThumb = Get-NormalizedThumbprint $Certificate

    $needsSigning = $true
    if ($existing.Status -eq 'Valid' -and $existing.SignerCertificate) {
        $existingThumb = Get-NormalizedThumbprint $existing.SignerCertificate
        if ($existingThumb -eq $certThumb) {
            $needsSigning = $false
        }
    }

    if (-not $needsSigning) {
        Write-Host "BIN/CAT bereits gültig signiert: $Path" -ForegroundColor Green
        return
    }

    Write-Host "Signiere BIN/CAT: $Path" -ForegroundColor Yellow

    $args = @(
        'sign',
        '/fd', 'SHA256',
        '/td', 'SHA256',
        '/tr', $TimestampUrl,
        '/s', 'My',
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

function Get-FilesToSign {
    param(
        [string]$RootPath,
        [string[]]$Extensions,
        [string[]]$ExcludedDirectoryNames
    )

    Ensure-PathExists -Path $RootPath -Description "Ordner"

    $normalizedExtensions = @(
        $Extensions | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLowerInvariant() }
    )

    $normalizedExcludedDirectoryNames = @(
        $ExcludedDirectoryNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() }
    )

    Get-ChildItem -Path $RootPath -Recurse -File | Where-Object {
        $file = $_

        if ($file.Extension.ToLowerInvariant() -notin $normalizedExtensions) {
            return $false
        }

        if (-not $normalizedExcludedDirectoryNames -or $normalizedExcludedDirectoryNames.Count -eq 0) {
            return $true
        }

        $directorySegments = @()
        if ($file.DirectoryName) {
            $directorySegments = $file.DirectoryName -split '[\/]'
        }

        foreach ($excludedName in $normalizedExcludedDirectoryNames) {
            if ($directorySegments -contains $excludedName) {
                return $false
            }
        }

        return $true
    }
}

function Copy-DirectoryContents {
    param(
        [string]$SourceDir,
        [string]$DestinationDir,
        [switch]$ClearDestination
    )

    Ensure-PathExists -Path $SourceDir -Description "Quellordner"
    Ensure-Directory -Path $DestinationDir

    if ($ClearDestination -and (Test-Path -LiteralPath $DestinationDir)) {
        Get-ChildItem -LiteralPath $DestinationDir -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction Stop
    }

    Copy-Item -Path (Join-Path $SourceDir '*') -Destination $DestinationDir -Recurse -Force
}

function Copy-FileSafe {
    param(
        [string]$SourceFile,
        [string]$DestinationFile
    )

    Ensure-PathExists -Path $SourceFile -Description "Quelldatei"
    Ensure-Directory -Path (Split-Path -Path $DestinationFile -Parent)
    Copy-Item -LiteralPath $SourceFile -Destination $DestinationFile -Force
}

function Sync-ReleasePayload {
    param([string]$TargetRoot)

    Ensure-Directory -Path $TargetRoot

    $targetConfigDir         = Join-Path $TargetRoot 'Config'
    $targetTrustedConfigDir  = Join-Path $TargetRoot 'TrustedConfig'
    $targetScriptsDir        = Join-Path $TargetRoot 'Scripts'

    Write-Host "Synchronisiere Payload nach: $TargetRoot" -ForegroundColor Yellow

    Copy-FileSafe -SourceFile $SourceConfigJson -DestinationFile (Join-Path $targetConfigDir 'config.json')
    Copy-FileSafe -SourceFile $SourceTrustedConfigJson -DestinationFile (Join-Path $targetTrustedConfigDir 'TrustedConfig.json')
    Copy-DirectoryContents -SourceDir $SourceScriptsDir -DestinationDir $targetScriptsDir -ClearDestination
}

function New-SignedCatalogForTrustedConfig {
    param(
        [string]$TrustedConfigJson,
        [string]$CatalogFile,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$TimestampUrl,
        [string]$SignToolPath,
        [ValidateSet('CurrentUser','LocalMachine')]
        [string]$StoreLocation = 'CurrentUser'
    )

    Ensure-PathExists -Path $TrustedConfigJson -Description "TrustedConfig.json"

    $catalogDir = Split-Path -Path $CatalogFile -Parent
    Ensure-Directory -Path $catalogDir

    if (Test-Path -LiteralPath $CatalogFile) {
        Remove-Item -LiteralPath $CatalogFile -Force
    }

        $trustedConfigDir = Split-Path -Path $TrustedConfigJson -Parent
    Ensure-PathExists -Path $trustedConfigDir -Description "TrustedConfig-Verzeichnis"

    Write-Host "Erzeuge Catalog für Verzeichnis: $trustedConfigDir" -ForegroundColor Yellow
    New-FileCatalog -Path $trustedConfigDir -CatalogFilePath $CatalogFile -CatalogVersion 2.0 | Out-Null

    Sign-BinaryWithSignTool -Path $CatalogFile -Certificate $Certificate -TimestampUrl $TimestampUrl -SignToolPath $SignToolPath -StoreLocation $StoreLocation
}

function Verify-CatalogMatchesTrustedConfig {
    param(
        [string]$TrustedConfigJson,
        [string]$CatalogFile
    )

    Ensure-PathExists -Path $TrustedConfigJson -Description "TrustedConfig.json"
    Ensure-PathExists -Path $CatalogFile -Description "Catalog-Datei"

        $trustedConfigDir = Split-Path -Path $TrustedConfigJson -Parent
    Ensure-PathExists -Path $trustedConfigDir -Description "TrustedConfig-Verzeichnis"

    Write-Host "Prüfe Catalog gegen TrustedConfig-Verzeichnis ..." -ForegroundColor Yellow
    $result = Test-FileCatalog -CatalogFilePath $CatalogFile -Path $trustedConfigDir -Detailed

    if ($result.Status -ne 'Valid') {
        throw "Catalog-Prüfung fehlgeschlagen. Status: $($result.Status)"
    }

    if (-not $result.Signature -or $result.Signature.Status -ne 'Valid') {
        $sigStatus = if ($result.Signature) { $result.Signature.Status } else { 'Unbekannt' }
        throw "Catalog-Signatur ist nicht gültig. Status: $sigStatus"
    }

    $catalogKeys = if ($result.CatalogItems) { @($result.CatalogItems.Keys | ForEach-Object { [string]$_ }) } else { @() }
    $pathKeys = if ($result.PathItems) { @($result.PathItems.Keys | ForEach-Object { [string]$_ }) } else { @() }

    if (-not ($catalogKeys -contains 'TrustedConfig.json') -or -not ($pathKeys -contains 'TrustedConfig.json')) {
        throw "Catalog ist zwar gültig, enthält TrustedConfig.json aber nicht wie erwartet. CatalogItems=$($catalogKeys -join ','); PathItems=$($pathKeys -join ',')"
    }

    Write-Host "Catalog passt zu TrustedConfig.json: $TrustedConfigJson" -ForegroundColor Green
}

function Invoke-DotnetPublish {
    param(
        [string]$ProjectFilePath,
        [string]$PublishOutputDirectory,
        [string]$ConfigurationName,
        [string]$RuntimeId
    )

    Ensure-PathExists -Path $ProjectFilePath -Description "Projektdatei"
    Ensure-DotnetAvailable | Out-Null

    if ($CleanPublishOutput -and (Test-Path -LiteralPath $PublishOutputDirectory)) {
        Write-Host "Lösche vorhandenen Publish-Ordner: $PublishOutputDirectory" -ForegroundColor Yellow
        Remove-Item -LiteralPath $PublishOutputDirectory -Recurse -Force
    }

    Ensure-Directory -Path $PublishOutputDirectory

    Write-Host "Starte dotnet publish ..." -ForegroundColor Yellow
    & dotnet publish $ProjectFilePath -c $ConfigurationName -r $RuntimeId --self-contained true -o $PublishOutputDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish fehlgeschlagen mit ExitCode $LASTEXITCODE"
    }
}

function Sign-AllScriptsInDirectory {
    param(
        [string]$ScriptsRoot,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$TimestampUrl,
        [string[]]$ExcludedDirectoryNames = @()
    )

    if (-not (Test-Path -LiteralPath $ScriptsRoot)) {
        Write-Host "Kein Script-Ordner vorhanden, überspringe: $ScriptsRoot" -ForegroundColor DarkYellow
        return
    }

    $files = Get-FilesToSign -RootPath $ScriptsRoot -Extensions @('.ps1') -ExcludedDirectoryNames $ExcludedDirectoryNames
    foreach ($file in $files) {
        Sign-ScriptFile -Path $file.FullName -Certificate $Certificate -TimestampUrl $TimestampUrl
    }
}

# =========================
# VORBEREITUNG
# =========================

Write-Step "Vorbereitung"
Assert-SafePathSegment -Value $ReleaseName -Name 'ReleaseName'
Assert-SafePathSegment -Value $DotnetConfiguration -Name 'DotnetConfiguration'
Ensure-PathExists -Path $ProjectRoot -Description "Projektordner"
Ensure-PathExists -Path $ProjectFile -Description "Projektdatei"
Ensure-PathExists -Path $SourceConfigJson -Description "Source config.json"
Ensure-PathExists -Path $SourceTrustedConfigJson -Description "Source TrustedConfig.json"
Ensure-PathExists -Path $SourceScriptsDir -Description "Source Scripts"

$cert = Get-CodeSigningCertificate -Thumbprint $CertThumbprint -StoreLocation $CertStoreLocation
$signTool = Get-SignToolPath -OverridePath $SignToolOverride
$dotnet = Ensure-DotnetAvailable

Write-Host "Verwendetes Zertifikat:" -ForegroundColor Green
Write-Host "  Subject    : $($cert.Subject)"
Write-Host "  Thumbprint : $(Get-NormalizedThumbprint $cert)"
Write-Host "  Store      : Cert:\$CertStoreLocation\My"

Write-Host "Verwendetes SignTool:" -ForegroundColor Green
Write-Host "  $signTool"

Write-Host "Verwendetes dotnet:" -ForegroundColor Green
Write-Host "  $dotnet"

Write-Host "Release-/Build-Konfiguration:" -ForegroundColor Green
Write-Host "  ReleaseName         : $ReleaseName"
Write-Host "  DotnetConfiguration : $DotnetConfiguration"

# =========================
# 1) QUELL-SKRIPTE SIGNIEREN
# =========================

Write-Step "PS1-Quellscripte signieren"
Sign-AllScriptsInDirectory -ScriptsRoot $SourceScriptsDir -Certificate $cert -TimestampUrl $TimestampServer -ExcludedDirectoryNames $ExcludeDirectories

# =========================
# 2) SOURCE-CATALOG ERZEUGEN, SIGNIEREN, PRÜFEN
# =========================

Write-Step "Source-Catalog erzeugen und prüfen"
New-SignedCatalogForTrustedConfig `
    -TrustedConfigJson $SourceTrustedConfigJson `
    -CatalogFile $SourceCatalogFile `
    -Certificate $cert `
    -TimestampUrl $TimestampServer `
    -SignToolPath $signTool `
    -StoreLocation $CertStoreLocation

Verify-CatalogMatchesTrustedConfig `
    -TrustedConfigJson $SourceTrustedConfigJson `
    -CatalogFile $SourceCatalogFile

# =========================
# 3) PUBLISH
# =========================

Write-Step "dotnet publish ausführen"
Invoke-DotnetPublish `
    -ProjectFilePath $ProjectFile `
    -PublishOutputDirectory $PublishDir `
    -ConfigurationName $DotnetConfiguration `
    -RuntimeId $RuntimeIdentifier

Ensure-PathExists -Path $RidRoot -Description "RID-Root"
Ensure-PathExists -Path $PublishDir -Description "Publish-Ordner"

# =========================
# 4) RELEASE-PAYLOAD IN RID-ROOT UND PUBLISH SYNCHRONISIEREN
# =========================

Write-Step "Release-Payload synchronisieren"
Sync-ReleasePayload -TargetRoot $RidRoot
Sync-ReleasePayload -TargetRoot $PublishDir

Ensure-PathExists -Path $RidRootExe -Description "RID-Root EXE"
Ensure-PathExists -Path $PublishExe -Description "Publish EXE"
Ensure-PathExists -Path $RidRootTrustedConfigJson -Description "RID-Root TrustedConfig.json"
Ensure-PathExists -Path $PublishTrustedConfigJson -Description "Publish TrustedConfig.json"

# =========================
# 5) RELEASE-SKRIPTE SIGNIEREN
# =========================

Write-Step "Release-Skripte signieren"
Sign-AllScriptsInDirectory -ScriptsRoot $RidRootScriptsDir -Certificate $cert -TimestampUrl $TimestampServer
Sign-AllScriptsInDirectory -ScriptsRoot $PublishScriptsDir -Certificate $cert -TimestampUrl $TimestampServer

# =========================
# 6) RID-ROOT-EXE SIGNIEREN
# =========================

Write-Step "RID-Root EXE signieren"
Sign-BinaryWithSignTool `
    -Path $RidRootExe `
    -Certificate $cert `
    -TimestampUrl $TimestampServer `
    -SignToolPath $signTool `
    -StoreLocation $CertStoreLocation

# =========================
# 7) PUBLISH-EXE SIGNIEREN
# =========================

Write-Step "Publish-EXE signieren"
Sign-BinaryWithSignTool `
    -Path $PublishExe `
    -Certificate $cert `
    -TimestampUrl $TimestampServer `
    -SignToolPath $signTool `
    -StoreLocation $CertStoreLocation

# =========================
# 8) RID-ROOT-CATALOG ERZEUGEN, SIGNIEREN, PRÜFEN
# =========================

Write-Step "RID-Root Catalog erzeugen und prüfen"
New-SignedCatalogForTrustedConfig `
    -TrustedConfigJson $RidRootTrustedConfigJson `
    -CatalogFile $RidRootCatalogFile `
    -Certificate $cert `
    -TimestampUrl $TimestampServer `
    -SignToolPath $signTool `
    -StoreLocation $CertStoreLocation

Verify-CatalogMatchesTrustedConfig `
    -TrustedConfigJson $RidRootTrustedConfigJson `
    -CatalogFile $RidRootCatalogFile

# =========================
# 9) PUBLISH-CATALOG ERZEUGEN, SIGNIEREN, PRÜFEN
# =========================

Write-Step "Publish-Catalog erzeugen und prüfen"
New-SignedCatalogForTrustedConfig `
    -TrustedConfigJson $PublishTrustedConfigJson `
    -CatalogFile $PublishCatalogFile `
    -Certificate $cert `
    -TimestampUrl $TimestampServer `
    -SignToolPath $signTool `
    -StoreLocation $CertStoreLocation

Verify-CatalogMatchesTrustedConfig `
    -TrustedConfigJson $PublishTrustedConfigJson `
    -CatalogFile $PublishCatalogFile

# =========================
# 10) SIGNER-GLEICHHEIT PRÜFEN
# =========================

Write-Step "RID-Root EXE und RID-Root Catalog auf identisches Zertifikat prüfen"
Compare-SignerEquality -PathA $RidRootExe -PathB $RidRootCatalogFile

Write-Step "Publish-EXE und Publish-Catalog auf identisches Zertifikat prüfen"
Compare-SignerEquality -PathA $PublishExe -PathB $PublishCatalogFile

# =========================
# 11) FERTIG
# =========================

Write-Step "Fertig"
Write-Host "Alles erfolgreich abgeschlossen." -ForegroundColor Green
Write-Host "RID-Root ($ReleaseName): $RidRoot" -ForegroundColor Green
Write-Host "RID-Root EXE     : $RidRootExe" -ForegroundColor Green
Write-Host "RID-Root CAT     : $RidRootCatalogFile" -ForegroundColor Green
Write-Host "Publish-Ordner   : $PublishDir" -ForegroundColor Green
Write-Host "Publish EXE      : $PublishExe" -ForegroundColor Green
Write-Host "Publish CAT      : $PublishCatalogFile" -ForegroundColor Green
