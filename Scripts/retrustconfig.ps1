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
        DapIntuneSupportSuite.exe
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
$ExeName = "DapIntuneSupportSuite.exe"

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

# SIG # Begin signature block
# MIIl6QYJKoZIhvcNAQcCoIIl2jCCJdYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCj0anmx52a9Vpy
# zzQnPYyct7SJqr1NnO5pEmZkQxf2FaCCH/UwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggXMMIIDtKADAgECAhMcAAAQVt4x3kNIQXsJAAEAABBWMA0G
# CSqGSIb3DQEBCwUAMFcxEjAQBgoJkiaJk/IsZAEZFgJjaDEUMBIGCgmSJomT8ixk
# ARkWBGt0emgxEjAQBgoJkiaJk/IsZAEZFgJrdDEXMBUGA1UEAxMOWkggU2Vydmlj
# ZSBJQ0EwHhcNMjYwMzE2MTAwMjQ5WhcNMjgwMzE1MTAwMjQ5WjB4MQswCQYDVQQG
# EwJDSDEnMCUGA1UECgweRmluYW56ZGlyZWt0aW9uIEthbnRvbiBaw7xyaWNoMRww
# GgYDVQQLDBNBbXQgZsO8ciBJbmZvcm1hdGlrMSIwIAYDVQQDExlaSCBDb2RlIFNp
# Z25pbmcgV29ya3BsYWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# tqg9HqKerzZ4zOmO9vTyDTtCMnd8s6Zn1f9iLdYNO1C/6HlW5npliLMNHEFVTrQ/
# xrrbi070sFym/qyBcZJ9cvGvFi0ZM0FFOkVRvrrz2tpMfTf1qj/mB1/+eraqBtaC
# 71U5ZpJTu+EjbRSytNC7kdJDk2GaFfLgJ2ocuGXA9JjbsITu19USDG3+p2FBFUER
# sH4ZzmxpHrtHuk1HMPHU1wlRWhxU7RwOvZHbPNETtvYpSqIeE/rFajBQD72LMLDk
# +K0TRHeklwLtwG0Yofs8biY3mDofrgCModY0eNsUUJaMDGyt4W/iROThGiT2XpX4
# Ljn2Eew2JvatvJLabG0f1QIDAQABo4IBbjCCAWowPAYJKwYBBAGCNxUHBC8wLQYl
# KwYBBAGCNxUIgvHQDYKJ0RuNnw6G/8MBgcHHRwaDlIwghNemXwIBZAIBGTATBgNV
# HSUEDDAKBggrBgEFBQcDAzALBgNVHQ8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAK
# BggrBgEFBQcDAzAdBgNVHQ4EFgQUtJz3gac85SnSmROsIJYaddFE3aowHwYDVR0j
# BBgwFoAUxw5a+cCJIxnGqKVw27LV33NzjgswPAYDVR0fBDUwMzAxoC+gLYYraHR0
# cDovL3BraS56aC5jaC9jZHAvWkglMjBTZXJ2aWNlJTIwSUNBLmNybDBtBggrBgEF
# BQcBAQRhMF8wOgYIKwYBBQUHMAKGLmh0dHA6Ly9wa2kuemguY2gvYWlhL1pIJTIw
# U2VydmljZSUyMElDQSgxKS5jcnQwIQYIKwYBBQUHMAGGFWh0dHA6Ly9wa2kuemgu
# Y2gvb2NzcDANBgkqhkiG9w0BAQsFAAOCAgEAns9MXLEwpYzFrMHESCGQA/dXkaSu
# i9AxiqZ/YWcSNJB8Yimrw0iQSzK7T7bMAo7A1+ZJOAkWCGqXODkB5N0D8WPLbNkE
# SDrud7B098LNqOimNhTh1V/8dBc98xm62Nuf1fqwQuXPRJf/lpvAOUp79z03gGN7
# oa9uBvd3CWSR5FAZso6AIIhD6qZ5Z+6MDsUCMvcUVq4Z44k0EuL9kU2RVh7NJpA6
# Epy6DLVGfuxsMfmaBVC53kIGfiKYTu1ACoefzA9BAJmcA/wXMSAuU7Sitn+iTLmO
# U9dl3XHx2DDkd5J842Hnje4VNmdQclMN5at+MI7IXkJaCNkh53XEsRSu4czVQ2Y3
# hwLrS0qYTNL7yIGh7glIKFiZtb9Fvoi8y6/177mes3VpNPSXeYr3iKVPOCG4uC67
# 3vEH6H8I9yYdh6OpNANAbcVJ5LKVwotzCfLf1w7ba+jg21Yl0BhJ8dqQy5aGhPlC
# 1Uck6ZvdLJWpI+EqwxWY8DeMv7wOGa0mQE8Us5gqAFIGra0V3xbO686f20nd8eUg
# vs9I82H6qIaOwqRFXLb+KCC4vkOSNgVHj7hM47Lk30IzKjNIEZDJfaU6STtBCRc3
# p34FXuy/cmd2lwA+rPA6oQ7jUVGMO3IjeuR9xzWLPxJdcwGbBQmdvcsW8pxMTImw
# mxgtRnob02zwgX4wgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG5zCCBM+gAwIBAgITJQAAAAnfjziB099G6wABAAAACTANBgkqhkiG9w0B
# AQsFADCBkjESMBAGCgmSJomT8ixkARkWAmNoMRIwEAYKCZImiZPyLGQBGRYCemgx
# DzANBgNVBAgTBlp1cmljaDEPMA0GA1UEBxMGWnVyaWNoMRYwFAYDVQQLEw1LYW50
# b24gWnVyaWNoMQwwCgYDVQQKEwNBRkkxCzAJBgNVBAYTAkNIMRMwEQYDVQQDEwpa
# SCBSb290IENBMB4XDTI1MDYxNzE0MTIxNFoXDTM1MDYxNzE0MjIxNFowVzESMBAG
# CgmSJomT8ixkARkWAmNoMRQwEgYKCZImiZPyLGQBGRYEa3R6aDESMBAGCgmSJomT
# 8ixkARkWAmt0MRcwFQYDVQQDEw5aSCBTZXJ2aWNlIElDQTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAOKblMYzN+JUnXDsWAkWf0m8fVvcSlZbquO1kFdV
# 5I8MkRwrx7MBNKoONrrH7CH9RpqyWy/6I+QYC/smqab4F14kJ10sARsX7mHjlAIT
# OK66HadYF5eWh0KeLLvTOw+n+UKriHE5Y9DwpawsAYTwIyDlH7J/Fetl2h1c4xVE
# 7lLvaBuN0KL/uoVCXBoMNInidwGjC5xiwpnZZkciBln+HewB+FipoYKwlOwm9+IB
# R53WVNC+RcfuBATLOhrU1t3XQ3+41e2GUgWNhMbO3gEzF3H7hGwp84xaDjMOtep6
# HqZCf2GBxdY5fSMIsZf4LWXpgvkC2eOdkkXUbqfWfTxw+PEFCVI06hZ2WQjjB1Kj
# MYqxTQbvBV37dN8vSFz/ESwxQbPIHBED4nbsDS76HbNBfb6XlHh3W9NRyBl0Llng
# TaOZZppbh8THxiI2NPFtUY6qktnISas7Fln7e8Ha4Qv6EbBSNXm7HJekfsRb0tiz
# Tf3oX0/tKyffr88tKeLXMoWhPynfF6rh+HC/ROXOZerZgrAZl0S9UZC2L7HZHhwe
# 5eZEgnp3MaprtScomlmGijXTEFJB2K3dHi/Tgs+6x8ENYk5m5gfO5QsiPCr709hM
# zgjFqwFuILER/wWFA6NIUN6a0cLbFXfhdaybd8ewH8dUVIS4TtGS6n8o+Ha/lMck
# 3NbrAgMBAAGjggFuMIIBajAQBgkrBgEEAYI3FQEEAwIBATAjBgkrBgEEAYI3FQIE
# FgQU6UQpdgNipioUEekn5Op5gNqRNBUwHQYDVR0OBBYEFMcOWvnAiSMZxqilcNuy
# 1d9zc44LMDYGA1UdIAQvMC0wKwYFYIV0BTIwIjAgBggrBgEFBQcCARYUaHR0cDov
# L3BraS56aC5jaC9jcHMwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0P
# BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUx9RCa22dv9AhR5gL
# oHla6iQTvGowOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovL3BraS56aC5jaC9jZHAv
# WkglMjBSb290JTIwQ0EuY3JsMEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAoYq
# aHR0cDovL3BraS56aC5jaC9haWEvWkglMjBSb290JTIwQ0EoMSkuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQCMcRfYL4AR3iUK7fYGJrHp3sr5f0p66K9eB0hM9mPq7JNK
# JPpt7UYbOkWPDo003vuVNd8AasAq+y+a9w1UQUtoSv0h6qp3KDYCtEswy2oAuvWd
# XFdYb7G2yh1xstDqjITZtSHf4eN2PwHuL0kE7y7rADg6ns1BPxfLvJFDx5IWFMpH
# 0C+YTDmuOEfZ3eFi7ZGwsO7r0ceQjR/us4xIKT4zfuvrKSec9TbC8J+zkgHF+1MF
# aSYJrXyfNI65QcQ6/GjbF9lePQh/JsSogBSYRp6M2KG+cfwfIktnAgnpj2vExIjj
# X/SpeqzK+ptxvMwirIjmVdvV1QKNcDchKIAY34XC+HGf75XrelnT8dwrxhcg3TXk
# /TBsX6yPZZqnsJKcc5QZrOr1a5KQYgGIVPA+MEqvRxQ2aYyt1zfvux4+PDDTdQK+
# TWL3kR7bKQekbmKVPBDvtAX+TjRGQYwPDpkq3eDzki3OLysGAZQCwwL4sU91KV74
# Dcqmi2xMLoSYbDCtxGurJhXoS5pApkVqYJ4zziVwHk2DmMrP6zfWwzyxcMjpl9Nl
# MOathjV5M1NYtA0B9soDlwkBzHQpXbJRBF/KxVlG3KtBxaYVV4JtsMROgp0Ohj1+
# BWBlx6jqdkJSNoJtiEyxmE7XYB7K9MGy82hQ6hImDfTKVFwi7/tsG0A7JJtrvTCC
# Bu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhE
# aWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAy
# MDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNl
# cnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/
# hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7
# zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0D
# vbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAldytxNM89PZXUP/5wWWURK+If
# xiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYev
# vOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZr
# eiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz
# 8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVC
# GZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40h5avMcpi54wm0i2ePZD5pPIssosz
# QyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOz
# aQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlw
# CUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
# FgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQ
# VvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAy
# NUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIw
# MjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkq
# hkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+F
# ERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQ
# uPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9kt
# x0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xe
# jEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0
# fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu
# /3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTl
# QJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaeh
# r0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK
# +At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1
# Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcx
# ggVKMIIFRgIBATBuMFcxEjAQBgoJkiaJk/IsZAEZFgJjaDEUMBIGCgmSJomT8ixk
# ARkWBGt0emgxEjAQBgoJkiaJk/IsZAEZFgJrdDEXMBUGA1UEAxMOWkggU2Vydmlj
# ZSBJQ0ECExwAABBW3jHeQ0hBewkAAQAAEFYwDQYJYIZIAWUDBAIBBQCggYQwGAYK
# KwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg
# 29+i3dNAq/6TDNokgcXtYuSbgKBWNfS9rfOwbbz/GTAwDQYJKoZIhvcNAQEBBQAE
# ggEAe6AkIOaeGEbuE/DKu2bdksC6BcCK517xh9/fa3fXU1LkRV/NDCiKdmrer7Np
# 4QO3rLj+eEFd2Rf4jWSWSFaO7MgoXoLVZb11zrpljiADcXWGUhCCBXoPEhaS/Thh
# PvOVac/BG+OA3qFVHRM3GiaWLoHQtASyynvZ0Cqvs8einbEUpn3ETqdkYGU6kbtk
# 1+n2sEnBenMhVnjICM73wqxlO/kQ432VLr3D10/tsV84SZXASGQXikvm0K6ea198
# 9Wuxl9i4JI3W57QYq9+Mk4JyByG4I0L+Wa5YimGGHYlPaxKcvrFAGbL5Pg2mIGMo
# xXrzcoMOsmbrq+tAo6qdfSGaN6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIB
# ATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCg
# aTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0
# MjQxMjUwMjdaMC8GCSqGSIb3DQEJBDEiBCDx90ZzOP5V21c0f9N94AGKC2REsqR4
# Ez4f7lwsV1VJOTANBgkqhkiG9w0BAQEFAASCAgBuBcd+65BbbvCmOfubuKges+04
# pCW8ZRec7TZD7YMW2h8DMeYNmE5qW3pYskIWQb9IKVFivWOX08Mu2NKeHD6Nr9iB
# lqiBzwLThdAFAZHuPzOY0QoxxfnVUy4I1zWUYjjoAP51fGGjDsp9FhF2KIBqpDGO
# VVEGG57cM92Y0loKzUOD3sGXTxJf8CPGb8aUpupwREs98uyqPHMW81SEF6bAG669
# QKjMHfaLEJzdou9c9tSqmfQ9PDtLN53dQjX+FKPtcLjFp+29hX5dzo6fCACwGdMX
# Ap6F8X7I0yDv6qXAe7Nig2/68IQ+cqAIXP71fRoOB9VMdRSkEmBtwOct+CSA4ovW
# Wz7SvVPmf767SMSzE9oAURMZWB9tgbvvM/hybUEfppORdct31tL996dWVtprA/jg
# BnE1vy3bmZ0gP37O/TWq/87DuTvhHg+bgVNVAP6Z9MLPXxg0Kk/o9gy91DEqGFFV
# 7g0OQbhqIgHq3pJw6/Wd5v0dTD3IY/eF4b3zBoyKkb5x7eBm9HN+3T/wiW7zawpR
# k6SYSgufZ5Cqy+40yAspCfYlMJcW3vqkSnpscsxaWfTkK1EhlYuo+dYRHr2l7ymg
# VSDVjcQBT6+RfJCVKuXvtEkc9Ia7Ezk+mBErk0ql7hNtgj8eQSPuQdTNiXDhmMbI
# ldAMjrZgONXATgdfRA==
# SIG # End signature block
