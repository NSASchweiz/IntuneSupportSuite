param(
    [Parameter(Mandatory = $true)] [string]$ComputerName,
    [Parameter(Mandatory = $true)] [string]$RemoteAuditLogDirectory,
    [Parameter(Mandatory = $true)] [string]$ServiceName,
    [Parameter(Mandatory = $false)] [string]$SimulationMode = 'False',
    [Parameter(Mandatory = $true)] [string]$PsExecPath,
    [Parameter(Mandatory = $true)] [string]$PowerShellExecutable,
    [Parameter(Mandatory = $true)] [string]$SupportClientDirectory,
    [Parameter(Mandatory = $true)] [string]$FallbackConfigFileName,
    [Parameter(Mandatory = $true)] [string]$FallbackScriptFileName,
    [Parameter(Mandatory = $true)] [string]$FallbackScheduledTaskName,
    [Parameter(Mandatory = $true)] [string]$FallbackRunOnceValueName,
    [Parameter(Mandatory = $true)] [string]$RemoteFallbackLogFileName,
    [Parameter(Mandatory = $false)] [string]$ConnectionFallback = 'False',
    [Parameter(Mandatory = $false)] [string]$RestoreRemotingState = 'True',
    [Parameter(Mandatory = $false)] [string]$OperationId = '',
    [Parameter(Mandatory = $false)] [string]$FallbackTaskDelayMinutes = '15',
    [Parameter(Mandatory = $false)] [string]$SourceHost = '',
    [Parameter(Mandatory = $false)] [string]$ExpectedAppSignerThumbprint = '',
    [Parameter(Mandatory = $false)] [string]$ExpectedAppSignerPublicKey = ''
)
. (Join-Path $PSScriptRoot 'SupportBootstrap.ps1')
if ($SimulationMode -eq 'True') { Write-Output 'SIMULATION'; exit 0 }
if ([string]::IsNullOrWhiteSpace($OperationId)) { $OperationId = [guid]::NewGuid().ToString() }

function Invoke-RemoteWsReset {
    Invoke-Command -ComputerName $ComputerName -ArgumentList $RemoteAuditLogDirectory,$ServiceName,$OperationId -ScriptBlock {
        param($RemoteAuditLogDirectory,$ServiceName,$OperationId)

        $ErrorActionPreference = 'Stop'
        $null = New-Item -Path $RemoteAuditLogDirectory -ItemType Directory -Force
        $auditFile = Join-Path $RemoteAuditLogDirectory 'DAP-Remote-Audit.log'

        function Write-AuditLine {
            param(
                [Parameter(Mandatory = $true)][string]$Level,
                [Parameter(Mandatory = $true)][string]$Message
            )

            $line = "{0}`t{1}`tSource=RemoteAction`tOperationId={2}`tTarget={3}`tAction=WSReset`tMessage={4}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $OperationId, $env:COMPUTERNAME, $Message
            Add-Content -Path $auditFile -Value $line -Encoding UTF8
        }

        function Convert-ToAuditExcerpt {
            param(
                [string]$Text,
                [int]$MaxLength = 350
            )

            if ([string]::IsNullOrWhiteSpace($Text)) {
                return ''
            }

            $singleLine = (($Text -replace "`r?`n", ' | ') -replace '\s{2,}', ' ').Trim()
            if ($singleLine.Length -gt $MaxLength) {
                return $singleLine.Substring(0, $MaxLength) + '...'
            }

            return $singleLine
        }

        function Invoke-NonInteractiveProcess {
            param(
                [Parameter(Mandatory = $true)][string]$ExecutablePath,
                [int]$TimeoutSeconds = 180
            )

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'cmd.exe'
            $psi.Arguments = ('/d /q /c ""{0}""' -f $ExecutablePath)
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardInput = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $psi
            $process.EnableRaisingEvents = $false

            [void]$process.Start()
            Write-AuditLine -Level 'INFO' -Message ("WSReset Prozess gestartet. PID={0}" -f $process.Id)

            $confirmationInputs = @('', 'Y', 'J', 'Yes', 'Ja')
            foreach ($confirmationInput in $confirmationInputs) {
                $visibleValue = if ([string]::IsNullOrEmpty($confirmationInput)) { '<Enter>' } else { $confirmationInput }
                Write-AuditLine -Level 'INFO' -Message ("Vordefinierte WSReset-Bestätigung wurde an stdin übergeben: {0}" -f $visibleValue)
                $process.StandardInput.WriteLine($confirmationInput)
            }
            $process.StandardInput.Flush()
            $process.StandardInput.Close()

            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                try {
                    $process.Kill()
                }
                catch {
                }

                $stdout = $stdoutTask.GetAwaiter().GetResult()
                $stderr = $stderrTask.GetAwaiter().GetResult()
                if (-not [string]::IsNullOrWhiteSpace($stdout)) {
                    Write-AuditLine -Level 'WARN' -Message ("WSReset StandardOutput vor Timeout: {0}" -f (Convert-ToAuditExcerpt -Text $stdout))
                }
                if (-not [string]::IsNullOrWhiteSpace($stderr)) {
                    Write-AuditLine -Level 'WARN' -Message ("WSReset StandardError vor Timeout: {0}" -f (Convert-ToAuditExcerpt -Text $stderr))
                }

                throw 'WSReset wurde nach 180 Sekunden abgebrochen. Wahrscheinlich blockierte ein Fenster oder eine Rückfrage den Abschluss.'
            }

            $stdoutText = $stdoutTask.GetAwaiter().GetResult()
            $stderrText = $stderrTask.GetAwaiter().GetResult()

            return [pscustomobject]@{
                ExitCode = $process.ExitCode
                StandardOutput = $stdoutText
                StandardError = $stderrText
            }
        }

        try {
            Write-AuditLine -Level 'INFO' -Message 'WSReset wurde gestartet.'

            $wsresetPath = Join-Path $env:SystemRoot 'System32\wsreset.exe'
            if (-not (Test-Path -LiteralPath $wsresetPath)) {
                $resolved = Get-Command wsreset.exe -ErrorAction SilentlyContinue
                if ($resolved) {
                    $wsresetPath = $resolved.Source
                }
            }

            if (-not (Test-Path -LiteralPath $wsresetPath)) {
                throw 'wsreset.exe wurde auf dem Zielgerät nicht gefunden.'
            }

            Write-AuditLine -Level 'INFO' -Message ("WSReset wird nicht-interaktiv ausgeführt. Antworten auf mögliche Rückfragen werden automatisch an stdin übergeben. Pfad={0}" -f $wsresetPath)
            $processResult = Invoke-NonInteractiveProcess -ExecutablePath $wsresetPath -TimeoutSeconds 180

            if (-not [string]::IsNullOrWhiteSpace($processResult.StandardOutput)) {
                Write-AuditLine -Level 'INFO' -Message ("WSReset StandardOutput: {0}" -f (Convert-ToAuditExcerpt -Text $processResult.StandardOutput))
            }
            if (-not [string]::IsNullOrWhiteSpace($processResult.StandardError)) {
                Write-AuditLine -Level 'WARN' -Message ("WSReset StandardError: {0}" -f (Convert-ToAuditExcerpt -Text $processResult.StandardError))
            }

            if ($processResult.ExitCode -ne 0) {
                throw ("WSReset wurde mit ExitCode {0} beendet." -f $processResult.ExitCode)
            }

            Write-AuditLine -Level 'INFO' -Message ("WSReset wurde erfolgreich abgeschlossen. ExitCode={0}" -f $processResult.ExitCode)
            Write-AuditLine -Level 'INFO' -Message 'IME Dienst wird nach WSReset neu gestartet.'
            Restart-Service -Name $ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            $service = Get-Service -Name $ServiceName -ErrorAction Stop
            if ($service.Status -ne 'Running') {
                throw ("IME Dienst wurde nach WSReset neu gestartet, ist aber nicht im Status Running. Aktueller Status: {0}" -f $service.Status)
            }
            Write-AuditLine -Level 'INFO' -Message ("IME Dienst wurde nach WSReset erfolgreich neu gestartet. Status={0}" -f $service.Status)
            'WSReset wurde erfolgreich ausgeführt. Der IME Dienst wurde anschliessend neu gestartet.'
        }
        catch {
            Write-AuditLine -Level 'ERROR' -Message ("WSReset fehlgeschlagen: {0}" -f $_.Exception.Message)
            throw
        }
    } -ErrorAction Stop
}

try {
    try { $result = Invoke-RemoteWsReset }
    catch {
        if ($ConnectionFallback -ne 'True') { throw }
        $testResult = Invoke-PsExecPowerShell -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -ScriptText '$env:COMPUTERNAME'
        if (-not $testResult.Success) { throw "PSExec Verbindung fehlgeschlagen: $($testResult.StandardError)" }
        $fallbackConfigArg = ''
        if ($RestoreRemotingState -eq 'True') {
            $copyResult = Copy-RemoteSupportFile -ComputerName $ComputerName -RemoteDirectory $SupportClientDirectory -SourcePath (Join-Path $PSScriptRoot 'fallbackcore.ps1') -TargetFileName $FallbackScriptFileName
            $copyMessage = if ($copyResult.ExistedBefore) { 'fallbackcore.ps1 wurde auf dem Zielgerät aktualisiert.' } else { 'fallbackcore.ps1 wurde auf dem Zielgerät erstellt.' }
            Write-RemoteBootstrapLog -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -RemoteAuditLogDirectory $RemoteAuditLogDirectory -RemoteFallbackLogFileName $RemoteFallbackLogFileName -OperationId $OperationId -SourceHost $SourceHost -Level 'INFO' -Action 'FallbackScript' -Message $copyMessage -AffectedPath (Join-Path $SupportClientDirectory $FallbackScriptFileName) -Result $copyResult.Result
            $bootstrapResult = New-RemoteFallbackConfig -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -SupportClientDirectory $SupportClientDirectory -FallbackConfigFileName $FallbackConfigFileName -FallbackScriptFileName $FallbackScriptFileName -RemoteAuditLogDirectory $RemoteAuditLogDirectory -RemoteFallbackLogFileName $RemoteFallbackLogFileName -FallbackScheduledTaskName $FallbackScheduledTaskName -FallbackRunOnceValueName $FallbackRunOnceValueName -OperationId $OperationId -FallbackTaskDelayMinutes $FallbackTaskDelayMinutes -SourceHost $SourceHost -ExpectedAppSignerThumbprint $ExpectedAppSignerThumbprint -ExpectedAppSignerPublicKey $ExpectedAppSignerPublicKey
            if (-not $bootstrapResult.Success) { throw "Fallback konnte nicht vorbereitet werden: $($bootstrapResult.StandardError)" }
            $fallbackConfigArg = $FallbackConfigFileName
        }
        else {
            Write-RemoteBootstrapLog -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -RemoteAuditLogDirectory $RemoteAuditLogDirectory -RemoteFallbackLogFileName $RemoteFallbackLogFileName -OperationId $OperationId -SourceHost $SourceHost -Level 'INFO' -Action 'FallbackArm' -Message 'ConnectionFallback aktiv, RestoreRemotingState deaktiviert. Es wird kein Restore-Fallback auf dem Zielgerät abgelegt.'
        }
        $enableResult = Enable-TemporaryPsRemoting -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -SupportClientDirectory $SupportClientDirectory -FallbackConfigFileName $fallbackConfigArg -RemoteAuditLogDirectory $RemoteAuditLogDirectory -RemoteFallbackLogFileName $RemoteFallbackLogFileName -OperationId $OperationId -SourceHost $SourceHost
        if (-not $enableResult.Success) { throw "PSRemoting konnte nicht aktiviert werden: $($enableResult.StandardError)" }
        $result = Invoke-RemoteWsReset
    }
    Write-Output ($result | Out-String).Trim()
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

# SIG # Begin signature block
# MIIl6QYJKoZIhvcNAQcCoIIl2jCCJdYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALFYwUg7X7hytJ
# kmYP1VofZKLDAR4ZBKLePnSMT5KcB6CCH/UwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# l1y+3PzfIFE0a/dzGJmrAgmWGrRNIoFHeT+YeXuFAOQwDQYJKoZIhvcNAQEBBQAE
# ggEAIjv+nkN8g7p04Ja/xYIRpc8Jkc2k/9B+uzbKGmsmE7xW7NmyJyUKm/5HP1th
# 54TnLH536kdRBqSUh1TW77zw8ty5i2C+lkc3J77R4e5viVSFvfKiSW4rvCwoABda
# 9dgBB4oZgPjtbz50/jP5WXuN0uFH/ebhKv3zoljwmWqbD+u8+JIpXd0AfN38mC8L
# jKdlpOMKlf4NTY9uX6xrlB/AzSajzWSouu0pzal2KqSH1bp+NHDxxqHb6EKmHpiY
# 0/31tbbhPYASK+lN0BOPx3Yi0a53wvYja4qvyV5Es1LE4AFmE5JXsVV1+rNevyAF
# HErasaNMxEEoYKGul1H2R2ujUqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIB
# ATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCg
# aTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0
# MjQxMjUwMjZaMC8GCSqGSIb3DQEJBDEiBCAEsEtVq0v+YdG6kk/BGF/PLuyBnXst
# loqjSXPNKasXdTANBgkqhkiG9w0BAQEFAASCAgBwjJuGiDaPRTxdmwrHD3cGeKhU
# +G6bVV24F2uIXAcT3X4wYCSAde4QpSz1txOz4E8JKRknLDF3/tf28/OPHSRS5rS9
# DsBBqiGv2eFndvR74fLubU/KlRFVl9hR4LTCpuZmwQ9mZI70xVdevO79doCnaHWK
# 5pRLRJrWdTEDIvW16S4kk6dwLVfGa0CAxyQMXERbW23ieV0eYCOZ38Ug7e/J18Nz
# UjVZiNv9Ox+2iWbgE8xZ6Q+m5yE1ZTYCB3HYYvC1OO1AsWDLefvjUu/+IIwVDs1K
# mOrQsBYlp0j/oev5NB1iCWVMzcnR36GoS1e9NR9QZu7x2yXwqVv6W/5bB6mEy/TN
# 3z9O3KhC/0tf0rMRmB4t6VoL7OLD+QypWUFMV74kk1KtEUBj7PMFXtuJB7zLpmhV
# Ck64YkQnRpn+OkMTeoYTEJTT45NRrk1arFeS8PEAPYA7HmJ/rrg8Elic9YqQt6yp
# USrfU6PDOsxczenfZ3NLw15DZ4EvYeuk5Lb/J7EEXK7qqw13y+KTxMYwSm9gzvyF
# PWNBl167Q0F3+YxnLXzsqQEeEvYW7oCh/aMcasVd/s1yQBJHMulTnfiS1q957osm
# KFNnFMlBYBL3jqXsYIe7HDg4WDbt93bPKGmmeOs7DxWpRgo4gkuwwFeITLAXgYjd
# ZLFEXyBlqZR0KlptFQ==
# SIG # End signature block
