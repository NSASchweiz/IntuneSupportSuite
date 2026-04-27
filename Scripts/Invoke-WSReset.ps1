param(
    [Parameter(Mandatory = $true)] [string]$ComputerName,
    [Parameter(Mandatory = $true)] [string]$RemoteAuditLogDirectory,
    [Parameter(Mandatory = $true)] [string]$RemoteAuditLogFileName,
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
    Invoke-Command -ComputerName $ComputerName -ArgumentList $RemoteAuditLogDirectory,$RemoteAuditLogFileName,$ServiceName,$OperationId -ScriptBlock {
        param($RemoteAuditLogDirectory,$RemoteAuditLogFileName,$ServiceName,$OperationId)

        $ErrorActionPreference = 'Stop'
        $null = New-Item -Path $RemoteAuditLogDirectory -ItemType Directory -Force
        $auditFile = Join-Path $RemoteAuditLogDirectory $RemoteAuditLogFileName

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
            Write-RemoteBootstrapLog -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -RemoteAuditLogDirectory $RemoteAuditLogDirectory -RemoteAuditLogFileName $RemoteAuditLogFileName -RemoteFallbackLogFileName $RemoteFallbackLogFileName -OperationId $OperationId -SourceHost $SourceHost -Level 'INFO' -Action 'FallbackScript' -Message $copyMessage -AffectedPath (Join-Path $SupportClientDirectory $FallbackScriptFileName) -Result $copyResult.Result
            $bootstrapResult = New-RemoteFallbackConfig -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -SupportClientDirectory $SupportClientDirectory -FallbackConfigFileName $FallbackConfigFileName -FallbackScriptFileName $FallbackScriptFileName -RemoteAuditLogDirectory $RemoteAuditLogDirectory -RemoteAuditLogFileName $RemoteAuditLogFileName -RemoteFallbackLogFileName $RemoteFallbackLogFileName -FallbackScheduledTaskName $FallbackScheduledTaskName -FallbackRunOnceValueName $FallbackRunOnceValueName -OperationId $OperationId -FallbackTaskDelayMinutes $FallbackTaskDelayMinutes -SourceHost $SourceHost -ExpectedAppSignerThumbprint $ExpectedAppSignerThumbprint -ExpectedAppSignerPublicKey $ExpectedAppSignerPublicKey
            if (-not $bootstrapResult.Success) { throw "Fallback konnte nicht vorbereitet werden: $($bootstrapResult.StandardError)" }
            $fallbackConfigArg = $FallbackConfigFileName
        }
        else {
            Write-RemoteBootstrapLog -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -RemoteAuditLogDirectory $RemoteAuditLogDirectory -RemoteAuditLogFileName $RemoteAuditLogFileName -RemoteFallbackLogFileName $RemoteFallbackLogFileName -OperationId $OperationId -SourceHost $SourceHost -Level 'INFO' -Action 'FallbackArm' -Message 'ConnectionFallback aktiv, RestoreRemotingState deaktiviert. Es wird kein Restore-Fallback auf dem Zielgerät abgelegt.'
        }
        $enableResult = Enable-TemporaryPsRemoting -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -SupportClientDirectory $SupportClientDirectory -FallbackConfigFileName $fallbackConfigArg -RemoteAuditLogDirectory $RemoteAuditLogDirectory -RemoteAuditLogFileName $RemoteAuditLogFileName -RemoteFallbackLogFileName $RemoteFallbackLogFileName -OperationId $OperationId -SourceHost $SourceHost
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
