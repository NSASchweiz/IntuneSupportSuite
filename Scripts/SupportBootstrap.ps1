function New-EncodedCommand {
    param([Parameter(Mandatory = $true)][string]$ScriptText)
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ScriptText))
}

function Invoke-PsExecPowerShell {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$PsExecPath,
        [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
        [Parameter(Mandatory = $true)][string]$ScriptText,
        [int]$TimeoutSeconds = 30
    )

    $encoded = New-EncodedCommand -ScriptText $ScriptText
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()

    try {
        $argumentList = @(
            "\\$ComputerName",
            '-nobanner',
            '-h',
            $PowerShellExecutable,
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-EncodedCommand',
            $encoded
        )

        $process = Start-Process -FilePath $PsExecPath -ArgumentList $argumentList -PassThru -Wait -NoNewWindow -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
        $output = if (Test-Path $stdoutFile) { [System.IO.File]::ReadAllText($stdoutFile) } else { '' }
        $error = if (Test-Path $stderrFile) { [System.IO.File]::ReadAllText($stderrFile) } else { '' }

        [pscustomobject]@{
            Success = ($process.ExitCode -eq 0)
            ExitCode = $process.ExitCode
            StandardOutput = $output.Trim()
            StandardError = $error.Trim()
        }
    }
    finally {
        Remove-Item -Path $stdoutFile, $stderrFile -ErrorAction SilentlyContinue -Force
    }
}

function Copy-RemoteSupportFile {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$RemoteDirectory,
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$TargetFileName
    )

    $adminRemoteDirectory = $RemoteDirectory -replace '^C:\\', 'C$\'
    $uncDirectory = "\\$ComputerName\$adminRemoteDirectory"
    if (-not (Test-Path -Path $uncDirectory)) {
        New-Item -Path $uncDirectory -ItemType Directory -Force | Out-Null
    }

    Copy-Item -Path $SourcePath -Destination (Join-Path $uncDirectory $TargetFileName) -Force
}

function Write-RemoteBootstrapLog {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$PsExecPath,
        [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
        [Parameter(Mandatory = $true)][string]$RemoteAuditLogDirectory,
        [Parameter(Mandatory = $true)][string]$RemoteAuditLogFileName,
        [Parameter(Mandatory = $true)][string]$RemoteFallbackLogFileName,
        [Parameter(Mandatory = $true)][string]$OperationId,
        [Parameter(Mandatory = $true)][string]$Level,
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][string]$SourceHost = '',
        [Parameter(Mandatory = $false)][string]$AffectedPath = '',
        [Parameter(Mandatory = $false)][string]$Result = 'Logged'
    )

    $remoteScript = @"
`$ErrorActionPreference = 'Stop'
`$auditDir = '$($RemoteAuditLogDirectory.Replace("'","''"))'
`$remoteAuditLog = '$($RemoteAuditLogFileName.Replace("'","''"))'
`$fallbackLog = '$($RemoteFallbackLogFileName.Replace("'","''"))'
`$operationId = '$($OperationId.Replace("'","''"))'
`$level = '$($Level.Replace("'","''"))'
`$action = '$($Action.Replace("'","''"))'
`$message = '$($Message.Replace("'","''"))'
`$sourceHost = '$($SourceHost.Replace("'","''"))'
`$affectedPath = '$($AffectedPath.Replace("'","''"))'
`$result = '$($Result.Replace("'","''"))'

New-Item -Path `$auditDir -ItemType Directory -Force | Out-Null
foreach (`$fileName in @(`$remoteAuditLog, `$fallbackLog)) {
    `$logFile = Join-Path `$auditDir `$fileName
    `$line = "{0}`t{1}`tSource=Bootstrap`tAction={2}`tOperationId={3}`tUser={4}`tSourceHost={5}`tDestinationHost={6}`tResult={7}`tPath={8}`tDetails={9}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), `$level, `$action, `$operationId, `$env:USERNAME, `$sourceHost, `$env:COMPUTERNAME, `$result, `$affectedPath, `$message
    Add-Content -Path `$logFile -Value `$line -Encoding UTF8
}
"@

    Invoke-PsExecPowerShell -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -ScriptText $remoteScript | Out-Null
}

function New-RemoteFallbackConfig {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$PsExecPath,
        [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
        [Parameter(Mandatory = $true)][string]$SupportClientDirectory,
        [Parameter(Mandatory = $true)][string]$FallbackConfigFileName,
        [Parameter(Mandatory = $true)][string]$FallbackScriptFileName,
        [Parameter(Mandatory = $true)][string]$RemoteAuditLogDirectory,
        [Parameter(Mandatory = $true)][string]$RemoteAuditLogFileName,
        [Parameter(Mandatory = $true)][string]$RemoteFallbackLogFileName,
        [Parameter(Mandatory = $true)][string]$FallbackScheduledTaskName,
        [Parameter(Mandatory = $true)][string]$FallbackRunOnceValueName,
        [Parameter(Mandatory = $true)][string]$OperationId,
        [Parameter(Mandatory = $false)][string]$FallbackTaskDelayMinutes = '15',
        [Parameter(Mandatory = $false)][string]$SourceHost = '',
        [Parameter(Mandatory = $false)][string]$ExpectedAppSignerThumbprint = '',
        [Parameter(Mandatory = $false)][string]$ExpectedAppSignerPublicKey = ''
    )

    $remoteScript = @"
`$ErrorActionPreference = 'Stop'
`$supportDir = '$($SupportClientDirectory.Replace("'","''"))'
`$configFileName = '$($FallbackConfigFileName.Replace("'","''"))'
`$scriptFileName = '$($FallbackScriptFileName.Replace("'","''"))'
`$auditDir = '$($RemoteAuditLogDirectory.Replace("'","''"))'
`$remoteAuditLogFileName = '$($RemoteAuditLogFileName.Replace("'","''"))'
`$fallbackLogFileName = '$($RemoteFallbackLogFileName.Replace("'","''"))'
`$taskName = '$($FallbackScheduledTaskName.Replace("'","''"))'
`$runOnceBaseName = '$($FallbackRunOnceValueName.Replace("'","''"))'
`$runOnceName = '$($FallbackRunOnceValueName.Replace("'","''"))-$($OperationId.Replace("'","''"))'
`$operationId = '$($OperationId.Replace("'","''"))'
`$taskDelayMinutes = [int]'$($FallbackTaskDelayMinutes.Replace("'","''"))'
`$sourceHost = '$($SourceHost.Replace("'","''"))'
`$expectedThumbprint = ('$($ExpectedAppSignerThumbprint.Replace("'","''"))' -replace '\s','').ToUpperInvariant()
`$expectedPublicKey = '$($ExpectedAppSignerPublicKey.Replace("'","''"))'

function Write-TargetLine {
    param([string]`$Level,[string]`$Action,[string]`$Result,[string]`$Details,[string]`$FileName,[string]`$Path='')
    New-Item -Path `$auditDir -ItemType Directory -Force | Out-Null
    `$logFile = Join-Path `$auditDir `$FileName
    `$line = "{0}`t{1}`tSource=Bootstrap`tAction={2}`tOperationId={3}`tUser={4}`tSourceHost={5}`tDestinationHost={6}`tResult={7}`tPath={8}`tDetails={9}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), `$Level, `$Action, `$operationId, `$env:USERNAME, `$sourceHost, `$env:COMPUTERNAME, `$Result, `$Path, `$Details
    Add-Content -Path `$logFile -Value `$line -Encoding UTF8
}
function Write-BothLogs {
    param([string]`$Level,[string]`$Action,[string]`$Result,[string]`$Details,[string]`$Path='')
    Write-TargetLine -Level `$Level -Action `$Action -Result `$Result -Details `$Details -FileName `$remoteAuditLogFileName -Path `$Path
    Write-TargetLine -Level `$Level -Action `$Action -Result `$Result -Details `$Details -FileName `$fallbackLogFileName -Path `$Path
}
function Remove-FallbackTriggers {
    param([string]`$Reason)
    try {
        if (Get-ScheduledTask -TaskName `$taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName `$taskName -Confirm:`$false -ErrorAction SilentlyContinue
            Write-BothLogs -Level 'WARN' -Action 'ScheduledTask' -Result 'Removed' -Details ('Vorhandener Scheduled Task wurde entfernt. Grund=' + `$Reason) -Path `$taskName
        }
    }
    catch {
        Write-BothLogs -Level 'WARN' -Action 'ScheduledTask' -Result 'RemoveFailed' -Details ('Scheduled Task konnte nicht entfernt werden: ' + `$_.Exception.Message) -Path `$taskName
    }
    try {
        if (Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name `$runOnceName -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name `$runOnceName -ErrorAction SilentlyContinue
            Write-BothLogs -Level 'WARN' -Action 'RunOnce' -Result 'Removed' -Details ('Vorhandener RunOnce wurde entfernt. Grund=' + `$Reason) -Path `$runOnceName
        }
    }
    catch {
        Write-BothLogs -Level 'WARN' -Action 'RunOnce' -Result 'RemoveFailed' -Details ('RunOnce konnte nicht entfernt werden: ' + `$_.Exception.Message) -Path `$runOnceName
    }
}
function Set-HardenedAcl {
    param([string]`$Path,[bool]`$IsDirectory)
    if (-not (Test-Path -LiteralPath `$Path)) { throw 'Pfad nicht gefunden: ' + `$Path }
    if (`$IsDirectory) {
        & icacls.exe `$Path '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    }
    else {
        & icacls.exe `$Path '/inheritance:r' '/grant:r' '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    }
    if (`$LASTEXITCODE -ne 0) { throw 'icacls konnte die ACL nicht setzen: ' + `$Path }
}
function Test-HardenedAcl {
    param([string]`$Path)
    if (-not (Test-Path -LiteralPath `$Path)) { return `$false }
    `$acl = Get-Acl -LiteralPath `$Path
    `$requiredSids = @('S-1-5-18','S-1-5-32-544')
    foreach (`$requiredSid in `$requiredSids) {
        `$hasRequired = `$false
        foreach (`$rule in `$acl.Access) {
            try { `$ruleSid = `$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if (`$rule.AccessControlType -eq 'Allow' -and `$ruleSid -eq `$requiredSid -and (`$rule.FileSystemRights.ToString() -match 'FullControl')) {
                `$hasRequired = `$true
                break
            }
        }
        if (-not `$hasRequired) { return `$false }
    }
    foreach (`$rule in `$acl.Access) {
        try { `$ruleSid = `$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if (`$rule.AccessControlType -ne 'Allow') { continue }
        if (`$requiredSids -contains `$ruleSid) { continue }
        if (`$rule.FileSystemRights.ToString() -match 'FullControl|Modify|Write|CreateFiles|CreateDirectories|AppendData|Delete|ChangePermissions|TakeOwnership') {
            return `$false
        }
    }
    return `$true
}
function Invoke-AclHardening {
    param([string]`$DirectoryPath,[string]`$ScriptPath,[string]`$ConfigPath)
    Write-BothLogs -Level 'INFO' -Action 'AclHardening' -Result 'Started' -Details 'ACL-Härtung wird gestartet.' -Path `$DirectoryPath
    Write-BothLogs -Level 'INFO' -Action 'AclHardening' -Result 'TargetPathRecognized' -Details 'Zielpfad erkannt.' -Path `$DirectoryPath
    Set-HardenedAcl -Path `$DirectoryPath -IsDirectory `$true
    Write-BothLogs -Level 'INFO' -Action 'AclHardening' -Result 'DirectoryAclSet' -Details 'ACLs für Zielordner gesetzt.' -Path `$DirectoryPath
    Set-HardenedAcl -Path `$ScriptPath -IsDirectory `$false
    Write-BothLogs -Level 'INFO' -Action 'AclHardening' -Result 'ScriptAclSet' -Details 'ACLs für fallbackcore.ps1 gesetzt.' -Path `$ScriptPath
    Set-HardenedAcl -Path `$ConfigPath -IsDirectory `$false
    Write-BothLogs -Level 'INFO' -Action 'AclHardening' -Result 'ConfigAclSet' -Details 'ACLs für fallback.json gesetzt.' -Path `$ConfigPath
    if (-not (Test-HardenedAcl -Path `$DirectoryPath) -or -not (Test-HardenedAcl -Path `$ScriptPath) -or -not (Test-HardenedAcl -Path `$ConfigPath)) {
        Write-BothLogs -Level 'ERROR' -Action 'AclHardening' -Result 'VerificationFailed' -Details 'ACL-Prüfung fehlgeschlagen.' -Path `$DirectoryPath
        return `$false
    }
    Write-BothLogs -Level 'INFO' -Action 'AclHardening' -Result 'VerificationSucceeded' -Details 'ACL-Prüfung erfolgreich.' -Path `$DirectoryPath
    return `$true
}
function Get-SignatureInfo {
    param([string]`$Path)
    if (-not (Test-Path -LiteralPath `$Path)) {
        return [pscustomobject]@{ Exists=`$false; Status='Missing'; Thumbprint=''; PublicKey=''; Subject='' }
    }
    `$sig = Get-AuthenticodeSignature -FilePath `$Path
    `$cert = `$sig.SignerCertificate
    `$thumb = if (`$cert) { (`$cert.Thumbprint -replace '\s','').ToUpperInvariant() } else { '' }
    `$publicKey = if (`$cert) { [System.Convert]::ToBase64String(`$cert.GetPublicKey()) } else { '' }
    `$subject = if (`$cert) { `$cert.Subject } else { '' }
    [pscustomobject]@{ Exists=`$true; Status=`$sig.Status.ToString(); Thumbprint=`$thumb; PublicKey=`$publicKey; Subject=`$subject }
}
function Test-FallbackScriptSignature {
    param([string]`$ScriptPath)
    Write-BothLogs -Level 'INFO' -Action 'FallbackScriptSignature' -Result 'Started' -Details 'Signaturprüfung von fallbackcore.ps1 gestartet.' -Path `$ScriptPath
    `$info = Get-SignatureInfo -Path `$ScriptPath
    if (-not `$info.Exists) {
        Write-BothLogs -Level 'ERROR' -Action 'FallbackScriptSignature' -Result 'Missing' -Details 'fallbackcore.ps1 fehlt.' -Path `$ScriptPath
        return `$false
    }
    Write-BothLogs -Level 'INFO' -Action 'FallbackScriptSignature' -Result ('Status=' + `$info.Status) -Details ('Signer=' + `$info.Subject + '; Thumbprint=' + `$info.Thumbprint + '; PublicKey=' + `$info.PublicKey) -Path `$ScriptPath
    if (`$info.Status -ne 'Valid') {
        Write-BothLogs -Level 'ERROR' -Action 'FallbackScriptSignature' -Result 'Invalid' -Details 'Signatur von fallbackcore.ps1 ist ungültig.' -Path `$ScriptPath
        return `$false
    }
    if (-not [string]::IsNullOrWhiteSpace(`$expectedThumbprint) -and `$info.Thumbprint -ne `$expectedThumbprint) {
        Write-BothLogs -Level 'ERROR' -Action 'FallbackScriptSignature' -Result 'SignerMismatch' -Details ('Thumbprint stimmt nicht mit App-EXE überein. Expected=' + `$expectedThumbprint + '; Actual=' + `$info.Thumbprint) -Path `$ScriptPath
        return `$false
    }
    if (-not [string]::IsNullOrWhiteSpace(`$expectedPublicKey) -and `$info.PublicKey -ne `$expectedPublicKey) {
        Write-BothLogs -Level 'ERROR' -Action 'FallbackScriptSignature' -Result 'SignerMismatch' -Details 'Public Key stimmt nicht mit App-EXE überein.' -Path `$ScriptPath
        return `$false
    }
    Write-BothLogs -Level 'INFO' -Action 'FallbackScriptSignature' -Result 'Valid' -Details 'Signer von fallbackcore.ps1 stimmt mit App-EXE überein.' -Path `$ScriptPath
    return `$true
}
function Register-FallbackTask {
    param([string]`$TaskName,[string]`$ScriptPath,[int]`$DelayMinutes)
    `$taskArgument = '-NoProfile -ExecutionPolicy Bypass -File "' + `$ScriptPath + '"'
    `$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `$taskArgument
    `$startupTrigger = New-ScheduledTaskTrigger -AtStartup
    `$onceTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(`$DelayMinutes))
    `$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
    Register-ScheduledTask -TaskName `$TaskName -Action `$action -Trigger @(`$startupTrigger, `$onceTrigger) -Principal `$principal -Force | Out-Null
}
function Ensure-StateShape {
    param([Parameter(Mandatory=`$true)]`$State,[Parameter(Mandatory=`$true)]`$WinRmService,[int]`$ListenerCount,[string[]]`$EnabledFirewallRules)
    foreach (`$name in @('OperationId','CreatedAt','JumpHost','SupportUser','SupportClientDirectory','RemoteAuditLogDirectory','RemoteAuditLogFileName','RemoteFallbackLogFileName','FallbackScriptPath','FallbackConfigPath','FallbackScheduledTaskName','FallbackRunOnceValueName','RestoreCompleted','Armed','LastRestoreResult','RestoredAt','ScheduledTaskCreated','RunOnceCreated','ScheduledTaskRetryAttempted')) {
        if (-not (`$State.PSObject.Properties.Name -contains `$name)) {
            `$default = switch (`$name) {
                'OperationId' { `$operationId }
                'CreatedAt' { (Get-Date).ToString('o') }
                'JumpHost' { `$sourceHost }
                'SupportUser' { `$env:USERNAME }
                'SupportClientDirectory' { `$supportDir }
                'RemoteAuditLogDirectory' { `$auditDir }
                'RemoteAuditLogFileName' { `$remoteAuditLogFileName }
                'RemoteFallbackLogFileName' { `$fallbackLogFileName }
                'FallbackScriptPath' { Join-Path `$supportDir `$scriptFileName }
                'FallbackConfigPath' { Join-Path `$supportDir `$configFileName }
                'FallbackScheduledTaskName' { `$taskName }
                'FallbackRunOnceValueName' { `$runOnceBaseName }
                'RestoreCompleted' { `$false }
                'Armed' { `$true }
                'LastRestoreResult' { '' }
                'RestoredAt' { '' }
                'ScheduledTaskCreated' { `$false }
                'RunOnceCreated' { `$false }
                'ScheduledTaskRetryAttempted' { `$false }
            }
            `$State | Add-Member -NotePropertyName `$name -NotePropertyValue `$default -Force
        }
    }
    if (-not (`$State.PSObject.Properties.Name -contains 'OriginalState') -or `$null -eq `$State.OriginalState) {
        `$original = [pscustomobject]@{ WinRMStatus = `$WinRmService.State; WinRMStartMode = `$WinRmService.StartMode; ListenerCount = `$ListenerCount; EnabledFirewallRuleNames = `$EnabledFirewallRules }
        `$State | Add-Member -NotePropertyName OriginalState -NotePropertyValue `$original -Force
    }
    return `$State
}
New-Item -Path `$supportDir -ItemType Directory -Force | Out-Null
Write-BothLogs -Level 'INFO' -Action 'FallbackDirectory' -Result 'Ensured' -Details 'SupportClientDirectory wurde geprüft bzw. erstellt.' -Path `$supportDir
`$configPath = Join-Path `$supportDir `$configFileName
`$scriptPath = Join-Path `$supportDir `$scriptFileName
if (-not (Test-Path -LiteralPath `$scriptPath)) {
    Write-BothLogs -Level 'ERROR' -Action 'FallbackScript' -Result 'Missing' -Details 'fallbackcore.ps1 wurde auf dem Zielgerät nicht gefunden.' -Path `$scriptPath
    throw 'fallbackcore.ps1 wurde auf dem Zielgerät nicht gefunden.'
}
`$winRmService = Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'"
`$listenerCount = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction SilentlyContinue).Count
`$enabledFirewallRules = @(Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True' | Select-Object -ExpandProperty Name)
if (Test-Path `$configPath) {
    `$state = Get-Content -Path `$configPath -Raw | ConvertFrom-Json
    `$state = Ensure-StateShape -State `$state -WinRmService `$winRmService -ListenerCount `$listenerCount -EnabledFirewallRules `$enabledFirewallRules
    Write-BothLogs -Level 'INFO' -Action 'FallbackConfig' -Result 'Updated' -Details 'Bestehende fallbackconfig.json wurde erkannt und für den aktuellen Vorgang aktualisiert.' -Path `$configPath
}
else {
    `$state = [pscustomobject]@{
        OperationId = `$operationId
        CreatedAt = (Get-Date).ToString('o')
        JumpHost = `$sourceHost
        SupportUser = `$env:USERNAME
        SupportClientDirectory = `$supportDir
        RemoteAuditLogDirectory = `$auditDir
        RemoteAuditLogFileName = `$remoteAuditLogFileName
        RemoteFallbackLogFileName = `$fallbackLogFileName
        FallbackScriptPath = `$scriptPath
        FallbackConfigPath = `$configPath
        FallbackScheduledTaskName = `$taskName
        FallbackRunOnceValueName = `$runOnceBaseName
        RestoreCompleted = `$false
        Armed = `$true
        LastRestoreResult = ''
        RestoredAt = ''
        ScheduledTaskCreated = `$false
        RunOnceCreated = `$false
        ScheduledTaskRetryAttempted = `$false
        OriginalState = [pscustomobject]@{ WinRMStatus = `$winRmService.State; WinRMStartMode = `$winRmService.StartMode; ListenerCount = `$listenerCount; EnabledFirewallRuleNames = `$enabledFirewallRules }
    }
    `$state | ConvertTo-Json -Depth 8 | Set-Content -Path `$configPath -Encoding UTF8
    Write-BothLogs -Level 'INFO' -Action 'FallbackConfig' -Result 'Created' -Details 'fallbackconfig.json wurde erfolgreich erstellt.' -Path `$configPath
}
if (-not (Invoke-AclHardening -DirectoryPath `$supportDir -ScriptPath `$scriptPath -ConfigPath `$configPath)) {
    Remove-FallbackTriggers -Reason 'ACL validation failed'
    Write-BothLogs -Level 'ERROR' -Action 'FallbackArm' -Result 'BlockedByAcl' -Details 'Produktive Fallback-Nutzung wegen ACL-Fehler blockiert.' -Path `$supportDir
    throw 'ACL-Härtung für Fallback-Artefakte fehlgeschlagen.'
}
if (-not (Test-FallbackScriptSignature -ScriptPath `$scriptPath)) {
    Remove-FallbackTriggers -Reason 'Fallback script signature invalid'
    Write-BothLogs -Level 'ERROR' -Action 'FallbackArm' -Result 'BlockedBySignature' -Details 'Restore-Fallback wegen ungültigem Script blockiert.' -Path `$scriptPath
    throw 'fallbackcore.ps1 ist nicht gültig signiert oder der Signer stimmt nicht mit der App-EXE überein.'
}
`$triggerCommand = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + `$scriptPath + '"'
try {
    `$taskPreviouslyExisted = [bool](Get-ScheduledTask -TaskName `$taskName -ErrorAction SilentlyContinue)
    Register-FallbackTask -TaskName `$taskName -ScriptPath `$scriptPath -DelayMinutes `$taskDelayMinutes
    `$state.ScheduledTaskCreated = `$true
    `$taskResult = if (`$taskPreviouslyExisted) { 'Updated' } else { 'Created' }
    `$taskMessage = if (`$taskPreviouslyExisted) { 'Geplanter Task wurde erfolgreich aktualisiert: ' } else { 'Geplanter Task wurde erfolgreich erstellt: ' }
    Write-BothLogs -Level 'INFO' -Action 'ScheduledTask' -Result `$taskResult -Details (`$taskMessage + `$taskName + '; ActionPath=' + `$scriptPath + '; SecurityContext=SYSTEM') -Path `$taskName
}
catch {
    `$state.ScheduledTaskCreated = `$false
    Write-BothLogs -Level 'WARN' -Action 'ScheduledTask' -Result 'NotCreated' -Details ('Geplanter Task konnte nicht erstellt werden: ' + `$_.Exception.Message + '; ActionPath=' + `$scriptPath + '; SecurityContext=SYSTEM') -Path `$taskName
}
try {
    `$runOncePreviouslyExisted = [bool](Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name `$runOnceName -ErrorAction SilentlyContinue)
    New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name `$runOnceName -Value `$triggerCommand -Force
    `$state.RunOnceCreated = `$true
    `$runOnceResult = if (`$runOncePreviouslyExisted) { 'Updated' } else { 'Created' }
    `$runOnceMessage = if (`$runOncePreviouslyExisted) { 'RunOnce-Eintrag wurde erfolgreich aktualisiert: ' } else { 'RunOnce-Eintrag wurde erfolgreich erstellt: ' }
    Write-BothLogs -Level 'INFO' -Action 'RunOnce' -Result `$runOnceResult -Details (`$runOnceMessage + `$runOnceName + '; ActionPath=' + `$triggerCommand + '; SecurityContext=HKLM') -Path `$runOnceName
}
catch {
    `$state.RunOnceCreated = `$false
    Write-BothLogs -Level 'WARN' -Action 'RunOnce' -Result 'NotCreated' -Details ('RunOnce-Eintrag konnte nicht erstellt werden: ' + `$_.Exception.Message + '; ActionPath=' + `$triggerCommand) -Path `$runOnceName
}
`$state | ConvertTo-Json -Depth 8 | Set-Content -Path `$configPath -Encoding UTF8
if (-not `$state.RunOnceCreated -and -not `$state.ScheduledTaskCreated) {
    Remove-FallbackTriggers -Reason 'No trigger could be created'
    throw 'Weder RunOnce noch geplanter Task konnten erstellt werden.'
}
Write-BothLogs -Level 'INFO' -Action 'FallbackArm' -Result 'Prepared' -Details ('Fallback vorbereitet. TaskCreated=' + `$state.ScheduledTaskCreated + '; RunOnceCreated=' + `$state.RunOnceCreated) -Path `$supportDir
"@

    Invoke-PsExecPowerShell -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -ScriptText $remoteScript
}

function Retry-RemoteFallbackScheduledTask {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$PsExecPath,
        [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
        [Parameter(Mandatory = $true)][string]$SupportClientDirectory,
        [Parameter(Mandatory = $true)][string]$FallbackConfigFileName,
        [Parameter(Mandatory = $true)][string]$RemoteAuditLogDirectory,
        [Parameter(Mandatory = $true)][string]$RemoteAuditLogFileName,
        [Parameter(Mandatory = $true)][string]$RemoteFallbackLogFileName,
        [Parameter(Mandatory = $true)][string]$FallbackScheduledTaskName,
        [Parameter(Mandatory = $true)][string]$OperationId,
        [Parameter(Mandatory = $false)][string]$FallbackTaskDelayMinutes = '15',
        [Parameter(Mandatory = $false)][string]$SourceHost = '',
        [Parameter(Mandatory = $false)][string]$ExpectedAppSignerThumbprint = '',
        [Parameter(Mandatory = $false)][string]$ExpectedAppSignerPublicKey = ''
    )

    $remoteScript = @"
`$ErrorActionPreference = 'Stop'
`$supportDir = '$($SupportClientDirectory.Replace("'","''"))'
`$configFileName = '$($FallbackConfigFileName.Replace("'","''"))'
`$configPath = if ([string]::IsNullOrWhiteSpace(`$supportDir) -or [string]::IsNullOrWhiteSpace(`$configFileName)) { '' } else { Join-Path `$supportDir `$configFileName }
`$auditDir = '$($RemoteAuditLogDirectory.Replace("'","''"))'
`$remoteAuditLog = '$($RemoteAuditLogFileName.Replace("'","''"))'
`$fallbackLog = '$($RemoteFallbackLogFileName.Replace("'","''"))'
`$taskName = '$($FallbackScheduledTaskName.Replace("'","''"))'
`$operationId = '$($OperationId.Replace("'","''"))'
`$taskDelayMinutes = [int]'$($FallbackTaskDelayMinutes.Replace("'","''"))'
`$sourceHost = '$($SourceHost.Replace("'","''"))'
`$expectedThumbprint = ('$($ExpectedAppSignerThumbprint.Replace("'","''"))' -replace '\s','').ToUpperInvariant()
`$expectedPublicKey = '$($ExpectedAppSignerPublicKey.Replace("'","''"))'
function Write-TargetLine {
    param([string]`$Level,[string]`$Action,[string]`$Result,[string]`$Details,[string]`$FileName,[string]`$Path='')
    New-Item -Path `$auditDir -ItemType Directory -Force | Out-Null
    `$logFile = Join-Path `$auditDir `$FileName
    `$line = "{0}`t{1}`tSource=Bootstrap`tAction={2}`tOperationId={3}`tUser={4}`tSourceHost={5}`tDestinationHost={6}`tResult={7}`tPath={8}`tDetails={9}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), `$Level, `$Action, `$operationId, `$env:USERNAME, `$sourceHost, `$env:COMPUTERNAME, `$Result, `$Path, `$Details
    Add-Content -Path `$logFile -Value `$line -Encoding UTF8
}
function Write-BothLogs {
    param([string]`$Level,[string]`$Action,[string]`$Result,[string]`$Details,[string]`$Path='')
    Write-TargetLine -Level `$Level -Action `$Action -Result `$Result -Details `$Details -FileName `$remoteAuditLogFileName -Path `$Path
    Write-TargetLine -Level `$Level -Action `$Action -Result `$Result -Details `$Details -FileName `$fallbackLog -Path `$Path
}
function Register-FallbackTask {
    param([string]`$TaskName,[string]`$ScriptPath,[int]`$DelayMinutes)
    `$taskArgument = '-NoProfile -ExecutionPolicy Bypass -File "' + `$ScriptPath + '"'
    `$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `$taskArgument
    `$startupTrigger = New-ScheduledTaskTrigger -AtStartup
    `$onceTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(`$DelayMinutes))
    `$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount
    Register-ScheduledTask -TaskName `$TaskName -Action `$action -Trigger @(`$startupTrigger, `$onceTrigger) -Principal `$principal -Force | Out-Null
}
function Set-HardenedAcl {
    param([string]`$Path,[bool]`$IsDirectory)
    if (-not (Test-Path -LiteralPath `$Path)) { throw 'Pfad nicht gefunden: ' + `$Path }
    if (`$IsDirectory) {
        & icacls.exe `$Path '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    }
    else {
        & icacls.exe `$Path '/inheritance:r' '/grant:r' '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    }
    if (`$LASTEXITCODE -ne 0) { throw 'icacls konnte die ACL nicht setzen: ' + `$Path }
}
function Test-HardenedAcl {
    param([string]`$Path)
    if (-not (Test-Path -LiteralPath `$Path)) { return `$false }
    `$acl = Get-Acl -LiteralPath `$Path
    `$requiredSids = @('S-1-5-18','S-1-5-32-544')
    foreach (`$requiredSid in `$requiredSids) {
        `$hasRequired = `$false
        foreach (`$rule in `$acl.Access) {
            try { `$ruleSid = `$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if (`$rule.AccessControlType -eq 'Allow' -and `$ruleSid -eq `$requiredSid -and (`$rule.FileSystemRights.ToString() -match 'FullControl')) { `$hasRequired = `$true; break }
        }
        if (-not `$hasRequired) { return `$false }
    }
    foreach (`$rule in `$acl.Access) {
        try { `$ruleSid = `$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if (`$rule.AccessControlType -ne 'Allow') { continue }
        if (`$requiredSids -contains `$ruleSid) { continue }
        if (`$rule.FileSystemRights.ToString() -match 'FullControl|Modify|Write|CreateFiles|CreateDirectories|AppendData|Delete|ChangePermissions|TakeOwnership') { return `$false }
    }
    return `$true
}
function Get-SignatureInfo {
    param([string]`$Path)
    if (-not (Test-Path -LiteralPath `$Path)) {
        return [pscustomobject]@{ Exists=`$false; Status='Missing'; Thumbprint=''; PublicKey=''; Subject='' }
    }
    `$sig = Get-AuthenticodeSignature -FilePath `$Path
    `$cert = `$sig.SignerCertificate
    `$thumb = if (`$cert) { (`$cert.Thumbprint -replace '\s','').ToUpperInvariant() } else { '' }
    `$publicKey = if (`$cert) { [System.Convert]::ToBase64String(`$cert.GetPublicKey()) } else { '' }
    `$subject = if (`$cert) { `$cert.Subject } else { '' }
    [pscustomobject]@{ Exists=`$true; Status=`$sig.Status.ToString(); Thumbprint=`$thumb; PublicKey=`$publicKey; Subject=`$subject }
}
if (-not (Test-Path `$configPath)) {
    Write-BothLogs -Level 'WARN' -Action 'ScheduledTaskRetry' -Result 'Skipped' -Details 'Kein fallback.json vorhanden. Task-Retry übersprungen.' -Path `$configPath
    return
}
`$config = Get-Content -Path `$configPath -Raw | ConvertFrom-Json
`$config | Add-Member -NotePropertyName ScheduledTaskRetryAttempted -NotePropertyValue `$true -Force
if (`$config.ScheduledTaskCreated -eq `$true) {
    `$config | ConvertTo-Json -Depth 8 | Set-Content -Path `$configPath -Encoding UTF8
    Write-BothLogs -Level 'INFO' -Action 'ScheduledTaskRetry' -Result 'Skipped' -Details 'Task-Retry war nicht nötig, Task existiert bereits.' -Path `$taskName
    return
}
`$scriptPath = `$config.FallbackScriptPath
try {
    Set-HardenedAcl -Path `$supportDir -IsDirectory `$true
    Set-HardenedAcl -Path `$scriptPath -IsDirectory `$false
    Set-HardenedAcl -Path `$configPath -IsDirectory `$false
    if (-not (Test-HardenedAcl -Path `$supportDir) -or -not (Test-HardenedAcl -Path `$scriptPath) -or -not (Test-HardenedAcl -Path `$configPath)) {
        throw 'ACL-Prüfung fehlgeschlagen.'
    }
    Write-BothLogs -Level 'INFO' -Action 'AclHardening' -Result 'VerificationSucceeded' -Details 'ACL-Prüfung vor Task-Retry erfolgreich.' -Path `$supportDir
    `$sigInfo = Get-SignatureInfo -Path `$scriptPath
    if (`$sigInfo.Status -ne 'Valid' -or ((-not [string]::IsNullOrWhiteSpace(`$expectedThumbprint)) -and `$sigInfo.Thumbprint -ne `$expectedThumbprint) -or ((-not [string]::IsNullOrWhiteSpace(`$expectedPublicKey)) -and `$sigInfo.PublicKey -ne `$expectedPublicKey)) {
        throw 'fallbackcore.ps1 ist für den Task-Retry nicht zulässig signiert.'
    }
    Register-FallbackTask -TaskName `$taskName -ScriptPath `$scriptPath -DelayMinutes `$taskDelayMinutes
    `$config.ScheduledTaskCreated = `$true
    Write-BothLogs -Level 'INFO' -Action 'ScheduledTaskRetry' -Result 'Created' -Details ('Geplanter Task wurde im zweiten Versuch erfolgreich erstellt oder aktualisiert: ' + `$taskName + '; ActionPath=' + `$scriptPath + '; SecurityContext=SYSTEM') -Path `$taskName
}
catch {
    Write-BothLogs -Level 'WARN' -Action 'ScheduledTaskRetry' -Result 'NotCreated' -Details ('Geplanter Task konnte im zweiten Versuch nicht erstellt werden: ' + `$_.Exception.Message) -Path `$taskName
}
`$config | ConvertTo-Json -Depth 8 | Set-Content -Path `$configPath -Encoding UTF8
"@

    Invoke-PsExecPowerShell -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -ScriptText $remoteScript
}

function Enable-TemporaryPsRemoting {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$PsExecPath,
        [Parameter(Mandatory = $true)][string]$PowerShellExecutable,
        [Parameter(Mandatory = $false)][string]$SupportClientDirectory,
        [Parameter(Mandatory = $false)][string]$FallbackConfigFileName,
        [Parameter(Mandatory = $true)][string]$RemoteAuditLogDirectory,
        [Parameter(Mandatory = $true)][string]$RemoteAuditLogFileName,
        [Parameter(Mandatory = $true)][string]$RemoteFallbackLogFileName,
        [Parameter(Mandatory = $true)][string]$OperationId,
        [Parameter(Mandatory = $false)][string]$SourceHost = ''
    )

    $remoteScript = @"
`$ErrorActionPreference = 'Stop'
`$supportDir = '$($SupportClientDirectory.Replace("'","''"))'
`$configFileName = '$($FallbackConfigFileName.Replace("'","''"))'
`$configPath = if ([string]::IsNullOrWhiteSpace(`$supportDir) -or [string]::IsNullOrWhiteSpace(`$configFileName)) { '' } else { Join-Path `$supportDir `$configFileName }
`$auditDir = '$($RemoteAuditLogDirectory.Replace("'","''"))'
`$remoteAuditLog = '$($RemoteAuditLogFileName.Replace("'","''"))'
`$fallbackLog = '$($RemoteFallbackLogFileName.Replace("'","''"))'
`$operationId = '$($OperationId.Replace("'","''"))'
`$sourceHost = '$($SourceHost.Replace("'","''"))'
function Write-TargetLine {
    param([string]`$Level,[string]`$Action,[string]`$Result,[string]`$Details,[string]`$FileName,[string]`$Path='')
    New-Item -Path `$auditDir -ItemType Directory -Force | Out-Null
    `$logFile = Join-Path `$auditDir `$FileName
    `$line = "{0}`t{1}`tSource=Bootstrap`tAction={2}`tOperationId={3}`tUser={4}`tSourceHost={5}`tDestinationHost={6}`tResult={7}`tPath={8}`tDetails={9}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), `$Level, `$Action, `$operationId, `$env:USERNAME, `$sourceHost, `$env:COMPUTERNAME, `$Result, `$Path, `$Details
    Add-Content -Path `$logFile -Value `$line -Encoding UTF8
}
`$config = `$null
if (-not [string]::IsNullOrWhiteSpace(`$configPath) -and (Test-Path `$configPath)) {
    `$config = Get-Content -Path `$configPath -Raw | ConvertFrom-Json
}
`$beforeListenerCount = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction SilentlyContinue).Count
`$beforeStatus = (Get-Service -Name WinRM -ErrorAction SilentlyContinue).Status
try {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name WinRM -ErrorAction SilentlyContinue
    if (`$null -ne `$config) {
        `$config.Armed = `$true
        `$config | ConvertTo-Json -Depth 8 | Set-Content -Path `$configPath -Encoding UTF8
    }
    Write-TargetLine -Level 'INFO' -Action 'EnablePsRemoting' -Result 'Enabled' -Details ('PSRemoting aktiviert. Vorheriger Status=' + `$beforeStatus + '; Listener=' + `$beforeListenerCount) -FileName `$remoteAuditLog -Path `$configPath
    Write-TargetLine -Level 'INFO' -Action 'EnablePsRemoting' -Result 'Enabled' -Details ('PSRemoting aktiviert. Vorheriger Status=' + `$beforeStatus + '; Listener=' + `$beforeListenerCount) -FileName `$fallbackLog -Path `$configPath
}
catch {
    Write-TargetLine -Level 'ERROR' -Action 'EnablePsRemoting' -Result 'Failed' -Details ('PSRemoting konnte nicht aktiviert werden: ' + `$_.Exception.Message) -FileName `$remoteAuditLog -Path `$configPath
    Write-TargetLine -Level 'ERROR' -Action 'EnablePsRemoting' -Result 'Failed' -Details ('PSRemoting konnte nicht aktiviert werden: ' + `$_.Exception.Message) -FileName `$fallbackLog -Path `$configPath
    throw
}
"@

    Invoke-PsExecPowerShell -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -ScriptText $remoteScript
}

# SIG # Begin signature block
# MIIl6QYJKoZIhvcNAQcCoIIl2jCCJdYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCQIufS/zd2+ORX
# c0brIbSMu+00M/DiyiWaGsWyl7F++6CCH/UwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# CXQ8djb/utVOhyaZq3Q9aAyV5uy+52Rcgyf0c2dTtPAwDQYJKoZIhvcNAQEBBQAE
# ggEAM4Jef4Cywmw1/6iI/R4rAHjYf91kHWLWbJRjKvOpnOFTDUd+8JBke5QoQR+s
# oALi9zDxJgssPVKS18LLfizJHs0rrHVd1ecsRVs5tHu1TXt00WvBdsa4nkSYx7wM
# CHwi8tWxrAsJSoaiQg3CqbU4GVHyZO6O3lQvhGWStfhfZc2Yp3xNdFgvBQKZHzXA
# 9pQQPMuHCtHm6cbFBYu5mlh0MTqM8Ebmb94JykRp7IwIV0XcfE051eMVmM2/7og9
# H2NsHrBqn7RNWzHA3ejDW0q3iMjdy6NZiDlOCZzMoLDVWKREmYV/6mxy9LHikEME
# IOJwNgJAncPzM0LhnH4avUuKR6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIB
# ATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCg
# aTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0
# MTcxNDEzMzJaMC8GCSqGSIb3DQEJBDEiBCAfLNBACNM0f/Z24rrjSmrHvXUgVqTs
# dtTUdquVU8s0fzANBgkqhkiG9w0BAQEFAASCAgDKSiBaWSKXH6frvoyRTuqB9ttY
# b7J+9bKMgy2NaHqVRLR8tQ5Ss4iF75kmVdNImslALeY04Z1JJq/yrIVb/aDTgIcQ
# m/B/pmKTtCTQ9q1vOhe26JSbfAkBPbL9HIMT5YNxfi9XWfNkuJyghesb+kk6V/wr
# rLxFJVT2BwbR1yIf9gp2ONqJxdASm44udKBs33RxLSVktrAatAmUUThQJI5oijkJ
# aDXyo0AGwfie1uB8SHGYWyh3sPQQTShkv0sNvgA5UA3L+QRNIRroFcvNIm6mNg43
# 8n4V/HwkmhZnhK2gzJxbNlXFqxFMXFiYc4wRwtckwQRIRKgJUqEVNJMqhPoSgwHL
# PHJVzlLaYqGs/0j+S7f7kc4EV2voqvu4RxkmjxlethUnUUnkeQ5KNe9PvPBXM8bB
# flknGq1znn9j0wthnE9n1zeh/Y4FTRVLemjJrLvhKf/ss0d8rgmbDvjkJmnHPoiR
# t7eTf+H1TCfBJneLY+ZMLuwKJs288UlZBfSK2qwgwtfEsxwzdzKxYH9L0jfuXg+b
# phM2nUmUsRHQgpmiZe/MEepU9j4fyb3qgy/eIwO/m1OcIInkz5+vW0oo/Pq58RtR
# Q47/Fi6OuY/SrHPczvEngM6vxbds/A6JNt/+D+f3GeXzJXH70Wd2DtuV/7hzVGzo
# g4UfHv6msld5fH2udw==
# SIG # End signature block
