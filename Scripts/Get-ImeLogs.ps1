param(
    [Parameter(Mandatory = $true)] [string]$ComputerName,
    [Parameter(Mandatory = $false)] [string]$AppGuid,
    [Parameter(Mandatory = $true)] [string]$ImeLogPath,
    [Parameter(Mandatory = $false)] [string]$ServiceName = 'IntuneManagementExtension',
    [Parameter(Mandatory = $true)] [string]$RemoteAuditLogDirectory,
    [Parameter(Mandatory = $true)] [string]$RemoteAuditLogFileName,
    [Parameter(Mandatory = $true)] [string]$RemoteTempDirectory,
    [Parameter(Mandatory = $true)] [string]$LogFilesCsv,
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
    [Parameter(Mandatory = $false)] [string]$ExpectedAppSignerPublicKey = '',
    [Parameter(Mandatory = $false)] [string]$SuppressReadAudit = 'False',
    [Parameter(Mandatory = $false)] [string]$ShortDestinationLogs = 'True',
    [Parameter(Mandatory = $false)] [string]$DestinationLogMaxAgeDays = '10',
    [Parameter(Mandatory = $false)] [string]$PreviousLogStatesJson = ''
)

. (Join-Path $PSScriptRoot 'SupportBootstrap.ps1')

if ($SimulationMode -eq 'True') {
    $logs = @{ AgentExecutor=@('SIMULATION'); AppActionProcessor=@(); AppWorkload=@(); ClientCertCheck=@(); ClientHealth=@(); DeviceHealthMonitoring=@(); HealthScripts=@(); IntuneManagementExtension=@(); CompanyPortal=@(); Enrollment=@(); MdmDiagnostics=@(); EventLogChannels=@(); InstallAgentEvents=@(); DeviceRegistrySettings=@(); NotificationInfraLogs=@(); Sensor=@(); Win321AppInventory=@(); Win32AppsRegistry=@(); RemoteAuditLog=@(); FallbackLog=@() }
    [pscustomobject]@{ Success = $true; ErrorMessage = ''; Logs = $logs } | ConvertTo-Json -Depth 8 -Compress
    exit 0
}

if ([string]::IsNullOrWhiteSpace($OperationId)) { $OperationId = [guid]::NewGuid().ToString() }
$logFiles = $LogFilesCsv -split ';' | Where-Object { $_ -and $_.Trim().Length -gt 0 }

function Invoke-LogRead {
    Invoke-Command -ComputerName $ComputerName -ArgumentList $ImeLogPath, $ServiceName, $RemoteAuditLogDirectory, $RemoteAuditLogFileName, $logFiles, $RemoteFallbackLogFileName, $OperationId, $SuppressReadAudit, $AppGuid, $ShortDestinationLogs, $DestinationLogMaxAgeDays, $PreviousLogStatesJson -ScriptBlock {
        param($ImeLogPath, $ServiceName, $RemoteAuditLogDirectory, $RemoteAuditLogFileName, $LogFiles, $RemoteFallbackLogFileName, $OperationId, $SuppressReadAudit, $AppGuid, $ShortDestinationLogs, $DestinationLogMaxAgeDays, $PreviousLogStatesJson)
        function Convert-PreviousStates {
            param([string]$Json)
            $map = @{}
            if ([string]::IsNullOrWhiteSpace($Json)) { return $map }
            try {
                $parsed = $Json | ConvertFrom-Json -Depth 8
                if ($parsed) {
                    foreach ($item in $parsed.PSObject.Properties) {
                        $map[$item.Name] = $item.Value
                    }
                }
            }
            catch {
                # ignorieren, Fallback auf vollständiges Laden
            }
            return $map
        }
        function Get-FilteredLogPayload {
            param(
                [string]$LogKey,
                [string]$FilePath,
                [hashtable]$PreviousStates,
                [string]$AppGuid,
                [bool]$UseShortLogs,
                [int]$MaxAgeDays
            )

            $exists = Test-Path $FilePath
            $allLines = if ($exists) { @(Get-Content -Path $FilePath -ErrorAction SilentlyContinue) } else { @() }
            $filtered = @(Filter-Lines -Lines $allLines -LogKey $LogKey -AppGuid $AppGuid -UseShortLogs $UseShortLogs -MaxAgeDays $MaxAgeDays)
            $filteredCount = @($filtered).Count
            $lastWriteUtc = if ($exists) { (Get-Item $FilePath).LastWriteTimeUtc.ToString('o') } else { '' }
            $updateMode = 'Full'
            $linesToReturn = $filtered

            if ($PreviousStates.ContainsKey($LogKey)) {
                $previous = $PreviousStates[$LogKey]
                $previousCount = 0
                $previousLastWriteUtc = ''
                if ($previous -and $previous.PSObject.Properties['FilteredLineCount']) { $previousCount = [int]$previous.FilteredLineCount }
                if ($previous -and $previous.PSObject.Properties['LastWriteUtc']) { $previousLastWriteUtc = [string]$previous.LastWriteUtc }

                if ($exists -and $previousLastWriteUtc -eq $lastWriteUtc -and $previousCount -eq $filteredCount) {
                    $updateMode = 'Unchanged'
                    $linesToReturn = @()
                }
                elseif ($exists -and $filteredCount -gt $previousCount -and $previousCount -ge 0) {
                    $updateMode = 'Append'
                    $deltaCount = $filteredCount - $previousCount
                    $linesToReturn = if ($deltaCount -gt 0) { @($filtered | Select-Object -Last $deltaCount) } else { @() }
                }
            }

            [pscustomobject]@{
                Lines = @($linesToReturn)
                UpdateMode = $updateMode
                LastWriteUtc = $lastWriteUtc
                FilteredLineCount = $filteredCount
                Exists = $exists
            }
        }
        function Write-AuditLine {
            param([string]$Level, [string]$Action, [string]$Message)
            $null = New-Item -Path $RemoteAuditLogDirectory -ItemType Directory -Force
            $auditFile = Join-Path $RemoteAuditLogDirectory $RemoteAuditLogFileName
            $line = "{0}`t{1}`tSource=RemoteAction`tTrigger=InvokeCommand`tOperationId={2}`tTarget={3}`tAction={4}`tMessage={5}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $OperationId, $env:COMPUTERNAME, $Action, $Message
            Add-Content -Path $auditFile -Value $line -Encoding UTF8
        }
        function Try-ParseLogTimestamp {
            param([string]$Line)
            if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
            if ($Line.Length -ge 19) {
                $prefix = $Line.Substring(0, [Math]::Min(19, $Line.Length))
                $parsed = [datetime]::MinValue
                if ([datetime]::TryParse($prefix, [ref]$parsed)) { return $parsed }
            }
            if ($Line -match 'date="(?<date>[^"]+)"' -and $Line -match 'time="(?<time>[^"]+)"') {
                $combined = "$($matches['date']) $($matches['time'])"
                $parsed = [datetime]::MinValue
                if ([datetime]::TryParse($combined, [ref]$parsed)) { return $parsed }
            }
            return $null
        }
        function Filter-Lines {
            param(
                [string[]]$Lines,
                [string]$LogKey,
                [string]$AppGuid,
                [bool]$UseShortLogs,
                [int]$MaxAgeDays
            )

            $filtered = @($Lines)
            if ($UseShortLogs) {
                $threshold = (Get-Date).AddDays(-1 * [Math]::Max(1, $MaxAgeDays))
                $filtered = foreach ($line in $filtered) {
                    $ts = Try-ParseLogTimestamp -Line $line
                    if ($null -eq $ts -or $ts -ge $threshold) { $line }
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($AppGuid) -and $LogKey -notin @('RemoteAuditLog','FallbackLog')) {
                $filtered = @($filtered | Where-Object { $_ -like "*$AppGuid*" })
            }

            return @($filtered)
        }
        function Read-AllLines { param([string]$FilePath) if (-not (Test-Path $FilePath)) { return @() } @(Get-Content -Path $FilePath -ErrorAction SilentlyContinue) }
        function New-VirtualLogPayload {
            param([string[]]$Lines, [bool]$Exists = $true)
            [pscustomobject]@{
                Lines = @($Lines)
                UpdateMode = 'Full'
                LastWriteUtc = (Get-Date).ToUniversalTime().ToString('o')
                FilteredLineCount = @($Lines).Count
                Exists = $Exists
            }
        }
        function Format-EventRecords {
            param([System.Collections.IEnumerable]$Records)
            foreach ($record in $Records) {
                $level = if ($record.LevelDisplayName) { $record.LevelDisplayName } else { 'Info' }
                $message = (([string]$record.Message) -replace "`r?`n", ' ').Trim()
                '{0} [{1}] [EventId={2}] [{3}] {4}' -f $record.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $level, $record.Id, $record.LogName, $message
            }
        }
        function Get-EventLines {
            param([string[]]$LogNames, [int]$MaxEventsPerLog = 80)
            $items = @()
            foreach ($logName in $LogNames) {
                try {
                    $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEventsPerLog -ErrorAction Stop
                    $items += @(Format-EventRecords -Records $events)
                }
                catch {
                    $items += @((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' [Warning] [' + $logName + '] Konnte nicht gelesen werden: ' + $_.Exception.Message)
                }
            }
            @($items | Select-Object -First ($MaxEventsPerLog * [Math]::Max(1, $LogNames.Count)))
        }
        function Get-CompanyPortalLines {
            $roots = Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
            $items = New-Object System.Collections.Generic.List[string]
            foreach ($root in $roots) {
                $localState = Join-Path $root.FullName 'AppData\Local\Packages\Microsoft.CompanyPortal_8wekyb3d8bbwe\LocalState'
                if (-not (Test-Path $localState)) { continue }
                $files = Get-ChildItem -Path (Join-Path $localState '*') -File -Include *.log,*.txt -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 3
                foreach ($file in $files) {
                    $lines = @(Get-Content -Path $file.FullName -Tail 80 -ErrorAction SilentlyContinue)
                    foreach ($line in $lines) {
                        $items.Add(('{0} [Info] [CompanyPortal] [{1}] [{2}] {3}' -f $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'), $root.Name, $file.Name, $line))
                    }
                }
            }
            @($items | Select-Object -Last 400)
        }
        function Escape-LogValue {
            param([object]$Value)
            if ($null -eq $Value) { return '' }
            return (([string]$Value) -replace "`r?`n", ' ' -replace ';', ',' -replace "\s+", ' ').Trim()
        }
        function Get-Win32AppsRegistryLines {
            $rootPath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
            if (-not (Test-Path $rootPath)) {
                return @()
            }

            $items = @()
            $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
            $zeroGuid = '00000000-0000-0000-0000-000000000000'

            function Get-AppGuidFromKeyName {
                param([string]$Name)
                if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
                if ($Name -match '^(?<app>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:_\d+)?$') {
                    return $Matches['app']
                }
                return $null
            }

            function Get-RegistryStringValue {
                param(
                    [string]$BasePath,
                    [string]$SubKeyName,
                    [string]$ValueName
                )

                if ([string]::IsNullOrWhiteSpace($BasePath) -or [string]::IsNullOrWhiteSpace($SubKeyName) -or [string]::IsNullOrWhiteSpace($ValueName)) {
                    return $null
                }

                $subPath = Join-Path $BasePath $SubKeyName
                if (-not (Test-Path $subPath)) {
                    return $null
                }

                try {
                    $subProps = Get-ItemProperty -Path $subPath -ErrorAction Stop
                    return [string]$subProps.$ValueName
                }
                catch {
                    return $null
                }
            }

            function Get-RegistryDirectStringValue {
                param(
                    [string]$Path,
                    [string]$ValueName
                )

                if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($ValueName) -or -not (Test-Path $Path)) {
                    return $null
                }

                try {
                    $props = Get-ItemProperty -Path $Path -ErrorAction Stop
                    return [string]$props.$ValueName
                }
                catch {
                    return $null
                }
            }

            try {
                $targetingKeys = @(Get-ChildItem -Path $rootPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match $guidPattern })
                $computerId = $zeroGuid
                $userTargetingId = ($targetingKeys | Where-Object { $_.PSChildName -ne $zeroGuid } | Select-Object -First 1 -ExpandProperty PSChildName)

                foreach ($targetingKey in $targetingKeys) {
                    $targetingId = [string]$targetingKey.PSChildName
                    $targetingMethod = if ($targetingId -eq $zeroGuid) { 'Device' } else { 'User' }
                    $grsAppGuids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                    $grsPath = Join-Path $targetingKey.PSPath 'GRS'
                    if (Test-Path $grsPath) {
                        foreach ($grsKey in @(Get-ChildItem -Path $grsPath -Recurse -ErrorAction SilentlyContinue)) {
                            $candidateGuid = Get-AppGuidFromKeyName -Name $grsKey.PSChildName
                            if (-not [string]::IsNullOrWhiteSpace($candidateGuid)) {
                                [void]$grsAppGuids.Add($candidateGuid)
                            }
                            try {
                                $grsProps = Get-ItemProperty -Path $grsKey.PSPath -ErrorAction Stop
                                foreach ($property in $grsProps.PSObject.Properties) {
                                    if ($property.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                                    $candidateGuid = Get-AppGuidFromKeyName -Name ([string]$property.Name)
                                    if (-not [string]::IsNullOrWhiteSpace($candidateGuid)) {
                                        [void]$grsAppGuids.Add($candidateGuid)
                                    }
                                }
                            }
                            catch { }
                        }
                    }

                    $appKeys = @(Get-ChildItem -Path $targetingKey.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne 'GRS' })
                    foreach ($appKey in $appKeys) {
                        $appKeyName = [string]$appKey.PSChildName
                        $appGuid = Get-AppGuidFromKeyName -Name $appKeyName
                        if ([string]::IsNullOrWhiteSpace($appGuid)) { continue }

                        $complianceStateMessage = Escape-LogValue (Get-RegistryDirectStringValue -Path $appKey.PSPath -ValueName 'ComplianceStateMessage')
                        if ([string]::IsNullOrWhiteSpace($complianceStateMessage)) {
                            $complianceStateMessage = Escape-LogValue (Get-RegistryStringValue -BasePath $appKey.PSPath -SubKeyName 'ComplianceStateMessage' -ValueName 'ComplianceStateMessage')
                        }

                        $enforcementStateMessage = Escape-LogValue (Get-RegistryDirectStringValue -Path $appKey.PSPath -ValueName 'EnforcementStateMessage')
                        if ([string]::IsNullOrWhiteSpace($enforcementStateMessage)) {
                            $enforcementStateMessage = Escape-LogValue (Get-RegistryStringValue -BasePath $appKey.PSPath -SubKeyName 'EnforcementStateMessage' -ValueName 'EnforcementStateMessage')
                        }

                        $productVersion = Escape-LogValue (Get-RegistryDirectStringValue -Path $appKey.PSPath -ValueName 'ProductVersion')
                        if ([string]::IsNullOrWhiteSpace($productVersion)) {
                            $productVersion = Escape-LogValue (Get-RegistryStringValue -BasePath $appKey.PSPath -SubKeyName 'ComplianceStateMessage' -ValueName 'ProductVersion')
                        }
                        if ([string]::IsNullOrWhiteSpace($productVersion)) {
                            $productVersion = Escape-LogValue (Get-RegistryStringValue -BasePath $appKey.PSPath -SubKeyName 'EnforcementStateMessage' -ValueName 'ProductVersion')
                        }

                        $rebootStatus = Escape-LogValue (Get-RegistryDirectStringValue -Path $appKey.PSPath -ValueName 'RebootStatus')
                        if ([string]::IsNullOrWhiteSpace($rebootStatus)) {
                            $rebootStatus = Escape-LogValue (Get-RegistryStringValue -BasePath $appKey.PSPath -SubKeyName 'ComplianceStateMessage' -ValueName 'RebootStatus')
                        }
                        if ([string]::IsNullOrWhiteSpace($rebootStatus)) {
                            $rebootStatus = Escape-LogValue (Get-RegistryStringValue -BasePath $appKey.PSPath -SubKeyName 'EnforcementStateMessage' -ValueName 'RebootStatus')
                        }

                        $rebootReason = Escape-LogValue (Get-RegistryDirectStringValue -Path $appKey.PSPath -ValueName 'RebootReason')
                        if ([string]::IsNullOrWhiteSpace($rebootReason)) {
                            $rebootReason = Escape-LogValue (Get-RegistryStringValue -BasePath $appKey.PSPath -SubKeyName 'ComplianceStateMessage' -ValueName 'RebootReason')
                        }
                        if ([string]::IsNullOrWhiteSpace($rebootReason)) {
                            $rebootReason = Escape-LogValue (Get-RegistryStringValue -BasePath $appKey.PSPath -SubKeyName 'EnforcementStateMessage' -ValueName 'RebootReason')
                        }
                        $hasGrsFailure = $grsAppGuids.Contains($appGuid)

                        if ([string]::IsNullOrWhiteSpace($enforcementStateMessage) -and [string]::IsNullOrWhiteSpace($complianceStateMessage) -and [string]::IsNullOrWhiteSpace($productVersion) -and [string]::IsNullOrWhiteSpace($rebootStatus) -and [string]::IsNullOrWhiteSpace($rebootReason) -and -not $hasGrsFailure) {
                            continue
                        }

                        $items += ('{0} [Info] [Win32AppsRegistry] ComputerId={1}; UserTargetingId={2}; TargetingMethod={3}; AppGuid={4}; AppSubKeyName={5}; HasGrsFailure={6}; EnforcementStateMessage={7}; ComplianceStateMessage={8}; ProductVersion={9}; RebootStatus={10}; RebootReason={11}; RegistryPath={12}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $computerId, $userTargetingId, $targetingMethod, $appGuid, (Escape-LogValue $appKeyName), $hasGrsFailure, $enforcementStateMessage, $complianceStateMessage, $productVersion, $rebootStatus, $rebootReason, (Escape-LogValue $appKey.Name))
                    }
                }
            }
            catch {
                return @()
            }

            @($items)
        }
        function Get-InstallAgentEventLines {
            param(
                [string]$AppGuid,
                [bool]$UseShortLogs,
                [int]$MaxAgeDays,
                [int]$MaxEvents = 2000
            )

            $identifiers = New-Object System.Collections.Generic.List[string]
            foreach ($value in @($AppGuid, 'Microsoft.CompanyPortal', 'Microsoft.CompanyPortal_8wekyb3d8bbwe')) {
                if (-not [string]::IsNullOrWhiteSpace($value) -and -not $identifiers.Contains($value)) {
                    [void]$identifiers.Add($value)
                }
            }

            if ($identifiers.Count -eq 0) {
                return @()
            }

            $escapedPatterns = $identifiers | ForEach-Object { [regex]::Escape($_) }
            $regex = ($escapedPatterns -join '|')
            $threshold = if ($UseShortLogs) { (Get-Date).AddDays(-1 * [Math]::Max(1, $MaxAgeDays)) } else { $null }
            $logs = @(
                'Microsoft-Windows-AppXDeploymentServer/Operational',
                'Microsoft-Windows-Store/Operational'
            )

            $results = foreach ($logName in $logs) {
                try {
                    Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction Stop |
                        Where-Object {
                            $message = [string]$_.Message
                            if ([string]::IsNullOrWhiteSpace($message)) { return $false }
                            if ($threshold -ne $null -and $_.TimeCreated -lt $threshold) { return $false }
                            return $message -match $regex
                        } |
                        ForEach-Object {
                            $message = Escape-LogValue $_.Message
                            $matchedIdentifier = ($identifiers | Where-Object { $message -match [regex]::Escape($_) }) -join ', '
                            $level = if ($_.LevelDisplayName) { $_.LevelDisplayName } else { 'Info' }
                            '{0} [{1}] [InstallAgentEvents] LogName={2}; EventId={3}; ProviderName={4}; MatchedIdentifier={5}; Message={6}' -f $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $level, (Escape-LogValue $logName), $_.Id, (Escape-LogValue $_.ProviderName), (Escape-LogValue $matchedIdentifier), $message
                        }
                }
                catch {
                    @('{0} [Warning] [InstallAgentEvents] LogName={1}; EventId=; ProviderName=; MatchedIdentifier=; Message={2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (Escape-LogValue $logName), (Escape-LogValue ("Could not read log '$logName': $($_.Exception.Message)")))
                }
            }

            @($results | Sort-Object { if ($_ -match '^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}') { [datetime]::Parse($matches[0]) } else { [datetime]::MinValue } } -Descending | Select-Object -First $MaxEvents)
        }
        function Get-IntuneRelevantRegistrySettingLines {
            $definitions = @(
                @{ Category='Delivery Optimization'; Setting='Policy DODownloadMode'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DODownloadMode' },
                @{ Category='Delivery Optimization'; Setting='Policy DOGroupId'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOGroupId' },
                @{ Category='Delivery Optimization'; Setting='Policy DODelayBackgroundDownloadFromHttp'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DODelayBackgroundDownloadFromHttp' },
                @{ Category='Delivery Optimization'; Setting='Policy DODelayForegroundDownloadFromHttp'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DODelayForegroundDownloadFromHttp' },
                @{ Category='Delivery Optimization'; Setting='Policy DOMinRAMAllowedToPeer'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOMinRAMAllowedToPeer' },
                @{ Category='Delivery Optimization'; Setting='Policy DOMinDiskSizeAllowedToPeer'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOMinDiskSizeAllowedToPeer' },
                @{ Category='Delivery Optimization'; Setting='Policy DOMinFileSizeToCache'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOMinFileSizeToCache' },
                @{ Category='Delivery Optimization'; Setting='Policy DOMaxCacheAge'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOMaxCacheAge' },
                @{ Category='Delivery Optimization'; Setting='Effective DODownloadMode'; RegistryPath='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'; ValueName='DODownloadMode' },
                @{ Category='Delivery Optimization'; Setting='PolicyManager DODownloadMode'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization'; ValueName='DODownloadMode' },
                @{ Category='Delivery Optimization'; Setting='PolicyManager DOGroupId'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization'; ValueName='DOGroupId' },
                @{ Category='Delivery Optimization'; Setting='Policy DOMaxCacheSize'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOMaxCacheSize' },
                @{ Category='Delivery Optimization'; Setting='Policy DOAbsoluteMaxCacheSize'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOAbsoluteMaxCacheSize' },
                @{ Category='Delivery Optimization'; Setting='Policy DOMaxBackgroundDownloadBandwidth'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOMaxBackgroundDownloadBandwidth' },
                @{ Category='Delivery Optimization'; Setting='Policy DOMaxForegroundDownloadBandwidth'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOMaxForegroundDownloadBandwidth' },
                @{ Category='Delivery Optimization'; Setting='Policy DOMinBatteryPercentageAllowedToUpload'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName='DOMinBatteryPercentageAllowedToUpload' },
                @{ Category='Windows Update'; Setting='UseWUServer'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; ValueName='UseWUServer' },
                @{ Category='Windows Update'; Setting='WUServer'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='WUServer' },
                @{ Category='Windows Update'; Setting='WUStatusServer'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='WUStatusServer' },
                @{ Category='Windows Update'; Setting='UpdateServiceUrlAlternate'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='UpdateServiceUrlAlternate' },
                @{ Category='Windows Update'; Setting='NoAutoUpdate'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; ValueName='NoAutoUpdate' },
                @{ Category='Windows Update'; Setting='AUOptions'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; ValueName='AUOptions' },
                @{ Category='Windows Update'; Setting='DetectionFrequencyEnabled'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; ValueName='DetectionFrequencyEnabled' },
                @{ Category='Windows Update'; Setting='DetectionFrequency'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; ValueName='DetectionFrequency' },
                @{ Category='Windows Update'; Setting='DoNotConnectToWindowsUpdateInternetLocations'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='DoNotConnectToWindowsUpdateInternetLocations' },
                @{ Category='Windows Update'; Setting='AllowMUUpdateService'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='AllowMUUpdateService' },
                @{ Category='Windows Update'; Setting='ExcludeWUDriversInQualityUpdate'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='ExcludeWUDriversInQualityUpdate' },
                @{ Category='Windows Update'; Setting='DisableWindowsUpdateAccess'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='DisableWindowsUpdateAccess' },
                @{ Category='Windows Update'; Setting='SetDisableUXWUAccess'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='SetDisableUXWUAccess' },
                @{ Category='Windows Update'; Setting='DoNotAllowUpdateDeferralPoliciesToCauseScanAgainstWindowsUpdate'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='DoNotAllowUpdateDeferralPoliciesToCauseScanAgainstWindowsUpdate' },
                @{ Category='Windows Update'; Setting='SetPolicyDrivenUpdateSourceForQualityUpdates'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='SetPolicyDrivenUpdateSourceForQualityUpdates' },
                @{ Category='Windows Update'; Setting='SetPolicyDrivenUpdateSourceForFeatureUpdates'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='SetPolicyDrivenUpdateSourceForFeatureUpdates' },
                @{ Category='Windows Update'; Setting='SetPolicyDrivenUpdateSourceForDriverUpdates'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='SetPolicyDrivenUpdateSourceForDriverUpdates' },
                @{ Category='Windows Update'; Setting='SetPolicyDrivenUpdateSourceForOtherUpdates'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='SetPolicyDrivenUpdateSourceForOtherUpdates' },
                @{ Category='Windows Update'; Setting='UseUpdateClassPolicySource'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='UseUpdateClassPolicySource' },
                @{ Category='Windows Update for Business'; Setting='BranchReadinessLevel'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='BranchReadinessLevel' },
                @{ Category='Windows Update for Business'; Setting='DeferFeatureUpdates'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='DeferFeatureUpdates' },
                @{ Category='Windows Update for Business'; Setting='DeferFeatureUpdatesPeriodInDays'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='DeferFeatureUpdatesPeriodInDays' },
                @{ Category='Windows Update for Business'; Setting='DeferQualityUpdates'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='DeferQualityUpdates' },
                @{ Category='Windows Update for Business'; Setting='DeferQualityUpdatesPeriodInDays'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='DeferQualityUpdatesPeriodInDays' },
                @{ Category='Windows Update for Business'; Setting='TargetReleaseVersion'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='TargetReleaseVersion' },
                @{ Category='Windows Update for Business'; Setting='TargetReleaseVersionInfo'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='TargetReleaseVersionInfo' },
                @{ Category='Windows Update for Business'; Setting='ProductVersion'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='ProductVersion' },
                @{ Category='Windows Update for Business'; Setting='DisableDualScan'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='DisableDualScan' },
                @{ Category='Windows Update for Business'; Setting='ManagePreviewBuilds'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='ManagePreviewBuilds' },
                @{ Category='Windows Update for Business'; Setting='ManagePreviewBuildsPolicyValue'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='ManagePreviewBuildsPolicyValue' },
                @{ Category='Windows Update for Business'; Setting='PauseFeatureUpdatesStartTime'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='PauseFeatureUpdatesStartTime' },
                @{ Category='Windows Update for Business'; Setting='PauseFeatureUpdatesEndTime'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='PauseFeatureUpdatesEndTime' },
                @{ Category='Windows Update for Business'; Setting='PauseQualityUpdatesStartTime'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='PauseQualityUpdatesStartTime' },
                @{ Category='Windows Update for Business'; Setting='PauseQualityUpdatesEndTime'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='PauseQualityUpdatesEndTime' },
                @{ Category='Windows Update for Business'; Setting='PauseUpdatesExpiryTime'; RegistryPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName='PauseUpdatesExpiryTime' },
                @{ Category='PolicyManager Update'; Setting='AllowAutoUpdate'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='AllowAutoUpdate' },
                @{ Category='PolicyManager Update'; Setting='UpdateNotificationLevel'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='UpdateNotificationLevel' },
                @{ Category='PolicyManager Update'; Setting='AllowMUUpdateService'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='AllowMUUpdateService' },
                @{ Category='PolicyManager Update'; Setting='DoNotConnectToWindowsUpdateInternetLocations'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='DoNotConnectToWindowsUpdateInternetLocations' },
                @{ Category='PolicyManager Update'; Setting='ExcludeWUDriversInQualityUpdate'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='ExcludeWUDriversInQualityUpdate' },
                @{ Category='PolicyManager Update'; Setting='SetPolicyDrivenUpdateSourceForQualityUpdates'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='SetPolicyDrivenUpdateSourceForQualityUpdates' },
                @{ Category='PolicyManager Update'; Setting='SetPolicyDrivenUpdateSourceForFeatureUpdates'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='SetPolicyDrivenUpdateSourceForFeatureUpdates' },
                @{ Category='PolicyManager Update'; Setting='SetPolicyDrivenUpdateSourceForDriverUpdates'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='SetPolicyDrivenUpdateSourceForDriverUpdates' },
                @{ Category='PolicyManager Update'; Setting='SetPolicyDrivenUpdateSourceForOtherUpdates'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='SetPolicyDrivenUpdateSourceForOtherUpdates' },
                @{ Category='PolicyManager Update'; Setting='BranchReadinessLevel'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='BranchReadinessLevel' },
                @{ Category='PolicyManager Update'; Setting='TargetReleaseVersion'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='TargetReleaseVersion' },
                @{ Category='PolicyManager Update'; Setting='TargetReleaseVersionInfo'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='TargetReleaseVersionInfo' },
                @{ Category='PolicyManager Update'; Setting='ProductVersion'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='ProductVersion' },
                @{ Category='PolicyManager Update'; Setting='DeferFeatureUpdatesPeriodInDays'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='DeferFeatureUpdatesPeriodInDays' },
                @{ Category='PolicyManager Update'; Setting='DeferQualityUpdatesPeriodInDays'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='DeferQualityUpdatesPeriodInDays' },
                @{ Category='PolicyManager Update'; Setting='PauseFeatureUpdatesStartTime'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='PauseFeatureUpdatesStartTime' },
                @{ Category='PolicyManager Update'; Setting='PauseQualityUpdatesStartTime'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='PauseQualityUpdatesStartTime' },
                @{ Category='PolicyManager Update'; Setting='UseUpdateClassPolicySource'; RegistryPath='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'; ValueName='UseUpdateClassPolicySource' }
            )

            function Resolve-RegistrySettingInterpretation {
                param([string]$SettingName, [string]$Value)

                if ([string]::IsNullOrWhiteSpace($Value)) {
                    return 'Nicht konfiguriert'
                }

                switch ($SettingName) {
                    'Policy DODownloadMode' {
                        switch ($Value) {
                            '0' { return 'HTTP only' }
                            '1' { return 'LAN' }
                            '2' { return 'Group' }
                            '3' { return 'Internet' }
                            '99' { return 'Simple' }
                            '100' { return 'Bypass' }
                            default { return "Rohwert: $Value" }
                        }
                    }
                    'Effective DODownloadMode' {
                        switch ($Value) {
                            '0' { return 'HTTP only' }
                            '1' { return 'LAN' }
                            '2' { return 'Group' }
                            '3' { return 'Internet' }
                            '99' { return 'Simple' }
                            '100' { return 'Bypass' }
                            default { return "Rohwert: $Value" }
                        }
                    }
                    'PolicyManager DODownloadMode' {
                        switch ($Value) {
                            '0' { return 'HTTP only' }
                            '1' { return 'LAN' }
                            '2' { return 'Group' }
                            '3' { return 'Internet' }
                            '99' { return 'Simple' }
                            '100' { return 'Bypass' }
                            default { return "Rohwert: $Value" }
                        }
                    }
                    'UseWUServer' {
                        if ($Value -eq '1') { return 'WSUS/Intranet-Updatequelle erzwungen' }
                        elseif ($Value -eq '0') { return 'Windows Update / WUfB möglich' }
                        return "Rohwert: $Value"
                    }
                    'NoAutoUpdate' {
                        if ($Value -eq '1') { return 'Automatische Updates deaktiviert' }
                        elseif ($Value -eq '0') { return 'Automatische Updates erlaubt' }
                        return "Rohwert: $Value"
                    }
                    'AUOptions' {
                        switch ($Value) {
                            '2' { return 'Nur Benachrichtigung' }
                            '3' { return 'Auto Download, Benachrichtigung vor Installation' }
                            '4' { return 'Auto Download und geplanter Install' }
                            '5' { return 'Lokaler Admin wählt Einstellung' }
                            default { return "Rohwert: $Value" }
                        }
                    }
                    'TargetReleaseVersion' {
                        if ($Value -eq '1') { return 'Zielrelease aktiviert' }
                        elseif ($Value -eq '0') { return 'Zielrelease deaktiviert' }
                        return "Rohwert: $Value"
                    }
                    'DisableDualScan' {
                        if ($Value -eq '1') { return 'Dual Scan deaktiviert' }
                        elseif ($Value -eq '0') { return 'Dual Scan nicht deaktiviert' }
                        return "Rohwert: $Value"
                    }
                    'DoNotConnectToWindowsUpdateInternetLocations' {
                        if ($Value -eq '1') { return 'Öffentliche Windows-Update-Dienste blockiert' }
                        elseif ($Value -eq '0') { return 'Öffentliche Windows-Update-Dienste nicht blockiert' }
                        return "Rohwert: $Value"
                    }
                    'AllowMUUpdateService' {
                        if ($Value -eq '1') { return 'Microsoft Update für App-/Produktupdates erlaubt' }
                        elseif ($Value -eq '0') { return 'Microsoft Update blockiert' }
                        return "Rohwert: $Value"
                    }
                    'ExcludeWUDriversInQualityUpdate' {
                        if ($Value -eq '1') { return 'Windows Update Treiber ausgeschlossen' }
                        elseif ($Value -eq '0') { return 'Windows Update Treiber erlaubt' }
                        return "Rohwert: $Value"
                    }
                    'DisableWindowsUpdateAccess' {
                        if ($Value -eq '1') { return 'Windows-Update-Benutzerzugriff blockiert' }
                        elseif ($Value -eq '0') { return 'Windows-Update-Benutzerzugriff erlaubt' }
                        return "Rohwert: $Value"
                    }
                    'SetDisableUXWUAccess' {
                        if ($Value -eq '1') { return 'Windows-Update-UX blockiert' }
                        elseif ($Value -eq '0') { return 'Windows-Update-UX erlaubt' }
                        return "Rohwert: $Value"
                    }
                    'DoNotAllowUpdateDeferralPoliciesToCauseScanAgainstWindowsUpdate' {
                        if ($Value -eq '1') { return 'Deferral-Policies erzwingen keinen Scan gegen Windows Update' }
                        elseif ($Value -eq '0') { return 'Deferral-Policies dürfen Windows-Update-Scan beeinflussen' }
                        return "Rohwert: $Value"
                    }
                    'SetPolicyDrivenUpdateSourceForQualityUpdates' {
                        if ($Value -eq '1') { return 'Qualitätsupdates von Microsoft Update' }
                        elseif ($Value -eq '0') { return 'Nicht festgelegt / WSUS je nach Gesamtmodus' }
                        return "Rohwert: $Value"
                    }
                    'SetPolicyDrivenUpdateSourceForFeatureUpdates' {
                        if ($Value -eq '1') { return 'Featureupdates von Microsoft Update' }
                        elseif ($Value -eq '0') { return 'Nicht festgelegt / WSUS je nach Gesamtmodus' }
                        return "Rohwert: $Value"
                    }
                    'SetPolicyDrivenUpdateSourceForDriverUpdates' {
                        if ($Value -eq '1') { return 'Treiberupdates von Microsoft Update' }
                        elseif ($Value -eq '0') { return 'Nicht festgelegt / WSUS je nach Gesamtmodus' }
                        return "Rohwert: $Value"
                    }
                    'SetPolicyDrivenUpdateSourceForOtherUpdates' {
                        if ($Value -eq '1') { return 'Sonstige Updates von Microsoft Update' }
                        elseif ($Value -eq '0') { return 'Nicht festgelegt / WSUS je nach Gesamtmodus' }
                        return "Rohwert: $Value"
                    }
                    'UseUpdateClassPolicySource' {
                        if ($Value -eq '1') { return 'Quellsystem je Updateklasse explizit vorgegeben' }
                        elseif ($Value -eq '0') { return 'Keine getrennte Quellsteuerung je Updateklasse' }
                        return "Rohwert: $Value"
                    }
                    default {
                        return "Rohwert: $Value"
                    }
                }
            }

            $items = foreach ($definition in $definitions) {
                $value = $null
                if (Test-Path $definition.RegistryPath) {
                    try {
                        $props = Get-ItemProperty -Path $definition.RegistryPath -ErrorAction Stop
                        if ($props.PSObject.Properties.Name -contains $definition.ValueName) {
                            $value = $props.($definition.ValueName)
                        }
                    }
                    catch { }
                }

                $normalizedValue = if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { '' } else { Escape-LogValue $value }
                $status = if ([string]::IsNullOrWhiteSpace($normalizedValue)) { 'NotConfigured' } else { 'Configured' }
                $interpretation = Resolve-RegistrySettingInterpretation -SettingName $definition.Setting -Value $normalizedValue
                $displayValue = if ([string]::IsNullOrWhiteSpace($normalizedValue)) { 'Nicht gesetzt' } else { $normalizedValue }

                '{0} [Info] [DeviceRegistrySettings] Category={1}; Setting={2}; Value={3}; Interpretation={4}; Status={5}; RegistryPath={6}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (Escape-LogValue $definition.Category), (Escape-LogValue $definition.Setting), (Escape-LogValue $displayValue), (Escape-LogValue $interpretation), $status, (Escape-LogValue $definition.RegistryPath)
            }

            return @($items)
        }
        function Get-ServiceStatusLines {
            param([string]$ServiceName)

            $resolvedServiceName = if ([string]::IsNullOrWhiteSpace($ServiceName)) { 'IntuneManagementExtension' } else { $ServiceName }
            try {
                $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f ($resolvedServiceName -replace "'", "''")) -ErrorAction Stop | Select-Object -First 1
                if ($null -eq $service) {
                    return @((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + " [Warning] [Services] ServiceName=" + $resolvedServiceName + "; Status=NotFound; StartType=Unknown")
                }

                $level = if ($service.State -eq 'Running') { 'Info' } else { 'Warning' }
                return @('{0} [{1}] [Services] ServiceName={2}; DisplayName={3}; Status={4}; StartType={5}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $level, $service.Name, (Escape-LogValue $service.DisplayName), (Escape-LogValue $service.State), (Escape-LogValue $service.StartMode))
            }
            catch {
                return @((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + " [Warning] [Services] ServiceName=" + $resolvedServiceName + "; Status=Error; StartType=Unknown; Message=" + (Escape-LogValue $_.Exception.Message))
            }
        }

        function Get-MdmDiagnosticsLines {
            $candidateDirectories = @(
                (Join-Path $env:PUBLIC 'Documents'),
                'C:\Users\Public\Documents',
                (Join-Path $env:WINDIR 'Temp')
            ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

            $files = foreach ($dir in $candidateDirectories) {
                Get-ChildItem -Path $dir -File -Filter '*MDMDiag*' -ErrorAction SilentlyContinue
                Get-ChildItem -Path $dir -File -Filter '*MDM*Diagnostic*' -ErrorAction SilentlyContinue
            }

            $files = @($files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -Unique -First 20)
            if ($files.Count -eq 0) {
                return @((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' [Info] [MDMDiagnostics] Keine exportierten MDM-Diagnoseartefakte in den üblichen Pfaden gefunden.')
            }

            foreach ($file in $files) {
                '{0} [Info] [MDMDiagnostics] {1} | {2:N1} KB' -f $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'), $file.FullName, ($file.Length / 1KB)
            }
        }
        if ($SuppressReadAudit -ne 'True') { Write-AuditLine -Level 'INFO' -Action 'ReadLogs' -Message 'Auslesen der IME Logs gestartet.' }
        $logMap = [ordered]@{ AgentExecutor='AgentExecutor.log'; AppActionProcessor='AppActionProcessor.log'; AppWorkload='AppWorkload.log'; ClientCertCheck='ClientCertCheck.log'; ClientHealth='ClientHealth.log'; DeviceHealthMonitoring='DeviceHealthMonitoring.log'; HealthScripts='HealthScripts.log'; IntuneManagementExtension='IntuneManagementExtension.log'; NotificationInfraLogs='NotificationInfraLogs.log'; Sensor='Sensor.log'; Win321AppInventory='Win32AppInventory.log' }
        $logs = [ordered]@{}
        $previousStates = Convert-PreviousStates -Json $PreviousLogStatesJson
        $useShortLogs = $ShortDestinationLogs -eq 'True'
        $maxAgeDaysInt = 10
        [void][int]::TryParse($DestinationLogMaxAgeDays, [ref]$maxAgeDaysInt)
        foreach ($entry in $logMap.GetEnumerator()) {
            if ($LogFiles -contains $entry.Value) {
                $logs[$entry.Key] = Get-FilteredLogPayload -LogKey $entry.Key -FilePath (Join-Path $ImeLogPath $entry.Value) -PreviousStates $previousStates -AppGuid $AppGuid -UseShortLogs $useShortLogs -MaxAgeDays $maxAgeDaysInt
            } else { $logs[$entry.Key] = [pscustomobject]@{ Lines=@(); UpdateMode='Unchanged'; LastWriteUtc=''; FilteredLineCount=0; Exists=$false } }
        }
        $companyPortalLines = @(Get-CompanyPortalLines)
        $logs['CompanyPortal'] = New-VirtualLogPayload -Lines $companyPortalLines -Exists ($companyPortalLines.Count -gt 0)

        $enrollmentLines = @(Get-EventLines -LogNames @('Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin','Microsoft-Windows-User Device Registration/Admin') -MaxEventsPerLog 60)
        $logs['Enrollment'] = New-VirtualLogPayload -Lines $enrollmentLines -Exists ($enrollmentLines.Count -gt 0)

        $mdmDiagnosticsLines = @(Get-MdmDiagnosticsLines)
        $logs['MdmDiagnostics'] = New-VirtualLogPayload -Lines $mdmDiagnosticsLines -Exists ($mdmDiagnosticsLines.Count -gt 0)

        $eventChannelLines = @(Get-EventLines -LogNames @('Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin','Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational') -MaxEventsPerLog 80)
        $serviceStatusLines = @(Get-ServiceStatusLines -ServiceName $ServiceName)
        $eventChannelLines = @($serviceStatusLines + $eventChannelLines)
        $logs['EventLogChannels'] = New-VirtualLogPayload -Lines $eventChannelLines -Exists ($eventChannelLines.Count -gt 0)

        $installAgentEventLines = @(Get-InstallAgentEventLines -AppGuid $AppGuid -UseShortLogs $useShortLogs -MaxAgeDays $maxAgeDaysInt -MaxEvents 2000)
        $logs['InstallAgentEvents'] = New-VirtualLogPayload -Lines $installAgentEventLines -Exists ($installAgentEventLines.Count -gt 0)

        $deviceRegistrySettingLines = @(Get-IntuneRelevantRegistrySettingLines)
        $logs['DeviceRegistrySettings'] = New-VirtualLogPayload -Lines $deviceRegistrySettingLines -Exists ($deviceRegistrySettingLines.Count -gt 0)

        $win32AppsRegistryLines = @(Get-Win32AppsRegistryLines)
        if (-not [string]::IsNullOrWhiteSpace($AppGuid)) {
            $win32AppsRegistryLines = @($win32AppsRegistryLines | Where-Object { $_ -like "*$AppGuid*" })
        }
        $logs['Win32AppsRegistry'] = New-VirtualLogPayload -Lines $win32AppsRegistryLines -Exists ($win32AppsRegistryLines.Count -gt 0)

        $logs['RemoteAuditLog'] = Get-FilteredLogPayload -LogKey 'RemoteAuditLog' -FilePath (Join-Path $RemoteAuditLogDirectory $RemoteAuditLogFileName) -PreviousStates $previousStates -AppGuid $AppGuid -UseShortLogs $useShortLogs -MaxAgeDays $maxAgeDaysInt
        $logs['FallbackLog'] = Get-FilteredLogPayload -LogKey 'FallbackLog' -FilePath (Join-Path $RemoteAuditLogDirectory $RemoteFallbackLogFileName) -PreviousStates $previousStates -AppGuid $AppGuid -UseShortLogs $useShortLogs -MaxAgeDays $maxAgeDaysInt
        if ($SuppressReadAudit -ne 'True') { Write-AuditLine -Level 'INFO' -Action 'ReadLogs' -Message 'Auslesen der IME Logs abgeschlossen.' }
        [pscustomobject]@{ Success = $true; ErrorMessage = ''; Logs = $logs }
    } -ErrorAction Stop
}

try {
    try { $result = Invoke-LogRead }
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
        if ($RestoreRemotingState -eq 'True') {
            $taskRetryResult = Retry-RemoteFallbackScheduledTask -ComputerName $ComputerName -PsExecPath $PsExecPath -PowerShellExecutable $PowerShellExecutable -SupportClientDirectory $SupportClientDirectory -FallbackConfigFileName $FallbackConfigFileName -RemoteAuditLogDirectory $RemoteAuditLogDirectory -RemoteAuditLogFileName $RemoteAuditLogFileName -RemoteFallbackLogFileName $RemoteFallbackLogFileName -FallbackScheduledTaskName $FallbackScheduledTaskName -OperationId $OperationId -FallbackTaskDelayMinutes $FallbackTaskDelayMinutes -SourceHost $SourceHost -ExpectedAppSignerThumbprint $ExpectedAppSignerThumbprint -ExpectedAppSignerPublicKey $ExpectedAppSignerPublicKey
            if (-not $taskRetryResult.Success) { Write-Warning "Scheduled Task Retry meldete einen Fehler: $($taskRetryResult.StandardError)" }
        }
        $result = Invoke-LogRead
    }
    $result | ConvertTo-Json -Depth 8 -Compress
    exit 0
}
catch {
    [pscustomobject]@{ Success = $false; ErrorMessage = $_.Exception.Message; Logs = @{} } | ConvertTo-Json -Depth 8 -Compress
    exit 1
}

# SIG # Begin signature block
# MIIl6QYJKoZIhvcNAQcCoIIl2jCCJdYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBL6NBV1jb2KF0j
# dkZlI966AvefmvcmHvZ0TKhuhYBac6CCH/UwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# YrZiwKwfgOo60BbrEifXXGLjNCN/1XOH6+HfiFcKLA4wDQYJKoZIhvcNAQEBBQAE
# ggEAXjO9pQCau3TDomFpGi6wwFLlwB9DPEhE7kUGcyGpWocYsccSFPOvmp+C7dCg
# 2YZnkJUjKaZQHUFzr9UHiLOV5l1wuohqLjs7HYD8Dq1KpVBMa2GJC4lCjVTvkull
# NVM/ij0NfZey5DPJYfJdIo/yec17bIMzyAETR09sZy6nkUkr+nucHvSRq+aHpU9s
# iAUmKXiCBrC30oHsaWx30NOxGHPIvhDy0As9dJMpZ5N8rvJh3kJEZdng/LhsgjTb
# qp7eKktD/27ur6h43D/ZoPtGWLd5dhtEnR+i7Z09BNWJxZw4cDUCH0mbMVyw8EXJ
# EPJDvuhnF8fk+eFj64WpvVPxyqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIB
# ATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCg
# aTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA0
# MTcxNDEzMzFaMC8GCSqGSIb3DQEJBDEiBCDN34jgbAUMDWZL4E8mFF5d5JLZSAL6
# KOy6DcBLuZfvXDANBgkqhkiG9w0BAQEFAASCAgC6hFJBYpLdcb2xilg62fXooh8Y
# y+SBPgiimScB//KO84yPZ8Hp3P7T/Y0SV9dBPM3Pn07fSWo4nb/an6XP1JmMFCoH
# amYJ0cpEHx2RLcmReOAAzI7zqXflBqONiIDUsK5Nuj0mWU8C2XlwoocHKcLEONi1
# ZP2KkxfNiezwQuSQ3T1n7gTOSWZzmlHpGNlCITqGbK042UVXi0c2iacY48sywmsf
# ZY7oFPbcbFvS07SywNodj0q6OGkYvFr5ROW09aB1xzJzr/AuavbJF80gHqtVlHrZ
# AWEqlX8ColJnqXY7Ij9tGQS9e33nKsj+YQi+EAtEJXmMFB174qNFtQA61DrA/0A7
# MTWiiUmDcUvGaegiIPYALTtyAZVgxkq8bBRhSoGf93OqnkYy8m37qXPap48Wq/ZS
# OMGcbK90fJqwv/I+8fQRF9zgqUPLTza4YJsPNa4twsdiSLOJHomhervvTRTXPIhZ
# W5pFmThyzeEN7eWMedCQD3gZH02XkVFH/PjEAO8gzFNYcb3hFRJ7lhnbRixjaw+F
# TIMTzCXCOuvZarnLA8UOMcsx/kXmpZjbl3RtZacx9hTvVkZIOhsMy4EBpVpgTl6S
# yVZZdrqf713/tN3tltn3imuzySunHluytQOHWgC2sUac7wJtR9pWRmIrlUloQu43
# QjH2Hz5Wbt02KqBcbA==
# SIG # End signature block