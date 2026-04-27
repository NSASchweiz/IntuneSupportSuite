param(
    [Parameter(Mandatory = $true)] [string]$ComputerName,
    [Parameter(Mandatory = $false)] [string]$AppGuidsCsv = '',
    [Parameter(Mandatory = $false)] [string]$SimulationMode = 'False',
    [Parameter(Mandatory = $false)] [string]$OperationId = ''
)

if ([string]::IsNullOrWhiteSpace($OperationId)) { $OperationId = [guid]::NewGuid().ToString() }

if ($SimulationMode -eq 'True' -or [string]::IsNullOrWhiteSpace($AppGuidsCsv)) {
    [pscustomobject]@{ Success = $true; Names = @{} } | ConvertTo-Json -Depth 6 -Compress
    exit 0
}

$guids = $AppGuidsCsv -split ';' | Where-Object { $_ -and $_.Trim().Length -gt 0 } | ForEach-Object { $_.Trim() } | Select-Object -Unique
if (-not $guids -or $guids.Count -eq 0) {
    [pscustomobject]@{ Success = $true; Names = @{} } | ConvertTo-Json -Depth 6 -Compress
    exit 0
}

try {
    $remoteResult = Invoke-Command -ComputerName $ComputerName -ArgumentList (, $guids) -ScriptBlock {
        param([string[]]$Guids)

        $resolved = @{}
        foreach ($guid in $Guids) {
            if ([string]::IsNullOrWhiteSpace($guid)) { continue }

            $name = $null
            try {
                $normalizedGuid = $guid.Trim().ToUpperInvariant()
                $product = Get-CimInstance Win32_Product -Filter ("IdentifyingNumber='{0}'" -f $normalizedGuid) -ErrorAction Stop | Select-Object -First 1
                if ($product -and -not [string]::IsNullOrWhiteSpace($product.Name)) {
                    $name = [string]$product.Name
                }
            }
            catch {
                $name = $null
            }

            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $resolved[$guid] = $name.Trim()
            }
        }

        return [pscustomobject]@{ Names = $resolved }
    } -ErrorAction Stop

    $names = @{}
    if ($remoteResult -and $remoteResult.PSObject.Properties['Names']) {
        foreach ($item in $remoteResult.Names.GetEnumerator()) {
            if ($item.Key -and $item.Value) {
                $names[[string]$item.Key] = [string]$item.Value
            }
        }
    }

    [pscustomobject]@{ Success = $true; Names = $names } | ConvertTo-Json -Depth 6 -Compress
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
