using System.IO;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace DapIntuneSupportSuite.Services;

public sealed class FileCatalogVerifier
{
    public CatalogValidationResult Verify(string catalogFilePath, string itemPath)
    {
        return Verify(catalogFilePath, itemPath, Path.GetFileName(itemPath));
    }

    public CatalogValidationResult Verify(string catalogFilePath, string itemPath, string itemLabel)
    {
        var itemDirectory = Path.GetDirectoryName(itemPath);
        var itemLeaf = Path.GetFileName(itemPath);

        if (string.IsNullOrWhiteSpace(itemDirectory) || string.IsNullOrWhiteSpace(itemLeaf))
        {
            return CatalogValidationResult.Failed($"Pfad zu {itemLabel} ist ungültig.");
        }

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            Arguments = BuildArguments(catalogFilePath, itemDirectory, itemLeaf, itemLabel)
        };

        try
        {
            using var process = Process.Start(psi);
            if (process is null)
            {
                return CatalogValidationResult.Failed("Powershell konnte nicht gestartet werden.");
            }

            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                return CatalogValidationResult.Failed(string.IsNullOrWhiteSpace(error) ? "Catalog-Prüfung fehlgeschlagen." : error.Trim());
            }

            if (string.IsNullOrWhiteSpace(output))
            {
                return CatalogValidationResult.Failed("Keine Catalog-Prüfdaten zurückgegeben.");
            }

            var payload = JsonSerializer.Deserialize<CatalogValidationPayload>(output.Trim(), new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (payload is null)
            {
                return CatalogValidationResult.Failed("Catalog-Prüfdaten konnten nicht interpretiert werden.");
            }

            return new CatalogValidationResult
            {
                Success = string.Equals(payload.Status, "Valid", StringComparison.OrdinalIgnoreCase) && payload.Success,
                Status = payload.Status ?? "Unknown",
                SignatureStatus = payload.SignatureStatus ?? string.Empty,
                StatusMessage = payload.StatusMessage ?? string.Empty
            };
        }
        catch (Exception ex)
        {
            return CatalogValidationResult.Failed(ex.Message);
        }
    }

    private static string BuildArguments(string catalogFilePath, string itemDirectory, string itemLeaf, string itemLabel)
    {
        var escapedCatalog = catalogFilePath.Replace("'", "''");
        var escapedDirectory = itemDirectory.Replace("'", "''");
        var escapedLeaf = itemLeaf.Replace("'", "''");

        var script = $@"
$ErrorActionPreference = 'Stop'
$result = Test-FileCatalog -CatalogFilePath '{escapedCatalog}' -Path '{escapedDirectory}' -Detailed
$signatureStatus = if ($null -ne $result.Signature) {{ $result.Signature.Status.ToString() }} else {{ '' }}
$status = if ($null -ne $result.Status) {{ $result.Status.ToString() }} else {{ 'Unknown' }}
$catalogKeys = @()
if ($result.CatalogItems) {{
    $catalogKeys = @($result.CatalogItems.Keys | ForEach-Object {{ [string]$_ }})
}}
$pathKeys = @()
if ($result.PathItems) {{
    $pathKeys = @($result.PathItems.Keys | ForEach-Object {{ [string]$_ }})
}}
$targetPresentInCatalog = $catalogKeys -contains '{escapedLeaf}'
$targetPresentOnDisk = $pathKeys -contains '{escapedLeaf}'
$catalogList = if ($catalogKeys) {{ $catalogKeys -join ',' }} else {{ '' }}
$pathList = if ($pathKeys) {{ $pathKeys -join ',' }} else {{ '' }}
$success = $status -eq 'Valid' -and $targetPresentInCatalog -and $targetPresentOnDisk
$successLabel = 'Catalog passt zu ' + '{escapedLeaf}' + '.'
$failureLabel = 'Catalog-Prüfung fehlgeschlagen. Element=' + '{escapedLeaf}' + '; Status='
$message = if ($success) {{
    $successLabel
}} else {{
    $failureLabel + $status + '; CatalogItems=' + $catalogList + '; PathItems=' + $pathList
}}
[pscustomobject]@{{
    Success = $success
    Status = $status
    SignatureStatus = $signatureStatus
    StatusMessage = $message
}} | ConvertTo-Json -Compress
";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}";
    }

    private sealed class CatalogValidationPayload
    {
        public bool Success { get; set; }
        public string? Status { get; set; }
        public string? SignatureStatus { get; set; }
        public string? StatusMessage { get; set; }
    }
}

public sealed class CatalogValidationResult
{
    public bool Success { get; init; }
    public string Status { get; init; } = "Unknown";
    public string SignatureStatus { get; init; } = string.Empty;
    public string StatusMessage { get; init; } = string.Empty;

    public static CatalogValidationResult Failed(string message) => new()
    {
        Success = false,
        Status = "Invalid",
        StatusMessage = message
    };
}
