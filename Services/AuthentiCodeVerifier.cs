using System.Diagnostics;
using System.Text.Json;

namespace DapIntuneSupportSuite.Services;

public sealed class AuthentiCodeVerifier
{
    public SignatureVerificationResult Verify(string filePath)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            Arguments = BuildArguments(filePath)
        };

        try
        {
            using var process = Process.Start(psi);
            if (process is null)
            {
                return SignatureVerificationResult.Failed("Powershell konnte nicht gestartet werden.");
            }

            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                return SignatureVerificationResult.Failed(string.IsNullOrWhiteSpace(error) ? "Signaturprüfung fehlgeschlagen." : error.Trim());
            }

            if (string.IsNullOrWhiteSpace(output))
            {
                return SignatureVerificationResult.Failed("Keine Signaturdaten zurückgegeben.");
            }

            var payload = JsonSerializer.Deserialize<SignatureVerificationPayload>(output.Trim(), new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (payload is null)
            {
                return SignatureVerificationResult.Failed("Signaturdaten konnten nicht interpretiert werden.");
            }

            return new SignatureVerificationResult
            {
                Success = string.Equals(payload.Status, "Valid", StringComparison.OrdinalIgnoreCase),
                Status = payload.Status ?? "Unknown",
                StatusMessage = payload.StatusMessage ?? string.Empty,
                Thumbprint = payload.Thumbprint ?? string.Empty,
                PublicKey = payload.PublicKey ?? string.Empty,
                Subject = payload.Subject ?? string.Empty
            };
        }
        catch (Exception ex)
        {
            return SignatureVerificationResult.Failed(ex.Message);
        }
    }

    private static string BuildArguments(string filePath)
    {
        var escaped = filePath.Replace("'", "''");
        var script = "$sig = Get-AuthenticodeSignature -FilePath '" + escaped + "'; " +
                     "$cert = $sig.SignerCertificate; " +
                     "$publicKey = if ($cert) { [System.Convert]::ToBase64String($cert.GetPublicKey()) } else { '' }; " +
                     "[pscustomobject]@{ Status=$sig.Status.ToString(); StatusMessage=$sig.StatusMessage; Thumbprint=if($cert){$cert.Thumbprint}else{''}; PublicKey=$publicKey; Subject=if($cert){$cert.Subject}else{''} } | ConvertTo-Json -Compress";
        return $"-NoProfile -ExecutionPolicy Bypass -Command \"{script.Replace("\"", "`\"")}\"";
    }

    private sealed class SignatureVerificationPayload
    {
        public string? Status { get; set; }
        public string? StatusMessage { get; set; }
        public string? Thumbprint { get; set; }
        public string? PublicKey { get; set; }
        public string? Subject { get; set; }
    }
}

public sealed class SignatureVerificationResult
{
    public bool Success { get; init; }
    public string Status { get; init; } = "Unknown";
    public string StatusMessage { get; init; } = string.Empty;
    public string Thumbprint { get; init; } = string.Empty;
    public string PublicKey { get; init; } = string.Empty;
    public string Subject { get; init; } = string.Empty;

    public static SignatureVerificationResult Failed(string message) => new()
    {
        Success = false,
        Status = "Invalid",
        StatusMessage = message
    };
}
