using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Windows;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class PsExecDependencyService
{
    private static readonly string[] TrustedDownloadHosts =
    [
        "download.sysinternals.com",
        "live.sysinternals.com",
        "download.microsoft.com"
    ];

    private readonly AuditLogger _logger;
    private readonly AppConfig _config;
    private readonly ConfigBootstrapper _configBootstrapper;
    private readonly AuthentiCodeVerifier _authentiCodeVerifier = new();
    private readonly FileCatalogVerifier _catalogVerifier = new();

    public PsExecDependencyService(AuditLogger logger, AppConfig config, ConfigBootstrapper configBootstrapper)
    {
        _logger = logger;
        _config = config;
        _configBootstrapper = configBootstrapper;
    }

    public async Task<PsExecInitializationResult> InitializeForStartupAsync()
    {
        var evaluation = await EnsurePsExecReadyAsync("Startup", requiredForProductiveUse: _config.ConnectionFallback);
        return evaluation.ToInitializationResult();
    }

    public bool TryEnsureAvailableSilent()
    {
        var evaluation = EnsurePsExecReadyAsync("ConnectionFallback", requiredForProductiveUse: true).GetAwaiter().GetResult();
        return evaluation.Success;
    }

    private async Task<PsExecEvaluationResult> EnsurePsExecReadyAsync(string action, bool requiredForProductiveUse)
    {
        var trustLogger = new TrustLogger(_config.TrustLogPath);
        var operationId = $"PSEXEC-{NormalizeAction(action)}";
        trustLogger.Info("PsExecProcurementCheck", "Started", "Start der PsExec-Beschaffungs- und Integritätsprüfung.", operationId, Environment.MachineName, null, action);

        var toolsDirectory = ResolveToolsDirectory();
        var toolsDirectoryExists = !string.IsNullOrWhiteSpace(toolsDirectory) && Directory.Exists(toolsDirectory);
        var configuredOrExistingPath = ResolveConfiguredOrExistingPsExecPath();
        var psexecPotentiallyUsed = requiredForProductiveUse || !string.IsNullOrWhiteSpace(configuredOrExistingPath);

        if (!toolsDirectoryExists && !psexecPotentiallyUsed)
        {
            trustLogger.Info("PsExecProcurementCheck", "Skipped", "Kein Tools-Ordner vorhanden und PsExec wird aktuell nicht benötigt.", operationId, Environment.MachineName, null, action);
            return PsExecEvaluationResult.CreateSkipped();
        }

        var localPath = configuredOrExistingPath;
        var underManagedTools = IsManagedToolsPath(localPath, toolsDirectory);

        Version? latestPublishedVersion = null;
        if (psexecPotentiallyUsed || toolsDirectoryExists)
        {
            var latestVersionResult = await TryResolveLatestPublishedVersionAsync(operationId, action);
            latestPublishedVersion = latestVersionResult.Version;
            _config.LatestPublishedPsExecVersion = latestVersionResult.VersionText;
            _config.LastPsExecVersionCheck = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            if (!string.IsNullOrWhiteSpace(latestVersionResult.ValidationResult))
            {
                _config.LastDownloadValidationResult = latestVersionResult.ValidationResult;
            }
        }

        if (string.IsNullOrWhiteSpace(localPath) && requiredForProductiveUse)
        {
            var acquireResult = await AcquireManagedPsExecAsync(operationId, action, toolsDirectory);
            if (!acquireResult.Success)
            {
                return FinalizeFailure(acquireResult.ErrorMessage, operationId, action, localPath);
            }

            localPath = acquireResult.PsExecPath;
            underManagedTools = true;
        }

        if (string.IsNullOrWhiteSpace(localPath))
        {
            trustLogger.Info("PsExecProcurementCheck", "Skipped", "Kein PsExec-Pfad vorhanden. Integritätsprüfung wird übersprungen, solange PsExec nicht verwendet wird.", operationId, Environment.MachineName, null, action);
            PersistConfiguration();
            return PsExecEvaluationResult.CreateSkipped();
        }

        if (!File.Exists(localPath))
        {
            if (requiredForProductiveUse && underManagedTools)
            {
                var acquireResult = await AcquireManagedPsExecAsync(operationId, action, toolsDirectory);
                if (!acquireResult.Success)
                {
                    return FinalizeFailure(acquireResult.ErrorMessage, operationId, action, localPath);
                }

                localPath = acquireResult.PsExecPath;
            }
            else
            {
                return FinalizeFailure($"PsExec.exe wurde nicht gefunden: {localPath}", operationId, action, localPath);
            }
        }

        var integrity = VerifyIntegrity(localPath, operationId, action, toolsDirectory);
        UpdatePsExecMetadata(localPath, integrity.VersionText);

        if (!integrity.Success)
        {
            if (underManagedTools)
            {
                TryDeleteFile(localPath);
                trustLogger.Warn("PsExecManagedFileDeleted", "Deleted", $"Beschädigte oder unzulässige PsExec.exe im Tools-Unterordner wurde gelöscht. {integrity.Message}", operationId, Environment.MachineName, null, action);
            }

            if (requiredForProductiveUse && underManagedTools)
            {
                var reacquire = await AcquireManagedPsExecAsync(operationId, action, toolsDirectory);
                if (!reacquire.Success)
                {
                    return FinalizeFailure(reacquire.ErrorMessage, operationId, action, localPath);
                }

                localPath = reacquire.PsExecPath;
                integrity = VerifyIntegrity(localPath, operationId, action, toolsDirectory);
                UpdatePsExecMetadata(localPath, integrity.VersionText);
            }

            if (!integrity.Success)
            {
                return FinalizeFailure(integrity.Message, operationId, action, localPath, integrity);
            }
        }

        var localVersion = ParseVersionOrNull(integrity.VersionText);
        var versionStatus = DetermineVersionStatus(localVersion, latestPublishedVersion);
        _config.LocalPsExecVersion = integrity.VersionText;
        _config.PsExecVersionStatus = versionStatus;
        trustLogger.Info("PsExecVersionCheck", versionStatus, $"Vergleich Local vs LatestPublished. Lokal={_config.LocalPsExecVersion}; Latest={_config.LatestPublishedPsExecVersion}; Status={versionStatus}", operationId, Environment.MachineName, null, action, psExecPath: localPath, psExecVersion: _config.LocalPsExecVersion, signer: integrity.Subject, thumbprint: integrity.Thumbprint);

        if ((versionStatus == "Outdated" || versionStatus == "Unknown") && requiredForProductiveUse)
        {
            if (underManagedTools)
            {
                trustLogger.Warn("PsExecVersionManagedDelete", "Deleting", "Veraltete oder unbekannte PsExec.exe im Tools-Unterordner wird gelöscht und neu beschafft.", operationId, Environment.MachineName, null, action, psExecPath: localPath, psExecVersion: integrity.VersionText);
                TryDeleteFile(localPath);
                var reacquire = await AcquireManagedPsExecAsync(operationId, action, toolsDirectory);
                if (!reacquire.Success)
                {
                    return FinalizeFailure(reacquire.ErrorMessage, operationId, action, localPath, integrity);
                }

                localPath = reacquire.PsExecPath;
                integrity = VerifyIntegrity(localPath, operationId, action, toolsDirectory);
                UpdatePsExecMetadata(localPath, integrity.VersionText);
                localVersion = ParseVersionOrNull(integrity.VersionText);
                versionStatus = DetermineVersionStatus(localVersion, latestPublishedVersion);
                _config.LocalPsExecVersion = integrity.VersionText;
                _config.PsExecVersionStatus = versionStatus;
            }

            if (versionStatus == "Outdated" || versionStatus == "Unknown")
            {
                return FinalizeFailure($"PsExec-Version ist nicht zulässig. Lokal={_config.LocalPsExecVersion}; Latest={_config.LatestPublishedPsExecVersion}; Status={versionStatus}", operationId, action, localPath, integrity);
            }
        }

        _config.PsExecPath = localPath;
        _config.LastDownloadValidationResult = "Freigegeben";
        PersistConfiguration();
        EnsureEulaAccepted();
        trustLogger.Info("PsExecUsageAllowed", "Success", "PsExec wurde nach Integritäts- und Versionsprüfung freigegeben.", operationId, Environment.MachineName, null, action, psExecPath: localPath, psExecVersion: _config.LocalPsExecVersion, signer: integrity.Subject, thumbprint: integrity.Thumbprint);
        return PsExecEvaluationResult.Successful(localPath, versionStatus);
    }

    private PsExecEvaluationResult FinalizeFailure(string message, string operationId, string action, string? psexecPath, PsExecIntegrityResult? integrity = null)
    {
        _config.SimulationMode = true;
        _config.IsSimulationModeEnforced = true;
        _config.StartupSecurityBlockReason = message;
        _config.LastDownloadValidationResult = message;
        _config.PsExecVersionStatus = string.IsNullOrWhiteSpace(_config.PsExecVersionStatus) ? "Blocked" : _config.PsExecVersionStatus;
        PersistConfiguration();

        var trustLogger = new TrustLogger(_config.TrustLogPath);
        trustLogger.Error("PsExecUsageBlocked", "Blocked", message, operationId, Environment.MachineName, null, action, psExecPath: psexecPath ?? string.Empty, psExecVersion: integrity?.VersionText ?? _config.LocalPsExecVersion, signer: integrity?.Subject ?? string.Empty, thumbprint: integrity?.Thumbprint ?? string.Empty);
        trustLogger.Error("ConnectionFallbackBlocked", "Blocked", "ConnectionFallback wegen Integritäts-, Bezugs- oder Versionsfehler blockiert.", operationId, Environment.MachineName, null, action, psExecPath: psexecPath ?? string.Empty, psExecVersion: integrity?.VersionText ?? _config.LocalPsExecVersion);
        return PsExecEvaluationResult.Failed(message);
    }

    private void UpdatePsExecMetadata(string localPath, string versionText)
    {
        _config.PsExecPath = localPath;
        _config.LocalPsExecVersion = versionText;
    }

    private PsExecIntegrityResult VerifyIntegrity(string localPath, string operationId, string action, string toolsDirectory)
    {
        var trustLogger = new TrustLogger(_config.TrustLogPath);
        trustLogger.Info("PsExecIntegrityCheck", "Started", "Start der PsExec-Integritätsprüfung.", operationId, Environment.MachineName, null, action, psExecPath: localPath);

        if (!File.Exists(localPath))
        {
            return PsExecIntegrityResult.Failed("PsExec.exe fehlt.");
        }

        var signature = _authentiCodeVerifier.Verify(localPath);
        var versionText = GetFileVersionText(localPath);
        trustLogger.Info("PsExecSignatureCheck", signature.Success ? "Success" : "Failed", $"Ergebnis der Signaturprüfung: Status={signature.Status}; Message={signature.StatusMessage}", operationId, Environment.MachineName, null, action, psExecPath: localPath, psExecVersion: versionText, signer: signature.Subject, thumbprint: signature.Thumbprint);
        trustLogger.Info("PsExecSignerInfo", signature.Success ? "Detected" : "Unknown", $"Erkannter Signer={signature.Subject}; Thumbprint={signature.Thumbprint}; PublicKey={signature.PublicKey}", operationId, Environment.MachineName, null, action, psExecPath: localPath, psExecVersion: versionText, signer: signature.Subject, thumbprint: signature.Thumbprint);

        if (!signature.Success)
        {
            return PsExecIntegrityResult.FromSignature(signature, versionText, "PsExec.exe ist nicht gültig signiert.");
        }

        if (!SignerMatchesExpectation(signature))
        {
            return PsExecIntegrityResult.FromSignature(signature, versionText, "PsExec.exe wurde mit einem nicht erwarteten Signer signiert.");
        }

        if (_config.EnablePsExecCatalogValidation && !string.IsNullOrWhiteSpace(_config.PsExecCatalogFilePath) && File.Exists(_config.PsExecCatalogFilePath))
        {
            trustLogger.Info("PsExecCatalogCheck", "Started", "Start der Katalogprüfung für PsExec/Sysinternals-Ordner.", operationId, Environment.MachineName, null, action, psExecPath: localPath, psExecVersion: versionText);
            var catalogCheck = _catalogVerifier.Verify(_config.PsExecCatalogFilePath, localPath, "PsExec.exe");
            trustLogger.Info("PsExecCatalogCheck", catalogCheck.Success ? "Success" : "Failed", catalogCheck.StatusMessage, operationId, Environment.MachineName, null, action, psExecPath: localPath, psExecVersion: versionText);
            if (!catalogCheck.Success)
            {
                return PsExecIntegrityResult.FromSignature(signature, versionText, $"Katalogprüfung fehlgeschlagen: {catalogCheck.StatusMessage}");
            }
        }
        else if (_config.EnablePsExecCatalogValidation && Directory.Exists(toolsDirectory))
        {
            trustLogger.Info("PsExecCatalogCheck", "Skipped", "Kein lokaler Katalog vorhanden. Katalogprüfung wird übersprungen.", operationId, Environment.MachineName, null, action, psExecPath: localPath, psExecVersion: versionText);
        }

        return PsExecIntegrityResult.Successful(signature, versionText);
    }

    private bool SignerMatchesExpectation(SignatureVerificationResult signature)
    {
        var thumbprintExpected = NormalizeHex(_config.PsExecExpectedThumbprint);
        var publicKeyExpected = NormalizeBase64OrText(_config.PsExecExpectedPublicKey);
        var signerExpected = (_config.PsExecExpectedSigner ?? string.Empty).Trim();

        if (!string.IsNullOrWhiteSpace(thumbprintExpected) && !string.Equals(thumbprintExpected, NormalizeHex(signature.Thumbprint), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(publicKeyExpected) && !string.Equals(publicKeyExpected, NormalizeBase64OrText(signature.PublicKey), StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(signerExpected) && (signature.Subject?.Contains(signerExpected, StringComparison.OrdinalIgnoreCase) != true))
        {
            return false;
        }

        return true;
    }

    private async Task<PsExecDownloadResult> AcquireManagedPsExecAsync(string operationId, string action, string toolsDirectory)
    {
        var trustLogger = new TrustLogger(_config.TrustLogPath);
        var rootDirectory = string.IsNullOrWhiteSpace(toolsDirectory) ? Path.Combine(AppContext.BaseDirectory, "Tools") : toolsDirectory;
        Directory.CreateDirectory(rootDirectory);

        var downloadSource = string.IsNullOrWhiteSpace(_config.PsExecDownloadSource)
            ? "https://download.sysinternals.com/files/PSTools.zip"
            : _config.PsExecDownloadSource.Trim();

        var sourceValidation = await ValidateDownloadSourceAsync(downloadSource);
        _config.LastDownloadSource = sourceValidation.FinalUri?.ToString() ?? downloadSource;
        _config.LastDownloadValidationResult = sourceValidation.Message;
        trustLogger.Info("PsExecDownloadSourceCheck", sourceValidation.Success ? "Success" : "Failed", sourceValidation.Message, operationId, Environment.MachineName, null, action, redirectChain: sourceValidation.RedirectChain, downloadSource: sourceValidation.FinalUri?.ToString() ?? downloadSource);
        PersistConfiguration();

        if (!sourceValidation.Success || sourceValidation.FinalUri is null)
        {
            return PsExecDownloadResult.Failed(sourceValidation.Message);
        }

        var tempDownload = Path.Combine(Path.GetTempPath(), $"PSEXEC_{Guid.NewGuid():N}");
        var finalPath = Path.Combine(rootDirectory, "PsExec.exe");

        try
        {
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            using var response = await client.GetAsync(sourceValidation.FinalUri, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();
            var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            var extension = GuessDownloadExtension(sourceValidation.FinalUri, mediaType);
            tempDownload += extension;
            await using (var sourceStream = await response.Content.ReadAsStreamAsync())
            await using (var fileStream = File.Create(tempDownload))
            {
                await sourceStream.CopyToAsync(fileStream);
            }

            trustLogger.Info("PsExecDownload", "Success", "Download erfolgreich abgeschlossen.", operationId, Environment.MachineName, null, action, psExecPath: finalPath, downloadSource: sourceValidation.FinalUri.ToString());

            if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
            {
                File.Copy(tempDownload, finalPath, true);
            }
            else
            {
                ExtractPsExecFromArchive(tempDownload, finalPath);
            }

            _config.LastDownloadSource = sourceValidation.FinalUri.ToString();
            _config.LastDownloadValidationResult = "Download und Extraktion erfolgreich";
            PersistConfiguration();
            trustLogger.Info("PsExecPostDownloadCheck", "Started", "Integritätsprüfung nach Download/Entpacken gestartet.", operationId, Environment.MachineName, null, action, psExecPath: finalPath);
            return PsExecDownloadResult.Successful(finalPath);
        }
        catch (Exception ex)
        {
            trustLogger.Error("PsExecDownload", "Failed", ex.Message, operationId, Environment.MachineName, null, action, downloadSource: sourceValidation.FinalUri.ToString());
            return PsExecDownloadResult.Failed($"Download von PsExec fehlgeschlagen: {ex.Message}");
        }
        finally
        {
            TryDeleteFile(tempDownload);
        }
    }

    private async Task<LatestVersionCheckResult> TryResolveLatestPublishedVersionAsync(string operationId, string action)
    {
        var trustLogger = new TrustLogger(_config.TrustLogPath);
        trustLogger.Info("PsExecLatestVersionCheck", "Started", "Ermittlung der zuletzt veröffentlichten PsExec-Version gestartet.", operationId, Environment.MachineName, null, action);

        var source = string.IsNullOrWhiteSpace(_config.PsExecDownloadSource)
            ? "https://download.sysinternals.com/files/PSTools.zip"
            : _config.PsExecDownloadSource.Trim();
        var sourceValidation = await ValidateDownloadSourceAsync(source);
        if (!sourceValidation.Success || sourceValidation.FinalUri is null)
        {
            trustLogger.Warn("PsExecLatestVersionCheck", "Failed", sourceValidation.Message, operationId, Environment.MachineName, null, action, redirectChain: sourceValidation.RedirectChain, downloadSource: sourceValidation.FinalUri?.ToString() ?? source);
            return LatestVersionCheckResult.Failed(sourceValidation.Message);
        }

        var tempDownload = Path.Combine(Path.GetTempPath(), $"PSEXEC_VER_{Guid.NewGuid():N}");
        var tempExtract = Path.Combine(Path.GetTempPath(), $"PSEXEC_VER_EXTRACT_{Guid.NewGuid():N}");
        try
        {
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            using var response = await client.GetAsync(sourceValidation.FinalUri, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();
            var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            var extension = GuessDownloadExtension(sourceValidation.FinalUri, mediaType);
            tempDownload += extension;
            await using (var sourceStream = await response.Content.ReadAsStreamAsync())
            await using (var fileStream = File.Create(tempDownload))
            {
                await sourceStream.CopyToAsync(fileStream);
            }

            string candidatePath;
            if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
            {
                candidatePath = tempDownload;
            }
            else
            {
                Directory.CreateDirectory(tempExtract);
                candidatePath = Path.Combine(tempExtract, "PsExec.exe");
                ExtractPsExecFromArchive(tempDownload, candidatePath);
            }

            var versionText = GetFileVersionText(candidatePath);
            trustLogger.Info("PsExecLatestVersionCheck", string.IsNullOrWhiteSpace(versionText) ? "Unknown" : "Success", $"Ermittelte zuletzt veröffentlichte PsExec-Version: {versionText}", operationId, Environment.MachineName, null, action, psExecVersion: versionText, downloadSource: sourceValidation.FinalUri.ToString());
            return LatestVersionCheckResult.Successful(versionText, sourceValidation.FinalUri.ToString());
        }
        catch (Exception ex)
        {
            trustLogger.Warn("PsExecLatestVersionCheck", "Failed", ex.Message, operationId, Environment.MachineName, null, action, downloadSource: sourceValidation.FinalUri.ToString());
            return LatestVersionCheckResult.Failed(ex.Message);
        }
        finally
        {
            TryDeleteFile(tempDownload);
            TryDeleteDirectory(tempExtract);
        }
    }

    private static string GuessDownloadExtension(Uri uri, string mediaType)
    {
        if (!string.IsNullOrWhiteSpace(mediaType) && mediaType.Contains("zip", StringComparison.OrdinalIgnoreCase))
        {
            return ".zip";
        }

        var fileName = Path.GetFileName(uri.AbsolutePath);
        var extension = Path.GetExtension(fileName);
        return string.IsNullOrWhiteSpace(extension) ? ".bin" : extension;
    }

    private static void ExtractPsExecFromArchive(string archivePath, string targetExePath)
    {
        using var archive = ZipFile.OpenRead(archivePath);
        var entry = archive.Entries.FirstOrDefault(entry =>
            string.Equals(Path.GetFileName(entry.FullName), "PsExec.exe", StringComparison.OrdinalIgnoreCase));
        if (entry is null)
        {
            throw new InvalidOperationException("Im Archiv wurde keine PsExec.exe gefunden.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(targetExePath)!);
        entry.ExtractToFile(targetExePath, true);
    }

    private async Task<DownloadSourceValidationResult> ValidateDownloadSourceAsync(string source)
    {
        try
        {
            if (!Uri.TryCreate(source, UriKind.Absolute, out var currentUri))
            {
                return DownloadSourceValidationResult.Failed("PsExec-Downloadquelle ist keine gültige absolute URL.");
            }

            if (!string.Equals(currentUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return DownloadSourceValidationResult.Failed("PsExec-Downloadquelle muss HTTPS verwenden.");
            }

            var redirectChain = new List<string> { currentUri.ToString() };
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };

            for (var i = 0; i < 5; i++)
            {
                using var response = await SendValidationRequestAsync(client, currentUri);
                if ((int)response.StatusCode is >= 300 and < 400)
                {
                    var location = response.Headers.Location;
                    if (location is null)
                    {
                        return DownloadSourceValidationResult.Failed("Redirect ohne Location-Header erkannt.", string.Join(" -> ", redirectChain));
                    }

                    currentUri = location.IsAbsoluteUri ? location : new Uri(currentUri, location);
                    redirectChain.Add(currentUri.ToString());
                    if (!string.Equals(currentUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                    {
                        return DownloadSourceValidationResult.Failed("Redirect-Ziel verwendet kein HTTPS.", string.Join(" -> ", redirectChain));
                    }

                    if (!IsTrustedDownloadHost(currentUri.Host))
                    {
                        return DownloadSourceValidationResult.Failed("Redirect-Ziel gehört nicht zu einer plausiblen Microsoft-/Sysinternals-Domain.", string.Join(" -> ", redirectChain));
                    }

                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    return DownloadSourceValidationResult.Failed($"Downloadquelle antwortete mit HTTP {(int)response.StatusCode}.", string.Join(" -> ", redirectChain));
                }

                if (!IsTrustedDownloadHost(currentUri.Host))
                {
                    return DownloadSourceValidationResult.Failed("Downloadquelle gehört nicht zu einer plausiblen Microsoft-/Sysinternals-Domain.", string.Join(" -> ", redirectChain));
                }

                return DownloadSourceValidationResult.Successful(currentUri, string.Join(" -> ", redirectChain));
            }

            return DownloadSourceValidationResult.Failed("Zu viele Redirects bei der PsExec-Quelle.", string.Join(" -> ", redirectChain));
        }
        catch (TaskCanceledException ex)
        {
            return DownloadSourceValidationResult.Failed($"Prüfung der PsExec-Downloadquelle lief in einen Timeout: {ex.Message}");
        }
        catch (HttpRequestException ex)
        {
            return DownloadSourceValidationResult.Failed($"Prüfung der PsExec-Downloadquelle ist fehlgeschlagen: {ex.Message}");
        }
        catch (Exception ex)
        {
            return DownloadSourceValidationResult.Failed($"Prüfung der PsExec-Downloadquelle ist unerwartet fehlgeschlagen: {ex.Message}");
        }
    }

    private static async Task<HttpResponseMessage> SendValidationRequestAsync(HttpClient client, Uri currentUri)
    {
        var request = new HttpRequestMessage(HttpMethod.Head, currentUri);
        var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);

        if (response.StatusCode == HttpStatusCode.MethodNotAllowed || response.StatusCode == HttpStatusCode.NotImplemented)
        {
            response.Dispose();
            request.Dispose();
            request = new HttpRequestMessage(HttpMethod.Get, currentUri);
            return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        }

        request.Dispose();
        return response;
    }

    private static bool IsTrustedDownloadHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var normalized = host.Trim().ToLowerInvariant();
        return TrustedDownloadHosts.Contains(normalized, StringComparer.OrdinalIgnoreCase) ||
               normalized.EndsWith(".microsoft.com", StringComparison.Ordinal) ||
               normalized.EndsWith(".sysinternals.com", StringComparison.Ordinal);
    }

    private string ResolveToolsDirectory()
    {
        var configured = string.IsNullOrWhiteSpace(_config.ToolsDirectoryPath) ? Path.Combine(AppContext.BaseDirectory, "Tools") : ExpandProgramDir(_config.ToolsDirectoryPath);
        return string.IsNullOrWhiteSpace(configured) ? Path.Combine(AppContext.BaseDirectory, "Tools") : configured;
    }

    private string ResolveConfiguredOrExistingPsExecPath()
    {
        if (!string.IsNullOrWhiteSpace(_config.PsExecPath))
        {
            var expanded = ExpandProgramDir(_config.PsExecPath);
            if (!string.IsNullOrWhiteSpace(expanded))
            {
                return expanded;
            }
        }

        if (TryResolveFromProgramDirectory(out var programResolved))
        {
            return programResolved;
        }

        if (TryResolveFromPath(out var pathResolved))
        {
            return pathResolved;
        }

        return string.Empty;
    }

    private bool IsManagedToolsPath(string? candidatePath, string toolsDirectory)
    {
        if (string.IsNullOrWhiteSpace(candidatePath) || string.IsNullOrWhiteSpace(toolsDirectory))
        {
            return false;
        }

        try
        {
            var candidateFull = Path.GetFullPath(candidatePath);
            var toolsFull = Path.GetFullPath(toolsDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return candidateFull.StartsWith(toolsFull, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private void PersistConfiguration()
    {
        try
        {
            _configBootstrapper.Save(_config);
        }
        catch (Exception ex)
        {
            _logger.Warn("DependencyCheck", $"Konfiguration konnte nicht gespeichert werden: {ex.Message}");
        }
    }

    private bool EnsureEulaAccepted()
    {
        try
        {
            var setRegistry = new ProcessStartInfo
            {
                FileName = _config.PowerShellExecutable,
                Arguments = @"-NoProfile -ExecutionPolicy Bypass -Command ""New-Item -Path 'HKCU:\Software\Sysinternals\PsExec' -Force | Out-Null; New-ItemProperty -Path 'HKCU:\Software\Sysinternals\PsExec' -Name 'EulaAccepted' -Value 1 -PropertyType DWord -Force | Out-Null""",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var ps = new Process { StartInfo = setRegistry };
            ps.Start();
            if (!ps.WaitForExit(5000))
            {
                TryKill(ps);
                _logger.Warn("DependencyCheck", "Setzen des PsExec-EULA-Registry-Werts lief in einen Timeout.");
                return false;
            }

            _logger.Info("DependencyCheck", "PsExec-EULA wurde global im Benutzerkontext gesetzt.");
            return true;
        }
        catch (Exception ex)
        {
            _logger.Warn("DependencyCheck", $"Globale PsExec-EULA-Akzeptanz fehlgeschlagen: {ex.Message}");
            return false;
        }
    }

    private bool TryResolveFromPath(out string resolvedPath)
    {
        resolvedPath = string.Empty;
        return TryResolveExecutable("PsExec.exe", out resolvedPath) || TryResolveExecutable("PsExec64.exe", out resolvedPath);
    }

    private bool TryResolveFromProgramDirectory(out string resolvedPath)
    {
        resolvedPath = string.Empty;
        var configured = string.IsNullOrWhiteSpace(_config.PsExecPath) ? null : ExpandProgramDir(_config.PsExecPath);
        var toolsDirectory = ResolveToolsDirectory();
        var candidateDirectories = new List<string>
        {
            AppContext.BaseDirectory,
            toolsDirectory,
            Path.Combine(AppContext.BaseDirectory, "Tools", "SysinternalsSuite"),
            Path.Combine(AppContext.BaseDirectory, "Sysinternals")
        };

        if (!string.IsNullOrWhiteSpace(configured))
        {
            var configuredDirectory = Path.GetDirectoryName(configured);
            if (!string.IsNullOrWhiteSpace(configuredDirectory))
            {
                candidateDirectories.Insert(0, configuredDirectory);
            }
        }

        foreach (var directory in candidateDirectories.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            foreach (var fileName in new[] { "PsExec.exe", "PsExec64.exe" })
            {
                var candidate = Path.Combine(directory, fileName);
                if (File.Exists(candidate))
                {
                    resolvedPath = candidate;
                    return true;
                }
            }
        }

        return false;
    }

    private static bool TryResolveExecutable(string executableName, out string resolvedPath)
    {
        resolvedPath = string.Empty;
        var pathEntries = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var entry in pathEntries)
        {
            try
            {
                var candidate = Path.Combine(entry, executableName);
                if (File.Exists(candidate))
                {
                    resolvedPath = candidate;
                    return true;
                }
            }
            catch
            {
            }
        }

        return false;
    }

    private static string ExpandProgramDir(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var replaced = value.Replace("ProgramDir", AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
        return Environment.ExpandEnvironmentVariables(replaced);
    }

    private static string GetFileVersionText(string filePath)
    {
        try
        {
            return FileVersionInfo.GetVersionInfo(filePath).FileVersion ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static Version? ParseVersionOrNull(string? versionText)
    {
        if (string.IsNullOrWhiteSpace(versionText))
        {
            return null;
        }

        return Version.TryParse(versionText, out var version) ? version : null;
    }

    private static string DetermineVersionStatus(Version? localVersion, Version? latestPublishedVersion)
    {
        if (localVersion is null || latestPublishedVersion is null)
        {
            return "Unknown";
        }

        if (localVersion > latestPublishedVersion || localVersion == latestPublishedVersion)
        {
            return "Current";
        }

        var localMinor = localVersion.Minor;
        var latestMinor = latestPublishedVersion.Minor;
        return latestMinor - localMinor <= 5 ? "Allowed" : "Outdated";
    }

    private static string NormalizeHex(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : new string(value.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();

    private static string NormalizeBase64OrText(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static string NormalizeAction(string action)
        => string.IsNullOrWhiteSpace(action) ? "UNKNOWN" : action.Trim().ToUpperInvariant().Replace(' ', '-');

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            {
                Directory.Delete(path, true);
            }
        }
        catch
        {
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
        }
    }
}

internal sealed class PsExecEvaluationResult
{
    public bool Success { get; init; }
    public bool Skipped { get; init; }
    public string ErrorMessage { get; init; } = string.Empty;
    public string PsExecPath { get; init; } = string.Empty;
    public string VersionStatus { get; init; } = string.Empty;

    public static PsExecEvaluationResult Successful(string path, string versionStatus) => new() { Success = true, PsExecPath = path, VersionStatus = versionStatus };
    public static PsExecEvaluationResult Failed(string message) => new() { Success = false, ErrorMessage = message ?? string.Empty };
    public static PsExecEvaluationResult CreateSkipped() => new() { Success = true, Skipped = true, VersionStatus = "Skipped" };

    public PsExecInitializationResult ToInitializationResult()
        => Success ? PsExecInitializationResult.Successful(false) : PsExecInitializationResult.Failed(ErrorMessage);
}

internal sealed class PsExecDownloadResult
{
    public bool Success { get; init; }
    public string PsExecPath { get; init; } = string.Empty;
    public string ErrorMessage { get; init; } = string.Empty;

    public static PsExecDownloadResult Successful(string path) => new() { Success = true, PsExecPath = path };
    public static PsExecDownloadResult Failed(string message) => new() { Success = false, ErrorMessage = message ?? string.Empty };
}

internal sealed class LatestVersionCheckResult
{
    public Version? Version { get; init; }
    public string VersionText { get; init; } = string.Empty;
    public string ValidationResult { get; init; } = string.Empty;

    public static LatestVersionCheckResult Successful(string versionText, string validationResult)
        => new() { Version = Version.TryParse(versionText, out var parsed) ? parsed : null, VersionText = versionText ?? string.Empty, ValidationResult = validationResult ?? string.Empty };

    public static LatestVersionCheckResult Failed(string validationResult)
        => new() { ValidationResult = validationResult ?? string.Empty };
}

internal sealed class DownloadSourceValidationResult
{
    public bool Success { get; init; }
    public Uri? FinalUri { get; init; }
    public string RedirectChain { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;

    public static DownloadSourceValidationResult Successful(Uri finalUri, string redirectChain)
        => new() { Success = true, FinalUri = finalUri, RedirectChain = redirectChain, Message = "Downloadquelle und Redirect-Kette sind plausibel." };

    public static DownloadSourceValidationResult Failed(string message, string redirectChain = "")
        => new() { Success = false, RedirectChain = redirectChain, Message = message ?? string.Empty };
}

internal sealed class PsExecIntegrityResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public string VersionText { get; init; } = string.Empty;
    public string Subject { get; init; } = string.Empty;
    public string Thumbprint { get; init; } = string.Empty;

    public static PsExecIntegrityResult Successful(SignatureVerificationResult signature, string versionText)
        => new() { Success = true, VersionText = versionText, Subject = signature.Subject, Thumbprint = signature.Thumbprint, Message = "Integritätsprüfung erfolgreich." };

    public static PsExecIntegrityResult Failed(string message)
        => new() { Success = false, Message = message ?? string.Empty };

    public static PsExecIntegrityResult FromSignature(SignatureVerificationResult signature, string versionText, string message)
        => new() { Success = false, VersionText = versionText, Subject = signature.Subject, Thumbprint = signature.Thumbprint, Message = message ?? string.Empty };
}

public sealed class PsExecInitializationResult
{
    public bool Success { get; init; }
    public bool ShowDirectInstallHint { get; init; }
    public string ErrorMessage { get; init; } = string.Empty;

    public static PsExecInitializationResult Successful(bool showDirectInstallHint = false)
        => new() { Success = true, ShowDirectInstallHint = showDirectInstallHint };

    public static PsExecInitializationResult Failed(string errorMessage)
        => new() { Success = false, ErrorMessage = errorMessage ?? string.Empty };
}
