using System.IO;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class TrustedConfigValidator
{
    private static readonly string[] AllowedRegistryPrefixes =
    [
        @"HKLM:\",
        @"HKCU:\",
        "Registry::HKEY_LOCAL_MACHINE\\",
        "Registry::HKEY_CURRENT_USER\\"
    ];

    private static readonly Regex AllowedHostPattern = new(
        @"^[A-Za-z0-9][A-Za-z0-9\-\*\?]*(\.[A-Za-z0-9][A-Za-z0-9\-\*\?]*)*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] RequiredTrustedStringProperties =
    [
        nameof(TrustedConfig.ConfigVersion),
        nameof(TrustedConfig.TrustedConfigPath),
        nameof(TrustedConfig.TrustLogPath),
        nameof(TrustedConfig.RemoteAuditLogDirectory),
        nameof(TrustedConfig.RemoteImeLogDirectory),
        nameof(TrustedConfig.RemoteTempDirectory),
        nameof(TrustedConfig.SupportClientDirectory),
        nameof(TrustedConfig.PowerShellExecutable),
        nameof(TrustedConfig.PsExecPath),
        nameof(TrustedConfig.ToolsDirectoryPath),
        nameof(TrustedConfig.PsExecCatalogFilePath),
        nameof(TrustedConfig.PsExecExpectedSigner),
        nameof(TrustedConfig.PsExecDownloadSource),
        nameof(TrustedConfig.FallbackConfigFileName),
        nameof(TrustedConfig.FallbackScriptFileName),
        nameof(TrustedConfig.FallbackScheduledTaskName),
        nameof(TrustedConfig.FallbackRunOnceValueName),
        nameof(TrustedConfig.RemoteFallbackLogFileName),
        nameof(TrustedConfig.ImeServiceName)
    ];

    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    public TrustedConfigValidationContext LoadAndValidateFromDisk(string trustedConfigPath, UserConfigData userConfig, string resolvedTrustedConfigPath, string resolvedTrustLogPath)
    {
        var result = new TrustedConfigValidationResult();
        var trustedConfig = new TrustedConfig
        {
            TrustedConfigPath = resolvedTrustedConfigPath,
            TrustLogPath = resolvedTrustLogPath
        };

        JsonDocument? document = null;
        try
        {
            var json = File.ReadAllText(trustedConfigPath);
            document = JsonDocument.Parse(json);
        }
        catch (Exception ex)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_JSON_PARSE", $"TrustedConfig.json ist nicht parsebar: {ex.Message}");
            FinalizeResult(result);
            return new TrustedConfigValidationContext
            {
                TrustedConfig = trustedConfig,
                RuntimeConfig = BuildRuntimeConfig(userConfig, trustedConfig, resolvedTrustedConfigPath, resolvedTrustLogPath),
                Validation = result
            };
        }

        using (document)
        {
            ValidateTrustedConfigJsonSchema(document.RootElement, result);

            if (!result.SchemaIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Error))
            {
                try
                {
                    trustedConfig = JsonSerializer.Deserialize<TrustedConfig>(document.RootElement.GetRawText(), _jsonOptions) ?? trustedConfig;
                    ApplyLegacyAllowListMigration(trustedConfig, result);
                }
                catch (Exception ex)
                {
                    AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_TYPED_LOAD", $"TrustedConfig konnte nicht in das stark typisierte Modell geladen werden: {ex.Message}");
                }
            }
        }

        ValidateTrustedConfigModelSchema(trustedConfig, result);
        var runtimeConfig = BuildRuntimeConfig(userConfig, trustedConfig, resolvedTrustedConfigPath, resolvedTrustLogPath);
        ValidateRuntimeConfigurationSchema(runtimeConfig, result);

        if (!result.SchemaIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Error))
        {
            ValidateConsistency(runtimeConfig, trustedConfig, result);
        }

        FinalizeResult(result);
        return new TrustedConfigValidationContext
        {
            TrustedConfig = trustedConfig,
            RuntimeConfig = runtimeConfig,
            Validation = result
        };
    }

    public TrustedConfigValidationResult ValidateForSave(AppConfig runtimeConfig, TrustedConfig trustedConfig)
    {
        var result = new TrustedConfigValidationResult();
        ValidateTrustedConfigModelSchema(trustedConfig, result);
        ValidateRuntimeConfigurationSchema(runtimeConfig, result);
        if (!result.SchemaIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Error))
        {
            ValidateConsistency(runtimeConfig, trustedConfig, result);
        }
        FinalizeResult(result);
        return result;
    }

    private static AppConfig BuildRuntimeConfig(UserConfigData userConfig, TrustedConfig trustedConfig, string resolvedTrustedConfigPath, string resolvedTrustLogPath)
    {
        return new AppConfig
        {
            ConfigVersion = userConfig.ConfigVersion,
            WindowTitle = userConfig.WindowTitle,
            AppDataFolderName = userConfig.AppDataFolderName,
            LocalLogDirectory = userConfig.LocalLogDirectory,
            PsExecTimeoutSeconds = userConfig.PsExecTimeoutSeconds,
            ConnectionStatusIntervalSeconds = userConfig.ConnectionStatusIntervalSeconds,
            ConnectionTimeoutSeconds = userConfig.ConnectionTimeoutSeconds,
            LiveViewRefreshSeconds = userConfig.LiveViewRefreshSeconds > 0 ? userConfig.LiveViewRefreshSeconds : (userConfig.AutoRefreshTargetLogs > 0 ? userConfig.AutoRefreshTargetLogs : 5),
            AutoRefreshTargetLogs = userConfig.AutoRefreshTargetLogs > 0 ? userConfig.AutoRefreshTargetLogs : (userConfig.LiveViewRefreshSeconds > 0 ? userConfig.LiveViewRefreshSeconds : 5),
            FallbackTaskDelayMinutes = userConfig.FallbackTaskDelayMinutes,
            LocalProcessingDirectory = userConfig.LocalProcessingDirectory,
            DefaultLogFiles = userConfig.DefaultLogFiles ?? [],
            WarningKeywords = userConfig.WarningKeywords ?? [],
            ErrorKeywords = userConfig.ErrorKeywords ?? [],
            LiveConnectionStatusMessage = userConfig.LiveConnectionStatusMessage,
            OptionsShowDefaultLogFiles = userConfig.OptionsShowDefaultLogFiles,
            Language = string.IsNullOrWhiteSpace(userConfig.Language) ? "Language-DEV" : userConfig.Language,
            ShortDestinationLogs = userConfig.ShortDestinationLogs,
            EnableAppLogRotation = userConfig.EnableAppLogRotation,
            MaxManagedLogSizeMb = userConfig.MaxManagedLogSizeMb,
            MaxManagedLogHistoryFiles = userConfig.MaxManagedLogHistoryFiles,
            MaxKeptLocalLogs = userConfig.MaxKeptLocalLogs,
            SimulationMode = userConfig.SimulationMode,
            LogTabs = userConfig.LogTabs ?? new LogTabVisibilityConfig(),
            TrustedConfigPath = resolvedTrustedConfigPath,
            TrustLogPath = resolvedTrustLogPath,
            RemoteAuditLogDirectory = trustedConfig.RemoteAuditLogDirectory,
            RemoteImeLogDirectory = trustedConfig.RemoteImeLogDirectory,
            RemoteTempDirectory = trustedConfig.RemoteTempDirectory,
            SupportClientDirectory = trustedConfig.SupportClientDirectory,
            PowerShellExecutable = trustedConfig.PowerShellExecutable,
            PsExecPath = ResolveTrustedPathValue(trustedConfig.PsExecPath),
            ToolsDirectoryPath = ResolveTrustedPathValue(trustedConfig.ToolsDirectoryPath),
            PsExecCatalogFilePath = ResolveTrustedPathValue(trustedConfig.PsExecCatalogFilePath),
            EnablePsExecCatalogValidation = trustedConfig.EnablePsExecCatalogValidation,
            PsExecExpectedSigner = trustedConfig.PsExecExpectedSigner,
            PsExecExpectedThumbprint = trustedConfig.PsExecExpectedThumbprint,
            PsExecExpectedPublicKey = trustedConfig.PsExecExpectedPublicKey,
            PsExecDownloadSource = trustedConfig.PsExecDownloadSource,
            LatestPublishedPsExecVersion = trustedConfig.LatestPublishedPsExecVersion,
            LocalPsExecVersion = trustedConfig.LocalPsExecVersion,
            PsExecVersionStatus = trustedConfig.PsExecVersionStatus,
            LastPsExecVersionCheck = trustedConfig.LastPsExecVersionCheck,
            LastDownloadSource = trustedConfig.LastDownloadSource,
            LastDownloadValidationResult = trustedConfig.LastDownloadValidationResult,
            FallbackConfigFileName = trustedConfig.FallbackConfigFileName,
            FallbackScriptFileName = trustedConfig.FallbackScriptFileName,
            FallbackScheduledTaskName = trustedConfig.FallbackScheduledTaskName,
            FallbackRunOnceValueName = trustedConfig.FallbackRunOnceValueName,
            RemoteFallbackLogFileName = trustedConfig.RemoteFallbackLogFileName,
            ConnectionFallback = trustedConfig.ConnectionFallback,
            RestoreRemotingState = trustedConfig.RestoreRemotingState,
            RegistryPathsForAppReset = trustedConfig.RegistryPathsForAppReset ?? [],
            ImeServiceName = trustedConfig.ImeServiceName,
            AllowedSources = trustedConfig.AllowedSources ?? [],
            AllowedDestinations = trustedConfig.AllowedDestinations ?? []
        };
    }

    private static void ApplyLegacyAllowListMigration(TrustedConfig trustedConfig, TrustedConfigValidationResult result)
    {
        if (trustedConfig.LegacyAllowedJumpHosts is null || trustedConfig.LegacyAllowedJumpHosts.Length == 0)
        {
            return;
        }

        if ((trustedConfig.AllowedSources?.Length ?? 0) == 0)
        {
            trustedConfig.AllowedSources = [];
        }

        if ((trustedConfig.AllowedDestinations?.Length ?? 0) == 0)
        {
            trustedConfig.AllowedDestinations = trustedConfig.LegacyAllowedJumpHosts
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim())
                .ToArray();
        }

        AddConsistencyIssue(result, ValidationIssueSeverity.Info, "CONSISTENCY_ALLOWEDJUMPHOSTS_LEGACYMIGRATION", "Legacy-Feld AllowedJumpHosts wurde nach AllowedDestinations migriert. AllowedSources bleibt leer und bedeutet 'alles erlaubt'.");
        trustedConfig.LegacyAllowedJumpHosts = null;
    }

    private void ValidateTrustedConfigJsonSchema(JsonElement root, TrustedConfigValidationResult result)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_ROOT_OBJECT", "TrustedConfig.json muss ein JSON-Objekt sein.");
            return;
        }

        foreach (var propertyName in RequiredTrustedStringProperties)
        {
            ValidateRequiredStringProperty(root, propertyName, result);
        }

        ValidateBooleanProperty(root, nameof(TrustedConfig.ConnectionFallback), result);
        ValidateBooleanProperty(root, nameof(TrustedConfig.EnablePsExecCatalogValidation), result);
        ValidateBooleanProperty(root, nameof(TrustedConfig.RestoreRemotingState), result);
        ValidateStringArrayProperty(root, nameof(TrustedConfig.RegistryPathsForAppReset), allowEmptyEntries: false, result);
        ValidateAllowListArrayProperty(root, nameof(TrustedConfig.AllowedSources), "AllowedJumpHosts", treatLegacyAsValidForMissing: true, result);
        ValidateAllowListArrayProperty(root, nameof(TrustedConfig.AllowedDestinations), "AllowedJumpHosts", treatLegacyAsValidForMissing: true, result);
    }

    private void ValidateTrustedConfigModelSchema(TrustedConfig trustedConfig, TrustedConfigValidationResult result)
    {
        foreach (var value in new Dictionary<string, string?>
                 {
                     [nameof(TrustedConfig.ConfigVersion)] = trustedConfig.ConfigVersion,
                     [nameof(TrustedConfig.TrustedConfigPath)] = trustedConfig.TrustedConfigPath,
                     [nameof(TrustedConfig.TrustLogPath)] = trustedConfig.TrustLogPath,
                     [nameof(TrustedConfig.RemoteAuditLogDirectory)] = trustedConfig.RemoteAuditLogDirectory,
                     [nameof(TrustedConfig.RemoteImeLogDirectory)] = trustedConfig.RemoteImeLogDirectory,
                     [nameof(TrustedConfig.RemoteTempDirectory)] = trustedConfig.RemoteTempDirectory,
                     [nameof(TrustedConfig.SupportClientDirectory)] = trustedConfig.SupportClientDirectory,
                     [nameof(TrustedConfig.PowerShellExecutable)] = trustedConfig.PowerShellExecutable,
                     [nameof(TrustedConfig.FallbackConfigFileName)] = trustedConfig.FallbackConfigFileName,
                     [nameof(TrustedConfig.FallbackScriptFileName)] = trustedConfig.FallbackScriptFileName,
                     [nameof(TrustedConfig.FallbackScheduledTaskName)] = trustedConfig.FallbackScheduledTaskName,
                     [nameof(TrustedConfig.FallbackRunOnceValueName)] = trustedConfig.FallbackRunOnceValueName,
                     [nameof(TrustedConfig.RemoteFallbackLogFileName)] = trustedConfig.RemoteFallbackLogFileName,
                     [nameof(TrustedConfig.ImeServiceName)] = trustedConfig.ImeServiceName
                 })
        {
            if (value.Value is null)
            {
                AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_MODEL_{value.Key.ToUpperInvariant()}", $"Pflichtattribut {value.Key} darf nicht null sein.");
            }
        }

        if (trustedConfig.RegistryPathsForAppReset is null)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_MODEL_REGISTRYPATHS", "RegistryPathsForAppReset muss als Array vorhanden sein.");
        }

        if (trustedConfig.AllowedSources is null)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_MODEL_ALLOWEDSOURCES", "AllowedSources muss als Array vorhanden sein.");
        }
        else if (trustedConfig.AllowedSources.Any(value => value is null))
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_MODEL_ALLOWEDSOURCES_NULLENTRY", "AllowedSources darf keine Null-Werte enthalten.");
        }

        if (trustedConfig.AllowedDestinations is null)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_MODEL_ALLOWEDDESTINATIONS", "AllowedDestinations muss als Array vorhanden sein.");
        }
        else if (trustedConfig.AllowedDestinations.Any(value => value is null))
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_MODEL_ALLOWEDDESTINATIONS_NULLENTRY", "AllowedDestinations darf keine Null-Werte enthalten.");
        }
    }

    private void ValidateRuntimeConfigurationSchema(AppConfig runtimeConfig, TrustedConfigValidationResult result)
    {
        if (runtimeConfig.DefaultLogFiles is null)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_MODEL_DEFAULTLOGFILES", "DefaultLogFiles muss als Array vorhanden sein.");
        }

        if (runtimeConfig.WarningKeywords is null)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_MODEL_WARNINGKEYWORDS", "WarningKeywords muss als Array vorhanden sein.");
        }

        if (runtimeConfig.ErrorKeywords is null)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_MODEL_ERRORKEYWORDS", "ErrorKeywords muss als Array vorhanden sein.");
        }

        if (runtimeConfig.LogTabs is null)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, "SCHEMA_MODEL_LOGTABS", "LogTabs muss als Objekt vorhanden sein.");
        }
    }

    private void ValidateConsistency(AppConfig runtimeConfig, TrustedConfig trustedConfig, TrustedConfigValidationResult result)
    {
        ValidateAbsolutePath(runtimeConfig.LocalLogDirectory, nameof(runtimeConfig.LocalLogDirectory), result);
        ValidateAbsolutePath(runtimeConfig.LocalProcessingDirectory, nameof(runtimeConfig.LocalProcessingDirectory), result);
        ValidateAbsolutePath(runtimeConfig.RemoteAuditLogDirectory, nameof(runtimeConfig.RemoteAuditLogDirectory), result);
        ValidateAbsolutePath(runtimeConfig.RemoteImeLogDirectory, nameof(runtimeConfig.RemoteImeLogDirectory), result);
        ValidateAbsolutePath(runtimeConfig.RemoteTempDirectory, nameof(runtimeConfig.RemoteTempDirectory), result);
        ValidateAbsolutePath(runtimeConfig.SupportClientDirectory, nameof(runtimeConfig.SupportClientDirectory), result);
        ValidateAbsolutePath(runtimeConfig.TrustedConfigPath, nameof(runtimeConfig.TrustedConfigPath), result);
        ValidateAbsolutePath(runtimeConfig.TrustLogPath, nameof(runtimeConfig.TrustLogPath), result);

        ValidatePositiveRange(runtimeConfig.PsExecTimeoutSeconds, 1, 600, nameof(runtimeConfig.PsExecTimeoutSeconds), result);
        ValidatePositiveRange(runtimeConfig.ConnectionStatusIntervalSeconds, 1, 600, nameof(runtimeConfig.ConnectionStatusIntervalSeconds), result);
        ValidatePositiveRange(runtimeConfig.ConnectionTimeoutSeconds, 1, 3600, nameof(runtimeConfig.ConnectionTimeoutSeconds), result);
        ValidatePositiveRange(runtimeConfig.LiveViewRefreshSeconds, 1, 600, nameof(runtimeConfig.LiveViewRefreshSeconds), result);
        ValidatePositiveRange(runtimeConfig.FallbackTaskDelayMinutes, 1, 1440, nameof(runtimeConfig.FallbackTaskDelayMinutes), result);

        if (runtimeConfig.ConnectionStatusIntervalSeconds > runtimeConfig.ConnectionTimeoutSeconds)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, "CONSISTENCY_INTERVAL_TIMEOUT", "ConnectionStatusIntervalSeconds darf nicht größer als ConnectionTimeoutSeconds sein.");
        }

        ValidateFileName(runtimeConfig.FallbackConfigFileName, nameof(runtimeConfig.FallbackConfigFileName), result);
        ValidateFileName(runtimeConfig.FallbackScriptFileName, nameof(runtimeConfig.FallbackScriptFileName), result);
        ValidateFileName(runtimeConfig.RemoteFallbackLogFileName, nameof(runtimeConfig.RemoteFallbackLogFileName), result);
        ValidateSimpleName(runtimeConfig.FallbackScheduledTaskName, nameof(runtimeConfig.FallbackScheduledTaskName), result);
        ValidateSimpleName(runtimeConfig.FallbackRunOnceValueName, nameof(runtimeConfig.FallbackRunOnceValueName), result);
        ValidateSimpleName(runtimeConfig.ImeServiceName, nameof(runtimeConfig.ImeServiceName), result);

        if (!string.IsNullOrWhiteSpace(runtimeConfig.PsExecPath))
        {
            if (!Path.IsPathRooted(runtimeConfig.PsExecPath))
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Error, "CONSISTENCY_PSEXECPATH_ROOTED", "PsExecPath muss ein absoluter Pfad sein, wenn er gesetzt ist.");
            }

            if (!string.Equals(Path.GetFileName(runtimeConfig.PsExecPath), "PsExec.exe", StringComparison.OrdinalIgnoreCase))
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Error, "CONSISTENCY_PSEXECPATH_FILENAME", "PsExecPath muss auf PsExec.exe zeigen.");
            }
        }
        else if (runtimeConfig.ConnectionFallback)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Info, "CONSISTENCY_PSEXEC_EMPTY", "PsExecPath ist leer. Die App muss PsExec zur Laufzeit aus PATH oder Programmverzeichnis auflösen.");
        }

        if (!string.IsNullOrWhiteSpace(runtimeConfig.ToolsDirectoryPath))
        {
            ValidateAbsolutePath(runtimeConfig.ToolsDirectoryPath, nameof(runtimeConfig.ToolsDirectoryPath), result);
        }

        if (!string.IsNullOrWhiteSpace(runtimeConfig.PsExecCatalogFilePath))
        {
            ValidateAbsolutePath(runtimeConfig.PsExecCatalogFilePath, nameof(runtimeConfig.PsExecCatalogFilePath), result);
            if (!string.Equals(Path.GetExtension(runtimeConfig.PsExecCatalogFilePath), ".cat", StringComparison.OrdinalIgnoreCase))
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Error, "CONSISTENCY_PSEXECCATALOGFILEPATH_EXTENSION", "PsExecCatalogFilePath muss auf eine .cat-Datei zeigen.");
            }
        }

        Uri? psexecDownloadUri = null;
        if (!string.IsNullOrWhiteSpace(runtimeConfig.PsExecDownloadSource) && !Uri.TryCreate(runtimeConfig.PsExecDownloadSource, UriKind.Absolute, out psexecDownloadUri))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, "CONSISTENCY_PSEXECDOWNLOADSOURCE_URI", "PsExecDownloadSource muss eine absolute URL sein.");
        }
        else if (!string.IsNullOrWhiteSpace(runtimeConfig.PsExecDownloadSource) && psexecDownloadUri is not null)
        {
            if (!string.Equals(psexecDownloadUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Error, "CONSISTENCY_PSEXECDOWNLOADSOURCE_HTTPS", "PsExecDownloadSource muss HTTPS verwenden.");
            }

            if (!IsTrustedMicrosoftHost(psexecDownloadUri.Host))
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Warning, "CONSISTENCY_PSEXECDOWNLOADSOURCE_HOST", "PsExecDownloadSource verweist nicht auf eine plausibel vertrauenswürdige Microsoft-/Sysinternals-Domain.");
            }
        }

        if (!string.IsNullOrWhiteSpace(runtimeConfig.LatestPublishedPsExecVersion) && !Version.TryParse(runtimeConfig.LatestPublishedPsExecVersion, out _))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Warning, "CONSISTENCY_PSEXEC_LATESTVERSION_FORMAT", "LatestPublishedPsExecVersion ist nicht im erwarteten Versionsformat.");
        }

        if (!string.IsNullOrWhiteSpace(runtimeConfig.LocalPsExecVersion) && !Version.TryParse(runtimeConfig.LocalPsExecVersion, out _))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Warning, "CONSISTENCY_PSEXEC_LOCALVERSION_FORMAT", "LocalPsExecVersion ist nicht im erwarteten Versionsformat.");
        }

        ValidateAllowList(runtimeConfig.AllowedSources, "AllowedSources", emptyListMeansAllAllowed: true, result);
        ValidateAllowList(runtimeConfig.AllowedDestinations, "AllowedDestinations", emptyListMeansAllAllowed: true, result);
        ValidateStringList(runtimeConfig.WarningKeywords, nameof(runtimeConfig.WarningKeywords), allowEmptyList: false, emptyEntrySeverity: ValidationIssueSeverity.Error, result);
        ValidateStringList(runtimeConfig.ErrorKeywords, nameof(runtimeConfig.ErrorKeywords), allowEmptyList: false, emptyEntrySeverity: ValidationIssueSeverity.Error, result);
        ValidateStringList(runtimeConfig.DefaultLogFiles, nameof(runtimeConfig.DefaultLogFiles), allowEmptyList: false, emptyEntrySeverity: ValidationIssueSeverity.Error, result);
        ValidateStringList(runtimeConfig.RegistryPathsForAppReset, nameof(runtimeConfig.RegistryPathsForAppReset), allowEmptyList: false, emptyEntrySeverity: ValidationIssueSeverity.Error, result);

        foreach (var logFile in runtimeConfig.DefaultLogFiles ?? [])
        {
            if (string.IsNullOrWhiteSpace(logFile))
            {
                continue;
            }

            ValidateFileName(logFile, nameof(runtimeConfig.DefaultLogFiles), result);
        }

        foreach (var registryPath in runtimeConfig.RegistryPathsForAppReset ?? [])
        {
            if (string.IsNullOrWhiteSpace(registryPath))
            {
                continue;
            }

            if (!AllowedRegistryPrefixes.Any(prefix => registryPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Error, "CONSISTENCY_REGISTRY_HIVE", $"RegistryPathsForAppReset enthält einen nicht erlaubten Hive-Pfad: {registryPath}");
            }
        }

        ValidateLogTabs(runtimeConfig.LogTabs, result);

        if (!string.Equals(Path.GetFileName(runtimeConfig.TrustedConfigPath), "TrustedConfig.json", StringComparison.OrdinalIgnoreCase))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Warning, "CONSISTENCY_TRUSTEDCONFIGPATH_NAME", "TrustedConfigPath endet nicht auf TrustedConfig.json.");
        }

        if (!string.Equals(Path.GetFileName(runtimeConfig.TrustLogPath), "Trust.log", StringComparison.OrdinalIgnoreCase))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Warning, "CONSISTENCY_TRUSTLOGPATH_NAME", "TrustLogPath endet nicht auf Trust.log.");
        }

        if (runtimeConfig.RestoreRemotingState && !runtimeConfig.ConnectionFallback)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Warning, "CONSISTENCY_RESTORE_WITHOUT_FALLBACK", "RestoreRemotingState=true bei ConnectionFallback=false ist ein Logik-Warnzustand.");
        }

        if (!runtimeConfig.ConnectionFallback && !string.IsNullOrWhiteSpace(trustedConfig.PsExecPath))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Info, "CONSISTENCY_PSEXEC_UNUSED", "PsExecPath ist gesetzt, obwohl ConnectionFallback deaktiviert ist.");
        }
    }

    private static void ValidateRequiredStringProperty(JsonElement root, string propertyName, TrustedConfigValidationResult result)
    {
        if (!root.TryGetProperty(propertyName, out var property))
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_MISSING_{propertyName.ToUpperInvariant()}", $"Pflichtattribut {propertyName} fehlt.");
            return;
        }

        if (property.ValueKind != JsonValueKind.String)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_TYPE_{propertyName.ToUpperInvariant()}", $"{propertyName} muss ein String sein.");
            return;
        }

        if (property.GetString() is null)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_NULL_{propertyName.ToUpperInvariant()}", $"{propertyName} darf nicht null sein.");
        }
    }

    private static void ValidateBooleanProperty(JsonElement root, string propertyName, TrustedConfigValidationResult result)
    {
        if (!root.TryGetProperty(propertyName, out var property))
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_MISSING_{propertyName.ToUpperInvariant()}", $"Pflichtattribut {propertyName} fehlt.");
            return;
        }

        if (property.ValueKind is not JsonValueKind.True and not JsonValueKind.False)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_TYPE_{propertyName.ToUpperInvariant()}", $"{propertyName} muss ein bool-Wert sein.");
        }
    }

    private static void ValidateStringArrayProperty(JsonElement root, string propertyName, bool allowEmptyEntries, TrustedConfigValidationResult result)
    {
        if (!root.TryGetProperty(propertyName, out var property))
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_MISSING_{propertyName.ToUpperInvariant()}", $"Pflichtattribut {propertyName} fehlt.");
            return;
        }

        if (property.ValueKind != JsonValueKind.Array)
        {
            AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_TYPE_{propertyName.ToUpperInvariant()}", $"{propertyName} muss ein Array sein.");
            return;
        }

        var index = 0;
        foreach (var item in property.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_TYPE_{propertyName.ToUpperInvariant()}_ITEM", $"{propertyName}[{index}] muss ein String sein.");
            }
            else if (!allowEmptyEntries && string.IsNullOrWhiteSpace(item.GetString()))
            {
                AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_EMPTY_{propertyName.ToUpperInvariant()}_ITEM", $"{propertyName}[{index}] darf nicht leer sein.");
            }

            index++;
        }
    }

    private static void ValidateAllowListArrayProperty(JsonElement root, string propertyName, string legacyPropertyName, bool treatLegacyAsValidForMissing, TrustedConfigValidationResult result)
    {
        if (root.TryGetProperty(propertyName, out var property))
        {
            if (property.ValueKind != JsonValueKind.Array)
            {
                AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_TYPE_{propertyName.ToUpperInvariant()}", $"{propertyName} muss ein Array sein.");
                return;
            }

            var index = 0;
            foreach (var item in property.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_TYPE_{propertyName.ToUpperInvariant()}_ITEM", $"{propertyName}[{index}] muss ein String sein.");
                }
                else if (item.GetString() is null)
                {
                    AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_NULL_{propertyName.ToUpperInvariant()}_ITEM", $"{propertyName}[{index}] darf nicht null sein.");
                }

                index++;
            }
            return;
        }

        if (treatLegacyAsValidForMissing && root.TryGetProperty(legacyPropertyName, out var legacyProperty))
        {
            if (legacyProperty.ValueKind != JsonValueKind.Array)
            {
                AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_TYPE_{legacyPropertyName.ToUpperInvariant()}", $"{legacyPropertyName} muss ein Array sein.");
                return;
            }

            var index = 0;
            foreach (var item in legacyProperty.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_TYPE_{legacyPropertyName.ToUpperInvariant()}_ITEM", $"{legacyPropertyName}[{index}] muss ein String sein.");
                }
                else if (item.GetString() is null)
                {
                    AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_NULL_{legacyPropertyName.ToUpperInvariant()}_ITEM", $"{legacyPropertyName}[{index}] darf nicht null sein.");
                }
                index++;
            }

            AddSchemaIssue(result, ValidationIssueSeverity.Info, $"SCHEMA_LEGACY_{propertyName.ToUpperInvariant()}", $"{propertyName} wurde aus dem Legacy-Feld {legacyPropertyName} abgeleitet.");
            return;
        }

        AddSchemaIssue(result, ValidationIssueSeverity.Error, $"SCHEMA_MISSING_{propertyName.ToUpperInvariant()}", $"Pflichtattribut {propertyName} fehlt.");
    }

    private static void ValidateAbsolutePath(string value, string name, TrustedConfigValidationResult result)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_EMPTY", $"{name} darf nicht leer sein.");
            return;
        }

        var expanded = Environment.ExpandEnvironmentVariables(value);
        if (!Path.IsPathRooted(expanded))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_ROOTED", $"{name} muss ein absoluter Pfad sein.");
        }
    }

    private static void ValidatePositiveRange(int value, int min, int max, string name, TrustedConfigValidationResult result)
    {
        if (value < min || value > max)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_RANGE", $"{name} liegt außerhalb des erlaubten Bereichs ({min}-{max}). Aktuell: {value}");
        }
    }

    private static void ValidateFileName(string value, string name, TrustedConfigValidationResult result)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_EMPTY", $"{name} darf nicht leer sein.");
            return;
        }

        if (value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_INVALID", $"{name} enthält ungültige Zeichen.");
        }

        if (!string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_PATH", $"{name} darf nur einen Dateinamen und keinen Pfad enthalten.");
        }
    }

    private static void ValidateSimpleName(string value, string name, TrustedConfigValidationResult result)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_EMPTY", $"{name} darf nicht leer sein.");
            return;
        }

        if (value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_INVALID", $"{name} enthält ungültige Zeichen.");
        }
    }

    private static void ValidateAllowList(IEnumerable<string>? values, string name, bool emptyListMeansAllAllowed, TrustedConfigValidationResult result)
    {
        var upperName = name.ToUpperInvariant();
        if (values is null)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{upperName}_NULL", $"{name} darf nicht null sein.");
            return;
        }

        var list = values.ToList();
        if (list.Count == 0)
        {
            if (emptyListMeansAllAllowed)
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Info, $"CONSISTENCY_{upperName}_EMPTYLIST", $"{name} ist leer. Dies wird als 'alles erlaubt' interpretiert.");
            }
            else
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Warning, $"CONSISTENCY_{upperName}_EMPTYLIST", $"{name} ist leer.");
            }
            return;
        }

        if (list.Any(string.IsNullOrWhiteSpace))
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{upperName}_EMPTYENTRY", $"{name} enthält leere oder whitespace-only Einträge.");
        }

        var normalizedEntries = list
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .ToList();

        var duplicates = normalizedEntries
            .GroupBy(value => value, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToArray();
        if (duplicates.Length > 0)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Warning, $"CONSISTENCY_{upperName}_DUPLICATES", $"{name} enthält doppelte Einträge: {string.Join(", ", duplicates)}");
        }

        foreach (var entry in normalizedEntries)
        {
            if (!IsValidAllowListEntry(entry, out var reason))
            {
                var issueCode = entry.Contains('/', StringComparison.Ordinal)
                    ? $"CONSISTENCY_{upperName}_CIDR_INVALID"
                    : LooksLikeIpv4Candidate(entry)
                        ? $"CONSISTENCY_{upperName}_IP_INVALID"
                        : $"CONSISTENCY_{upperName}_FORMAT";
                AddConsistencyIssue(result, ValidationIssueSeverity.Error, issueCode, $"{name} enthält einen ungültigen Eintrag '{entry}': {reason}");
            }
            else if (entry == "*")
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Warning, $"CONSISTENCY_{upperName}_GLOBALWILDCARD", $"{name} enthält '*'. Dadurch werden alle passenden Systeme erlaubt.");
            }
        }
    }

    private static bool IsValidAllowListEntry(string entry, out string reason)
    {
        reason = string.Empty;
        if (string.IsNullOrWhiteSpace(entry))
        {
            reason = "Eintrag ist leer.";
            return false;
        }

        var trimmed = entry.Trim();
        if (trimmed.Any(char.IsWhiteSpace))
        {
            reason = "Leerzeichen sind nicht erlaubt.";
            return false;
        }

        if (trimmed.IndexOfAny(new[] { '\\', ':', ';', '"', '\'', '[', ']', '(', ')', '{', '}', '|' }) >= 0)
        {
            reason = "Eintrag enthält nicht erlaubte Zeichen.";
            return false;
        }

        if (TryParseCidr(trimmed, out _))
        {
            return true;
        }

        if (IPAddress.TryParse(trimmed, out var parsedAddress))
        {
            if (parsedAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                reason = "Nur IPv4-Adressen sind zulässig.";
                return false;
            }

            return true;
        }

        if (!AllowedHostPattern.IsMatch(trimmed))
        {
            reason = "Nur Hostnamen, FQDNs, IPv4, IPv4/CIDR oder kontrollierte Wildcards (*, ?) sind erlaubt.";
            return false;
        }

        if (trimmed.Contains("..", StringComparison.Ordinal))
        {
            reason = "Doppelte Punkte sind nicht erlaubt.";
            return false;
        }

        return true;
    }

    private static bool LooksLikeIpv4Candidate(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry))
        {
            return false;
        }

        var trimmed = entry.Trim();
        return trimmed.Any(static c => char.IsDigit(c)) && trimmed.Contains('.', StringComparison.Ordinal);
    }

    private static void ValidateStringList(IEnumerable<string>? values, string name, bool allowEmptyList, ValidationIssueSeverity emptyEntrySeverity, TrustedConfigValidationResult result)
    {
        if (values is null)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_NULL", $"{name} darf nicht null sein.");
            return;
        }

        var list = values.ToList();
        if (!allowEmptyList && list.Count == 0)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_{name.ToUpperInvariant()}_EMPTYLIST", $"{name} darf nicht leer sein.");
        }

        if (list.Any(string.IsNullOrWhiteSpace))
        {
            AddConsistencyIssue(result, emptyEntrySeverity, $"CONSISTENCY_{name.ToUpperInvariant()}_EMPTYENTRY", $"{name} enthält leere Einträge.");
        }

        var duplicates = list
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .GroupBy(value => value.Trim(), StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToArray();

        if (duplicates.Length > 0)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Warning, $"CONSISTENCY_{name.ToUpperInvariant()}_DUPLICATES", $"{name} enthält doppelte Einträge: {string.Join(", ", duplicates)}");
        }
    }

    private static void ValidateLogTabs(LogTabVisibilityConfig? logTabs, TrustedConfigValidationResult result)
    {
        if (logTabs is null)
        {
            AddConsistencyIssue(result, ValidationIssueSeverity.Error, "CONSISTENCY_LOGTABS_NULL", "LogTabs ist nicht vorhanden.");
            return;
        }

        var checks = new Dictionary<string, LogTabSetting?>
        {
            [nameof(logTabs.AgentExecutor)] = logTabs.AgentExecutor,
            [nameof(logTabs.AppActionProcessor)] = logTabs.AppActionProcessor,
            [nameof(logTabs.AppWorkload)] = logTabs.AppWorkload,
            [nameof(logTabs.ClientCertCheck)] = logTabs.ClientCertCheck,
            [nameof(logTabs.ClientHealth)] = logTabs.ClientHealth,
            [nameof(logTabs.DeviceHealthMonitoring)] = logTabs.DeviceHealthMonitoring,
            [nameof(logTabs.HealthScripts)] = logTabs.HealthScripts,
            [nameof(logTabs.IntuneManagementExtension)] = logTabs.IntuneManagementExtension,
            [nameof(logTabs.NotificationInfraLogs)] = logTabs.NotificationInfraLogs,
            [nameof(logTabs.Sensor)] = logTabs.Sensor,
            [nameof(logTabs.Win321AppInventory)] = logTabs.Win321AppInventory,
            [nameof(logTabs.LocalAppLog)] = logTabs.LocalAppLog,
            [nameof(logTabs.AppDataLogs)] = logTabs.AppDataLogs,
            [nameof(logTabs.RemoteAuditLog)] = logTabs.RemoteAuditLog,
            [nameof(logTabs.FallbackLog)] = logTabs.FallbackLog,
            [nameof(logTabs.TrustLog)] = logTabs.TrustLog
        };

        foreach (var check in checks)
        {
            if (check.Value is null)
            {
                AddConsistencyIssue(result, ValidationIssueSeverity.Error, $"CONSISTENCY_LOGTABS_{check.Key.ToUpperInvariant()}", $"LogTabs.{check.Key} fehlt oder ist ungültig.");
            }
        }
    }

    private static bool TryParseCidr(string value, out (uint network, uint mask) cidr)
    {
        cidr = default;
        var parts = value.Split('/');
        if (parts.Length != 2)
        {
            return false;
        }

        if (!IPAddress.TryParse(parts[0], out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        if (!int.TryParse(parts[1], out var prefixLength) || prefixLength < 0 || prefixLength > 32)
        {
            return false;
        }

        var mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        var ipValue = ToUInt32(address);
        cidr = (ipValue & mask, mask);
        return true;
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }
        return BitConverter.ToUInt32(bytes, 0);
    }


    private static string ResolveTrustedPathValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim().Replace("ProgramDir", AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
        return Environment.ExpandEnvironmentVariables(normalized);
    }

    private static bool IsTrustedMicrosoftHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var normalized = host.Trim().ToLowerInvariant();
        return normalized == "download.sysinternals.com" ||
               normalized == "live.sysinternals.com" ||
               normalized == "download.microsoft.com" ||
               normalized.EndsWith(".microsoft.com", StringComparison.Ordinal) ||
               normalized.EndsWith(".sysinternals.com", StringComparison.Ordinal);
    }

    private static void FinalizeResult(TrustedConfigValidationResult result)
    {
        var schemaErrorCount = result.SchemaIssues.Count(issue => issue.Severity == ValidationIssueSeverity.Error);
        var consistencyErrorCount = result.ConsistencyIssues.Count(issue => issue.Severity == ValidationIssueSeverity.Error);
        var consistencyWarningCount = result.ConsistencyIssues.Count(issue => issue.Severity == ValidationIssueSeverity.Warning);
        var consistencyInfoCount = result.ConsistencyIssues.Count(issue => issue.Severity == ValidationIssueSeverity.Info);

        result.LastSchemaValidation = schemaErrorCount > 0
            ? $"Schema-Validierung mit Fehlern ({schemaErrorCount})"
            : "Schema-Validierung erfolgreich";

        result.LastConsistencyValidation = consistencyErrorCount > 0
            ? $"Konsistenz-Validierung mit Fehlern ({consistencyErrorCount})"
            : consistencyWarningCount > 0
                ? $"Konsistenz-Validierung mit Warnungen ({consistencyWarningCount})"
                : consistencyInfoCount > 0
                    ? $"Konsistenz-Validierung erfolgreich mit Hinweisen ({consistencyInfoCount})"
                    : "Konsistenz-Validierung erfolgreich";

        result.ValidationSummary = $"Fehler={result.ErrorCount}; Warnungen={result.WarningCount}; Hinweise={result.InfoCount}";
    }

    private static void AddSchemaIssue(TrustedConfigValidationResult result, ValidationIssueSeverity severity, string code, string message)
        => result.SchemaIssues.Add(new TrustedConfigValidationIssue { Severity = severity, Code = code, Message = message });

    private static void AddConsistencyIssue(TrustedConfigValidationResult result, ValidationIssueSeverity severity, string code, string message)
        => result.ConsistencyIssues.Add(new TrustedConfigValidationIssue { Severity = severity, Code = code, Message = message });
}
