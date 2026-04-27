using System.IO;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class ConfigPathValidator
{
    public ConfigPathValidationResult ValidateForStartup(UserConfigData userConfig, AppConfig runtimeConfig)
    {
        var result = new ConfigPathValidationResult();

        ValidateDirectoryPath(result, "config.json", nameof(UserConfigData.LocalLogDirectory), userConfig.LocalLogDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "config.json", nameof(UserConfigData.LocalProcessingDirectory), userConfig.LocalProcessingDirectory, critical: true, absoluteExpected: true);

        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.RemoteAuditLogDirectory), runtimeConfig.RemoteAuditLogDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.RemoteImeLogDirectory), runtimeConfig.RemoteImeLogDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.RemoteTempDirectory), runtimeConfig.RemoteTempDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.SupportClientDirectory), runtimeConfig.SupportClientDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.ToolsDirectoryPath), runtimeConfig.ToolsDirectoryPath, critical: false, absoluteExpected: true, allowEmpty: true);
        ValidateFilePath(result, "TrustedConfig.json", nameof(AppConfig.PsExecPath), runtimeConfig.PsExecPath, critical: false, absoluteExpected: true, allowEmpty: true, expectedExtension: ".exe");
        ValidateFilePath(result, "TrustedConfig.json", nameof(AppConfig.PsExecCatalogFilePath), runtimeConfig.PsExecCatalogFilePath, critical: false, absoluteExpected: true, allowEmpty: true, expectedExtension: ".cat");
        ValidateExecutableReference(result, "TrustedConfig.json", nameof(AppConfig.PowerShellExecutable), runtimeConfig.PowerShellExecutable);
        ValidateFilePath(result, "TrustedConfig.json", nameof(AppConfig.TrustedConfigPath), runtimeConfig.TrustedConfigPath, critical: true, absoluteExpected: true, expectedExtension: ".json");
        ValidateFilePath(result, "TrustedConfig.json", nameof(AppConfig.TrustLogPath), runtimeConfig.TrustLogPath, critical: true, absoluteExpected: true, expectedExtension: ".log");

        return result;
    }

    public ConfigPathValidationResult ValidateForSave(AppConfig config)
    {
        var result = new ConfigPathValidationResult();

        ValidateDirectoryPath(result, "config.json", nameof(AppConfig.LocalLogDirectory), config.LocalLogDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "config.json", nameof(AppConfig.LocalProcessingDirectory), config.LocalProcessingDirectory, critical: true, absoluteExpected: true);

        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.RemoteAuditLogDirectory), config.RemoteAuditLogDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.RemoteImeLogDirectory), config.RemoteImeLogDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.RemoteTempDirectory), config.RemoteTempDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.SupportClientDirectory), config.SupportClientDirectory, critical: true, absoluteExpected: true);
        ValidateDirectoryPath(result, "TrustedConfig.json", nameof(AppConfig.ToolsDirectoryPath), config.ToolsDirectoryPath, critical: false, absoluteExpected: true, allowEmpty: true);
        ValidateFilePath(result, "TrustedConfig.json", nameof(AppConfig.PsExecPath), config.PsExecPath, critical: false, absoluteExpected: true, allowEmpty: true, expectedExtension: ".exe");
        ValidateFilePath(result, "TrustedConfig.json", nameof(AppConfig.PsExecCatalogFilePath), config.PsExecCatalogFilePath, critical: false, absoluteExpected: true, allowEmpty: true, expectedExtension: ".cat");
        ValidateExecutableReference(result, "TrustedConfig.json", nameof(AppConfig.PowerShellExecutable), config.PowerShellExecutable);
        ValidateFilePath(result, "TrustedConfig.json", nameof(AppConfig.TrustedConfigPath), config.TrustedConfigPath, critical: true, absoluteExpected: true, expectedExtension: ".json");
        ValidateFilePath(result, "TrustedConfig.json", nameof(AppConfig.TrustLogPath), config.TrustLogPath, critical: true, absoluteExpected: true, expectedExtension: ".log");

        return result;
    }

    private static void ValidateDirectoryPath(ConfigPathValidationResult result, string scope, string attributeName, string? value, bool critical, bool absoluteExpected, bool allowEmpty = false)
    {
        ValidatePathCore(result, scope, attributeName, value, critical, absoluteExpected, allowEmpty, expectedExtension: null, treatAsDirectory: true);
    }

    private static void ValidateFilePath(ConfigPathValidationResult result, string scope, string attributeName, string? value, bool critical, bool absoluteExpected, bool allowEmpty = false, string? expectedExtension = null)
    {
        ValidatePathCore(result, scope, attributeName, value, critical, absoluteExpected, allowEmpty, expectedExtension, treatAsDirectory: false);
    }

    private static void ValidateExecutableReference(ConfigPathValidationResult result, string scope, string attributeName, string? value)
    {
        var trimmed = value?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            AddIssue(result, ConfigPathValidationSeverity.Critical, scope, attributeName, trimmed, $"{attributeName} darf nicht leer sein.");
            return;
        }

        if (ContainsInvalidPathChars(trimmed))
        {
            AddIssue(result, ConfigPathValidationSeverity.Critical, scope, attributeName, trimmed, $"{attributeName} enthält ungültige Zeichen.");
            return;
        }

        if (trimmed.Contains(Path.DirectorySeparatorChar) || trimmed.Contains(Path.AltDirectorySeparatorChar))
        {
            ValidateFilePath(result, scope, attributeName, trimmed, critical: true, absoluteExpected: true, allowEmpty: false, expectedExtension: ".exe");
            return;
        }

        if (trimmed.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            AddIssue(result, ConfigPathValidationSeverity.Critical, scope, attributeName, trimmed, $"{attributeName} enthält einen ungültigen Dateinamen.");
        }
        else if (!trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            AddIssue(result, ConfigPathValidationSeverity.Informational, scope, attributeName, trimmed, $"{attributeName} verweist nicht auf eine .exe-Datei. Ein einfacher Kommandoalias ist nur zulässig, wenn er in der Zielumgebung auflösbar ist.");
        }
    }

    private static void ValidatePathCore(ConfigPathValidationResult result, string scope, string attributeName, string? value, bool critical, bool absoluteExpected, bool allowEmpty, string? expectedExtension, bool treatAsDirectory)
    {
        var trimmed = value?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            if (!allowEmpty)
            {
                AddIssue(result, critical ? ConfigPathValidationSeverity.Critical : ConfigPathValidationSeverity.Informational, scope, attributeName, trimmed, $"{attributeName} darf nicht leer sein.");
            }
            return;
        }

        var expanded = Environment.ExpandEnvironmentVariables(trimmed);
        if (ContainsInvalidPathChars(expanded))
        {
            AddIssue(result, ConfigPathValidationSeverity.Critical, scope, attributeName, trimmed, $"{attributeName} enthält ungültige Zeichen.");
            return;
        }

        if (expanded.Contains(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) || expanded.Contains("../", StringComparison.Ordinal) || expanded.Contains("..\\", StringComparison.Ordinal))
        {
            AddIssue(result, critical ? ConfigPathValidationSeverity.Critical : ConfigPathValidationSeverity.Informational, scope, attributeName, trimmed, $"{attributeName} enthält eine potenziell deformierte relative Pfadsequenz.");
        }

        if (absoluteExpected && !Path.IsPathRooted(expanded))
        {
            AddIssue(result, ConfigPathValidationSeverity.Critical, scope, attributeName, trimmed, $"{attributeName} muss ein absoluter Pfad sein.");
            return;
        }

        var root = Path.GetPathRoot(expanded);
        if (absoluteExpected && string.IsNullOrWhiteSpace(root))
        {
            AddIssue(result, ConfigPathValidationSeverity.Critical, scope, attributeName, trimmed, $"{attributeName} besitzt keine plausible Root-Struktur.");
            return;
        }

        var fileName = Path.GetFileName(expanded);
        if (!treatAsDirectory)
        {
            if (string.IsNullOrWhiteSpace(fileName))
            {
                AddIssue(result, ConfigPathValidationSeverity.Critical, scope, attributeName, trimmed, $"{attributeName} muss auf eine Datei zeigen.");
                return;
            }

            if (fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                AddIssue(result, ConfigPathValidationSeverity.Critical, scope, attributeName, trimmed, $"{attributeName} enthält einen ungültigen Dateinamen.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(expectedExtension) && !string.Equals(Path.GetExtension(fileName), expectedExtension, StringComparison.OrdinalIgnoreCase))
            {
                AddIssue(result, critical ? ConfigPathValidationSeverity.Critical : ConfigPathValidationSeverity.Informational, scope, attributeName, trimmed, $"{attributeName} endet nicht auf {expectedExtension}.");
            }
        }
        else if (fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            AddIssue(result, critical ? ConfigPathValidationSeverity.Critical : ConfigPathValidationSeverity.Informational, scope, attributeName, trimmed, $"{attributeName} enthält eine strukturell auffällige Verzeichniskomponente.");
        }
    }

    private static bool ContainsInvalidPathChars(string value)
    {
        return value.IndexOfAny(Path.GetInvalidPathChars()) >= 0 || value.Any(char.IsControl);
    }

    private static void AddIssue(ConfigPathValidationResult result, ConfigPathValidationSeverity severity, string scope, string attributeName, string pathValue, string message)
    {
        result.Issues.Add(new ConfigPathValidationIssue
        {
            Severity = severity,
            ConfigurationScope = scope,
            AttributeName = attributeName,
            PathValue = pathValue,
            Message = message
        });
    }
}
