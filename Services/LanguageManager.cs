using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class LanguageManager
{
    private const string AppDisplayPlaceholder = "<<__APPDISPLAY__>>";

    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private Dictionary<string, string> _translations = new(StringComparer.Ordinal);
    private List<KeyValuePair<string, string>> _fragmentTranslations = new();
    private LanguageFile _currentLanguage = new();

    public static LanguageManager Instance { get; } = new();

    public event EventHandler? LanguageChanged;

    public string CurrentLanguageId => string.IsNullOrWhiteSpace(_currentLanguage.Meta.LanguageId) ? "Language-DEV" : _currentLanguage.Meta.LanguageId;
    public string CurrentDisplayName => string.IsNullOrWhiteSpace(_currentLanguage.Meta.DisplayName) ? CurrentLanguageId : _currentLanguage.Meta.DisplayName;
    public string AppPrefix => _currentLanguage.Meta.AppPrefix?.Trim() ?? string.Empty;
    public string BaseAppName => string.IsNullOrWhiteSpace(_currentLanguage.Meta.AppName) ? "Intune Support Suite" : _currentLanguage.Meta.AppName.Trim();

    public string GetAppDisplayName()
    {
        return string.IsNullOrWhiteSpace(AppPrefix) ? BaseAppName : $"{AppPrefix} {BaseAppName}".Trim();
    }

    public string GetCompactAppToken() => SanitizeForFileStem(GetAppDisplayName(), removeSpaces: true);

    public string GetAppFileStem() => SanitizeForFileStem(GetAppDisplayName(), removeSpaces: false);

    public string GetLocalAppLogFileName() => $"{GetAppFileStem()}.log";

    public string GetRemoteAuditLogFileName() => $"{GetAppFileStem()}-Remote-Audit.log";

    public string GetFallbackLogFileName() => $"{GetAppFileStem()}-Fallback.log";

    public string GetLocalAppLogLabel() => GetAppDisplayName();

    public string GetRemoteAuditLogLabel() => $"{GetAppDisplayName()} Remote Audit Log".Trim();

    public string GetFallbackLogLabel() => $"{GetAppDisplayName()} Fallback Log".Trim();

    public IReadOnlyList<string> GetKnownLocalAppLogFileNameVariants()
        => GetDistinctList(GetLocalAppLogFileName(), "DAP-Intune-Support.log", "Intune-Support-Suite.log", "Intune-Support.log");

    public IReadOnlyList<string> GetKnownRemoteAuditLogFileNameVariants()
        => GetDistinctList(GetRemoteAuditLogFileName(), "DAP-Remote-Audit.log", "Intune-Support-Suite-Remote-Audit.log", "Remote-Audit.log");

    public IReadOnlyList<string> GetKnownFallbackLogFileNameVariants()
        => GetDistinctList(GetFallbackLogFileName(), "DAP-Fallback.log", "Intune-Support-Suite-Fallback.log", "Fallback.log");

    public string ComposeWindowTitle(string? suffix = null)
    {
        var title = GetAppDisplayName();
        if (string.IsNullOrWhiteSpace(suffix))
        {
            return title;
        }

        return $"{title} - {TranslateText(suffix)}";
    }

    public void ApplyLanguageDrivenConfigFields(AppConfig? config)
    {
        if (config is null)
        {
            return;
        }

        var appDisplayName = GetAppDisplayName();
        config.WindowTitle = appDisplayName;
        config.AppDataFolderName = appDisplayName;
        config.LocalLogDirectory = NormalizeAppNamedPath(config.LocalLogDirectory, appDisplayName, "Logs");
        config.LocalProcessingDirectory = NormalizeAppNamedPath(config.LocalProcessingDirectory, appDisplayName, "ProcessedLogs");
        config.RemoteFallbackLogFileName = GetFallbackLogFileName();
    }

    public IReadOnlyList<LanguageOption> DiscoverLanguages(string? executableDirectory = null)
    {
        var directory = ResolveLanguageDirectory(executableDirectory);
        if (!Directory.Exists(directory))
        {
            return Array.Empty<LanguageOption>();
        }

        var result = new List<LanguageOption>();
        foreach (var filePath in Directory.EnumerateFiles(directory, "*.json", SearchOption.TopDirectoryOnly).OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var file = JsonSerializer.Deserialize<LanguageFile>(File.ReadAllText(filePath), _jsonOptions) ?? new LanguageFile();
                var languageId = string.IsNullOrWhiteSpace(file.Meta.LanguageId) ? Path.GetFileNameWithoutExtension(filePath) : file.Meta.LanguageId.Trim();
                result.Add(new LanguageOption
                {
                    LanguageId = languageId,
                    FilePath = filePath,
                    DisplayName = string.IsNullOrWhiteSpace(file.Meta.DisplayName) ? languageId : file.Meta.DisplayName.Trim(),
                    ShowInGui = file.Meta.ShowInGui
                });
            }
            catch
            {
            }
        }

        return result;
    }

    public bool Load(string? executableDirectory, string? configuredLanguage, AuditLogger? logger = null)
    {
        try
        {
            var options = DiscoverLanguages(executableDirectory);
            var selected = ResolveLanguageOption(options, configuredLanguage) ?? options.FirstOrDefault();
            if (selected is null)
            {
                _currentLanguage = new LanguageFile();
                _translations = new Dictionary<string, string>(StringComparer.Ordinal);
                _fragmentTranslations = new List<KeyValuePair<string, string>>();
                LanguageChanged?.Invoke(this, EventArgs.Empty);
                return false;
            }

            var file = JsonSerializer.Deserialize<LanguageFile>(File.ReadAllText(selected.FilePath), _jsonOptions) ?? new LanguageFile();
            if (string.IsNullOrWhiteSpace(file.Meta.LanguageId))
            {
                file.Meta.LanguageId = selected.LanguageId;
            }

            if (string.IsNullOrWhiteSpace(file.Meta.DisplayName))
            {
                file.Meta.DisplayName = selected.DisplayName;
            }

            _currentLanguage = file;
            _translations = (file.Strings ?? new Dictionary<string, string>())
                .Where(pair => !string.IsNullOrWhiteSpace(pair.Key))
                .ToDictionary(pair => pair.Key, pair => pair.Value ?? string.Empty, StringComparer.Ordinal);
            _fragmentTranslations = _translations.OrderByDescending(pair => pair.Key.Length).ToList();
            logger?.Info("LanguageLoad", $"Language file loaded: {selected.LanguageId} ({selected.DisplayName})", "-", "-", "LANGUAGE-LOAD");
            LanguageChanged?.Invoke(this, EventArgs.Empty);
            return true;
        }
        catch (Exception ex)
        {
            logger?.Warn("LanguageLoad", ex.Message, "-", "-", "LANGUAGE-LOAD");
            return false;
        }
    }

    public string TranslateText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text ?? string.Empty;
        }

        var result = text;
        if (_translations.TryGetValue(result, out var exact))
        {
            result = exact;
        }
        else
        {
            foreach (var pair in _fragmentTranslations)
            {
                if (string.IsNullOrWhiteSpace(pair.Key) || string.Equals(pair.Key, result, StringComparison.Ordinal))
                {
                    continue;
                }

                if (result.Contains(pair.Key, StringComparison.Ordinal))
                {
                    result = result.Replace(pair.Key, pair.Value ?? string.Empty, StringComparison.Ordinal);
                }
            }
        }

        result = ReplaceTokens(result);
        result = ApplyAppNameReplacements(result);
        return result;
    }

    private static string ResolveLanguageDirectory(string? executableDirectory)
    {
        var root = string.IsNullOrWhiteSpace(executableDirectory) ? AppContext.BaseDirectory : executableDirectory;
        return Path.Combine(root, "Language");
    }

    private static LanguageOption? ResolveLanguageOption(IReadOnlyList<LanguageOption> options, string? configuredLanguage)
    {
        if (options.Count == 0)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(configuredLanguage))
        {
            var normalized = configuredLanguage.Trim();
            var selected = options.FirstOrDefault(option =>
                string.Equals(option.LanguageId, normalized, StringComparison.OrdinalIgnoreCase)
                || string.Equals(Path.GetFileName(option.FilePath), normalized, StringComparison.OrdinalIgnoreCase)
                || string.Equals(Path.GetFileNameWithoutExtension(option.FilePath), normalized, StringComparison.OrdinalIgnoreCase));
            if (selected is not null)
            {
                return selected;
            }
        }

        return options.FirstOrDefault(option => string.Equals(option.LanguageId, "Language-DEV", StringComparison.OrdinalIgnoreCase))
               ?? options.FirstOrDefault(option => string.Equals(Path.GetFileNameWithoutExtension(option.FilePath), "Language-DEV", StringComparison.OrdinalIgnoreCase));
    }

    private string ReplaceTokens(string value)
    {
        return value
            .Replace("{AppDisplayName}", GetAppDisplayName(), StringComparison.Ordinal)
            .Replace("{AppPrefix}", AppPrefix, StringComparison.Ordinal)
            .Replace("{AppName}", BaseAppName, StringComparison.Ordinal);
    }

    private string ApplyAppNameReplacements(string value)
    {
        var result = value;
        result = ReplaceKnownAppNameVariants(result, GetAppDisplayName());

        result = ReplaceKnownLabelVariants(result, GetRemoteAuditLogLabel(),
            "DAP Remote Audit Log",
            "Remote Audit Log",
            "Remote audit log",
            "Intune Support Suite Remote Audit Log");
        result = ReplaceKnownLabelVariants(result, GetFallbackLogLabel(),
            "DAP Fallback Log",
            "Fallback Log",
            "Fallback log",
            "Intune Support Suite Fallback Log");
        result = ReplaceKnownLabelVariants(result, GetLocalAppLogLabel(),
            "DAP Intune Support",
            "Intune Support",
            "Intune Support Suite");
        return result;
    }

    private static string ReplaceKnownLabelVariants(string source, string replacement, params string[] variants)
    {
        var result = source;
        foreach (var variant in variants.Where(variant => !string.IsNullOrWhiteSpace(variant)).Distinct(StringComparer.Ordinal).OrderByDescending(variant => variant.Length))
        {
            result = result.Replace(variant, replacement, StringComparison.Ordinal);
        }

        return result;
    }

    private string NormalizeAppNamedPath(string? currentValue, string appDisplayName, string leafFolderName)
    {
        var fallback = $@"%APPDATA%\{appDisplayName}\{leafFolderName}";
        if (string.IsNullOrWhiteSpace(currentValue))
        {
            return fallback;
        }

        var normalized = ReplaceKnownAppNameVariants(currentValue, appDisplayName);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return fallback;
        }

        if (ContainsKnownAppNameVariant(currentValue) || ContainsKnownAppNameVariant(normalized))
        {
            var appDataPrefix = @"%APPDATA%\";
            if (normalized.StartsWith(appDataPrefix, StringComparison.OrdinalIgnoreCase)
                && normalized.EndsWith($@"\{leafFolderName}", StringComparison.OrdinalIgnoreCase))
            {
                return fallback;
            }
        }

        return normalized;
    }

    private string ReplaceKnownAppNameVariants(string? source, string replacement)
    {
        if (string.IsNullOrEmpty(source))
        {
            return source ?? string.Empty;
        }

        var result = source;
        var variants = GetKnownAppNameVariants()
            .Where(variant => !string.IsNullOrWhiteSpace(variant))
            .Where(variant => !string.Equals(variant, replacement, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .OrderByDescending(variant => variant.Length)
            .ToList();

        foreach (var variant in variants)
        {
            if (result.Contains(variant, StringComparison.Ordinal))
            {
                result = result.Replace(variant, AppDisplayPlaceholder, StringComparison.Ordinal);
            }
        }

        if (result.Contains(AppDisplayPlaceholder, StringComparison.Ordinal))
        {
            result = result.Replace(AppDisplayPlaceholder, replacement, StringComparison.Ordinal);
        }

        return result;
    }

    private IEnumerable<string> GetKnownAppNameVariants()
    {
        yield return GetAppDisplayName();
        yield return BaseAppName;
        yield return "DAP Intune Support Suite";
        yield return "Intune Support Suite";

        if (!string.IsNullOrWhiteSpace(BaseAppName))
        {
            yield return $"DAP {BaseAppName}";
        }
    }

    private bool ContainsKnownAppNameVariant(string? source)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return false;
        }

        return GetKnownAppNameVariants()
            .Where(variant => !string.IsNullOrWhiteSpace(variant))
            .Distinct(StringComparer.Ordinal)
            .Any(variant => source.Contains(variant, StringComparison.Ordinal));
    }

    private static IReadOnlyList<string> GetDistinctList(params string[] values)
    {
        return values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string SanitizeForFileStem(string? value, bool removeSpaces)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "Intune-Support-Suite";
        }

        var invalid = Path.GetInvalidFileNameChars();
        var characters = value.Trim().Select(character => invalid.Contains(character) ? '-' : character).ToArray();
        var sanitized = new string(characters);
        sanitized = Regex.Replace(sanitized, @"\s+", removeSpaces ? string.Empty : "-");
        sanitized = Regex.Replace(sanitized, "-+", "-").Trim('-');
        return string.IsNullOrWhiteSpace(sanitized) ? "Intune-Support-Suite" : sanitized;
    }
}
