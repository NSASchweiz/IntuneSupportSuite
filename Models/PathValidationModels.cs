namespace DapIntuneSupportSuite.Models;

public enum ConfigPathValidationSeverity
{
    Critical,
    Informational
}

public sealed class ConfigPathValidationIssue
{
    public ConfigPathValidationSeverity Severity { get; init; }
    public string ConfigurationScope { get; init; } = string.Empty;
    public string AttributeName { get; init; } = string.Empty;
    public string PathValue { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

public sealed class ConfigPathValidationResult
{
    public List<ConfigPathValidationIssue> Issues { get; } = [];
    public bool HasCriticalIssues => Issues.Any(issue => issue.Severity == ConfigPathValidationSeverity.Critical);
    public bool HasInformationalIssues => Issues.Any(issue => issue.Severity == ConfigPathValidationSeverity.Informational);

    public string Summary
    {
        get
        {
            if (Issues.Count == 0)
            {
                return "Keine Pfadauffälligkeiten erkannt.";
            }

            return string.Join(" | ", Issues.Select(issue => $"{issue.ConfigurationScope}:{issue.AttributeName}: {issue.Message}"));
        }
    }
}
