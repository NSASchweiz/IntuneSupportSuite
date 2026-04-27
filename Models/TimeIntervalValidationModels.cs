namespace DapIntuneSupportSuite.Models;

public enum TimeIntervalValidationSeverity
{
    Critical,
    Hint
}

public sealed class TimeIntervalValidationIssue
{
    public TimeIntervalValidationSeverity Severity { get; init; }
    public string ConfigurationScope { get; init; } = string.Empty;
    public string AttributeName { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

public sealed class TimeIntervalValidationResult
{
    public List<TimeIntervalValidationIssue> Issues { get; } = [];
    public bool HasCriticalIssues => Issues.Any(issue => issue.Severity == TimeIntervalValidationSeverity.Critical);
    public bool HasHints => Issues.Any(issue => issue.Severity == TimeIntervalValidationSeverity.Hint);

    public string Summary
    {
        get
        {
            if (Issues.Count == 0)
            {
                return "Keine Auffälligkeiten bei Zeit- und Intervallwerten erkannt.";
            }

            return string.Join(" | ", Issues.Select(issue => $"{issue.ConfigurationScope}:{issue.AttributeName}: {issue.Message}"));
        }
    }
}
