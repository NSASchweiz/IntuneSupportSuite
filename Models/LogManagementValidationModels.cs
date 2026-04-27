namespace DapIntuneSupportSuite.Models;

public enum LogManagementValidationSeverity
{
    Critical,
    Informational
}

public sealed class LogManagementValidationIssue
{
    public LogManagementValidationSeverity Severity { get; init; }
    public string AttributeName { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

public sealed class LogManagementValidationResult
{
    public List<LogManagementValidationIssue> Issues { get; } = [];
    public bool HasCriticalIssues => Issues.Any(i => i.Severity == LogManagementValidationSeverity.Critical);
    public bool HasInformationalIssues => Issues.Any(i => i.Severity == LogManagementValidationSeverity.Informational);
    public string Summary => Issues.Count == 0 ? "Keine Auffälligkeiten beim Loggrößenmanagement erkannt." : string.Join(" | ", Issues.Select(i => $"{i.AttributeName}: {i.Message}"));
}
