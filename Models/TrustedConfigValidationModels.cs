namespace DapIntuneSupportSuite.Models;

public enum ValidationIssueSeverity
{
    Error,
    Warning,
    Info
}

public sealed class TrustedConfigValidationIssue
{
    public ValidationIssueSeverity Severity { get; init; }
    public string Code { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;

    public override string ToString() => $"{Severity}:{Code}:{Message}";
}

public sealed class TrustedConfigValidationResult
{
    public List<TrustedConfigValidationIssue> SchemaIssues { get; } = [];
    public List<TrustedConfigValidationIssue> ConsistencyIssues { get; } = [];

    public IEnumerable<TrustedConfigValidationIssue> AllIssues => SchemaIssues.Concat(ConsistencyIssues);
    public bool HasErrors => AllIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Error);
    public bool HasWarnings => AllIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Warning);
    public bool HasInfos => AllIssues.Any(issue => issue.Severity == ValidationIssueSeverity.Info);

    public int ErrorCount => AllIssues.Count(issue => issue.Severity == ValidationIssueSeverity.Error);
    public int WarningCount => AllIssues.Count(issue => issue.Severity == ValidationIssueSeverity.Warning);
    public int InfoCount => AllIssues.Count(issue => issue.Severity == ValidationIssueSeverity.Info);

    public string LastSchemaValidation { get; set; } = "Nicht geprüft";
    public string LastConsistencyValidation { get; set; } = "Nicht geprüft";
    public string ValidationSummary { get; set; } = "Keine Validierung durchgeführt.";

    public string ErrorSummary => string.Join("; ", AllIssues.Where(issue => issue.Severity == ValidationIssueSeverity.Error).Select(issue => issue.Message));
    public string WarningSummary => string.Join("; ", AllIssues.Where(issue => issue.Severity == ValidationIssueSeverity.Warning).Select(issue => issue.Message));
}

public sealed class TrustedConfigValidationContext
{
    public TrustedConfig TrustedConfig { get; init; } = new();
    public AppConfig RuntimeConfig { get; init; } = new();
    public TrustedConfigValidationResult Validation { get; init; } = new();
}

public sealed class ConfigSaveResult
{
    public bool Saved { get; init; }
    public bool HasWarnings { get; init; }
    public string Message { get; init; } = string.Empty;
    public bool TrustedConfigRewritten { get; init; }
    public TrustedConfigValidationResult Validation { get; init; } = new();
}

public sealed class RuntimeTrustCheckResult
{
    public bool Allowed { get; init; }
    public string Message { get; init; } = string.Empty;
    public bool SessionShouldClose { get; init; }
    public string SourceHost { get; init; } = string.Empty;
    public string[] SourceIps { get; init; } = [];
    public string DestinationHost { get; init; } = string.Empty;
    public string[] DestinationIps { get; init; } = [];
    public string MatchedAllowEntry { get; init; } = string.Empty;
    public string ExistingSessionTarget { get; init; } = string.Empty;
}
