namespace DapIntuneSupportSuite.Models;

public enum AppErrorClass
{
    CONFIG,
    TRUST,
    VALIDATION,
    CONNECTION,
    SECURITY,
    INTEGRITY,
    PSEXEC,
    FALLBACK,
    RESTORE,
    LOGGING,
    GUI,
    UNKNOWN
}

public sealed class AppErrorInfo
{
    public AppErrorClass ErrorClass { get; init; } = AppErrorClass.UNKNOWN;
    public string ErrorCode { get; init; } = "UNKNOWN-001";
    public string UserMessage { get; init; } = "Ein unerwarteter Fehler ist aufgetreten.";
    public string? TechnicalDetails { get; init; }
    public string Severity { get; init; } = "Error";
    public string? ActionContext { get; init; }
    public string? Component { get; init; }
    public bool IsKnown => ErrorClass != AppErrorClass.UNKNOWN && !string.IsNullOrWhiteSpace(ErrorCode);
}
