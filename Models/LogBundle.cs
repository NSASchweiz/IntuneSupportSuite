namespace DapIntuneSupportSuite.Models;

public sealed class LogBundle
{
    public Dictionary<string, List<LogEntry>> EntriesByKey { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, RemoteLogReadState> ReadStates { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public List<LogParseFailure> FailedLogs { get; init; } = [];
}

public sealed class LogParseFailure
{
    public string LogKey { get; init; } = string.Empty;
    public string LogName { get; init; } = string.Empty;
    public string Reason { get; init; } = string.Empty;
}
