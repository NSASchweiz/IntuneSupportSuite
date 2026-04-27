namespace DapIntuneSupportSuite.Models;

public sealed class LogParseExecutionResult
{
    public List<LogEntry> Entries { get; init; } = [];
    public int LineFallbackCount { get; init; }
}
