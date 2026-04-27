namespace DapIntuneSupportSuite.Models;

public sealed class RemoteOperationResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public string StandardOutput { get; init; } = string.Empty;
    public string StandardError { get; init; } = string.Empty;
}
