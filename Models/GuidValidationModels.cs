namespace DapIntuneSupportSuite.Models;

public sealed class AppGuidValidationResult
{
    public bool IsValid { get; init; }
    public bool IsEmpty { get; init; }
    public string NormalizedValue { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}
