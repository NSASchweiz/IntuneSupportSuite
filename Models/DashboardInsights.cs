namespace DapIntuneSupportSuite.Models;

public sealed class DeviceAppInsight
{
    public bool IsSelected { get; set; }
    public string AppGuid { get; set; } = string.Empty;
    public string AppName { get; set; } = string.Empty;
    public string PackageId { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Applicability { get; set; } = string.Empty;
    public string ErrorCode { get; set; } = string.Empty;
    public string DesiredState { get; set; } = string.Empty;
    public string TargetingMethod { get; set; } = string.Empty;
    public string InstallContext { get; set; } = string.Empty;
    public string TargetType { get; set; } = string.Empty;
    public string ProductVersion { get; set; } = string.Empty;
    public string RebootStatus { get; set; } = string.Empty;
    public string RebootReason { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string ComputerId { get; set; } = string.Empty;
    public string ComplianceStateMessage { get; set; } = string.Empty;
    public string EnforcementStateMessage { get; set; } = string.Empty;
    public string EnforcementState { get; set; } = string.Empty;
    public string ErrorHint { get; set; } = string.Empty;
    public string SourceLog { get; set; } = string.Empty;
    public string LastSeen { get; set; } = string.Empty;

    // Legacy properties kept for backward compatibility with older exports or bindings.
    public string InternalVersion { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;
    public string ExitCode { get; set; } = string.Empty;
    public string TargetMethod { get; set; } = string.Empty;
}

public sealed class DeviceIssueInsight
{
    public string Category { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string SourceLog { get; set; } = string.Empty;
    public string LastSeen { get; set; } = string.Empty;
}



public sealed class RegistrySettingInsight
{
    public string Category { get; set; } = string.Empty;
    public string SettingName { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public string Interpretation { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string RegistryPath { get; set; } = string.Empty;
    public string SourceLog { get; set; } = string.Empty;
    public string LastSeen { get; set; } = string.Empty;
}

public sealed class RegistryRecommendationDefinition
{
    public string Category { get; set; } = string.Empty;
    public string SettingName { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
}

public sealed class AppNameCacheEntry
{
    public string AppGuid { get; set; } = string.Empty;
    public string PackageId { get; set; } = string.Empty;
    public string PackageName { get; set; } = string.Empty;
}
