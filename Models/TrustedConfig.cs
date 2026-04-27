using System.Text.Json.Serialization;

namespace DapIntuneSupportSuite.Models;

public sealed class TrustedConfig
{
    public string ConfigVersion { get; set; } = "1.1.1-Test-hotfix8";
    public string TrustedConfigPath { get; set; } = string.Empty;
    public string TrustLogPath { get; set; } = string.Empty;
    public string RemoteAuditLogDirectory { get; set; } = @"C:\ProgramData\ktzh\logs\Intune Support Suite";
    public string RemoteImeLogDirectory { get; set; } = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs";
    public string RemoteTempDirectory { get; set; } = @"C:\ProgramData\IntuneSupportSuite\Temp";
    public string SupportClientDirectory { get; set; } = @"C:\ProgramData\Intune Support Client";
    public string PowerShellExecutable { get; set; } = "powershell.exe";
    public string PsExecPath { get; set; } = string.Empty;
    public string ToolsDirectoryPath { get; set; } = @"ProgramDir\Tools";
    public string PsExecCatalogFilePath { get; set; } = @"ProgramDir\Tools\PSTools.cat";
    public bool EnablePsExecCatalogValidation { get; set; } = true;
    public string PsExecExpectedSigner { get; set; } = "Microsoft";
    public string PsExecExpectedThumbprint { get; set; } = string.Empty;
    public string PsExecExpectedPublicKey { get; set; } = string.Empty;
    public string PsExecDownloadSource { get; set; } = "https://download.sysinternals.com/files/PSTools.zip";
    public string LatestPublishedPsExecVersion { get; set; } = string.Empty;
    public string LocalPsExecVersion { get; set; } = string.Empty;
    public string PsExecVersionStatus { get; set; } = "Unknown";
    public string LastPsExecVersionCheck { get; set; } = string.Empty;
    public string LastDownloadSource { get; set; } = string.Empty;
    public string LastDownloadValidationResult { get; set; } = string.Empty;
    public string FallbackConfigFileName { get; set; } = "fallbackconfig.json";
    public string FallbackScriptFileName { get; set; } = "fallbackcore.ps1";
    public string FallbackScheduledTaskName { get; set; } = "IntuneSupportSuiteFallback";
    public string FallbackRunOnceValueName { get; set; } = "IntuneSupportSuiteFallback";
    public string RemoteFallbackLogFileName { get; set; } = "Intune-Support-Suite-Fallback.log";
    public bool ConnectionFallback { get; set; } = false;
    public bool RestoreRemotingState { get; set; } = false;
    public string[] RegistryPathsForAppReset { get; set; } =
    [
        @"HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps",
        @"HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement"
    ];
    public string ImeServiceName { get; set; } = "IntuneManagementExtension";
    public string[] AllowedSources { get; set; } = [];
    public string[] AllowedDestinations { get; set; } = [];

    [JsonPropertyName("AllowedJumpHosts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? LegacyAllowedJumpHosts { get; set; }
}
