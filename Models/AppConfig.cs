using System.Text.Json;
using System.Text.Json.Serialization;

namespace DapIntuneSupportSuite.Models;

public sealed class AppConfig
{
    public string ConfigVersion { get; set; } = "1.1.1-Test-hotfix6";
    public string WindowTitle { get; set; } = "Intune Support Suite";
    public string AppDataFolderName { get; set; } = "Intune Support Suite";
    public string LocalLogDirectory { get; set; } = @"%APPDATA%\Intune Support Suite\Logs";
    public string RemoteAuditLogDirectory { get; set; } = @"C:\ProgramData\ktzh\logs\DAP Intune Support Suite";
    public string RemoteImeLogDirectory { get; set; } = @"C:\ProgramData\Microsoft\IntuneManagementExtension\Logs";
    public string RemoteTempDirectory { get; set; } = @"C:\ProgramData\DAPIntuneSupportSuite\Temp";
    public string SupportClientDirectory { get; set; } = @"C:\ProgramData\DAP Intune Support Client";
    public string PowerShellExecutable { get; set; } = "powershell.exe";
    public string PsExecPath { get; set; } = string.Empty;
    public string ToolsDirectoryPath { get; set; } = string.Empty;
    public string PsExecCatalogFilePath { get; set; } = string.Empty;
    public bool EnablePsExecCatalogValidation { get; set; } = true;
    public string PsExecExpectedSigner { get; set; } = string.Empty;
    public string PsExecExpectedThumbprint { get; set; } = string.Empty;
    public string PsExecExpectedPublicKey { get; set; } = string.Empty;
    public string PsExecDownloadSource { get; set; } = string.Empty;
    public string LatestPublishedPsExecVersion { get; set; } = string.Empty;
    public string LocalPsExecVersion { get; set; } = string.Empty;
    public string PsExecVersionStatus { get; set; } = "Unknown";
    public string LastPsExecVersionCheck { get; set; } = string.Empty;
    public string LastDownloadSource { get; set; } = string.Empty;
    public string LastDownloadValidationResult { get; set; } = string.Empty;
    public int PsExecTimeoutSeconds { get; set; } = 10;
    public int ConnectionStatusIntervalSeconds { get; set; } = 5;
    public int ConnectionTimeoutSeconds { get; set; } = 30;
    public int LiveViewRefreshSeconds { get; set; } = 5;

    [JsonPropertyName("autoRefreshTargetLogs")]
    public int AutoRefreshTargetLogs { get; set; } = 5;
    public int FallbackTaskDelayMinutes { get; set; } = 15;
    public string LocalProcessingDirectory { get; set; } = @"%APPDATA%\Intune Support Suite\ProcessedLogs";
    public string FallbackConfigFileName { get; set; } = "fallbackconfig.json";
    public string FallbackScriptFileName { get; set; } = "fallbackcore.ps1";
    public string FallbackScheduledTaskName { get; set; } = "DAPIntuneSupportFallback";
    public string FallbackRunOnceValueName { get; set; } = "DAPIntuneSupportFallback";
    public string RemoteFallbackLogFileName { get; set; } = "DAP-Fallback.log";
    public bool ConnectionFallback { get; set; }
    public bool RestoreRemotingState { get; set; } = false;
    public string[] DefaultLogFiles { get; set; } =
    [
        "IntuneManagementExtension.log",
        "AgentExecutor.log",
        "AppActionProcessor.log",
        "AppWorkload.log",
        "ClientCertCheck.log",
        "ClientHealth.log",
        "DeviceHealthMonitoring.log",
        "HealthScripts.log",
        "NotificationInfraLogs.log",
        "Sensor.log",
        "Win32AppInventory.log"
    ];
    public string[] WarningKeywords { get; set; } = ["warning", "warn", "retry", "timeout", "pending", "waiting", "restart required", "reboot required", "pending restart", "retrying"];
    public string[] ErrorKeywords { get; set; } = ["error", "failed", "failure", "nicht erfolgreich", "exception", "fatal", "unable", "cannot", "denied", "aborted", "rollback", "stack trace"];
    public string[] SuccessKeywords { get; set; } = ["success", "successful", "valid", "ok", "completed successfully", "completed", "installed", "detected", "healthy", "compliant", "resolved", "finished", "succeeded"];

    [JsonIgnore]
    public string[] PositiveKeywords
    {
        get => SuccessKeywords;
        set => SuccessKeywords = value ?? [];
    }
    public string[] RegistryPathsForAppReset { get; set; } =
    [
        @"HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps",
        @"HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement"
    ];
    public string ImeServiceName { get; set; } = "IntuneManagementExtension";
    public string LiveConnectionStatusMessage { get; set; } = "Live View aktiv.";
    public bool OptionsShowDefaultLogFiles { get; set; }
    public string Language { get; set; } = "Language-DEV";
    public bool ShortDestinationLogs { get; set; } = true;
    public bool EnableAppLogRotation { get; set; } = true;
    public int MaxManagedLogSizeMb { get; set; } = 5;
    public int MaxManagedLogHistoryFiles { get; set; } = 10;
    public int MaxKeptLocalLogs { get; set; } = 10;

    [JsonPropertyName("simulationMode")]
    public bool SimulationMode { get; set; }

    [JsonIgnore]
    public bool SimulateRemoteOperations => SimulationMode;

    [JsonIgnore]
    public string? ConfigFilePath { get; set; }

    [JsonIgnore]
    public string? TrustedConfigFilePath { get; set; }

    public string[] AllowedSources { get; set; } = [];
    public string[] AllowedDestinations { get; set; } = [];
    public LogTabVisibilityConfig LogTabs { get; set; } = new();

    public string TrustedConfigPath { get; set; } = string.Empty;
    public string TrustLogPath { get; set; } = string.Empty;

    [JsonIgnore]
    public TrustState TrustState { get; set; } = TrustState.NotTrusted;

    public string LastSignatureValidation { get; set; } = "Nicht geprüft";
    public string LastTrustedSignerThumbprint { get; set; } = string.Empty;
    public string LastSchemaValidation { get; set; } = "Nicht geprüft";
    public string LastConsistencyValidation { get; set; } = "Nicht geprüft";
    public string ValidationSummary { get; set; } = "Keine Validierung durchgeführt.";
    public int ValidationErrorCount { get; set; }
    public int ValidationWarningCount { get; set; }
    public int ValidationInfoCount { get; set; }
    public string StartupSecurityBlockReason { get; set; } = string.Empty;

    [JsonIgnore]
    public bool HasValidationWarnings => ValidationWarningCount > 0;

    [JsonIgnore]
    public bool IsProductiveModeAvailable => TrustState == TrustState.Trusted && !IsSimulationModeEnforced && string.IsNullOrWhiteSpace(StartupSecurityBlockReason);

    [JsonIgnore]
    public bool IsTrustedSectionReadOnly => TrustState == TrustState.Trusted;

    [JsonIgnore]
    public bool IsSimulationModeEnforced { get; set; }

    [JsonIgnore]
    public bool TrustedConfigWasSavedUntrusted { get; set; }

    [JsonIgnore]
    public bool TrustResetRequested { get; set; }

    public AppConfig Clone()
    {
        var json = JsonSerializer.Serialize(this);
        var clone = JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
        clone.ConfigFilePath = ConfigFilePath;
        clone.TrustedConfigFilePath = TrustedConfigFilePath;
        clone.TrustState = TrustState;
        clone.IsSimulationModeEnforced = IsSimulationModeEnforced;
        clone.TrustedConfigWasSavedUntrusted = TrustedConfigWasSavedUntrusted;
        clone.TrustResetRequested = TrustResetRequested;
        clone.StartupSecurityBlockReason = StartupSecurityBlockReason;
        return clone;
    }

    public void CopyFrom(AppConfig source)
    {
        var configFilePath = ConfigFilePath;
        var trustedConfigFilePath = TrustedConfigFilePath;
        var json = JsonSerializer.Serialize(source);
        var copy = JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();

        ConfigVersion = copy.ConfigVersion;
        WindowTitle = copy.WindowTitle;
        AppDataFolderName = copy.AppDataFolderName;
        LocalLogDirectory = copy.LocalLogDirectory;
        RemoteAuditLogDirectory = copy.RemoteAuditLogDirectory;
        RemoteImeLogDirectory = copy.RemoteImeLogDirectory;
        RemoteTempDirectory = copy.RemoteTempDirectory;
        SupportClientDirectory = copy.SupportClientDirectory;
        PowerShellExecutable = copy.PowerShellExecutable;
        PsExecPath = copy.PsExecPath;
        ToolsDirectoryPath = copy.ToolsDirectoryPath;
        PsExecCatalogFilePath = copy.PsExecCatalogFilePath;
        EnablePsExecCatalogValidation = copy.EnablePsExecCatalogValidation;
        PsExecExpectedSigner = copy.PsExecExpectedSigner;
        PsExecExpectedThumbprint = copy.PsExecExpectedThumbprint;
        PsExecExpectedPublicKey = copy.PsExecExpectedPublicKey;
        PsExecDownloadSource = copy.PsExecDownloadSource;
        LatestPublishedPsExecVersion = copy.LatestPublishedPsExecVersion;
        LocalPsExecVersion = copy.LocalPsExecVersion;
        PsExecVersionStatus = copy.PsExecVersionStatus;
        LastPsExecVersionCheck = copy.LastPsExecVersionCheck;
        LastDownloadSource = copy.LastDownloadSource;
        LastDownloadValidationResult = copy.LastDownloadValidationResult;
        PsExecTimeoutSeconds = copy.PsExecTimeoutSeconds;
        ConnectionStatusIntervalSeconds = copy.ConnectionStatusIntervalSeconds;
        ConnectionTimeoutSeconds = copy.ConnectionTimeoutSeconds;
        LiveViewRefreshSeconds = copy.LiveViewRefreshSeconds;
        AutoRefreshTargetLogs = copy.AutoRefreshTargetLogs;
        FallbackTaskDelayMinutes = copy.FallbackTaskDelayMinutes;
        LocalProcessingDirectory = copy.LocalProcessingDirectory;
        FallbackConfigFileName = copy.FallbackConfigFileName;
        FallbackScriptFileName = copy.FallbackScriptFileName;
        FallbackScheduledTaskName = copy.FallbackScheduledTaskName;
        FallbackRunOnceValueName = copy.FallbackRunOnceValueName;
        RemoteFallbackLogFileName = copy.RemoteFallbackLogFileName;
        ConnectionFallback = copy.ConnectionFallback;
        RestoreRemotingState = copy.RestoreRemotingState;
        DefaultLogFiles = copy.DefaultLogFiles;
        WarningKeywords = copy.WarningKeywords;
        ErrorKeywords = copy.ErrorKeywords;
        SuccessKeywords = copy.SuccessKeywords;
        RegistryPathsForAppReset = copy.RegistryPathsForAppReset;
        ImeServiceName = copy.ImeServiceName;
        LiveConnectionStatusMessage = copy.LiveConnectionStatusMessage;
        OptionsShowDefaultLogFiles = copy.OptionsShowDefaultLogFiles;
        Language = copy.Language;
        ShortDestinationLogs = copy.ShortDestinationLogs;
        EnableAppLogRotation = copy.EnableAppLogRotation;
        MaxManagedLogSizeMb = copy.MaxManagedLogSizeMb;
        MaxManagedLogHistoryFiles = copy.MaxManagedLogHistoryFiles;
        MaxKeptLocalLogs = copy.MaxKeptLocalLogs;
        SimulationMode = copy.SimulationMode;
        AllowedSources = copy.AllowedSources;
        AllowedDestinations = copy.AllowedDestinations;
        LogTabs = copy.LogTabs;
        TrustedConfigPath = copy.TrustedConfigPath;
        TrustLogPath = copy.TrustLogPath;
        TrustState = source.TrustState;
        LastSignatureValidation = copy.LastSignatureValidation;
        LastTrustedSignerThumbprint = copy.LastTrustedSignerThumbprint;
        LastSchemaValidation = copy.LastSchemaValidation;
        LastConsistencyValidation = copy.LastConsistencyValidation;
        ValidationSummary = copy.ValidationSummary;
        ValidationErrorCount = copy.ValidationErrorCount;
        ValidationWarningCount = copy.ValidationWarningCount;
        ValidationInfoCount = copy.ValidationInfoCount;
        IsSimulationModeEnforced = source.IsSimulationModeEnforced;
        TrustedConfigWasSavedUntrusted = source.TrustedConfigWasSavedUntrusted;
        TrustResetRequested = source.TrustResetRequested;
        StartupSecurityBlockReason = source.StartupSecurityBlockReason;
        ConfigFilePath = configFilePath ?? source.ConfigFilePath;
        TrustedConfigFilePath = trustedConfigFilePath ?? source.TrustedConfigFilePath;
    }
}

public sealed class LogTabVisibilityConfig
{
    public LogTabSetting CompanyPortal { get; set; } = new() { IsVisible = true };
    public LogTabSetting Enrollment { get; set; } = new() { IsVisible = true };
    public LogTabSetting MdmDiagnostics { get; set; } = new() { IsVisible = true };
    public LogTabSetting EventLogChannels { get; set; } = new() { IsVisible = true };
    public LogTabSetting InstallAgentEvents { get; set; } = new() { IsVisible = true };
    public LogTabSetting AgentExecutor { get; set; } = new();
    public LogTabSetting AppActionProcessor { get; set; } = new();
    public LogTabSetting AppWorkload { get; set; } = new();
    public LogTabSetting ClientCertCheck { get; set; } = new();
    public LogTabSetting ClientHealth { get; set; } = new();
    public LogTabSetting DeviceHealthMonitoring { get; set; } = new();
    public LogTabSetting HealthScripts { get; set; } = new();
    public LogTabSetting IntuneManagementExtension { get; set; } = new();
    public LogTabSetting NotificationInfraLogs { get; set; } = new();
    public LogTabSetting Sensor { get; set; } = new();
    public LogTabSetting Win321AppInventory { get; set; } = new();
    public LogTabSetting LocalAppLog { get; set; } = new() { IsVisible = true };
    public LogTabSetting AppDataLogs { get; set; } = new() { IsVisible = true };
    public LogTabSetting RemoteAuditLog { get; set; } = new() { IsVisible = true };
    public LogTabSetting FallbackLog { get; set; } = new() { IsVisible = true };
    public LogTabSetting TrustLog { get; set; } = new() { IsVisible = true };
}

public sealed class LogTabSetting
{
    public bool IsVisible { get; set; } = true;
}
