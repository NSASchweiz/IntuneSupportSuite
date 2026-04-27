using System.Text.Json.Serialization;

namespace DapIntuneSupportSuite.Models;

public sealed class UserConfigData
{
    public string ConfigVersion { get; set; } = "1.1.1-Test-hotfix8";
    public string WindowTitle { get; set; } = "Intune Support Suite";
    public string AppDataFolderName { get; set; } = "Intune Support Suite";
    public string LocalLogDirectory { get; set; } = @"%APPDATA%\Intune Support Suite\Logs";
    public int PsExecTimeoutSeconds { get; set; } = 10;
    public int ConnectionStatusIntervalSeconds { get; set; } = 5;
    public int ConnectionTimeoutSeconds { get; set; } = 30;
    public int LiveViewRefreshSeconds { get; set; } = 5;

    [JsonPropertyName("autoRefreshTargetLogs")]
    public int AutoRefreshTargetLogs { get; set; } = 5;
    public int FallbackTaskDelayMinutes { get; set; } = 15;
    public string LocalProcessingDirectory { get; set; } = @"%APPDATA%\Intune Support Suite\ProcessedLogs";
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

    public LogTabVisibilityConfig LogTabs { get; set; } = new();
}
