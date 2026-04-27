using System;
using DapIntuneSupportSuite.Helpers;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.ViewModels;

public sealed class OptionsViewModel : ObservableObject
{
    private TrustState _trustState;
    private string _lastSignatureValidation = string.Empty;
    private string _lastTrustedSignerThumbprint = string.Empty;
    private string _lastSchemaValidation = string.Empty;
    private string _lastConsistencyValidation = string.Empty;
    private string _validationSummary = string.Empty;
    private bool _trustResetRequested;
    private bool _simulationMode;
    private bool _isTrustStatusLoading;
    private double _trustStatusLoadProgress;

    public OptionsViewModel(AppConfig source)
    {
        ConfigVersion = source.ConfigVersion;
        WindowTitle = source.WindowTitle;
        AppDataFolderName = source.AppDataFolderName;
        LocalLogDirectory = source.LocalLogDirectory;
        RemoteAuditLogDirectory = source.RemoteAuditLogDirectory;
        RemoteImeLogDirectory = source.RemoteImeLogDirectory;
        RemoteTempDirectory = source.RemoteTempDirectory;
        SupportClientDirectory = source.SupportClientDirectory;
        LocalProcessingDirectory = source.LocalProcessingDirectory;
        PowerShellExecutable = source.PowerShellExecutable;
        PsExecPath = source.PsExecPath;
        ToolsDirectoryPath = source.ToolsDirectoryPath;
        PsExecCatalogFilePath = source.PsExecCatalogFilePath;
        EnablePsExecCatalogValidation = source.EnablePsExecCatalogValidation;
        PsExecExpectedSigner = source.PsExecExpectedSigner;
        PsExecExpectedThumbprint = source.PsExecExpectedThumbprint;
        PsExecExpectedPublicKey = source.PsExecExpectedPublicKey;
        PsExecDownloadSource = source.PsExecDownloadSource;
        LatestPublishedPsExecVersion = source.LatestPublishedPsExecVersion;
        LocalPsExecVersion = source.LocalPsExecVersion;
        PsExecVersionStatus = source.PsExecVersionStatus;
        LastPsExecVersionCheck = source.LastPsExecVersionCheck;
        LastDownloadSource = source.LastDownloadSource;
        LastDownloadValidationResult = source.LastDownloadValidationResult;
        PsExecTimeoutSeconds = source.PsExecTimeoutSeconds;
        ConnectionStatusIntervalSeconds = source.ConnectionStatusIntervalSeconds;
        ConnectionTimeoutSeconds = source.ConnectionTimeoutSeconds;
        LiveViewRefreshSeconds = source.LiveViewRefreshSeconds;
        AutoRefreshTargetLogs = source.AutoRefreshTargetLogs > 0 ? source.AutoRefreshTargetLogs : source.LiveViewRefreshSeconds;
        FallbackTaskDelayMinutes = source.FallbackTaskDelayMinutes;
        FallbackConfigFileName = source.FallbackConfigFileName;
        FallbackScriptFileName = source.FallbackScriptFileName;
        FallbackScheduledTaskName = source.FallbackScheduledTaskName;
        FallbackRunOnceValueName = source.FallbackRunOnceValueName;
        RemoteFallbackLogFileName = source.RemoteFallbackLogFileName;
        ConnectionFallback = source.ConnectionFallback;
        RestoreRemotingState = source.RestoreRemotingState;
        ImeServiceName = source.ImeServiceName;
        SimulationMode = source.SimulationMode;
        DefaultLogFiles = JoinLines(source.DefaultLogFiles);
        WarningKeywords = JoinLines(source.WarningKeywords);
        ErrorKeywords = JoinLines(source.ErrorKeywords);
        SuccessKeywords = JoinLines(source.SuccessKeywords);
        RegistryPathsForAppReset = JoinLines(source.RegistryPathsForAppReset);
        AllowedSources = JoinLines(source.AllowedSources);
        AllowedDestinations = JoinLines(source.AllowedDestinations);
        ShowDefaultLogFiles = source.OptionsShowDefaultLogFiles;
        ShortDestinationLogs = source.ShortDestinationLogs;
        EnableAppLogRotation = source.EnableAppLogRotation;
        MaxManagedLogSizeMb = source.MaxManagedLogSizeMb;
        MaxManagedLogHistoryFiles = source.MaxManagedLogHistoryFiles;
        MaxKeptLocalLogs = source.MaxKeptLocalLogs;
        TrustedConfigPath = source.TrustedConfigPath;
        TrustLogPath = source.TrustLogPath;
        TrustState = source.TrustState;
        LastSignatureValidation = source.LastSignatureValidation;
        LastTrustedSignerThumbprint = source.LastTrustedSignerThumbprint;
        LastSchemaValidation = source.LastSchemaValidation;
        LastConsistencyValidation = source.LastConsistencyValidation;
        ValidationSummary = source.ValidationSummary;
        ValidationErrorCount = source.ValidationErrorCount;
        ValidationWarningCount = source.ValidationWarningCount;
        ValidationInfoCount = source.ValidationInfoCount;
        IsSimulationModeEnforced = source.IsSimulationModeEnforced;
        TrustResetRequested = source.TrustResetRequested;
        IsTrustStatusLoading = false;
        TrustStatusLoadProgress = 0;

        CompanyPortalVisible = source.LogTabs.CompanyPortal.IsVisible;
        EnrollmentVisible = source.LogTabs.Enrollment.IsVisible;
        MdmDiagnosticsVisible = source.LogTabs.MdmDiagnostics.IsVisible;
        EventLogChannelsVisible = source.LogTabs.EventLogChannels.IsVisible;
        InstallAgentEventsVisible = source.LogTabs.InstallAgentEvents.IsVisible;
        AgentExecutorVisible = source.LogTabs.AgentExecutor.IsVisible;
        AppActionProcessorVisible = source.LogTabs.AppActionProcessor.IsVisible;
        AppWorkloadVisible = source.LogTabs.AppWorkload.IsVisible;
        ClientCertCheckVisible = source.LogTabs.ClientCertCheck.IsVisible;
        ClientHealthVisible = source.LogTabs.ClientHealth.IsVisible;
        DeviceHealthMonitoringVisible = source.LogTabs.DeviceHealthMonitoring.IsVisible;
        HealthScriptsVisible = source.LogTabs.HealthScripts.IsVisible;
        IntuneManagementExtensionVisible = source.LogTabs.IntuneManagementExtension.IsVisible;
        NotificationInfraLogsVisible = source.LogTabs.NotificationInfraLogs.IsVisible;
        SensorVisible = source.LogTabs.Sensor.IsVisible;
        Win321AppInventoryVisible = source.LogTabs.Win321AppInventory.IsVisible;
        LocalAppLogVisible = source.LogTabs.LocalAppLog.IsVisible;
        AppDataLogsVisible = source.LogTabs.AppDataLogs.IsVisible;
        RemoteAuditLogVisible = source.LogTabs.RemoteAuditLog.IsVisible;
        FallbackLogVisible = source.LogTabs.FallbackLog.IsVisible;
        TrustLogVisible = source.LogTabs.TrustLog.IsVisible;
    }

    public string ConfigVersion { get; set; } = string.Empty;
    public string WindowTitle { get; set; } = string.Empty;
    public string AppDataFolderName { get; set; } = string.Empty;
    public string LocalLogDirectory { get; set; } = string.Empty;
    public string RemoteAuditLogDirectory { get; set; } = string.Empty;
    public string RemoteImeLogDirectory { get; set; } = string.Empty;
    public string RemoteTempDirectory { get; set; } = string.Empty;
    public string SupportClientDirectory { get; set; } = string.Empty;
    public string LocalProcessingDirectory { get; set; } = string.Empty;
    public string PowerShellExecutable { get; set; } = string.Empty;
    public string PsExecPath { get; set; } = string.Empty;
    public string ToolsDirectoryPath { get; set; } = string.Empty;
    public string PsExecCatalogFilePath { get; set; } = string.Empty;
    public bool EnablePsExecCatalogValidation { get; set; }
    public string PsExecExpectedSigner { get; set; } = string.Empty;
    public string PsExecExpectedThumbprint { get; set; } = string.Empty;
    public string PsExecExpectedPublicKey { get; set; } = string.Empty;
    public string PsExecDownloadSource { get; set; } = string.Empty;
    public string LatestPublishedPsExecVersion { get; set; } = string.Empty;
    public string LocalPsExecVersion { get; set; } = string.Empty;
    public string PsExecVersionStatus { get; set; } = string.Empty;
    public string LastPsExecVersionCheck { get; set; } = string.Empty;
    public string LastDownloadSource { get; set; } = string.Empty;
    public string LastDownloadValidationResult { get; set; } = string.Empty;
    public int PsExecTimeoutSeconds { get; set; }
    public int ConnectionStatusIntervalSeconds { get; set; }
    public int ConnectionTimeoutSeconds { get; set; }
    public int LiveViewRefreshSeconds { get; set; }
    public int AutoRefreshTargetLogs { get; set; }
    public int FallbackTaskDelayMinutes { get; set; }
    public string FallbackConfigFileName { get; set; } = string.Empty;
    public string FallbackScriptFileName { get; set; } = string.Empty;
    public string FallbackScheduledTaskName { get; set; } = string.Empty;
    public string FallbackRunOnceValueName { get; set; } = string.Empty;
    public string RemoteFallbackLogFileName { get; set; } = string.Empty;
    public bool ConnectionFallback { get; set; }
    public bool RestoreRemotingState { get; set; }
    public string ImeServiceName { get; set; } = string.Empty;
    public string DefaultLogFiles { get; set; } = string.Empty;
    public string WarningKeywords { get; set; } = string.Empty;
    public string ErrorKeywords { get; set; } = string.Empty;
    public string SuccessKeywords { get; set; } = string.Empty;
    public string RegistryPathsForAppReset { get; set; } = string.Empty;
    public string AllowedSources { get; set; } = string.Empty;
    public string AllowedDestinations { get; set; } = string.Empty;
    public bool ShowDefaultLogFiles { get; set; }
    public bool ShortDestinationLogs { get; set; }
    public bool EnableAppLogRotation { get; set; }
    public int MaxManagedLogSizeMb { get; set; }
    public int MaxManagedLogHistoryFiles { get; set; }
    public int MaxKeptLocalLogs { get; set; }
    public string TrustedConfigPath { get; set; } = string.Empty;
    public string TrustLogPath { get; set; } = string.Empty;
    public int ValidationErrorCount { get; set; }
    public int ValidationWarningCount { get; set; }
    public int ValidationInfoCount { get; set; }
    public bool IsSimulationModeEnforced { get; set; }
    public bool CanEditSimulationMode => !IsSimulationModeEnforced;

    public TrustState TrustState
    {
        get => _trustState;
        set
        {
            if (SetProperty(ref _trustState, value))
            {
                OnPropertyChanged(nameof(TrustStateText));
            }
        }
    }

    public string TrustStateText => IsTrustStatusLoading ? "Lade Trust Status ..." : TrustState.ToString();
    public bool IsTrustedSectionReadOnly => IsTrustStatusLoading || !TrustResetRequested;
    public bool CanSaveTrustedConfig => !IsTrustStatusLoading && TrustResetRequested;

    public bool IsTrustStatusLoading
    {
        get => _isTrustStatusLoading;
        set
        {
            if (SetProperty(ref _isTrustStatusLoading, value))
            {
                OnPropertyChanged(nameof(TrustStateText));
                OnPropertyChanged(nameof(IsTrustedSectionReadOnly));
                OnPropertyChanged(nameof(CanSaveTrustedConfig));
            }
        }
    }

    public double TrustStatusLoadProgress
    {
        get => _trustStatusLoadProgress;
        set => SetProperty(ref _trustStatusLoadProgress, value);
    }

    public string LastSignatureValidation
    {
        get => _lastSignatureValidation;
        set => SetProperty(ref _lastSignatureValidation, value);
    }

    public string LastTrustedSignerThumbprint
    {
        get => _lastTrustedSignerThumbprint;
        set => SetProperty(ref _lastTrustedSignerThumbprint, value);
    }

    public string LastSchemaValidation
    {
        get => _lastSchemaValidation;
        set => SetProperty(ref _lastSchemaValidation, value);
    }

    public string LastConsistencyValidation
    {
        get => _lastConsistencyValidation;
        set => SetProperty(ref _lastConsistencyValidation, value);
    }

    public string ValidationSummary
    {
        get => _validationSummary;
        set => SetProperty(ref _validationSummary, value);
    }

    public bool TrustResetRequested
    {
        get => _trustResetRequested;
        set
        {
            if (SetProperty(ref _trustResetRequested, value))
            {
                OnPropertyChanged(nameof(IsTrustedSectionReadOnly));
                OnPropertyChanged(nameof(CanSaveTrustedConfig));
            }
        }
    }

    public bool SimulationMode
    {
        get => _simulationMode;
        set => SetProperty(ref _simulationMode, value);
    }

    public bool CompanyPortalVisible { get; set; }
    public bool EnrollmentVisible { get; set; }
    public bool MdmDiagnosticsVisible { get; set; }
    public bool EventLogChannelsVisible { get; set; }
    public bool InstallAgentEventsVisible { get; set; }
    public bool AgentExecutorVisible { get; set; }
    public bool AppActionProcessorVisible { get; set; }
    public bool AppWorkloadVisible { get; set; }
    public bool ClientCertCheckVisible { get; set; }
    public bool ClientHealthVisible { get; set; }
    public bool DeviceHealthMonitoringVisible { get; set; }
    public bool HealthScriptsVisible { get; set; }
    public bool IntuneManagementExtensionVisible { get; set; }
    public bool NotificationInfraLogsVisible { get; set; }
    public bool SensorVisible { get; set; }
    public bool Win321AppInventoryVisible { get; set; }
    public bool LocalAppLogVisible { get; set; }
    public bool AppDataLogsVisible { get; set; }
    public bool RemoteAuditLogVisible { get; set; }
    public bool FallbackLogVisible { get; set; }
    public bool TrustLogVisible { get; set; }

    public void BeginTrustStatusLoading()
    {
        IsTrustStatusLoading = true;
        TrustStatusLoadProgress = 8;
    }

    public void UpdateTrustStatusLoadProgress(double progress)
    {
        if (!IsTrustStatusLoading)
        {
            return;
        }

        TrustStatusLoadProgress = Math.Max(0, Math.Min(100, progress));
    }

    public void ApplyRuntimeTrustStatus(AppConfig source)
    {
        TrustedConfigPath = source.TrustedConfigPath;
        TrustLogPath = source.TrustLogPath;
        TrustState = source.TrustState;
        LastSignatureValidation = source.LastSignatureValidation;
        LastTrustedSignerThumbprint = source.LastTrustedSignerThumbprint;
        LastSchemaValidation = source.LastSchemaValidation;
        LastConsistencyValidation = source.LastConsistencyValidation;
        ValidationSummary = source.ValidationSummary;
        ValidationErrorCount = source.ValidationErrorCount;
        ValidationWarningCount = source.ValidationWarningCount;
        ValidationInfoCount = source.ValidationInfoCount;
        IsSimulationModeEnforced = source.IsSimulationModeEnforced;
        SimulationMode = source.SimulationMode;
        TrustResetRequested = source.TrustResetRequested;
        TrustStatusLoadProgress = 100;
        IsTrustStatusLoading = false;
        OnPropertyChanged(nameof(CanEditSimulationMode));
    }

    public void CompleteTrustStatusLoadingWithError(string message)
    {
        LastSignatureValidation = message;
        ValidationSummary = message;
        TrustStatusLoadProgress = 100;
        IsTrustStatusLoading = false;
        OnPropertyChanged(nameof(CanEditSimulationMode));
    }

    public void MarkTrustedConfigAsUntrusted()
    {
        TrustResetRequested = true;
        TrustState = TrustState.NotTrusted;
        LastSignatureValidation = "Signing state wurde zurückgesetzt. Externe Neuerzeugung und Signierung des Catalogs erforderlich.";
        SimulationMode = true;
        IsSimulationModeEnforced = true;
        OnPropertyChanged(nameof(CanEditSimulationMode));
    }

    public AppConfig ToUserSettingsConfig(AppConfig original)
    {
        var config = original.Clone();
        config.ConfigVersion = ConfigVersion;
        config.WindowTitle = WindowTitle;
        config.AppDataFolderName = AppDataFolderName;
        config.LocalLogDirectory = LocalLogDirectory;
        config.LocalProcessingDirectory = LocalProcessingDirectory;
        config.PsExecTimeoutSeconds = PsExecTimeoutSeconds;
        config.ConnectionStatusIntervalSeconds = ConnectionStatusIntervalSeconds;
        config.ConnectionTimeoutSeconds = ConnectionTimeoutSeconds;
        config.LiveViewRefreshSeconds = LiveViewRefreshSeconds;
        config.AutoRefreshTargetLogs = AutoRefreshTargetLogs;
        config.FallbackTaskDelayMinutes = FallbackTaskDelayMinutes;
        config.SimulationMode = SimulationMode;
        config.DefaultLogFiles = SplitLines(DefaultLogFiles);
        config.WarningKeywords = SplitLines(WarningKeywords);
        config.ErrorKeywords = SplitLines(ErrorKeywords);
        config.SuccessKeywords = SplitLines(SuccessKeywords);
        config.OptionsShowDefaultLogFiles = ShowDefaultLogFiles;
        config.ShortDestinationLogs = ShortDestinationLogs;
        config.EnableAppLogRotation = EnableAppLogRotation;
        config.MaxManagedLogSizeMb = MaxManagedLogSizeMb;
        config.MaxManagedLogHistoryFiles = MaxManagedLogHistoryFiles;
        config.MaxKeptLocalLogs = MaxKeptLocalLogs;
        config.LogTabs = BuildLogTabs();
        return config;
    }

    public AppConfig ToTrustedSettingsConfig(AppConfig original)
    {
        var config = original.Clone();
        config.ConfigVersion = ConfigVersion;
        config.RemoteAuditLogDirectory = RemoteAuditLogDirectory;
        config.RemoteImeLogDirectory = RemoteImeLogDirectory;
        config.RemoteTempDirectory = RemoteTempDirectory;
        config.SupportClientDirectory = SupportClientDirectory;
        config.PowerShellExecutable = PowerShellExecutable;
        config.PsExecPath = PsExecPath;
        config.ToolsDirectoryPath = ToolsDirectoryPath;
        config.PsExecCatalogFilePath = PsExecCatalogFilePath;
        config.EnablePsExecCatalogValidation = EnablePsExecCatalogValidation;
        config.PsExecExpectedSigner = PsExecExpectedSigner;
        config.PsExecExpectedThumbprint = PsExecExpectedThumbprint;
        config.PsExecExpectedPublicKey = PsExecExpectedPublicKey;
        config.PsExecDownloadSource = PsExecDownloadSource;
        config.LatestPublishedPsExecVersion = LatestPublishedPsExecVersion;
        config.LocalPsExecVersion = LocalPsExecVersion;
        config.PsExecVersionStatus = PsExecVersionStatus;
        config.LastPsExecVersionCheck = LastPsExecVersionCheck;
        config.LastDownloadSource = LastDownloadSource;
        config.LastDownloadValidationResult = LastDownloadValidationResult;
        config.FallbackConfigFileName = FallbackConfigFileName;
        config.FallbackScriptFileName = FallbackScriptFileName;
        config.FallbackScheduledTaskName = FallbackScheduledTaskName;
        config.FallbackRunOnceValueName = FallbackRunOnceValueName;
        config.RemoteFallbackLogFileName = RemoteFallbackLogFileName;
        config.ConnectionFallback = ConnectionFallback;
        config.RestoreRemotingState = RestoreRemotingState;
        config.ImeServiceName = ImeServiceName;
        config.RegistryPathsForAppReset = SplitLines(RegistryPathsForAppReset);
        config.AllowedSources = SplitLines(AllowedSources);
        config.AllowedDestinations = SplitLines(AllowedDestinations);
        config.TrustedConfigPath = TrustedConfigPath;
        config.TrustLogPath = TrustLogPath;
        config.TrustState = TrustState;
        config.LastSignatureValidation = LastSignatureValidation;
        config.LastTrustedSignerThumbprint = LastTrustedSignerThumbprint;
        config.LastSchemaValidation = LastSchemaValidation;
        config.LastConsistencyValidation = LastConsistencyValidation;
        config.ValidationSummary = ValidationSummary;
        config.ValidationErrorCount = ValidationErrorCount;
        config.ValidationWarningCount = ValidationWarningCount;
        config.ValidationInfoCount = ValidationInfoCount;
        config.IsSimulationModeEnforced = IsSimulationModeEnforced;
        config.TrustResetRequested = TrustResetRequested;
        return config;
    }

    private LogTabVisibilityConfig BuildLogTabs()
        => new()
        {
            CompanyPortal = new LogTabSetting { IsVisible = CompanyPortalVisible },
            Enrollment = new LogTabSetting { IsVisible = EnrollmentVisible },
            MdmDiagnostics = new LogTabSetting { IsVisible = MdmDiagnosticsVisible },
            EventLogChannels = new LogTabSetting { IsVisible = EventLogChannelsVisible },
            InstallAgentEvents = new LogTabSetting { IsVisible = InstallAgentEventsVisible },
            AgentExecutor = new LogTabSetting { IsVisible = AgentExecutorVisible },
            AppActionProcessor = new LogTabSetting { IsVisible = AppActionProcessorVisible },
            AppWorkload = new LogTabSetting { IsVisible = AppWorkloadVisible },
            ClientCertCheck = new LogTabSetting { IsVisible = ClientCertCheckVisible },
            ClientHealth = new LogTabSetting { IsVisible = ClientHealthVisible },
            DeviceHealthMonitoring = new LogTabSetting { IsVisible = DeviceHealthMonitoringVisible },
            HealthScripts = new LogTabSetting { IsVisible = HealthScriptsVisible },
            IntuneManagementExtension = new LogTabSetting { IsVisible = IntuneManagementExtensionVisible },
            NotificationInfraLogs = new LogTabSetting { IsVisible = NotificationInfraLogsVisible },
            Sensor = new LogTabSetting { IsVisible = SensorVisible },
            Win321AppInventory = new LogTabSetting { IsVisible = Win321AppInventoryVisible },
            LocalAppLog = new LogTabSetting { IsVisible = LocalAppLogVisible },
            AppDataLogs = new LogTabSetting { IsVisible = AppDataLogsVisible },
            RemoteAuditLog = new LogTabSetting { IsVisible = RemoteAuditLogVisible },
            FallbackLog = new LogTabSetting { IsVisible = FallbackLogVisible },
            TrustLog = new LogTabSetting { IsVisible = TrustLogVisible }
        };

    private static string JoinLines(IEnumerable<string> values) => string.Join(Environment.NewLine, values ?? []);

    private static string[] SplitLines(string value)
        => value.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
