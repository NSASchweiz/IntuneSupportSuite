using System.Linq;
using System.IO;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;
using System.Windows.Media;
using Microsoft.Win32;
using DapIntuneSupportSuite.Helpers;
using DapIntuneSupportSuite.Models;
using DapIntuneSupportSuite.Services;

namespace DapIntuneSupportSuite.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly IntuneSupportService _intuneSupportService;
    private readonly AuditLogger _logger;
    private readonly AppConfig _config;
    private readonly PsExecDependencyService _psExecDependencyService;
    private readonly SecurityGuardService _securityGuardService;
    private readonly AppInputValidator _appInputValidator;
    private readonly Dictionary<string, ObservableCollection<LogEntry>> _entryCollections = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ICollectionView> _entryViews = new(StringComparer.OrdinalIgnoreCase);
    private readonly DispatcherTimer _liveViewTimer;
    private readonly DispatcherTimer _localLogRefreshDebounceTimer;
    private readonly DispatcherTimer _viewRefreshDebounceTimer;
    private FileSystemWatcher? _localLogWatcher;
    private FileSystemWatcher? _trustLogWatcher;
    private readonly Dictionary<string, LocalLogMonitorState> _localLogMonitorStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, RemoteLogReadState> _remoteLogStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _pendingViewRefreshKeys = new(StringComparer.OrdinalIgnoreCase);
    private bool _localLogRefreshPending;
    private string _deviceName = string.Empty;
    private string _appGuid = string.Empty;
    private string _companyPortalSearchTerm = string.Empty;
    private string _companyPortalSelectedFilter = "Alle";
    private string _intuneLogsSearchTerm = string.Empty;
    private string _intuneLogsSelectedFilter = "Alle";
    private string _localLogsSearchTerm = string.Empty;
    private string _localLogsSelectedFilter = "Alle";
    private string _remediationSearchTerm = string.Empty;
    private string _remediationSelectedFilter = "Alle";
    private string _statusMessage;
    private double _progressValue;
    private bool _isBusy;
    private bool _hasActiveConnection;
    private bool _isLiveRefreshing;
    private string _activeSessionTargetDeviceName = string.Empty;
    private readonly Dictionary<string, AppNameCacheEntry> _appNameCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _cimResolvedInstalledGuids = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _appNameCachePath;
    private readonly string _registryRecommendationsPath;
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public MainViewModel(IntuneSupportService intuneSupportService, AuditLogger logger, AppConfig config, PsExecDependencyService psExecDependencyService, ConfigBootstrapper configBootstrapper, SecurityGuardService securityGuardService, AppInputValidator appInputValidator)
    {
        _intuneSupportService = intuneSupportService;
        _logger = logger;
        _config = config;
        _psExecDependencyService = psExecDependencyService;
        _securityGuardService = securityGuardService;
        _appInputValidator = appInputValidator;
        _appNameCachePath = ResolveAppNameCachePath();
        _registryRecommendationsPath = ResolveRegistryRecommendationsPath();
        LoadAppNameCache();
        _config.WindowTitle = LanguageManager.Instance.ComposeWindowTitle();
        _statusMessage = GetReadyStatus();

        AnalyzeCommand = new RelayCommand(_ => AnalyzeAsync(), _ => !string.IsNullOrWhiteSpace(DeviceName) && !IsBusy);
        RefreshCommand = new RelayCommand(_ => AnalyzeAsync(), _ => !string.IsNullOrWhiteSpace(DeviceName) && !IsBusy);
        ResetImeLogsCommand = new RelayCommand(_ => ResetImeLogsAsync(), _ => !string.IsNullOrWhiteSpace(DeviceName) && !IsBusy);
        RestartImeServiceCommand = new RelayCommand(_ => RestartImeServiceAsync(), _ => !string.IsNullOrWhiteSpace(DeviceName) && !IsBusy);
        ResetAppInstallCommand = new RelayCommand(_ => ResetAppInstallAsync(), _ => !string.IsNullOrWhiteSpace(DeviceName) && !IsBusy);
        WsResetCommand = new RelayCommand(_ => WsResetAsync(), _ => _hasActiveConnection && !string.IsNullOrWhiteSpace(_activeSessionTargetDeviceName) && !IsBusy);
        ExportLogBundleCommand = new RelayCommand(_ => ExportLogBundle(), _ => !IsBusy);

        AvailableFilters = new ObservableCollection<string>(["Alle", "Info", "Success", "Warning", "Error"]);

        InitializeLogCollection(nameof(AgentExecutorEntries));
        InitializeLogCollection(nameof(AppActionProcessorEntries));
        InitializeLogCollection(nameof(AppWorkloadEntries));
        InitializeLogCollection(nameof(ClientCertCheckEntries));
        InitializeLogCollection(nameof(ClientHealthEntries));
        InitializeLogCollection(nameof(DeviceHealthMonitoringEntries));
        InitializeLogCollection(nameof(HealthScriptsEntries));
        InitializeLogCollection(nameof(IntuneManagementExtensionEntries));
        InitializeLogCollection(nameof(CompanyPortalEntries));
        InitializeLogCollection(nameof(EnrollmentEntries));
        InitializeLogCollection(nameof(MdmDiagnosticsEntries));
        InitializeLogCollection(nameof(EventLogChannelEntries));
        InitializeLogCollection(nameof(InstallAgentEventsEntries));
        InitializeLogCollection(nameof(DeviceRegistrySettingsEntries));
        InitializeLogCollection(nameof(NotificationInfraLogsEntries));
        InitializeLogCollection(nameof(SensorEntries));
        InitializeLogCollection(nameof(Win321AppInventoryEntries));
        InitializeLogCollection(nameof(Win32AppsRegistryEntries));
        InitializeLogCollection(nameof(LocalAppLogEntries));
        InitializeLogCollection(nameof(AppDataLogsEntries));
        InitializeLogCollection(nameof(RemoteAuditEntries));
        InitializeLogCollection(nameof(FallbackEntries));
        InitializeLogCollection(nameof(TrustLogEntries));

        _liveViewTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(Math.Max(3, _config.AutoRefreshTargetLogs > 0 ? _config.AutoRefreshTargetLogs : _config.LiveViewRefreshSeconds))
        };
        _liveViewTimer.Tick += LiveViewTimerOnTick;

        _localLogRefreshDebounceTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(350)
        };
        _localLogRefreshDebounceTimer.Tick += LocalLogRefreshDebounceTimerOnTick;

        _viewRefreshDebounceTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(250)
        };
        _viewRefreshDebounceTimer.Tick += ViewRefreshDebounceTimerOnTick;

        Application.Current?.Dispatcher.BeginInvoke(new Action(() =>
        {
            InitializeLocalLogMonitoring();
            RefreshLocalProgramLogs(forceFullReload: true);
        }), DispatcherPriority.Background);
    }

    public string DeviceName
    {
        get => _deviceName;
        set
        {
            if (SetProperty(ref _deviceName, value))
            {
                RaiseCommands();
                NotifyDashboardStateChanged();
            }
        }
    }

    public string AppGuid
    {
        get => _appGuid;
        set => SetProperty(ref _appGuid, value);
    }

    public string CompanyPortalSearchTerm
    {
        get => _companyPortalSearchTerm;
        set
        {
            if (SetProperty(ref _companyPortalSearchTerm, value))
            {
                ScheduleViewRefresh(GetCollectionsForFilterGroup("CompanyPortal"));
            }
        }
    }

    public string CompanyPortalSelectedFilter
    {
        get => _companyPortalSelectedFilter;
        set
        {
            if (SetProperty(ref _companyPortalSelectedFilter, value))
            {
                ScheduleViewRefresh(GetCollectionsForFilterGroup("CompanyPortal"));
            }
        }
    }

    public string IntuneLogsSearchTerm
    {
        get => _intuneLogsSearchTerm;
        set
        {
            if (SetProperty(ref _intuneLogsSearchTerm, value))
            {
                ScheduleViewRefresh(GetCollectionsForFilterGroup("Intune"));
            }
        }
    }

    public string IntuneLogsSelectedFilter
    {
        get => _intuneLogsSelectedFilter;
        set
        {
            if (SetProperty(ref _intuneLogsSelectedFilter, value))
            {
                ScheduleViewRefresh(GetCollectionsForFilterGroup("Intune"));
            }
        }
    }

    public string LocalLogsSearchTerm
    {
        get => _localLogsSearchTerm;
        set
        {
            if (SetProperty(ref _localLogsSearchTerm, value))
            {
                ScheduleViewRefresh(GetCollectionsForFilterGroup("Local"));
            }
        }
    }

    public string LocalLogsSelectedFilter
    {
        get => _localLogsSelectedFilter;
        set
        {
            if (SetProperty(ref _localLogsSelectedFilter, value))
            {
                ScheduleViewRefresh(GetCollectionsForFilterGroup("Local"));
            }
        }
    }

    public string RemediationSearchTerm
    {
        get => _remediationSearchTerm;
        set
        {
            if (SetProperty(ref _remediationSearchTerm, value))
            {
                ScheduleViewRefresh(GetCollectionsForFilterGroup("Remediation"));
            }
        }
    }

    public string RemediationSelectedFilter
    {
        get => _remediationSelectedFilter;
        set
        {
            if (SetProperty(ref _remediationSelectedFilter, value))
            {
                ScheduleViewRefresh(GetCollectionsForFilterGroup("Remediation"));
            }
        }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, LT(value));
    }

    public double ProgressValue
    {
        get => _progressValue;
        set => SetProperty(ref _progressValue, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
            {
                RaiseCommands();
            }
        }
    }

    public string ConfigVersionText => LT($"Version {_config.ConfigVersion}");
    public string RuntimeModeText => LT(_config.SimulationMode
        ? (_config.IsSimulationModeEnforced ? "Simulationsmodus erzwungen" : "Simulationsmodus aktiv")
        : "Echte Remote-Steuerung aktiv");
    public string TrustStateText => LT(_config.TrustState.ToString());
    public string RuntimeModeHint => LT(!string.IsNullOrWhiteSpace(_config.StartupSecurityBlockReason)
        ? _config.StartupSecurityBlockReason
        : _config.SimulationMode
            ? "Warnung: Es werden keine echten Änderungen auf Zielgeräten ausgeführt."
            : "Achtung: Aktionen greifen direkt auf das Zielgerät zu und ändern Dienste, Logs und Registry.");

    public bool IsCompanyPortalVisible => _config.LogTabs.CompanyPortal.IsVisible;
    public bool IsEnrollmentVisible => _config.LogTabs.Enrollment.IsVisible;
    public bool IsMdmDiagnosticsVisible => _config.LogTabs.MdmDiagnostics.IsVisible;
    public bool IsEventLogChannelsVisible => _config.LogTabs.EventLogChannels.IsVisible;
    public bool IsInstallAgentEventsVisible => _config.LogTabs.InstallAgentEvents.IsVisible;
    public bool IsAgentExecutorVisible => _config.LogTabs.AgentExecutor.IsVisible;
    public bool IsAppActionProcessorVisible => _config.LogTabs.AppActionProcessor.IsVisible;
    public bool IsAppWorkloadVisible => _config.LogTabs.AppWorkload.IsVisible;
    public bool IsClientCertCheckVisible => _config.LogTabs.ClientCertCheck.IsVisible;
    public bool IsClientHealthVisible => _config.LogTabs.ClientHealth.IsVisible;
    public bool IsDeviceHealthMonitoringVisible => _config.LogTabs.DeviceHealthMonitoring.IsVisible;
    public bool IsHealthScriptsVisible => _config.LogTabs.HealthScripts.IsVisible;
    public bool IsIntuneManagementExtensionVisible => _config.LogTabs.IntuneManagementExtension.IsVisible;
    public bool IsNotificationInfraLogsVisible => _config.LogTabs.NotificationInfraLogs.IsVisible;
    public bool IsSensorVisible => _config.LogTabs.Sensor.IsVisible;
    public bool IsWin321AppInventoryVisible => _config.LogTabs.Win321AppInventory.IsVisible;
    public bool IsLocalAppLogVisible => _config.LogTabs.LocalAppLog.IsVisible;
    public bool IsAppDataLogsVisible => _config.LogTabs.AppDataLogs.IsVisible;
    public bool IsRemoteAuditVisible => _config.LogTabs.RemoteAuditLog.IsVisible;
    public bool IsFallbackVisible => _config.LogTabs.FallbackLog.IsVisible;
    public bool IsTrustLogVisible => _config.LogTabs.TrustLog.IsVisible;

    public ObservableCollection<string> AvailableFilters { get; }
    public ObservableCollection<LogEntry> AgentExecutorEntries => _entryCollections[nameof(AgentExecutorEntries)];
    public ObservableCollection<LogEntry> AppActionProcessorEntries => _entryCollections[nameof(AppActionProcessorEntries)];
    public ObservableCollection<LogEntry> AppWorkloadEntries => _entryCollections[nameof(AppWorkloadEntries)];
    public ObservableCollection<LogEntry> ClientCertCheckEntries => _entryCollections[nameof(ClientCertCheckEntries)];
    public ObservableCollection<LogEntry> ClientHealthEntries => _entryCollections[nameof(ClientHealthEntries)];
    public ObservableCollection<LogEntry> DeviceHealthMonitoringEntries => _entryCollections[nameof(DeviceHealthMonitoringEntries)];
    public ObservableCollection<LogEntry> HealthScriptsEntries => _entryCollections[nameof(HealthScriptsEntries)];
    public ObservableCollection<LogEntry> IntuneManagementExtensionEntries => _entryCollections[nameof(IntuneManagementExtensionEntries)];
    public ObservableCollection<LogEntry> CompanyPortalEntries => _entryCollections[nameof(CompanyPortalEntries)];
    public ObservableCollection<LogEntry> EnrollmentEntries => _entryCollections[nameof(EnrollmentEntries)];
    public ObservableCollection<LogEntry> MdmDiagnosticsEntries => _entryCollections[nameof(MdmDiagnosticsEntries)];
    public ObservableCollection<LogEntry> EventLogChannelEntries => _entryCollections[nameof(EventLogChannelEntries)];
    public ObservableCollection<LogEntry> InstallAgentEventsEntries => _entryCollections[nameof(InstallAgentEventsEntries)];
    public ObservableCollection<LogEntry> DeviceRegistrySettingsEntries => _entryCollections[nameof(DeviceRegistrySettingsEntries)];
    public ObservableCollection<LogEntry> NotificationInfraLogsEntries => _entryCollections[nameof(NotificationInfraLogsEntries)];
    public ObservableCollection<LogEntry> SensorEntries => _entryCollections[nameof(SensorEntries)];
    public ObservableCollection<LogEntry> Win321AppInventoryEntries => _entryCollections[nameof(Win321AppInventoryEntries)];
    public ObservableCollection<LogEntry> Win32AppsRegistryEntries => _entryCollections[nameof(Win32AppsRegistryEntries)];
    public ObservableCollection<LogEntry> LocalAppLogEntries => _entryCollections[nameof(LocalAppLogEntries)];
    public ObservableCollection<LogEntry> AppDataLogsEntries => _entryCollections[nameof(AppDataLogsEntries)];
    public ObservableCollection<LogEntry> RemoteAuditEntries => _entryCollections[nameof(RemoteAuditEntries)];
    public ObservableCollection<LogEntry> FallbackEntries => _entryCollections[nameof(FallbackEntries)];
    public ObservableCollection<LogEntry> TrustLogEntries => _entryCollections[nameof(TrustLogEntries)];

    public ICollectionView AgentExecutorEntriesView => _entryViews[nameof(AgentExecutorEntries)];
    public ICollectionView AppActionProcessorEntriesView => _entryViews[nameof(AppActionProcessorEntries)];
    public ICollectionView AppWorkloadEntriesView => _entryViews[nameof(AppWorkloadEntries)];
    public ICollectionView ClientCertCheckEntriesView => _entryViews[nameof(ClientCertCheckEntries)];
    public ICollectionView ClientHealthEntriesView => _entryViews[nameof(ClientHealthEntries)];
    public ICollectionView DeviceHealthMonitoringEntriesView => _entryViews[nameof(DeviceHealthMonitoringEntries)];
    public ICollectionView HealthScriptsEntriesView => _entryViews[nameof(HealthScriptsEntries)];
    public ICollectionView IntuneManagementExtensionEntriesView => _entryViews[nameof(IntuneManagementExtensionEntries)];
    public ICollectionView CompanyPortalEntriesView => _entryViews[nameof(CompanyPortalEntries)];
    public ICollectionView EnrollmentEntriesView => _entryViews[nameof(EnrollmentEntries)];
    public ICollectionView MdmDiagnosticsEntriesView => _entryViews[nameof(MdmDiagnosticsEntries)];
    public ICollectionView EventLogChannelEntriesView => _entryViews[nameof(EventLogChannelEntries)];
    public ICollectionView InstallAgentEventsEntriesView => _entryViews[nameof(InstallAgentEventsEntries)];
    public ICollectionView DeviceRegistrySettingsEntriesView => _entryViews[nameof(DeviceRegistrySettingsEntries)];
    public ICollectionView NotificationInfraLogsEntriesView => _entryViews[nameof(NotificationInfraLogsEntries)];
    public ICollectionView SensorEntriesView => _entryViews[nameof(SensorEntries)];
    public ICollectionView Win321AppInventoryEntriesView => _entryViews[nameof(Win321AppInventoryEntries)];
    public ICollectionView Win32AppsRegistryEntriesView => _entryViews[nameof(Win32AppsRegistryEntries)];
    public ICollectionView LocalAppLogEntriesView => _entryViews[nameof(LocalAppLogEntries)];
    public ICollectionView AppDataLogsEntriesView => _entryViews[nameof(AppDataLogsEntries)];
    public ICollectionView RemoteAuditEntriesView => _entryViews[nameof(RemoteAuditEntries)];
    public ICollectionView FallbackEntriesView => _entryViews[nameof(FallbackEntries)];
    public ICollectionView TrustLogEntriesView => _entryViews[nameof(TrustLogEntries)];

    public string ImeHealthTargetDevice => string.IsNullOrWhiteSpace(DeviceName) ? "-" : DeviceName.Trim();
    public string ImeHealthConnectionState => LT(_hasActiveConnection
        ? $"Aktive Session zu {_activeSessionTargetDeviceName}"
        : "Keine aktive Live-Session.");
    public string ImeHealthRemoteLogStats => LT($"Einträge: {GetRemoteLogEntries().Count()} | Fehler: {GetSeverityCount(GetRemoteLogEntries(), "Error")} | Warnungen: {GetSeverityCount(GetRemoteLogEntries(), "Warning")} | Quellen: {GetRemoteLogEntries().Select(entry => entry.SourceFile).Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).Count()}");
    public string ImeHealthLatestSignal => GetLatestSignalText();
    public string ImeHealthRemediationSignal => GetRemediationSignalText();
    public string ImeHealthRemediationSummary => GetRemediationSummary();
    public string ImeHealthPendingRestartText => GetPendingRestartSummary();
    public string ImeHealthManagedAppsSummary => GetManagedAppsSummary();
    public string ImeHealthEnrollmentSummary => GetEnrollmentSummary();
    public string ImeHealthIssueSummary => GetIssueSummary();
    public string CompanyPortalSummaryText => GetLogCollectionSummary("Company Portal", CompanyPortalEntries);
    public string EnrollmentSummaryText => GetLogCollectionSummary("Enrollment", EnrollmentEntries);
    public string MdmDiagnosticsSummaryText => GetLogCollectionSummary("MDM Diagnoseartefakte", MdmDiagnosticsEntries);
    public string EventLogChannelsSummaryText => GetLogCollectionSummary("Event-Log-Kanäle", EventLogChannelEntries);
    public string InstallAgentEventsSummaryText => GetLogCollectionSummary("Install-Agent Events", InstallAgentEventsEntries);
    public string CompanyPortalOverviewText => BuildGroupOverviewText("Company Portal / Enrollment / Install-Agent", GetCompanyPortalLogEntries());
    public string CompanyPortalOverviewSignalText => BuildGroupSignalText(GetCompanyPortalLogEntries(), "Noch keine Company-Portal-, Enrollment-, Install-Agent- oder MDM-Daten geladen.");
    public string IntuneLogsOverviewText => BuildGroupOverviewText("Intune Logs", GetIntuneLogEntries());
    public string IntuneLogsOverviewSignalText => BuildGroupSignalText(GetIntuneLogEntries(), "Noch keine Intune-Logdaten geladen.");
    public string LocalAppLogsOverviewText => BuildGroupOverviewText("Lokale App Logs", GetLocalAppLogEntries());
    public string LocalAppLogsOverviewSignalText => BuildGroupSignalText(GetLocalAppLogEntries(), "Noch keine lokalen App-Logs geladen.");
    public string RemediationSummaryText => LT($"HealthScripts.log: {HealthScriptsEntries.Count} Einträge | DeviceHealthMonitoring.log: {DeviceHealthMonitoringEntries.Count} Einträge | Fehler: {GetSeverityCount(HealthScriptsEntries, "Error") + GetSeverityCount(DeviceHealthMonitoringEntries, "Error")} | Warnungen: {GetSeverityCount(HealthScriptsEntries, "Warning") + GetSeverityCount(DeviceHealthMonitoringEntries, "Warning")}");
    public string IntuneRelevantRegistrySettingsSummaryText => GetRegistrySettingsSummary();
    public ObservableCollection<DeviceAppInsight> ManagedAppInsights { get; } = new();
    public ObservableCollection<DeviceIssueInsight> ImeHealthIssueInsights { get; } = new();
    public ObservableCollection<RegistrySettingInsight> IntuneRelevantRegistrySettings { get; } = new();

    public RelayCommand AnalyzeCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public RelayCommand ResetImeLogsCommand { get; }
    public RelayCommand RestartImeServiceCommand { get; }
    public RelayCommand ResetAppInstallCommand { get; }
    public RelayCommand WsResetCommand { get; }
    public RelayCommand ExportLogBundleCommand { get; }

    public void ApplyConfigurationChanges()
    {
        _liveViewTimer.Interval = TimeSpan.FromSeconds(Math.Max(3, _config.AutoRefreshTargetLogs > 0 ? _config.AutoRefreshTargetLogs : _config.LiveViewRefreshSeconds));
        InitializeLocalLogMonitoring();
        OnPropertyChanged(nameof(ConfigVersionText));
        OnPropertyChanged(nameof(RuntimeModeText));
        OnPropertyChanged(nameof(TrustStateText));
        OnPropertyChanged(nameof(RuntimeModeHint));
        OnPropertyChanged(nameof(IsCompanyPortalVisible));
        OnPropertyChanged(nameof(IsEnrollmentVisible));
        OnPropertyChanged(nameof(IsMdmDiagnosticsVisible));
        OnPropertyChanged(nameof(IsEventLogChannelsVisible));
        OnPropertyChanged(nameof(IsInstallAgentEventsVisible));
        OnPropertyChanged(nameof(IsAgentExecutorVisible));
        OnPropertyChanged(nameof(IsAppActionProcessorVisible));
        OnPropertyChanged(nameof(IsAppWorkloadVisible));
        OnPropertyChanged(nameof(IsClientCertCheckVisible));
        OnPropertyChanged(nameof(IsClientHealthVisible));
        OnPropertyChanged(nameof(IsDeviceHealthMonitoringVisible));
        OnPropertyChanged(nameof(IsHealthScriptsVisible));
        OnPropertyChanged(nameof(IsIntuneManagementExtensionVisible));
        OnPropertyChanged(nameof(IsNotificationInfraLogsVisible));
        OnPropertyChanged(nameof(IsSensorVisible));
        OnPropertyChanged(nameof(IsWin321AppInventoryVisible));
        OnPropertyChanged(nameof(IsLocalAppLogVisible));
        OnPropertyChanged(nameof(IsAppDataLogsVisible));
        OnPropertyChanged(nameof(IsRemoteAuditVisible));
        OnPropertyChanged(nameof(IsFallbackVisible));
        OnPropertyChanged(nameof(IsTrustLogVisible));

        ScheduleLocalLogRefresh();

        NotifyDashboardStateChanged();

        if (_hasActiveConnection)
        {
            SetLiveStatus(DateTime.Now);
        }
        else
        {
            StatusMessage = GetReadyStatus();
        }
    }

    public async Task ShutdownAsync()
    {
        _liveViewTimer.Stop();
        _localLogRefreshDebounceTimer.Stop();
        _viewRefreshDebounceTimer.Stop();
        _localLogWatcher?.Dispose();
        _localLogWatcher = null;
        _trustLogWatcher?.Dispose();
        _trustLogWatcher = null;
        await CloseActiveConnectionIfRequiredAsync();
    }

    public async void NotifySecurityContextChanged()
    {
        try
        {
            ApplyConfigurationChanges();
            if (!_hasActiveConnection)
            {
                StatusMessage = GetReadyStatus();
                return;
            }

            var sessionCheck = _securityGuardService.RevalidateActiveSession(_config, "ConfigChange", DeviceName, _activeSessionTargetDeviceName);
            ApplyConfigurationChanges();
            if (!sessionCheck.Allowed)
            {
                await HandleSecurityStopAsync(sessionCheck, "Verbindung aus Sicherheitsgründen beendet.");
            }
        }
        catch (Exception ex)
        {
            _logger.Warn("SecurityContextChange", ex.Message, DeviceName, AppGuid);
        }
    }

    private async Task AnalyzeAsync()
    {
        IsBusy = true;
        ProgressValue = 8;

        try
        {
            await CloseActiveConnectionIfRequiredAsync();

            var guidValidation = ValidateOptionalAppGuidOrShowMessage("Analyze");
            if (guidValidation is null)
            {
                ProgressValue = 0;
                return;
            }

            if (!await EnsureProductiveActionAllowedAsync("Analyze", DeviceName, _activeSessionTargetDeviceName))
            {
                ProgressValue = 0;
                return;
            }

            if (_config.TrustState == TrustState.Trusted && _config.ConnectionFallback && !_config.SimulationMode)
            {
                if (!_psExecDependencyService.TryEnsureAvailableSilent())
                {
                    var psExecError = AppErrorCatalog.PsExecBlocked("Bitte prüfen Sie Tools-Ordner, Signatur, Downloadquelle und Trust.log.");
                    _logger.Error("PsExec", psExecError.UserMessage, DeviceName, AppGuid, "ANALYZE-PSEXEC", psExecError.ErrorClass.ToString(), psExecError.ErrorCode, psExecError.UserMessage, psExecError.TechnicalDetails, psExecError.Component);
                    ScheduleLocalLogRefresh();
                    AppErrorPresenter.Show(_config.WindowTitle, psExecError, MessageBoxImage.Error);
                    StatusMessage = "PsExec blockiert.";
                    ProgressValue = 0;
                    return;
                }
            }

            var connectionResult = await ConnectWithRetriesAsync();
            if (!connectionResult.Success)
            {
                var diagnostic = _intuneSupportService.GetConnectionTimeoutDiagnostic(DeviceName);
                var message = $"Keine Verbindung zu {DeviceName} möglich.";
                if (!string.IsNullOrWhiteSpace(diagnostic))
                {
                    message += Environment.NewLine + Environment.NewLine + diagnostic;
                }
                else if (!string.IsNullOrWhiteSpace(connectionResult.StandardError))
                {
                    message += Environment.NewLine + Environment.NewLine + connectionResult.StandardError;
                }

                var connectionError = AppErrorCatalog.ConnectionFailed(DeviceName, message);
                _logger.Error("Connect", connectionError.UserMessage, DeviceName, AppGuid, "ANALYZE-CONNECT", connectionError.ErrorClass.ToString(), connectionError.ErrorCode, connectionError.UserMessage, connectionError.TechnicalDetails, connectionError.Component);
                ScheduleLocalLogRefresh();
                AppErrorPresenter.Show(_config.WindowTitle, connectionError, MessageBoxImage.Error);
                StatusMessage = "Verbindung fehlgeschlagen.";
                ProgressValue = 0;
                return;
            }

            _hasActiveConnection = true;
            _activeSessionTargetDeviceName = DeviceName.Trim();
            RaiseCommands();
            ProgressValue = 55;
            StatusMessage = "Logs werden geladen...";
            await LoadLogsIntoViewsAsync(false, guidValidation.IsEmpty ? null : guidValidation.NormalizedValue);
            ProgressValue = 100;
            SetLiveStatus(DateTime.Now);
            _liveViewTimer.Start();
        }
        catch (Exception ex)
        {
            var error = AppErrorCatalog.Unknown("Analyze", ex.ToString(), nameof(MainViewModel));
            _logger.Error("Analyze", error.UserMessage, DeviceName, AppGuid, "ANALYZE-ERROR", error.ErrorClass.ToString(), error.ErrorCode, error.UserMessage, error.TechnicalDetails, error.Component);
            ScheduleLocalLogRefresh();
            AppErrorPresenter.Show(_config.WindowTitle, error, MessageBoxImage.Error);
            StatusMessage = "Auswertung fehlgeschlagen.";
            ProgressValue = 0;
        }
        finally
        {
            IsBusy = false;
            if (_hasActiveConnection)
            {
                ProgressValue = 0;
            }
        }
    }

    private async Task<RemoteOperationResult> ConnectWithRetriesAsync()
    {
        var stepTimeoutSeconds = Math.Max(5, _config.ConnectionStatusIntervalSeconds);
        var totalTimeoutSeconds = Math.Max(30, _config.ConnectionTimeoutSeconds);
        var maxAttempts = Math.Min(5, Math.Max(1, totalTimeoutSeconds / stepTimeoutSeconds));
        RemoteOperationResult? lastResult = null;

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            lastResult = await _intuneSupportService.TestConnectionAsync(DeviceName, stepTimeoutSeconds);
            if (lastResult.Success)
            {
                return lastResult;
            }

            var bootstrapStatus = _intuneSupportService.GetLatestBootstrapStatus(DeviceName) ?? "Verbindung wird geprüft...";
            StatusMessage = $"{bootstrapStatus} Versuch {attempt}/{maxAttempts}";
            ProgressValue = Math.Min(45, 15 + (attempt * 6));
        }

        return lastResult ?? new RemoteOperationResult { Success = false, Message = "Verbindung fehlgeschlagen." };
    }

    private async Task LoadLogsIntoViewsAsync(bool suppressAudit, string? appGuidOverride = null)
    {
        using var perf = PerformanceTrace.Start(_logger, "LoadLogsIntoViewsAsync", suppressAudit ? "LIVE-REFRESH" : "READLOGS", DeviceName, appGuidOverride ?? AppGuid, nameof(MainViewModel), $"SuppressAudit={suppressAudit}");
        var effectiveGuid = appGuidOverride;
        if (appGuidOverride is null)
        {
            var guidValidation = ValidateOptionalAppGuidOrShowMessage(suppressAudit ? "LiveViewRefresh" : "ReadLogs");
            if (guidValidation is null)
            {
                return;
            }

            effectiveGuid = guidValidation.IsEmpty ? null : guidValidation.NormalizedValue;
        }

        var logs = await _intuneSupportService.ReadRelevantLogsAsync(DeviceName, effectiveGuid, suppressAudit, _remoteLogStates);
        var changedCollections = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ApplyRemoteLogUpdate(nameof(AgentExecutorEntries), logs, "AgentExecutor", changedCollections);
        ApplyRemoteLogUpdate(nameof(AppActionProcessorEntries), logs, "AppActionProcessor", changedCollections);
        ApplyRemoteLogUpdate(nameof(AppWorkloadEntries), logs, "AppWorkload", changedCollections);
        ApplyRemoteLogUpdate(nameof(ClientCertCheckEntries), logs, "ClientCertCheck", changedCollections);
        ApplyRemoteLogUpdate(nameof(ClientHealthEntries), logs, "ClientHealth", changedCollections);
        ApplyRemoteLogUpdate(nameof(DeviceHealthMonitoringEntries), logs, "DeviceHealthMonitoring", changedCollections);
        ApplyRemoteLogUpdate(nameof(HealthScriptsEntries), logs, "HealthScripts", changedCollections);
        ApplyRemoteLogUpdate(nameof(IntuneManagementExtensionEntries), logs, "IntuneManagementExtension", changedCollections);
        ApplyRemoteLogUpdate(nameof(CompanyPortalEntries), logs, "CompanyPortal", changedCollections);
        ApplyRemoteLogUpdate(nameof(EnrollmentEntries), logs, "Enrollment", changedCollections);
        ApplyRemoteLogUpdate(nameof(MdmDiagnosticsEntries), logs, "MdmDiagnostics", changedCollections);
        ApplyRemoteLogUpdate(nameof(EventLogChannelEntries), logs, "EventLogChannels", changedCollections);
        ApplyRemoteLogUpdate(nameof(InstallAgentEventsEntries), logs, "InstallAgentEvents", changedCollections);
        ApplyRemoteLogUpdate(nameof(DeviceRegistrySettingsEntries), logs, "DeviceRegistrySettings", changedCollections);
        ApplyRemoteLogUpdate(nameof(NotificationInfraLogsEntries), logs, "NotificationInfraLogs", changedCollections);
        ApplyRemoteLogUpdate(nameof(SensorEntries), logs, "Sensor", changedCollections);
        ApplyRemoteLogUpdate(nameof(Win321AppInventoryEntries), logs, "Win321AppInventory", changedCollections);
        ApplyRemoteLogUpdate(nameof(Win32AppsRegistryEntries), logs, "Win32AppsRegistry", changedCollections);
        ApplyRemoteLogUpdate(nameof(RemoteAuditEntries), logs, "RemoteAuditLog", changedCollections);
        ApplyRemoteLogUpdate(nameof(FallbackEntries), logs, "FallbackLog", changedCollections);
        if (changedCollections.Count > 0)
        {
            RefreshViews(changedCollections);
        }

        await WarmManagedAppNameCacheAsync();
        ScheduleLocalLogRefresh();
        if (logs.FailedLogs.Count > 0)
        {
            var parseError = AppErrorCatalog.LogParsingUnavailable(string.Join(Environment.NewLine, logs.FailedLogs.Select(item => $"- {item.LogName}: {item.Reason}")));
            _logger.Warn("LogParsing", parseError.UserMessage, DeviceName, effectiveGuid ?? "-", "LOG-PARSE", parseError.ErrorClass.ToString(), parseError.ErrorCode, parseError.UserMessage, parseError.TechnicalDetails, parseError.Component);
            AppErrorPresenter.Show(_config.WindowTitle, parseError, MessageBoxImage.Warning);
        }
    }

    private async void LiveViewTimerOnTick(object? sender, EventArgs e)
    {
        if (!_hasActiveConnection || _isLiveRefreshing || IsBusy || string.IsNullOrWhiteSpace(DeviceName))
        {
            return;
        }

        _isLiveRefreshing = true;
        try
        {
            var liveRefreshCheck = _securityGuardService.RevalidateActiveSession(_config, "LiveViewRefresh", DeviceName, _activeSessionTargetDeviceName);
            ApplyConfigurationChanges();
            if (!liveRefreshCheck.Allowed)
            {
                await HandleSecurityStopAsync(liveRefreshCheck, "Live View wegen Sicherheitswechsel beendet.");
                return;
            }

            if (!await _intuneSupportService.TestActiveConnectionAsync(_activeSessionTargetDeviceName))
            {
                _liveViewTimer.Stop();
                _hasActiveConnection = false;
                _activeSessionTargetDeviceName = string.Empty;
                RaiseCommands();
                ClearEntries();
                StatusMessage = AppendDestinationLogHint("Verbindung unterbrochen.");
                MessageBox.Show(LT("Die aktive Verbindung zum Zielgerät wurde geschlossen."), _config.WindowTitle, MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            await LoadLogsIntoViewsAsync(true);
            SetLiveStatus(DateTime.Now);
        }
        catch (Exception ex)
        {
            var error = AppErrorCatalog.LiveViewFailed(ex.ToString());
            _logger.Warn("LiveView", error.UserMessage, DeviceName, AppGuid, "LIVEVIEW-ERROR", error.ErrorClass.ToString(), error.ErrorCode, error.UserMessage, error.TechnicalDetails, error.Component);
            ScheduleLocalLogRefresh();
            await CloseActiveConnectionIfRequiredAsync(false);
            ClearEntries();
            StatusMessage = "Verbindung unterbrochen.";
            AppErrorPresenter.Show(_config.WindowTitle, error, MessageBoxImage.Warning);
        }
        finally
        {
            _isLiveRefreshing = false;
        }
    }

    private async Task CloseActiveConnectionIfRequiredAsync(bool allowFallback = true)
    {
        _liveViewTimer.Stop();
        if (!_hasActiveConnection)
        {
            _activeSessionTargetDeviceName = string.Empty;
            return;
        }

        if (allowFallback && _intuneSupportService.HasPreparedFallback)
        {
            try
            {
                await _intuneSupportService.TriggerFallbackAsync(_activeSessionTargetDeviceName);
            }
            catch (Exception ex)
            {
                _logger.Warn("FallbackTrigger", ex.Message, _activeSessionTargetDeviceName, AppGuid);
            }
        }

        _hasActiveConnection = false;
        _activeSessionTargetDeviceName = string.Empty;
        RaiseCommands();
    }

    private async Task ResetImeLogsAsync()
    {
        await ExecuteOperationAndRefreshAsync("IME Log Reset", "IME-Logs werden zurückgesetzt...", () => _intuneSupportService.ResetImeLogsAsync(GetEffectiveTargetDeviceName()));
    }

    private async Task RestartImeServiceAsync()
    {
        await ExecuteOperationAndRefreshAsync("IME Restart", "IME-Dienst wird neu gestartet...", () => _intuneSupportService.RestartImeServiceAsync(GetEffectiveTargetDeviceName()));
    }

    private async Task WsResetAsync()
    {
        await ExecuteOperationAndRefreshAsync("WSReset", "WSReset wird auf dem Zielgerät ausgeführt und danach der IME-Dienst neu gestartet...", () => _intuneSupportService.ExecuteWsResetAsync(_activeSessionTargetDeviceName));
    }

    private async Task ResetAppInstallAsync()
    {
        var selectedApps = ManagedAppInsights
            .Where(item => item.IsSelected && !string.IsNullOrWhiteSpace(item.AppGuid))
            .GroupBy(item => item.AppGuid, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();

        if (selectedApps.Count > 0)
        {
            var preview = string.Join(Environment.NewLine, selectedApps.Take(8).Select(item => $"- {item.AppName} ({item.AppGuid})"));
            if (selectedApps.Count > 8)
            {
                preview += Environment.NewLine + $"- ... und {selectedApps.Count - 8} weitere Einträge";
            }

            var confirmation = MessageBox.Show(
                LT($"Der Reset App Install wird als Batch über {selectedApps.Count} ausgewählte Applikationen ausgeführt.{Environment.NewLine}{Environment.NewLine}{preview}{Environment.NewLine}{Environment.NewLine}Sollen alle ausgewählten GUIDs zurückgesetzt werden?"),
                _config.WindowTitle,
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirmation != MessageBoxResult.Yes)
            {
                return;
            }

            await ExecuteBatchResetAppInstallAsync(selectedApps);
            return;
        }

        var inputGuid = ShowAppGuidInputDialog(AppGuid);
        if (inputGuid is null)
        {
            return;
        }

        var guidValidation = ValidateSpecificAppGuidOrShowMessage(inputGuid, "ResetAppInstall");
        if (guidValidation is null || guidValidation.IsEmpty)
        {
            return;
        }

        AppGuid = guidValidation.NormalizedValue;
        await ExecuteOperationAndRefreshAsync("Reset App Install", "App-Installationsstatus wird zurückgesetzt...", () => _intuneSupportService.ResetAppInstallAsync(GetEffectiveTargetDeviceName(), guidValidation.NormalizedValue));
    }

    private async Task ExecuteBatchResetAppInstallAsync(IReadOnlyList<DeviceAppInsight> selectedApps)
    {
        IsBusy = true;
        ProgressValue = 10;

        try
        {
            if (!await EnsureProductiveActionAllowedAsync("Reset App Install", GetEffectiveTargetDeviceName(), _activeSessionTargetDeviceName))
            {
                return;
            }

            var results = new List<(DeviceAppInsight App, RemoteOperationResult Result)>();
            for (var index = 0; index < selectedApps.Count; index++)
            {
                var item = selectedApps[index];
                StatusMessage = $"Reset App Install Batch {index + 1}/{selectedApps.Count}: {item.AppName} ({item.AppGuid})";
                ProgressValue = 10 + ((index + 1) * 80.0 / Math.Max(1, selectedApps.Count));
                var result = await _intuneSupportService.ResetAppInstallAsync(GetEffectiveTargetDeviceName(), item.AppGuid);
                results.Add((item, result));
            }

            ProgressValue = 100;
            var failed = results.Where(item => !item.Result.Success).ToList();
            if (failed.Count == 0)
            {
                var message = string.Join(Environment.NewLine, results.Select(item => $"- {item.App.AppName} ({item.App.AppGuid})"));
                MessageBox.Show(
                    LT($"Der Reset App Install wurde für {results.Count} ausgewählte Applikationen erfolgreich gestartet.{Environment.NewLine}{Environment.NewLine}{message}"),
                    _config.WindowTitle,
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else
            {
                var failureText = string.Join(Environment.NewLine + Environment.NewLine, failed.Select(item => string.Join(Environment.NewLine, new[]
                {
                    $"{item.App.AppName} ({item.App.AppGuid})",
                    item.Result.Message,
                    item.Result.StandardError
                }.Where(value => !string.IsNullOrWhiteSpace(value))).Trim()));
                var actionError = AppErrorCatalog.RemoteActionFailed("Reset App Install Batch", failureText);
                _logger.Error("Reset App Install Batch", actionError.UserMessage, GetEffectiveTargetDeviceName(), string.Join(",", failed.Select(item => item.App.AppGuid)), "ACTION-RESET-APP-INSTALL-BATCH", actionError.ErrorClass.ToString(), actionError.ErrorCode, actionError.UserMessage, actionError.TechnicalDetails, actionError.Component);
                ScheduleLocalLogRefresh();
                AppErrorPresenter.Show(_config.WindowTitle, actionError, MessageBoxImage.Error);
            }
        }
        finally
        {
            IsBusy = false;
            ProgressValue = 0;
        }

        await AnalyzeAsync();
    }

    private async Task ExecuteOperationAndRefreshAsync(string actionName, string status, Func<Task<RemoteOperationResult>> operation)
    {
        IsBusy = true;
        ProgressValue = 20;

        try
        {
            if (!await EnsureProductiveActionAllowedAsync(actionName, GetEffectiveTargetDeviceName(), _activeSessionTargetDeviceName))
            {
                return;
            }

            StatusMessage = status;
            var result = await operation();
            ProgressValue = 100;
            if (result.Success)
            {
                MessageBox.Show(
                    LT(result.Message + Environment.NewLine + result.StandardOutput),
                    _config.WindowTitle,
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else
            {
                var actionError = AppErrorCatalog.RemoteActionFailed(actionName, string.Join(Environment.NewLine, new[] { result.Message, result.StandardError, result.StandardOutput }.Where(value => !string.IsNullOrWhiteSpace(value))));
                _logger.Error(actionName, actionError.UserMessage, GetEffectiveTargetDeviceName(), AppGuid, $"ACTION-{actionName.ToUpperInvariant().Replace(' ', '-')}", actionError.ErrorClass.ToString(), actionError.ErrorCode, actionError.UserMessage, actionError.TechnicalDetails, actionError.Component);
                ScheduleLocalLogRefresh();
                AppErrorPresenter.Show(_config.WindowTitle, actionError, MessageBoxImage.Error);
            }
        }
        finally
        {
            IsBusy = false;
            ProgressValue = 0;
        }

        await AnalyzeAsync();
    }

    private void SetLiveStatus(DateTime timestamp)
    {
        StatusMessage = AppendDestinationLogHint($"{_config.LiveConnectionStatusMessage} Letzter Refresh um: {timestamp:dd.MM.yyyy HH:mm:ss}");
        NotifyDashboardStateChanged();
    }

    private static string LT(string? text) => LanguageManager.Instance.TranslateText(text);

    private string GetReadyStatus()
    {
        if (!string.IsNullOrWhiteSpace(_config.StartupSecurityBlockReason))
        {
            return LT(AppendDestinationLogHint($"Bereit. {_config.StartupSecurityBlockReason}"));
        }

        if (_config.TrustState != TrustState.Trusted)
        {
            return _config.TrustState == TrustState.NotTrusted
                ? LT(AppendDestinationLogHint("Bereit. TrustedConfig ist nicht vertrauenswürdig – Simulationsmodus erzwungen, produktiver Modus gesperrt."))
                : LT(AppendDestinationLogHint("Bereit. TrustedConfig ist fehlerhaft – Simulationsmodus erzwungen, produktiver Modus gesperrt."));
        }

        if (_config.HasValidationWarnings)
        {
            return LT(AppendDestinationLogHint($"Bereit. TrustedConfig ist gültig, enthält aber Warnungen – {_config.ValidationSummary}"));
        }

        return LT(AppendDestinationLogHint(_config.SimulationMode
            ? "Bereit. Simulationsmodus aktiv – es werden keine echten Änderungen auf dem Zielgerät ausgeführt."
            : "Bereit. Remote-Steuerung aktiv – Aktionen werden auf dem Zielgerät echt ausgeführt."));
    }

    private async Task<bool> EnsureProductiveActionAllowedAsync(string actionName, string targetDeviceName, string? activeSessionTargetDeviceName)
    {
        if (_config.SimulationMode && !_config.IsSimulationModeEnforced)
        {
            return true;
        }

        var guardResult = _securityGuardService.EnsureProductiveActionAllowed(_config, actionName, targetDeviceName, activeSessionTargetDeviceName);
        ApplyConfigurationChanges();
        if (guardResult.Allowed)
        {
            return true;
        }

        if (guardResult.SessionShouldClose && _hasActiveConnection)
        {
            await HandleSecurityStopAsync(guardResult, "Verbindung aus Sicherheitsgründen beendet.");
            return false;
        }

        StatusMessage = guardResult.Message;
        MessageBox.Show(guardResult.Message, _config.WindowTitle, MessageBoxButton.OK, MessageBoxImage.Warning);
        return false;
    }

    private AppGuidValidationResult? ValidateOptionalAppGuidOrShowMessage(string actionName)
    {
        return ValidateSpecificAppGuidOrShowMessage(AppGuid, actionName);
    }

    private AppGuidValidationResult? ValidateSpecificAppGuidOrShowMessage(string? rawGuid, string actionName)
    {
        var operationId = $"GUID-{actionName.ToUpperInvariant().Replace(' ', '-')}";
        var trimmedGuid = rawGuid?.Trim();
        var validationResult = _appInputValidator.ValidateOptionalGuid(trimmedGuid, actionName, DeviceName.Trim(), operationId);
        if (validationResult.IsValid)
        {
            return validationResult;
        }

        var guidError = AppErrorCatalog.InvalidGuid(trimmedGuid);
        _logger.Warn("GuidValidation", $"Aktion '{actionName}' wegen ungültiger GUID blockiert.", DeviceName.Trim(), trimmedGuid ?? "-", operationId, guidError.ErrorClass.ToString(), guidError.ErrorCode, guidError.UserMessage, validationResult.Message, guidError.Component);
        ScheduleLocalLogRefresh();
        StatusMessage = LT("Ungültige GUID – Aktion blockiert.");
        AppErrorPresenter.Show(_config.WindowTitle, guidError, MessageBoxImage.Warning);
        return null;
    }

    private string? ShowAppGuidInputDialog(string? initialValue)
    {
        var window = new Window
        {
            Title = LT("Reset App Install"),
            Width = 560,
            Height = 215,
            MinWidth = 560,
            MinHeight = 215,
            ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = Application.Current?.MainWindow,
            Background = Brushes.White,
            ShowInTaskbar = false
        };

        var root = new Grid { Margin = new Thickness(16) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        var hint = new TextBlock
        {
            Text = LT("Bitte die Intune App GUID eingeben. Ist bereits eine GUID im Hauptfenster vorhanden, kann sie hier nochmals geprüft oder angepasst werden."),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10)
        };
        Grid.SetRow(hint, 0);
        root.Children.Add(hint);

        var label = new TextBlock
        {
            Text = LT("Intune App GUID"),
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 4)
        };
        Grid.SetRow(label, 1);
        root.Children.Add(label);

        var input = new TextBox
        {
            Height = 30,
            Text = initialValue?.Trim() ?? string.Empty,
            VerticalContentAlignment = VerticalAlignment.Center
        };
        Grid.SetRow(input, 2);
        root.Children.Add(input);

        var buttonPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 14, 0, 0)
        };
        Grid.SetRow(buttonPanel, 3);
        root.Children.Add(buttonPanel);

        var okButton = new Button
        {
            Content = LT("OK"),
            Width = 100,
            Height = 30,
            Padding = new Thickness(12, 0, 12, 0),
            VerticalContentAlignment = VerticalAlignment.Center,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            IsDefault = true,
            Margin = new Thickness(0, 0, 8, 0)
        };
        okButton.Click += (_, _) => window.DialogResult = true;
        buttonPanel.Children.Add(okButton);

        var cancelButton = new Button
        {
            Content = LT("Abbrechen"),
            Width = 100,
            Height = 30,
            Padding = new Thickness(12, 0, 12, 0),
            VerticalContentAlignment = VerticalAlignment.Center,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0),
            IsCancel = true
        };
        buttonPanel.Children.Add(cancelButton);

        window.Content = root;
        window.Loaded += (_, _) =>
        {
            input.Focus();
            input.SelectAll();
        };

        return window.ShowDialog() == true ? input.Text?.Trim() : null;
    }


    private string GetEffectiveTargetDeviceName()
    {
        return !string.IsNullOrWhiteSpace(_activeSessionTargetDeviceName)
            ? _activeSessionTargetDeviceName
            : DeviceName.Trim();
    }

    private async Task HandleSecurityStopAsync(RuntimeTrustCheckResult guardResult, string fallbackStatusMessage)
    {
        await CloseActiveConnectionIfRequiredAsync(false);
        ClearEntries();
        ScheduleLocalLogRefresh();
        StatusMessage = AppendDestinationLogHint(string.IsNullOrWhiteSpace(guardResult.Message) ? fallbackStatusMessage : guardResult.Message);
        MessageBox.Show(StatusMessage, _config.WindowTitle, MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private string AppendDestinationLogHint(string status)
    {
        if (!_config.ShortDestinationLogs)
        {
            return status;
        }

        var hint = "Die Logs sind auf 10 Tage gekürzt.";
        if (string.IsNullOrWhiteSpace(status))
        {
            return hint;
        }

        return LT(status.Contains(hint, StringComparison.OrdinalIgnoreCase) ? status : status + " " + hint);
    }


private void ScheduleViewRefresh(IEnumerable<string>? collectionNames = null)
{
    if (collectionNames is null)
    {
        foreach (var key in _entryViews.Keys)
        {
            _pendingViewRefreshKeys.Add(key);
        }
    }
    else
    {
        foreach (var key in collectionNames)
        {
            _pendingViewRefreshKeys.Add(key);
        }
    }

    _viewRefreshDebounceTimer.Stop();
    _viewRefreshDebounceTimer.Start();
}

private void ViewRefreshDebounceTimerOnTick(object? sender, EventArgs e)
{
    _viewRefreshDebounceTimer.Stop();
    RefreshViews(_pendingViewRefreshKeys);
    _pendingViewRefreshKeys.Clear();
}

private void ApplyRemoteLogUpdate(string collectionName, LogBundle bundle, string logKey, ISet<string> changedCollections)
{
    bundle.EntriesByKey.TryGetValue(logKey, out var entries);
    entries ??= [];
    bundle.ReadStates.TryGetValue(logKey, out var readState);
    readState ??= new RemoteLogReadState { UpdateMode = "Full", FilteredLineCount = entries.Count };
    _remoteLogStates[logKey] = readState;

    var mode = readState.UpdateMode ?? "Full";
    if (string.Equals(mode, "Unchanged", StringComparison.OrdinalIgnoreCase))
    {
        return;
    }

    var target = _entryCollections[collectionName];
    if (string.Equals(mode, "Append", StringComparison.OrdinalIgnoreCase) && target.Count > 0)
    {
        var existing = new HashSet<string>(target.Select(GetEntryIdentity), StringComparer.Ordinal);
        var added = false;
        foreach (var entry in entries)
        {
            if (existing.Add(GetEntryIdentity(entry)))
            {
                target.Add(entry);
                added = true;
            }
        }
        if (added)
        {
            changedCollections.Add(collectionName);
        }
        return;
    }

    ReplaceEntries(collectionName, bundle, logKey);
    changedCollections.Add(collectionName);
}

private sealed class LocalLogMonitorState
{
    public string SourceSignature { get; set; } = string.Empty;
    public DateTime NewestTimestamp { get; set; }
    public int ContentLength { get; set; }
}

private void InitializeLocalLogMonitoring()
{
    try
    {
        _localLogWatcher?.Dispose();
        _localLogWatcher = null;
        _trustLogWatcher?.Dispose();
        _trustLogWatcher = null;

        var localLogDirectory = Environment.ExpandEnvironmentVariables(_config.LocalLogDirectory);
        if (Directory.Exists(localLogDirectory))
        {
            _localLogWatcher = new FileSystemWatcher(localLogDirectory, "*.log")
            {
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            _localLogWatcher.Changed += OnLocalLogFileChanged;
            _localLogWatcher.Created += OnLocalLogFileChanged;
            _localLogWatcher.Deleted += OnLocalLogFileChanged;
            _localLogWatcher.Renamed += OnLocalLogFileChanged;
            _localLogWatcher.EnableRaisingEvents = true;
        }

        var trustLogPath = Environment.ExpandEnvironmentVariables(_config.TrustLogPath ?? string.Empty);
        var trustDir = string.IsNullOrWhiteSpace(trustLogPath) ? string.Empty : Path.GetDirectoryName(trustLogPath) ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(trustDir) && Directory.Exists(trustDir))
        {
            _trustLogWatcher = new FileSystemWatcher(trustDir, Path.GetFileName(trustLogPath))
            {
                IncludeSubdirectories = false,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            _trustLogWatcher.Changed += OnLocalLogFileChanged;
            _trustLogWatcher.Created += OnLocalLogFileChanged;
            _trustLogWatcher.Deleted += OnLocalLogFileChanged;
            _trustLogWatcher.Renamed += OnLocalLogFileChanged;
            _trustLogWatcher.EnableRaisingEvents = true;
        }
    }
    catch
    {
        // Monitoring ist optional.
    }
}

private void OnLocalLogFileChanged(object? sender, FileSystemEventArgs e)
{
    ScheduleLocalLogRefresh();
}

private void ScheduleLocalLogRefresh()
{
    _localLogRefreshPending = true;
    _localLogRefreshDebounceTimer.Stop();
    _localLogRefreshDebounceTimer.Start();
}

private void LocalLogRefreshDebounceTimerOnTick(object? sender, EventArgs e)
{
    _localLogRefreshDebounceTimer.Stop();
    if (!_localLogRefreshPending)
    {
        return;
    }

    _localLogRefreshPending = false;
    RefreshLocalProgramLogs();
}

private static string BuildLocalSourceSignature(IEnumerable<LogEntry> entries, string logKey)
    => string.Join("|", entries.Select(entry => entry.SourceFile).Distinct(StringComparer.OrdinalIgnoreCase).DefaultIfEmpty(logKey).OrderBy(path => path, StringComparer.OrdinalIgnoreCase));

private static string GetEntryIdentity(LogEntry entry)
    => $"{entry.Timestamp:o}|{entry.Severity}|{entry.SourceFile}|{entry.Message}";

private bool UpdateLocalLogCollection(LogBundle bundle, string collectionName, string logKey, bool forceFullReload)
{
    bundle.EntriesByKey.TryGetValue(logKey, out var entries);
    entries ??= [];

    if (!_localLogMonitorStates.TryGetValue(collectionName, out var state))
    {
        state = new LocalLogMonitorState();
        _localLogMonitorStates[collectionName] = state;
    }

    var sourceSignature = BuildLocalSourceSignature(entries, logKey);
    var newestTimestamp = entries.Count > 0 ? entries.Max(entry => entry.Timestamp) : DateTime.MinValue;
    var contentLength = entries.Sum(entry => entry.Message?.Length ?? 0);
    var changed = forceFullReload
        || !string.Equals(state.SourceSignature, sourceSignature, StringComparison.OrdinalIgnoreCase)
        || newestTimestamp > state.NewestTimestamp
        || contentLength != state.ContentLength;

    if (!changed)
    {
        return false;
    }

    var target = _entryCollections[collectionName];
    var appendOnly = !forceFullReload && string.Equals(state.SourceSignature, sourceSignature, StringComparison.OrdinalIgnoreCase) && newestTimestamp >= state.NewestTimestamp && target.Count > 0;
    if (!appendOnly)
    {
        target.Clear();
        foreach (var entry in entries)
        {
            target.Add(entry);
        }
    }
    else
    {
        var existing = new HashSet<string>(target.Select(GetEntryIdentity), StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (existing.Add(GetEntryIdentity(entry)))
            {
                target.Add(entry);
            }
        }
    }

    var maxEntries = logKey.Equals("AppDataLogs", StringComparison.OrdinalIgnoreCase) ? 1000 : 500;
    while (target.Count > maxEntries)
    {
        target.RemoveAt(target.Count - 1);
    }

    state.SourceSignature = sourceSignature;
    state.NewestTimestamp = newestTimestamp;
    state.ContentLength = contentLength;
    return true;
}


    private IEnumerable<LogEntry> GetRemoteLogEntries()
    {
        return AgentExecutorEntries
            .Concat(AppActionProcessorEntries)
            .Concat(AppWorkloadEntries)
            .Concat(ClientCertCheckEntries)
            .Concat(ClientHealthEntries)
            .Concat(DeviceHealthMonitoringEntries)
            .Concat(HealthScriptsEntries)
            .Concat(IntuneManagementExtensionEntries)
            .Concat(CompanyPortalEntries)
            .Concat(EnrollmentEntries)
            .Concat(MdmDiagnosticsEntries)
            .Concat(EventLogChannelEntries)
            .Concat(InstallAgentEventsEntries)
            .Concat(DeviceRegistrySettingsEntries)
            .Concat(NotificationInfraLogsEntries)
            .Concat(SensorEntries)
            .Concat(Win321AppInventoryEntries)
            .Concat(RemoteAuditEntries)
            .Concat(FallbackEntries);
    }

    private static int GetSeverityCount(IEnumerable<LogEntry> entries, string severity)
        => entries.Count(entry => entry.Severity.Equals(severity, StringComparison.OrdinalIgnoreCase));

    private string GetLatestSignalText()
    {
        var latestEntry = GetRemoteLogEntries()
            .Where(entry => entry.Timestamp != DateTime.MinValue)
            .OrderByDescending(entry => entry.Timestamp)
            .FirstOrDefault();

        if (latestEntry is null)
        {
            return "Noch keine Remote-Logdaten geladen.";
        }

        return $"{latestEntry.DisplayTimestamp} | {latestEntry.SourceFile} | {latestEntry.Severity}";
    }

    private string GetRemediationSignalText()
    {
        var remediationEntry = HealthScriptsEntries
            .Concat(DeviceHealthMonitoringEntries)
            .Where(entry => entry.Timestamp != DateTime.MinValue)
            .OrderByDescending(entry => entry.Timestamp)
            .FirstOrDefault();

        if (remediationEntry is null)
        {
            return "Noch keine Remediation-Signale geladen.";
        }

        return $"{remediationEntry.DisplayTimestamp} | {remediationEntry.SourceFile} | {remediationEntry.Severity}";
    }


    private IEnumerable<LogEntry> GetCompanyPortalLogEntries()
        => CompanyPortalEntries
            .Concat(EnrollmentEntries)
            .Concat(MdmDiagnosticsEntries)
            .Concat(EventLogChannelEntries)
            .Concat(InstallAgentEventsEntries);

    private IEnumerable<LogEntry> GetIntuneLogEntries()
        => AgentExecutorEntries
            .Concat(AppActionProcessorEntries)
            .Concat(AppWorkloadEntries)
            .Concat(ClientCertCheckEntries)
            .Concat(ClientHealthEntries)
            .Concat(IntuneManagementExtensionEntries)
            .Concat(NotificationInfraLogsEntries)
            .Concat(SensorEntries)
            .Concat(Win321AppInventoryEntries)
            .Concat(RemoteAuditEntries)
            .Concat(FallbackEntries);

    private IEnumerable<LogEntry> GetLocalAppLogEntries()
        => LocalAppLogEntries
            .Concat(AppDataLogsEntries)
            .Concat(TrustLogEntries);

    private IEnumerable<LogEntry> GetRemediationLogEntries()
        => HealthScriptsEntries
            .Concat(DeviceHealthMonitoringEntries);

    private static string BuildGroupOverviewText(string label, IEnumerable<LogEntry> entries)
    {
        var list = entries.ToList();
        if (list.Count == 0)
        {
            return LT($"{label}: Noch keine Daten geladen.");
        }

        var errorCount = list.Count(entry => entry.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase));
        var warningCount = list.Count(entry => entry.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase));
        var sources = list.Select(entry => entry.SourceFile).Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var latest = list.Where(entry => entry.Timestamp != DateTime.MinValue).OrderByDescending(entry => entry.Timestamp).FirstOrDefault();

        return latest is null
            ? $"{label}: {list.Count} Einträge | Fehler: {errorCount} | Warnungen: {warningCount} | Quellen: {sources}"
            : $"{label}: {list.Count} Einträge | Fehler: {errorCount} | Warnungen: {warningCount} | Quellen: {sources} | Letzter Hinweis: {latest.DisplayTimestamp}";
    }

    private static string BuildGroupSignalText(IEnumerable<LogEntry> entries, string emptyText)
    {
        var list = entries.Where(entry => entry.Timestamp != DateTime.MinValue).OrderByDescending(entry => entry.Timestamp).ToList();
        if (list.Count == 0)
        {
            return LT(emptyText);
        }

        var latestErrorOrWarning = list.FirstOrDefault(entry => entry.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase) || entry.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase));
        var latest = latestErrorOrWarning ?? list.First();
        return $"Aktuell relevant: {latest.DisplayTimestamp} | {latest.SourceFile} | {latest.Severity} | {TrimForDashboard(latest.Message, 160)}";
    }

    private static IReadOnlyList<string> GetCollectionsForFilterGroup(string group)
        => group switch
        {
            "CompanyPortal" =>
            [
                nameof(CompanyPortalEntries),
                nameof(EnrollmentEntries),
                nameof(MdmDiagnosticsEntries),
                nameof(EventLogChannelEntries),
                nameof(InstallAgentEventsEntries)
            ],
            "Local" =>
            [
                nameof(LocalAppLogEntries),
                nameof(AppDataLogsEntries),
                nameof(TrustLogEntries)
            ],
            "Remediation" =>
            [
                nameof(HealthScriptsEntries),
                nameof(DeviceHealthMonitoringEntries)
            ],
            _ =>
            [
                nameof(AgentExecutorEntries),
                nameof(AppActionProcessorEntries),
                nameof(AppWorkloadEntries),
                nameof(ClientCertCheckEntries),
                nameof(ClientHealthEntries),
                nameof(IntuneManagementExtensionEntries),
                nameof(NotificationInfraLogsEntries),
                nameof(SensorEntries),
                nameof(Win321AppInventoryEntries),
                nameof(RemoteAuditEntries),
                nameof(FallbackEntries)
            ]
        };

    private string GetSearchTermForCollection(string collectionName)
        => ResolveFilterGroup(collectionName) switch
        {
            "CompanyPortal" => CompanyPortalSearchTerm,
            "Local" => LocalLogsSearchTerm,
            "Remediation" => RemediationSearchTerm,
            _ => IntuneLogsSearchTerm
        };

    private string GetSelectedFilterForCollection(string collectionName)
        => ResolveFilterGroup(collectionName) switch
        {
            "CompanyPortal" => CompanyPortalSelectedFilter,
            "Local" => LocalLogsSelectedFilter,
            "Remediation" => RemediationSelectedFilter,
            _ => IntuneLogsSelectedFilter
        };

    private static string ResolveFilterGroup(string collectionName)
        => collectionName switch
        {
            nameof(CompanyPortalEntries) or nameof(EnrollmentEntries) or nameof(MdmDiagnosticsEntries) or nameof(EventLogChannelEntries) or nameof(InstallAgentEventsEntries) => "CompanyPortal",
            nameof(LocalAppLogEntries) or nameof(AppDataLogsEntries) or nameof(TrustLogEntries) => "Local",
            nameof(HealthScriptsEntries) or nameof(DeviceHealthMonitoringEntries) => "Remediation",
            _ => "Intune"
        };

    private void ExportLogBundle()
    {
        try
        {
            var effectiveDeviceName = string.IsNullOrWhiteSpace(DeviceName) ? "UnknownDevice" : DeviceName.Trim();
            var defaultFileName = $"{SanitizeFileName(effectiveDeviceName)}_IntuneSupport_{DateTime.Now:yyyyMMddHHmmss}.zip";
            var dialog = new SaveFileDialog
            {
                Title = LT("Log Export speichern unter"),
                Filter = "ZIP-Datei (*.zip)|*.zip",
                DefaultExt = ".zip",
                AddExtension = true,
                OverwritePrompt = true,
                FileName = defaultFileName
            };

            if (dialog.ShowDialog() != true)
            {
                return;
            }

            if (File.Exists(dialog.FileName))
            {
                File.Delete(dialog.FileName);
            }

            using var archive = ZipFile.Open(dialog.FileName, ZipArchiveMode.Create);
            WriteArchiveTextEntry(archive, "Dashboard_Overview.txt", BuildDashboardOverviewExportText());
            WriteArchiveTextEntry(archive, "Managed_App_Insights.txt", BuildManagedAppInsightsExportText());
            WriteArchiveTextEntry(archive, "IME_Health_Issues.txt", BuildIssueInsightsExportText());
            WriteArchiveTextEntry(archive, "Intune_Registry_Settings.txt", BuildRegistrySettingsExportText());

            foreach (var collectionName in _entryCollections.Keys.OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
            {
                var entries = _entryCollections[collectionName];
                if (entries.Count == 0)
                {
                    continue;
                }

                var exportName = GetExportFileName(collectionName);
                WriteArchiveTextEntry(archive, $"Logs/{exportName}", BuildLogExportText(entries));
            }

            StatusMessage = AppendDestinationLogHint($"Log Export erstellt: {Path.GetFileName(dialog.FileName)}");
            MessageBox.Show($"Der Log Export wurde erfolgreich erstellt.\n\n{dialog.FileName}", _config.WindowTitle, MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _logger.Error("LogExport", ex.Message, DeviceName, AppGuid);
            MessageBox.Show($"Der Log Export konnte nicht erstellt werden.\n\n{ex.Message}", _config.WindowTitle, MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private string BuildDashboardOverviewExportText()
    {
        var lines = new List<string>
        {
            $"Gerät: {ImeHealthTargetDevice}",
            $"App GUID Filter: {(string.IsNullOrWhiteSpace(AppGuid) ? "-" : AppGuid.Trim())}",
            $"Status: {StatusMessage}",
            $"Runtime Mode: {RuntimeModeText}",
            $"Runtime Hinweis: {RuntimeModeHint}",
            string.Empty,
            "=== IME Health Dashboard ===",
            $"Session: {ImeHealthConnectionState}",
            $"Remote Log Stats: {ImeHealthRemoteLogStats}",
            $"Pending Restart: {ImeHealthPendingRestartText}",
            $"App Installationen: {ImeHealthManagedAppsSummary}",
            $"Enrollment / MDM: {ImeHealthEnrollmentSummary}",
            $"Remediation: {ImeHealthRemediationSummary}",
            $"Auffälligkeiten: {ImeHealthIssueSummary}",
            $"Letztes Signal: {ImeHealthLatestSignal}",
            string.Empty,
            "=== Company Portal Logs ===",
            CompanyPortalOverviewText,
            CompanyPortalOverviewSignalText,
            $"Company Portal: {CompanyPortalSummaryText}",
            $"Enrollment: {EnrollmentSummaryText}",
            $"MDM Diagnose: {MdmDiagnosticsSummaryText}",
            $"Event-Logs: {EventLogChannelsSummaryText}",
            $"Install-Agent Events: {InstallAgentEventsSummaryText}",
            string.Empty,
            "=== Intune Logs ===",
            IntuneLogsOverviewText,
            IntuneLogsOverviewSignalText,
            string.Empty,
            "=== Lokale App Logs ===",
            LocalAppLogsOverviewText,
            LocalAppLogsOverviewSignalText,
            string.Empty,
            "=== Remediation ===",
            RemediationSummaryText,
            ImeHealthRemediationSummary,
            ImeHealthRemediationSignal,
            string.Empty,
            "=== Registry Einstellungen ===",
            IntuneRelevantRegistrySettingsSummaryText
        };

        return string.Join(Environment.NewLine, lines);
    }

    private string BuildManagedAppInsightsExportText()
    {
        if (ManagedAppInsights.Count == 0)
        {
            return "Keine App-Insights geladen.";
        }

        var builder = new StringBuilder();
        foreach (var item in ManagedAppInsights)
        {
            builder.AppendLine($"App Name: {item.AppName}");
            builder.AppendLine($"GUID: {item.AppGuid}");
            builder.AppendLine($"Package ID: {item.PackageId}");
            builder.AppendLine($"Status: {item.Status}");
            builder.AppendLine($"Applicability: {item.Applicability}");
            builder.AppendLine($"Error Code: {item.ErrorCode}");
            builder.AppendLine($"Desired State: {item.DesiredState}");
            builder.AppendLine($"TargetingMethod: {item.TargetingMethod}");
            builder.AppendLine($"Install Context: {item.InstallContext}");
            builder.AppendLine($"TargetType: {item.TargetType}");
            builder.AppendLine($"Product Version: {item.ProductVersion}");
            builder.AppendLine($"RebootStatus: {item.RebootStatus}");
            builder.AppendLine($"RebootReason: {item.RebootReason}");
            builder.AppendLine($"UserID: {item.UserId}");
            builder.AppendLine($"ComputerID: {item.ComputerId}");
            builder.AppendLine($"ComplianceStateMessage: {item.ComplianceStateMessage}");
            builder.AppendLine($"EnforcementStateMessage: {item.EnforcementStateMessage}");
            builder.AppendLine($"EnforcementState: {item.EnforcementState}");
            builder.AppendLine($"Fehler / Hinweis: {item.ErrorHint}");
            builder.AppendLine($"Quelle: {item.SourceLog}");
            builder.AppendLine($"Letzter Hinweis: {item.LastSeen}");
            builder.AppendLine(new string('-', 80));
        }

        return builder.ToString();
    }

    private string BuildRegistrySettingsExportText()
    {
        if (IntuneRelevantRegistrySettings.Count == 0)
        {
            return "Keine Intune-relevanten Registry-Einstellungen geladen.";
        }

        var builder = new StringBuilder();
        foreach (var item in IntuneRelevantRegistrySettings)
        {
            builder.AppendLine($"Kategorie: {item.Category}");
            builder.AppendLine($"Setting: {item.SettingName}");
            builder.AppendLine($"Wert: {item.Value}");
            builder.AppendLine($"Empfehlung: {item.Recommendation}");
            builder.AppendLine($"Interpretation: {item.Interpretation}");
            builder.AppendLine($"Status: {item.Status}");
            builder.AppendLine($"Registry-Pfad: {item.RegistryPath}");
            builder.AppendLine($"Quelle: {item.SourceLog}");
            builder.AppendLine($"Letzter Hinweis: {item.LastSeen}");
            builder.AppendLine(new string('-', 80));
        }

        return builder.ToString();
    }

    private string BuildIssueInsightsExportText()
    {
        if (ImeHealthIssueInsights.Count == 0)
        {
            return "Keine Auffälligkeiten geladen.";
        }

        var builder = new StringBuilder();
        foreach (var item in ImeHealthIssueInsights)
        {
            builder.AppendLine($"Kategorie: {item.Category}");
            builder.AppendLine($"Zusammenfassung: {item.Summary}");
            builder.AppendLine($"Quelle: {item.SourceLog}");
            builder.AppendLine($"Letzter Hinweis: {item.LastSeen}");
            builder.AppendLine(new string('-', 80));
        }

        return builder.ToString();
    }

    private static string BuildLogExportText(IEnumerable<LogEntry> entries)
    {
        var builder = new StringBuilder();
        foreach (var entry in entries.OrderBy(item => item.Timestamp))
        {
            var timestamp = entry.Timestamp == DateTime.MinValue ? "-" : entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
            builder.AppendLine($"[{timestamp}] [{entry.Severity}] [{entry.SourceFile}] {entry.Message}");
        }

        return builder.ToString();
    }

    private static void WriteArchiveTextEntry(ZipArchive archive, string entryName, string content)
    {
        var entry = archive.CreateEntry(entryName, CompressionLevel.Fastest);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        writer.Write(content);
    }

    private string GetExportFileName(string collectionName)
        => collectionName switch
        {
            nameof(AgentExecutorEntries) => "AgentExecutor.log",
            nameof(AppActionProcessorEntries) => "AppActionProcessor.log",
            nameof(AppWorkloadEntries) => "AppWorkload.log",
            nameof(ClientCertCheckEntries) => "ClientCertCheck.log",
            nameof(ClientHealthEntries) => "ClientHealth.log",
            nameof(DeviceHealthMonitoringEntries) => "DeviceHealthMonitoring.log",
            nameof(HealthScriptsEntries) => "HealthScripts.log",
            nameof(IntuneManagementExtensionEntries) => "IntuneManagementExtension.log",
            nameof(CompanyPortalEntries) => "CompanyPortal.log",
            nameof(EnrollmentEntries) => "Enrollment.log",
            nameof(MdmDiagnosticsEntries) => "MdmDiagnostics.log",
            nameof(EventLogChannelEntries) => "EventLogChannels.log",
            nameof(InstallAgentEventsEntries) => "InstallAgentEvents.log",
            nameof(DeviceRegistrySettingsEntries) => "DeviceRegistrySettings.log",
            nameof(NotificationInfraLogsEntries) => "NotificationInfraLogs.log",
            nameof(SensorEntries) => "Sensor.log",
            nameof(Win321AppInventoryEntries) => "Win32AppInventory.log",
            nameof(Win32AppsRegistryEntries) => "Win32AppsRegistry.log",
            nameof(LocalAppLogEntries) => LanguageManager.Instance.GetLocalAppLogFileName(),
            nameof(AppDataLogsEntries) => "AppData_LogHistory.log",
            nameof(RemoteAuditEntries) => LanguageManager.Instance.GetRemoteAuditLogFileName(),
            nameof(FallbackEntries) => _config.RemoteFallbackLogFileName,
            nameof(TrustLogEntries) => "Trust.log",
            _ => SanitizeFileName(collectionName) + ".log"
        };

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var builder = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            builder.Append(invalid.Contains(character) ? '_' : character);
        }

        return builder.ToString();
    }

    private static readonly Regex GuidRegex = new(@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", RegexOptions.Compiled);

    private void RebuildDashboardInsights()
    {
        RebuildManagedAppInsights();
        RebuildIssueInsights();
        RebuildRegistrySettingInsights();
    }

    private void RebuildRegistrySettingInsights()
    {
        IntuneRelevantRegistrySettings.Clear();
        var recommendations = LoadRegistryRecommendations();

        var latestBySetting = new Dictionary<string, RegistrySettingInsight>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in DeviceRegistrySettingsEntries
            .Where(item => !string.IsNullOrWhiteSpace(item.Message))
            .OrderByDescending(item => item.Timestamp))
        {
            var category = ExtractRegistryTopLevelValue(entry.Message, new[] { "Category", "category" });
            var settingName = ExtractRegistryTopLevelValue(entry.Message, new[] { "Setting", "setting", "SettingName", "settingName" });
            if (string.IsNullOrWhiteSpace(category) || string.IsNullOrWhiteSpace(settingName))
            {
                continue;
            }

            var key = $"{category}|{settingName}";
            if (latestBySetting.ContainsKey(key))
            {
                continue;
            }

            latestBySetting[key] = new RegistrySettingInsight
            {
                Category = category,
                SettingName = settingName,
                Value = ExtractRegistryTopLevelValue(entry.Message, new[] { "Value", "value", "EffectiveValue", "effectiveValue" }),
                Recommendation = ResolveRegistryRecommendation(recommendations, category, settingName),
                Interpretation = ExtractRegistryTopLevelValue(entry.Message, new[] { "Interpretation", "interpretation" }),
                Status = ExtractRegistryTopLevelValue(entry.Message, new[] { "Status", "status" }),
                RegistryPath = ExtractRegistryTopLevelValue(entry.Message, new[] { "RegistryPath", "registryPath" }),
                SourceLog = entry.SourceFile,
                LastSeen = entry.DisplayTimestamp
            };
        }

        foreach (var item in latestBySetting.Values
            .OrderBy(value => value.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(value => value.SettingName, StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(item.Value))
            {
                item.Value = "-";
            }

            if (string.IsNullOrWhiteSpace(item.Recommendation))
            {
                item.Recommendation = "Keine Empfehlung hinterlegt";
            }

            if (string.IsNullOrWhiteSpace(item.Interpretation))
            {
                item.Interpretation = item.Status.Equals("Configured", StringComparison.OrdinalIgnoreCase) ? "Konfiguriert" : "Nicht konfiguriert";
            }

            if (string.IsNullOrWhiteSpace(item.Status))
            {
                item.Status = "Unknown";
            }

            IntuneRelevantRegistrySettings.Add(item);
        }

        OnPropertyChanged(nameof(IntuneRelevantRegistrySettingsSummaryText));
    }

    private string GetRegistrySettingsSummary()
    {
        if (IntuneRelevantRegistrySettings.Count == 0)
        {
            return "Intune Relevante Registry Einstellungen: Noch keine Daten geladen.";
        }

        var configured = IntuneRelevantRegistrySettings.Count(item => item.Status.Equals("Configured", StringComparison.OrdinalIgnoreCase));
        var notConfigured = IntuneRelevantRegistrySettings.Count(item => item.Status.Equals("NotConfigured", StringComparison.OrdinalIgnoreCase));
        var categories = IntuneRelevantRegistrySettings.Select(item => item.Category).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var latest = IntuneRelevantRegistrySettings
            .Where(item => !string.IsNullOrWhiteSpace(item.LastSeen) && !string.Equals(item.LastSeen, "-", StringComparison.OrdinalIgnoreCase))
            .Select(item => item.LastSeen)
            .FirstOrDefault();

        var summary = $"Einträge: {IntuneRelevantRegistrySettings.Count} | Kategorien: {categories} | Konfiguriert: {configured} | Nicht gesetzt: {notConfigured}";
        if (!string.IsNullOrWhiteSpace(latest))
        {
            summary += $" | Letzter Hinweis: {latest}";
        }

        return LT(summary);
    }

    private void RebuildManagedAppInsights()
    {
        ManagedAppInsights.Clear();
        var appLogs = GetManagedAppLogEntries().ToList();
        var registryAppGuids = ExtractRegistryAppGuids(Win32AppsRegistryEntries);
        if (registryAppGuids.Count == 0)
        {
            return;
        }

        var appWorkloadMetadataMap = ExtractAppWorkloadMetadataMap(AppWorkloadEntries);
        var inventoryMetadataMap = ExtractInventoryMetadataMap(Win321AppInventoryEntries, registryAppGuids);
        MergeResolvedAppMetadataIntoCache(inventoryMetadataMap, appWorkloadMetadataMap);
        var latestPayloadMap = ExtractLatestAppPayloadMap(AppWorkloadEntries);
        var latestAppWorkloadErrorMap = ExtractLatestAppWorkloadErrorMap(appLogs);
        var latestRelevantEntryMap = ExtractLatestRelevantEntryMap(appLogs, registryAppGuids);
        var registryStateMap = ExtractLatestRegistryStateMap(Win32AppsRegistryEntries, registryAppGuids);

        foreach (var appGuid in registryAppGuids
                     .Where(guid => GuidRegex.IsMatch(guid) && registryStateMap.ContainsKey(guid))
                     .OrderBy(guid => ResolveAppDisplayName(guid, inventoryMetadataMap, appWorkloadMetadataMap), StringComparer.OrdinalIgnoreCase)
                     .Take(120))
        {
            latestRelevantEntryMap.TryGetValue(appGuid, out var latestRelevantEntry);
            latestPayloadMap.TryGetValue(appGuid, out var payload);
            latestAppWorkloadErrorMap.TryGetValue(appGuid, out var latestErrorEntry);
            registryStateMap.TryGetValue(appGuid, out var registryState);
            inventoryMetadataMap.TryGetValue(appGuid, out var inventoryMetadata);

            var resolvedName = ResolveAppDisplayName(appGuid, inventoryMetadataMap, appWorkloadMetadataMap);
            var packageId = ResolveAppPackageId(appGuid, payload, appWorkloadMetadataMap);
            var hasCimInstallEvidence = HasInstalledCimEvidence(appGuid);

            if (!HasAppEvidence(appGuid, resolvedName, packageId, inventoryMetadata?.ProductVersion, payload, registryState, latestErrorEntry, latestRelevantEntry))
            {
                continue;
            }

            var sourceEntry = registryState?.SourceEntry ?? payload?.SourceEntry ?? latestErrorEntry ?? latestRelevantEntry;
            var errorCode = registryState?.ErrorCodeHex ?? string.Empty;
            var status = ResolveManagedAppStatus(registryState, hasCimInstallEvidence, !string.IsNullOrWhiteSpace(errorCode));
            var errorHint = !string.IsNullOrWhiteSpace(errorCode)
                ? errorCode
                : latestErrorEntry is not null
                    ? TrimForDashboard(latestErrorEntry.Message, 220)
                    : ResolveErrorHint(payload?.RawMessage ?? latestRelevantEntry?.Message);

            ManagedAppInsights.Add(new DeviceAppInsight
            {
                AppGuid = appGuid,
                AppName = string.IsNullOrWhiteSpace(resolvedName) ? "App-Name nicht aufgelöst" : resolvedName,
                PackageId = string.IsNullOrWhiteSpace(packageId) ? string.Empty : packageId,
                Status = status,
                Applicability = registryState?.Applicability ?? string.Empty,
                ErrorCode = errorCode,
                DesiredState = registryState?.DesiredState ?? string.Empty,
                TargetingMethod = registryState?.TargetingMethod ?? string.Empty,
                InstallContext = registryState?.InstallContext ?? string.Empty,
                TargetType = registryState?.TargetType ?? string.Empty,
                ProductVersion = !string.IsNullOrWhiteSpace(registryState?.ProductVersion)
                    ? registryState.ProductVersion
                    : inventoryMetadata?.ProductVersion ?? payload?.InternalVersion ?? string.Empty,
                InternalVersion = !string.IsNullOrWhiteSpace(registryState?.ProductVersion)
                    ? registryState.ProductVersion
                    : inventoryMetadata?.ProductVersion ?? payload?.InternalVersion ?? string.Empty,
                RebootStatus = registryState?.RebootStatus ?? payload?.RebootStatus ?? string.Empty,
                RebootReason = registryState?.RebootReason ?? payload?.RebootReason ?? string.Empty,
                UserId = registryState?.UserTargetingGuid ?? payload?.UserId ?? string.Empty,
                ComputerId = registryState?.ComputerId ?? string.Empty,
                DeviceId = registryState?.ComputerId ?? string.Empty,
                ComplianceStateMessage = registryState?.ComplianceStateMessage ?? string.Empty,
                EnforcementStateMessage = registryState?.EnforcementStateMessage ?? string.Empty,
                EnforcementState = registryState?.EnforcementState ?? string.Empty,
                ErrorHint = string.IsNullOrWhiteSpace(errorHint) ? string.Empty : errorHint,
                SourceLog = sourceEntry?.SourceFile ?? payload?.SourceLog ?? registryState?.SourceLog ?? "-",
                LastSeen = sourceEntry?.DisplayTimestamp ?? payload?.LastSeen ?? registryState?.LastSeen ?? "-",
                TargetMethod = registryState?.TargetingMethod ?? payload?.TargetMethod ?? string.Empty,
                ExitCode = payload?.ExitCode ?? string.Empty
            });
        }

        var ordered = ManagedAppInsights
            .Where(item => !string.IsNullOrWhiteSpace(item.AppGuid))
            .OrderByDescending(item => string.Equals(item.Status, "Fehler", StringComparison.OrdinalIgnoreCase))
            .ThenBy(item => item.AppName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        ManagedAppInsights.Clear();
        foreach (var insight in ordered)
        {
            ManagedAppInsights.Add(insight);
        }

        OnPropertyChanged(nameof(ImeHealthManagedAppsSummary));
    }

    private void RebuildIssueInsights()
    {
        ImeHealthIssueInsights.Clear();

        var pendingRestartSummary = GetPendingRestartSummary();
        var rebootPendingApp = ManagedAppInsights
            .FirstOrDefault(item => !string.IsNullOrWhiteSpace(item.RebootStatus) && !string.Equals(item.RebootStatus.Trim(), "clean", StringComparison.OrdinalIgnoreCase));
        ImeHealthIssueInsights.Add(new DeviceIssueInsight
        {
            Category = "Pending Restart",
            Summary = pendingRestartSummary,
            SourceLog = rebootPendingApp?.SourceLog ?? "-",
            LastSeen = rebootPendingApp?.LastSeen ?? "-"
        });

        var imeServiceStatusEntry = GetImeServiceStatusEntry();
        ImeHealthIssueInsights.Add(new DeviceIssueInsight
        {
            Category = "IME Service",
            Summary = GetImeServiceSummary(),
            SourceLog = "Dienste",
            LastSeen = imeServiceStatusEntry?.DisplayTimestamp ?? "-"
        });

        var enrollmentDashboardEntries = GetEnrollmentDashboardEntries();
        ImeHealthIssueInsights.Add(new DeviceIssueInsight
        {
            Category = "Enrollment / MDM",
            Summary = GetEnrollmentSummary(),
            SourceLog = ResolveLatestMatchingSource(enrollmentDashboardEntries, new[] { "error", "failed", "warn", "enroll", "mdm" }),
            LastSeen = ResolveLatestMatchingTimestamp(enrollmentDashboardEntries, new[] { "error", "failed", "warn", "enroll", "mdm" })
        });

        ImeHealthIssueInsights.Add(new DeviceIssueInsight
        {
            Category = "Remediation",
            Summary = GetRemediationSummary(),
            SourceLog = ResolveLatestMatchingSource(HealthScriptsEntries, new[] { "error", "failed", "warn", "remediation", "healthscript" }),
            LastSeen = ResolveLatestMatchingTimestamp(HealthScriptsEntries, new[] { "error", "failed", "warn", "remediation", "healthscript" })
        });

        var failedApps = ManagedAppInsights.Where(item => string.Equals(item.Status, "Fehler", StringComparison.OrdinalIgnoreCase)).Take(3).ToList();
        ImeHealthIssueInsights.Add(new DeviceIssueInsight
        {
            Category = "App Installationen",
            Summary = failedApps.Count == 0
                ? GetManagedAppsSummary()
                : string.Join(" | ", failedApps.Select(item => $"{item.AppName} ({item.AppGuid}): {item.ErrorHint}")),
            SourceLog = failedApps.FirstOrDefault()?.SourceLog ?? "-",
            LastSeen = failedApps.FirstOrDefault()?.LastSeen ?? "-"
        });
    }

    private string GetPendingRestartSummary()
    {
        if (ManagedAppInsights.Count == 0)
        {
            return LT("Nein | Noch keine installierten Intune-App-Daten für eine Reboot-Bewertung geladen.");
        }

        var pendingRebootApps = ManagedAppInsights
            .Where(item => !string.IsNullOrWhiteSpace(item.RebootStatus) && !string.Equals(item.RebootStatus.Trim(), "clean", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(item => string.Equals(item.Status, "Fehler", StringComparison.OrdinalIgnoreCase))
            .ThenBy(item => item.AppName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (pendingRebootApps.Count == 0)
        {
            return LT("Nein | Gemäss RebootStatus der installierten Intune-Apps ist kein Reboot erforderlich.");
        }

        var appSummary = string.Join(", ", pendingRebootApps.Take(3).Select(item => $"{item.AppName} ({item.RebootStatus})"));
        var moreSuffix = pendingRebootApps.Count > 3 ? $" +{pendingRebootApps.Count - 3} weitere" : string.Empty;
        return LT($"Ja | Reboot erforderlich. Betroffene Intune-Apps: {appSummary}{moreSuffix}");
    }

    private string GetManagedAppsSummary()
    {
        if (ManagedAppInsights.Count == 0)
        {
            return LT("Noch keine Intune-App-Installationshinweise aus den geladenen Logs extrahiert.");
        }

        var failed = ManagedAppInsights.Count(item => string.Equals(item.Status, "Fehler", StringComparison.OrdinalIgnoreCase));
        var installed = ManagedAppInsights.Count(item => string.Equals(item.Status, "Installiert", StringComparison.OrdinalIgnoreCase));
        var pending = ManagedAppInsights.Count(item => string.Equals(item.Status, "Pending", StringComparison.OrdinalIgnoreCase) || string.Equals(item.Status, "In Bearbeitung", StringComparison.OrdinalIgnoreCase));
        return LT($"Intune Apps | Total: {ManagedAppInsights.Count} | Installiert: {installed} | Fehler: {failed} | Pending: {pending}");
    }

    private string GetImeServiceSummary()
    {
        var serviceStatusEntry = GetImeServiceStatusEntry();
        if (serviceStatusEntry is null)
        {
            return LT("Noch kein IME-Service-Status aus der Geräteabfrage verfügbar.");
        }

        var message = serviceStatusEntry.Message ?? string.Empty;
        var status = ExtractPayloadValue(message, new[] { "Status", "status" });
        var startType = ExtractPayloadValue(message, new[] { "StartType", "startType" });
        var serviceName = ExtractPayloadValue(message, new[] { "ServiceName", "serviceName" });
        var displayName = ExtractPayloadValue(message, new[] { "DisplayName", "displayName" });
        var resolvedLabel = !string.IsNullOrWhiteSpace(displayName)
            ? displayName
            : (!string.IsNullOrWhiteSpace(serviceName) ? serviceName : (_config.ImeServiceName ?? "IntuneManagementExtension"));

        if (string.IsNullOrWhiteSpace(status))
        {
            return LT($"Unbekannt | Dienststatus für {resolvedLabel} konnte nicht bestimmt werden.");
        }

        var normalizedStatus = status.Trim();
        var prefix = string.Equals(normalizedStatus, "Running", StringComparison.OrdinalIgnoreCase)
            ? "Läuft"
            : "Fehler";

        var summary = $"{prefix} | {resolvedLabel}: {normalizedStatus}";
        if (!string.IsNullOrWhiteSpace(startType))
        {
            summary += $" | Starttyp: {startType.Trim()}";
        }

        return LT(summary);
    }

    private LogEntry? GetImeServiceStatusEntry()
    {
        var configuredServiceName = string.IsNullOrWhiteSpace(_config.ImeServiceName)
            ? "IntuneManagementExtension"
            : _config.ImeServiceName.Trim();

        return EventLogChannelEntries
            .Where(entry => !string.IsNullOrWhiteSpace(entry.Message)
                && (entry.Message.Contains("[Services]", StringComparison.OrdinalIgnoreCase)
                    || entry.Message.Contains($"ServiceName={configuredServiceName}", StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(entry => entry.Timestamp)
            .ThenByDescending(entry => entry.DisplayTimestamp)
            .FirstOrDefault();
    }

    private IReadOnlyList<LogEntry> GetEnrollmentDashboardEntries()
    {
        return EnrollmentEntries
            .Concat(EventLogChannelEntries)
            .Where(entry => !IsImeServiceStatusEntry(entry))
            .ToList();
    }

    private bool IsImeServiceStatusEntry(LogEntry? entry)
    {
        if (entry is null || string.IsNullOrWhiteSpace(entry.Message))
        {
            return false;
        }

        var configuredServiceName = string.IsNullOrWhiteSpace(_config.ImeServiceName)
            ? "IntuneManagementExtension"
            : _config.ImeServiceName.Trim();

        return entry.Message.Contains("[Services]", StringComparison.OrdinalIgnoreCase)
            || entry.Message.Contains($"ServiceName={configuredServiceName}", StringComparison.OrdinalIgnoreCase);
    }

    private string GetEnrollmentSummary()
    {
        var combined = GetEnrollmentDashboardEntries();
        if (combined.Count == 0)
        {
            return LT("Noch keine Enrollment- oder Event-Log-Hinweise geladen.");
        }

        var errors = combined.Count(entry => entry.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase));
        var warnings = combined.Count(entry => entry.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase));
        var latest = combined
            .Where(entry => entry.Timestamp != DateTime.MinValue)
            .OrderByDescending(entry => entry.Timestamp)
            .FirstOrDefault();

        return latest is null
            ? LT($"Einträge: {combined.Count} | Fehler: {errors} | Warnungen: {warnings}")
            : LT($"Einträge: {combined.Count} | Fehler: {errors} | Warnungen: {warnings} | Letzter Hinweis: {latest.DisplayTimestamp} | {latest.SourceFile}");
    }

    private string GetRemediationSummary()
    {
        var healthScriptEntries = HealthScriptsEntries.ToList();
        if (healthScriptEntries.Count == 0)
        {
            return LT("Noch keine HealthScripts.log-Hinweise geladen.");
        }

        var errors = healthScriptEntries.Count(entry => entry.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase));
        var warnings = healthScriptEntries.Count(entry => entry.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase));
        var latest = healthScriptEntries
            .Where(entry => entry.Timestamp != DateTime.MinValue)
            .OrderByDescending(entry => entry.Timestamp)
            .FirstOrDefault();

        return latest is null
            ? LT($"Einträge: {healthScriptEntries.Count} | Fehler: {errors} | Warnungen: {warnings}")
            : LT($"Einträge: {healthScriptEntries.Count} | Fehler: {errors} | Warnungen: {warnings} | Letzter Hinweis: {latest.DisplayTimestamp} | {latest.SourceFile}");
    }

    private string GetIssueSummary()
    {
        var totalErrors = GetSeverityCount(GetRemoteLogEntries(), "Error");
        var totalWarnings = GetSeverityCount(GetRemoteLogEntries(), "Warning");
        var appFailures = ManagedAppInsights.Count(item => string.Equals(item.Status, "Fehler", StringComparison.OrdinalIgnoreCase));
        return LT($"Remote-Gesamtfehler: {totalErrors} | Remote-Gesamtwarnungen: {totalWarnings} | Auffällige App-Installationen: {appFailures}");
    }

    private static string GetLogCollectionSummary(string label, IEnumerable<LogEntry> entries)
    {
        var list = entries.ToList();
        if (list.Count == 0)
        {
            return LT($"{label}: Noch keine Daten geladen.");
        }

        var latest = list.Where(entry => entry.Timestamp != DateTime.MinValue).OrderByDescending(entry => entry.Timestamp).FirstOrDefault();
        var errorCount = list.Count(entry => entry.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase));
        var warningCount = list.Count(entry => entry.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase));
        return latest is null
            ? LT($"{label}: {list.Count} Einträge | Fehler: {errorCount} | Warnungen: {warningCount}")
            : LT($"{label}: {list.Count} Einträge | Fehler: {errorCount} | Warnungen: {warningCount} | Letzter Hinweis: {latest.DisplayTimestamp}");
    }

    private static bool ContainsAny(string? message, IEnumerable<string> keywords)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return false;
        }

        foreach (var keyword in keywords)
        {
            if (message.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string ResolveLatestMatchingSource(IEnumerable<LogEntry> entries, IEnumerable<string> keywords)
        => entries.Where(entry => ContainsAny(entry.Message, keywords))
            .OrderByDescending(entry => entry.Timestamp)
            .Select(entry => entry.SourceFile)
            .FirstOrDefault() ?? "-";

    private static string ResolveLatestMatchingTimestamp(IEnumerable<LogEntry> entries, IEnumerable<string> keywords)
        => entries.Where(entry => ContainsAny(entry.Message, keywords))
            .OrderByDescending(entry => entry.Timestamp)
            .Select(entry => entry.DisplayTimestamp)
            .FirstOrDefault() ?? "-";


    private static HashSet<string> ExtractGrsAppGuids(IEnumerable<LogEntry> entries)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (!IsGrsRelatedEntry(entry))
            {
                continue;
            }

            foreach (Match match in GuidRegex.Matches(entry.Message ?? string.Empty))
            {
                if (match.Success)
                {
                    result.Add(match.Value);
                }
            }
        }

        return result;
    }

    private static HashSet<string> ExtractRegistryAppGuids(IEnumerable<LogEntry> entries)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            var message = entry.Message ?? string.Empty;
            if (string.IsNullOrWhiteSpace(message))
            {
                continue;
            }

            var appGuid = ExtractPayloadValue(message, new[] { "AppGuid", "appGuid" });
            if (GuidRegex.IsMatch(appGuid))
            {
                result.Add(appGuid);
            }
        }

        return result;
    }

    private sealed class AppWorkloadMetadata
    {
        public string AppGuid { get; set; } = string.Empty;
        public string AppName { get; set; } = string.Empty;
        public string PackageId { get; set; } = string.Empty;
    }

    private sealed class InventoryAppMetadata
    {
        public string AppGuid { get; set; } = string.Empty;
        public string AppName { get; set; } = string.Empty;
        public string ProductVersion { get; set; } = string.Empty;
    }

    private static Dictionary<string, AppWorkloadMetadata> ExtractAppWorkloadMetadataMap(IEnumerable<LogEntry> entries)
    {
        var result = new Dictionary<string, AppWorkloadMetadata>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries.OrderByDescending(item => item.Timestamp))
        {
            var message = entry.Message ?? string.Empty;
            if (string.IsNullOrWhiteSpace(message))
            {
                continue;
            }

            foreach (var metadata in ParsePolicyPayloadMetadata(message))
            {
                if (!GuidRegex.IsMatch(metadata.AppGuid))
                {
                    continue;
                }

                if (!result.TryGetValue(metadata.AppGuid, out var existing))
                {
                    result[metadata.AppGuid] = metadata;
                    continue;
                }

                if (!IsMeaningfulAppName(existing.AppName) && IsMeaningfulAppName(metadata.AppName))
                {
                    existing.AppName = metadata.AppName;
                }

                if (!IsMeaningfulPackageId(existing.PackageId) && IsMeaningfulPackageId(metadata.PackageId))
                {
                    existing.PackageId = metadata.PackageId;
                }
            }

            foreach (Match match in Regex.Matches(message, @"(?is)app with id:\s*(?<id>[0-9a-fA-F-]{36})\s+and package id:\s*(?<pkg>[A-Za-z0-9._-]{3,100})"))
            {
                if (!match.Success)
                {
                    continue;
                }

                var appGuid = match.Groups["id"].Value;
                var packageId = NormalizePayloadValue(match.Groups["pkg"].Value);
                if (!GuidRegex.IsMatch(appGuid) || !IsMeaningfulPackageId(packageId))
                {
                    continue;
                }

                if (!result.TryGetValue(appGuid, out var existing))
                {
                    existing = new AppWorkloadMetadata { AppGuid = appGuid };
                    result[appGuid] = existing;
                }

                if (!IsMeaningfulPackageId(existing.PackageId))
                {
                    existing.PackageId = packageId;
                }
            }
        }

        return result;
    }

    private static List<AppWorkloadMetadata> ParsePolicyPayloadMetadata(string message)
    {
        var result = new List<AppWorkloadMetadata>();
        if (!ContainsAny(message, new[] { "get policies" }))
        {
            return result;
        }

        var arrayStart = message.IndexOf('[');
        var arrayEnd = message.LastIndexOf(']');
        if (arrayStart < 0 || arrayEnd <= arrayStart)
        {
            return result;
        }

        var candidateJson = message[arrayStart..(arrayEnd + 1)];
        try
        {
            using var document = JsonDocument.Parse(candidateJson);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return result;
            }

            foreach (var element in document.RootElement.EnumerateArray())
            {
                var appGuid = NormalizePayloadValue(GetJsonStringProperty(element, "Id"));
                if (!GuidRegex.IsMatch(appGuid))
                {
                    continue;
                }

                result.Add(new AppWorkloadMetadata
                {
                    AppGuid = appGuid,
                    AppName = NormalizeAppNameCandidate(GetJsonStringProperty(element, "Name")),
                    PackageId = ExtractPackageIdFromPolicyElement(element)
                });
            }
        }
        catch (JsonException)
        {
            return result;
        }

        return result;
    }

    private static string GetJsonStringProperty(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property))
        {
            return string.Empty;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String => property.GetString() ?? string.Empty,
            JsonValueKind.Number => property.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => string.Empty
        };
    }

    private static string ExtractPackageIdFromPolicyElement(JsonElement element)
    {
        if (!element.TryGetProperty("InstallerData", out var installerDataElement))
        {
            return string.Empty;
        }

        try
        {
            if (installerDataElement.ValueKind == JsonValueKind.String)
            {
                var installerData = installerDataElement.GetString();
                if (string.IsNullOrWhiteSpace(installerData))
                {
                    return string.Empty;
                }

                using var installerDocument = JsonDocument.Parse(installerData);
                return NormalizePayloadValue(GetJsonStringProperty(installerDocument.RootElement, "PackageIdentifier"));
            }

            if (installerDataElement.ValueKind == JsonValueKind.Object)
            {
                return NormalizePayloadValue(GetJsonStringProperty(installerDataElement, "PackageIdentifier"));
            }
        }
        catch (JsonException)
        {
            return string.Empty;
        }

        return string.Empty;
    }

    private static bool IsGrsRelatedEntry(LogEntry entry)
    {
        if (ContainsAny(entry.Message, new[] { "grs", "global retry schedule" }))
        {
            return true;
        }

        return entry.SourceFile.Contains("GRS", StringComparison.OrdinalIgnoreCase);
    }

    private IEnumerable<LogEntry> GetManagedAppLogEntries()
    {
        return AppWorkloadEntries
            .Concat(IntuneManagementExtensionEntries)
            .Concat(AgentExecutorEntries)
            .Concat(AppActionProcessorEntries)
            .Concat(Win321AppInventoryEntries)
            .OrderByDescending(entry => entry.Timestamp);
    }

    private static Dictionary<string, RegistryAppStateSnapshot> ExtractLatestRegistryStateMap(IEnumerable<LogEntry> entries, IEnumerable<string> appGuids)
    {
        var guidSet = new HashSet<string>(appGuids, StringComparer.OrdinalIgnoreCase);
        var result = new Dictionary<string, RegistryAppStateSnapshot>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries.OrderByDescending(item => item.Timestamp))
        {
            var message = entry.Message ?? string.Empty;
            if (string.IsNullOrWhiteSpace(message))
            {
                continue;
            }

            var appGuid = ExtractPayloadValue(message, new[] { "AppGuid", "appGuid" });
            if (!GuidRegex.IsMatch(appGuid) || !guidSet.Contains(appGuid) || result.ContainsKey(appGuid))
            {
                continue;
            }

            var enforcementMessage = NormalizeStateField(ExtractRegistryTopLevelValue(message, new[] { "EnforcementStateMessage", "enforcementStateMessage" }));
            var complianceMessage = NormalizeStateField(ExtractRegistryTopLevelValue(message, new[] { "ComplianceStateMessage", "complianceStateMessage" }));
            var rebootStatus = NormalizeStateField(ExtractRegistryTopLevelValue(message, new[] { "RebootStatus", "rebootStatus" }));
            var rebootReason = NormalizeStateField(ExtractRegistryTopLevelValue(message, new[] { "RebootReason", "rebootReason" }));
            var userTargetingGuid = NormalizeStateField(ExtractRegistryTopLevelValue(message, new[] { "UserTargetingId", "userTargetingId", "UserTargetingGuid", "userTargetingGuid" }));
            var computerId = NormalizeStateField(ExtractRegistryTopLevelValue(message, new[] { "ComputerId", "computerId" }));
            var targetingMethod = NormalizeStateField(ExtractRegistryTopLevelValue(message, new[] { "TargetingMethod", "targetingMethod" }));
            var hasGrsFailure = string.Equals(NormalizeStateField(ExtractRegistryTopLevelValue(message, new[] { "HasGrsFailure", "hasGrsFailure" })), "true", StringComparison.OrdinalIgnoreCase);
            var errorCodeHex = ExtractStateErrorCodeHex(complianceMessage, enforcementMessage);
            var productVersion = NormalizeStateField(ExtractRegistryTopLevelValue(message, new[] { "ProductVersion", "productVersion" }));
            if (string.IsNullOrWhiteSpace(productVersion))
            {
                productVersion = ExtractProductVersionFromStateMessage(complianceMessage);
            }

            var complianceState = MapComplianceState(ExtractNumericStateValue(complianceMessage, "complianceState"));
            var applicability = MapApplicability(ExtractNumericStateValue(complianceMessage, "applicability"));
            var desiredState = MapDesiredState(ExtractNumericStateValue(complianceMessage, "desiredState"));
            var enforcementState = MapEnforcementState(ExtractNumericStateValue(complianceMessage, "enforcementState"));
            var installContext = MapInstallContext(ExtractNumericStateValue(complianceMessage, "installContext"));
            var targetType = MapTargetType(ExtractNumericStateValue(complianceMessage, "targetType"));

            if (string.IsNullOrWhiteSpace(rebootStatus))
            {
                rebootStatus = ExtractStateMessageValue(complianceMessage, new[] { "RebootStatus", "rebootStatus" });
                if (string.IsNullOrWhiteSpace(rebootStatus))
                {
                    rebootStatus = ExtractStateMessageValue(enforcementMessage, new[] { "RebootStatus", "rebootStatus" });
                }
            }

            if (string.IsNullOrWhiteSpace(rebootReason))
            {
                rebootReason = ExtractStateMessageValue(complianceMessage, new[] { "RebootReason", "rebootReason" });
                if (string.IsNullOrWhiteSpace(rebootReason))
                {
                    rebootReason = ExtractStateMessageValue(enforcementMessage, new[] { "RebootReason", "rebootReason" });
                }
            }

            if (string.IsNullOrWhiteSpace(targetingMethod))
            {
                targetingMethod = string.Equals(computerId, userTargetingGuid, StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(userTargetingGuid)
                    ? "Device"
                    : "User";
            }

            if (string.IsNullOrWhiteSpace(errorCodeHex)
                && string.IsNullOrWhiteSpace(complianceMessage)
                && string.IsNullOrWhiteSpace(enforcementMessage)
                && string.IsNullOrWhiteSpace(rebootStatus)
                && string.IsNullOrWhiteSpace(rebootReason)
                && string.IsNullOrWhiteSpace(complianceState)
                && string.IsNullOrWhiteSpace(applicability)
                && string.IsNullOrWhiteSpace(desiredState)
                && string.IsNullOrWhiteSpace(enforcementState)
                && string.IsNullOrWhiteSpace(installContext)
                && string.IsNullOrWhiteSpace(targetType)
                && !hasGrsFailure)
            {
                continue;
            }

            result[appGuid] = new RegistryAppStateSnapshot
            {
                AppGuid = appGuid,
                ComputerId = computerId,
                UserTargetingGuid = userTargetingGuid,
                TargetingMethod = targetingMethod,
                HasGrsFailure = hasGrsFailure,
                ErrorCodeHex = errorCodeHex,
                ComplianceState = complianceState,
                Applicability = applicability,
                DesiredState = desiredState,
                EnforcementState = enforcementState,
                InstallContext = installContext,
                TargetType = targetType,
                ComplianceStateMessage = complianceMessage,
                EnforcementStateMessage = enforcementMessage,
                ProductVersion = productVersion,
                RebootStatus = rebootStatus,
                RebootReason = rebootReason,
                SourceLog = entry.SourceFile,
                LastSeen = entry.DisplayTimestamp,
                SourceEntry = entry
            };
        }

        return result;
    }

    private static Dictionary<string, InventoryAppMetadata> ExtractInventoryMetadataMap(IEnumerable<LogEntry> entries, IEnumerable<string> appGuids)
    {
        var guidSet = new HashSet<string>(appGuids, StringComparer.OrdinalIgnoreCase);
        var result = new Dictionary<string, InventoryAppMetadata>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries.OrderByDescending(item => item.Timestamp))
        {
            var message = entry.Message ?? string.Empty;
            if (string.IsNullOrWhiteSpace(message))
            {
                continue;
            }

            foreach (Match match in GuidRegex.Matches(message))
            {
                if (!match.Success || !guidSet.Contains(match.Value))
                {
                    continue;
                }

                var appGuid = match.Value;
                if (!result.TryGetValue(appGuid, out var metadata))
                {
                    metadata = new InventoryAppMetadata { AppGuid = appGuid };
                    result[appGuid] = metadata;
                }

                if (!IsMeaningfulAppName(metadata.AppName))
                {
                    var name = NormalizeAppNameCandidate(ExtractPayloadValue(message, new[] { "Name", "name", "AppName", "appName", "DisplayName", "displayName", "ProductName", "productName" }));
                    if (!IsMeaningfulAppName(name))
                    {
                        foreach (var pattern in new[]
                                 {
                                     @"(?is)\b(?:display name|app name|product name|name)\b\s*[:=]\s*""?(?<value>[^"";,\r\n\]]{2,180})",
                                     @"(?is)""Name""\s*:\s*""(?<value>(?:\.|[^""])*)"""
                                 })
                        {
                            var nameMatch = Regex.Match(message, pattern);
                            if (nameMatch.Success)
                            {
                                name = NormalizeAppNameCandidate(nameMatch.Groups["value"].Value);
                                if (IsMeaningfulAppName(name))
                                {
                                    break;
                                }
                            }
                        }
                    }

                    if (IsMeaningfulAppName(name))
                    {
                        metadata.AppName = name;
                    }
                }

                if (string.IsNullOrWhiteSpace(metadata.ProductVersion))
                {
                    var version = ExtractPayloadValue(message, new[] { "ProductVersion", "productVersion", "InternalVersion", "internalVersion", "Version", "version" });
                    if (string.IsNullOrWhiteSpace(version))
                    {
                        var versionMatch = Regex.Match(message, @"(?is)\b(?:product version|internal version|version)\b\s*[:=]\s*(?<value>[A-Za-z0-9._-]{1,40})");
                        if (versionMatch.Success)
                        {
                            version = NormalizePayloadValue(versionMatch.Groups["value"].Value);
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(version))
                    {
                        metadata.ProductVersion = version;
                    }
                }
            }
        }

        return result;
    }

    private bool HasInstalledCimEvidence(string appGuid)
    {
        if (_cimResolvedInstalledGuids.Contains(appGuid))
        {
            return true;
        }

        return _appNameCache.TryGetValue(appGuid, out var cachedEntry)
               && IsMeaningfulAppName(cachedEntry.PackageName)
               && !IsMeaningfulPackageId(cachedEntry.PackageId);
    }

    private bool HasAppEvidence(string appGuid, string resolvedName, string packageId, string? inventoryVersion, AppPayloadSnapshot? payload, RegistryAppStateSnapshot? registryState, LogEntry? latestErrorEntry, LogEntry? latestRelevantEntry)
    {
        if (HasInstalledCimEvidence(appGuid))
        {
            return true;
        }

        if (IsMeaningfulAppName(resolvedName) || IsMeaningfulPackageId(packageId) || !string.IsNullOrWhiteSpace(inventoryVersion))
        {
            return true;
        }

        if (payload is not null)
        {
            return true;
        }

        if (registryState is not null)
        {
            return true;
        }

        if (latestErrorEntry is not null)
        {
            return true;
        }

        return latestRelevantEntry is not null && ContainsAny(latestRelevantEntry.Message, new[] { "app with id", "package id", "detected app" });
    }

    private static string ResolveManagedAppStatus(RegistryAppStateSnapshot? registryState, bool hasCimInstallEvidence, bool hasErrorCode)
    {
        if (!string.IsNullOrWhiteSpace(registryState?.ComplianceState))
        {
            return registryState.ComplianceState;
        }

        if (hasCimInstallEvidence)
        {
            return "Installiert";
        }

        if (hasErrorCode || registryState?.HasGrsFailure == true)
        {
            return "Fehler";
        }

        return "Unbekannt";
    }

    private static string ConvertDecimalErrorCodeToHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = NormalizePayloadValue(value);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return string.Empty;
        }

        var hexMatch = Regex.Match(normalized, @"0x[0-9a-fA-F]+");
        if (hexMatch.Success)
        {
            var candidateHex = hexMatch.Value.ToUpperInvariant();
            return string.Equals(candidateHex, "0x00000000", StringComparison.OrdinalIgnoreCase) ? string.Empty : candidateHex;
        }

        var decimalMatch = Regex.Match(normalized, @"^-?\d+$");
        if (!decimalMatch.Success)
        {
            return string.Empty;
        }

        if (!long.TryParse(decimalMatch.Value, out var numericValue) || numericValue == 0)
        {
            return string.Empty;
        }

        return numericValue >= 0
            ? $"0x{numericValue:X8}"
            : $"0x{unchecked((uint)numericValue):X8}";
    }

    private static string NormalizeStateField(string? value)
    {
        var normalized = NormalizePayloadValue(value);
        if (string.IsNullOrWhiteSpace(normalized)
            || string.Equals(normalized, "null", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalized, "none", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalized, "n/a", StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        return normalized;
    }

    private static string ExtractStateErrorCodeHex(string? complianceMessage, string? enforcementMessage)
    {
        foreach (var candidateMessage in new[] { enforcementMessage, complianceMessage })
        {
            var normalized = NormalizeStateField(candidateMessage);
            if (string.IsNullOrWhiteSpace(normalized))
            {
                continue;
            }

            var jsonValue = ExtractStateMessageValue(normalized, new[] { "ErrorCode", "errorCode", "ReturnCode", "returnCode", "Code", "code" });
            var jsonConverted = ConvertDecimalErrorCodeToHex(jsonValue);
            if (!string.IsNullOrWhiteSpace(jsonConverted))
            {
                return jsonConverted;
            }

            var hexMatch = Regex.Match(normalized, @"0x[0-9a-fA-F]+");
            if (hexMatch.Success)
            {
                return hexMatch.Value.ToUpperInvariant();
            }

            foreach (var pattern in new[]
                     {
                         @"(?is)\b(?:errorcode|error code)\b\s*[:=]?\s*(?<value>-?\d+)",
                         @"(?is)\b(?:returncode|return code|code)\b\s*[:=]?\s*(?<value>-?\d+)"
                     })
            {
                var match = Regex.Match(normalized, pattern);
                if (match.Success)
                {
                    var converted = ConvertDecimalErrorCodeToHex(match.Groups["value"].Value);
                    if (!string.IsNullOrWhiteSpace(converted))
                    {
                        return converted;
                    }
                }
            }

            var direct = ConvertDecimalErrorCodeToHex(normalized);
            if (!string.IsNullOrWhiteSpace(direct))
            {
                return direct;
            }
        }

        return string.Empty;
    }

    private static string ExtractProductVersionFromStateMessage(string? complianceMessage)
    {
        var normalized = NormalizeStateField(complianceMessage);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return string.Empty;
        }

        var jsonValue = ExtractStateMessageValue(normalized, new[] { "ProductVersion", "productVersion", "Version", "version" });
        if (!string.IsNullOrWhiteSpace(jsonValue))
        {
            return jsonValue;
        }

        foreach (var pattern in new[]
                 {
                     @"(?is)\bProductVersion\b\s*[:=]\s*""?(?<value>[A-Za-z0-9._-]{1,40})",
                     @"(?is)\bVersion\b\s*[:=]\s*""?(?<value>[A-Za-z0-9._-]{1,40})"
                 })
        {
            var match = Regex.Match(normalized, pattern);
            if (match.Success)
            {
                return NormalizePayloadValue(match.Groups["value"].Value);
            }
        }

        return string.Empty;
    }

    private static string ExtractStateMessageValue(string? message, IEnumerable<string> keys)
    {
        var normalized = NormalizeStateField(message);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return string.Empty;
        }

        if (TryParseJsonDocument(normalized, out var document) && document is not null)
        {
            using (document)
            {
                if (document.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var key in keys)
                    {
                        if (string.IsNullOrWhiteSpace(key))
                        {
                            continue;
                        }

                        if (TryGetJsonPropertyIgnoreCase(document.RootElement, key, out var valueElement))
                        {
                            var candidate = NormalizeJsonElementValue(valueElement);
                            if (!string.IsNullOrWhiteSpace(candidate))
                            {
                                return candidate;
                            }
                        }
                    }
                }
            }
        }

        return ExtractPayloadValue(normalized, keys);
    }

    private static int? ExtractNumericStateValue(string? message, string key)
    {
        var normalized = NormalizeStateField(message);
        if (string.IsNullOrWhiteSpace(normalized) || string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        if (TryParseJsonDocument(normalized, out var document) && document is not null)
        {
            using (document)
            {
                if (document.RootElement.ValueKind == JsonValueKind.Object
                    && TryGetJsonPropertyIgnoreCase(document.RootElement, key, out var valueElement))
                {
                    if (TryGetJsonInt32Value(valueElement, out var numericFromJson))
                    {
                        return numericFromJson;
                    }

                    return null;
                }
            }
        }

        var value = ExtractPayloadValue(normalized, new[] { key });
        if (string.IsNullOrWhiteSpace(value) || string.Equals(value, "null", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return int.TryParse(value, out var numericValue) ? numericValue : null;
    }

    private static bool TryParseJsonDocument(string message, out JsonDocument? document)
    {
        try
        {
            document = JsonDocument.Parse(message);
            return true;
        }
        catch
        {
            document = null;
            return false;
        }
    }

    private static bool TryGetJsonPropertyIgnoreCase(JsonElement element, string propertyName, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private static string NormalizeJsonElementValue(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => NormalizePayloadValue(element.GetString()),
            JsonValueKind.Number => NormalizePayloadValue(element.GetRawText()),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null or JsonValueKind.Undefined => string.Empty,
            _ => NormalizePayloadValue(element.GetRawText())
        };
    }

    private static bool TryGetJsonInt32Value(JsonElement element, out int value)
    {
        if (element.ValueKind == JsonValueKind.Number)
        {
            return element.TryGetInt32(out value);
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            return int.TryParse(element.GetString(), out value);
        }

        value = default;
        return false;
    }

    private static string MapComplianceState(int? value) => value switch
    {
        1 => "Installiert",
        2 => "Nicht installiert",
        4 => "Fehler",
        5 => "Unbekannt",
        100 => "Cleanup",
        _ => string.Empty
    };

    private static string MapApplicability(int? value) => value switch
    {
        0 => "Applicable",
        1 => "RequirementsNotMet",
        3 => "HostPlatformNotApplicable",
        1000 => "ProcessorArchitectureNotApplicable",
        1001 => "MinimumDiskSpaceNotMet",
        1002 => "MinimumOSVersionNotMet",
        1003 => "MinimumPhysicalMemoryNotMet",
        1004 => "MinimumLogicalProcessorCountNotMet",
        1005 => "MinimumCPUSpeedNotMet",
        1006 => "FileSystemRequirementRuleNotMet",
        1007 => "RegistryRequirementRuleNotMet",
        1008 => "ScriptRequirementRuleNotMet",
        1009 => "NotTargetedAndSupersedingAppsNotApplicable",
        1010 => "AssignmentFiltersCriteriaNotMet",
        1011 => "AppUnsupportedDueToUnknownReason",
        1012 => "UserContextAppNotSupportedDuringDeviceOnlyCheckin",
        2000 => "COSUMinimumApiLevelNotMet",
        2001 => "COSUManagementMode",
        2002 => "COSUUnsupported",
        2003 => "COSUAppIncompatible",
        _ => string.Empty
    };

    private static string MapDesiredState(int? value) => value switch
    {
        0 => "None",
        1 => "Not Present",
        2 => "Present",
        3 => "Unknown",
        4 => "Available",
        _ => string.Empty
    };


    private static string MapInstallContext(int? value) => value switch
    {
        1 => "User",
        2 => "System",
        _ => string.Empty
    };

    private static string MapTargetType(int? value) => value switch
    {
        0 => "Unknown",
        1 => "User",
        2 => "Device",
        _ => string.Empty
    };

    private static string MapEnforcementState(int? value) => value switch
    {
        1000 => "Success",
        1003 => "SuccessFastNotify",
        1004 => "SuccessButDependencyFailedToInstall",
        1005 => "SuccessButDependencyWithRequirementsNotMet",
        1006 => "SuccessButDependencyPendingReboot",
        1007 => "SuccessButDependencyWithAutoInstallOff",
        1008 => "SuccessButIOSAppStoreUpdateFailedToInstall",
        1009 => "SuccessVPPAppHasUpdateAvailable",
        1010 => "SuccessButUserRejectedUpdate",
        1011 => "SuccessUninstallPendingReboot",
        1012 => "SuccessSupersededAppUninstallFailed",
        1013 => "SuccessSupersededAppUninstallPendingReboot",
        1014 => "SuccessSupersedingAppsDetected",
        1015 => "SuccessSupersededAppsDetected",
        1016 => "SuccessAppRemovedBySupersedence",
        1017 => "SuccessButDependencyBlockedByManagedInstallerPolicy",
        1018 => "SuccessUninstallingSupersededApps",
        2000 => "InProgress",
        2007 => "InProgressDependencyInstalling",
        2008 => "InProgressPendingReboot",
        2009 => "InProgressDownloadCompleted",
        2010 => "InProgressPendingUninstallOfSupersededApps",
        2011 => "InProgressUninstallPendingReboot",
        2012 => "InProgressPendingManagedInstaller",
        3000 => "RequirementsNotMet",
        4000 => "Unknown",
        5000 => "Error",
        5003 => "ErrorDownloadingContent",
        5006 => "ErrorConflictsPreventInstallation",
        5015 => "ErrorManagedInstallerAppLockerPolicyNotApplied",
        5999 => "ErrorWithImmeadiateRetry",
        6000 => "NotAttempted",
        6001 => "NotAttemptedDependencyWithFailure",
        6002 => "NotAttemptedPendingReboot",
        6003 => "NotAttemptedDependencyWithRequirementsNotMet",
        6004 => "NotAttemptedAutoInstallOff",
        6005 => "NotAttemptedDependencyWithAutoInstallOff",
        6006 => "NotAttemptedWithManagedAppNoLongerPresent",
        6007 => "NotAttemptedBecauseUserRejectedInstall",
        6008 => "NotAttemptedBecauseUserIsNotLoggedIntoAppStore",
        6009 => "NotAttemptedSupersededAppUninstallFailed",
        6010 => "NotAttemptedSupersededAppUninstallPendingReboot",
        6011 => "NotAttemptedUntargetedSupersedingAppsDetected",
        6012 => "NotAttemptedDependencyBlockedByManagedInstallerPolicy",
        6013 => "NotAttemptedUnsupportedOrIndeterminateSupersededApp",
        _ => string.Empty
    };

    private string ResolveAppDisplayName(string appGuid, IReadOnlyDictionary<string, InventoryAppMetadata> inventoryMetadataMap, IReadOnlyDictionary<string, AppWorkloadMetadata> appWorkloadMetadataMap)
    {
        if (_appNameCache.TryGetValue(appGuid, out var cachedEntry) && IsMeaningfulAppName(cachedEntry.PackageName))
        {
            return cachedEntry.PackageName;
        }

        if (inventoryMetadataMap.TryGetValue(appGuid, out var inventoryMetadata) && IsMeaningfulAppName(inventoryMetadata.AppName))
        {
            return inventoryMetadata.AppName;
        }

        if (appWorkloadMetadataMap.TryGetValue(appGuid, out var metadata) && IsMeaningfulAppName(metadata.AppName))
        {
            return metadata.AppName;
        }

        return "App-Name nicht aufgelöst";
    }

    private string ResolveAppPackageId(string appGuid, AppPayloadSnapshot? payload, IReadOnlyDictionary<string, AppWorkloadMetadata> appWorkloadMetadataMap)
    {
        if (_appNameCache.TryGetValue(appGuid, out var cachedEntry) && IsMeaningfulPackageId(cachedEntry.PackageId))
        {
            return NormalizePackageIdValue(cachedEntry.PackageId);
        }

        if (!string.IsNullOrWhiteSpace(payload?.PackageId) && IsMeaningfulPackageId(payload.PackageId))
        {
            return NormalizePackageIdValue(payload.PackageId);
        }

        if (appWorkloadMetadataMap.TryGetValue(appGuid, out var metadata) && IsMeaningfulPackageId(metadata.PackageId))
        {
            return NormalizePackageIdValue(metadata.PackageId);
        }

        return string.Empty;
    }

    private void MergeResolvedAppMetadataIntoCache(IReadOnlyDictionary<string, InventoryAppMetadata> inventoryMetadataMap, IReadOnlyDictionary<string, AppWorkloadMetadata> appWorkloadMetadataMap)
    {
        var changed = false;
        foreach (var item in inventoryMetadataMap)
        {
            appWorkloadMetadataMap.TryGetValue(item.Key, out var workloadMetadata);
            changed |= UpsertAppNameCacheEntry(item.Key, workloadMetadata?.PackageId, item.Value.AppName);
        }

        foreach (var item in appWorkloadMetadataMap)
        {
            changed |= UpsertAppNameCacheEntry(item.Key, item.Value.PackageId, item.Value.AppName);
        }

        if (changed)
        {
            SaveAppNameCache();
        }
    }

    private bool UpsertAppNameCacheEntry(string appGuid, string? packageId, string? packageName)
    {
        if (!GuidRegex.IsMatch(appGuid))
        {
            return false;
        }

        var normalizedName = NormalizeAppNameCandidate(packageName);
        var normalizedPackageId = NormalizePackageIdValue(packageId);
        if (!IsMeaningfulAppName(normalizedName) && !IsMeaningfulPackageId(normalizedPackageId))
        {
            return false;
        }

        if (!_appNameCache.TryGetValue(appGuid, out var existing))
        {
            _appNameCache[appGuid] = new AppNameCacheEntry
            {
                AppGuid = appGuid,
                PackageId = IsMeaningfulPackageId(normalizedPackageId) ? normalizedPackageId : string.Empty,
                PackageName = IsMeaningfulAppName(normalizedName) ? normalizedName : string.Empty
            };
            return true;
        }

        var changed = false;
        if (IsMeaningfulPackageId(normalizedPackageId)
            && (!IsMeaningfulPackageId(existing.PackageId) || GetPackageIdQuality(normalizedPackageId) > GetPackageIdQuality(existing.PackageId)))
        {
            existing.PackageId = normalizedPackageId;
            changed = true;
        }

        if (IsMeaningfulAppName(normalizedName))
        {
            var shouldReplaceName = !IsMeaningfulAppName(existing.PackageName)
                || (IsMeaningfulPackageId(normalizedPackageId)
                    && IsMeaningfulPackageId(existing.PackageId)
                    && string.Equals(existing.PackageId, normalizedPackageId, StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(existing.PackageName, normalizedName, StringComparison.OrdinalIgnoreCase)
                    && GetAppNameQuality(normalizedName) > GetAppNameQuality(existing.PackageName));

            if (shouldReplaceName)
            {
                existing.PackageName = normalizedName;
                changed = true;
            }
        }

        if (string.IsNullOrWhiteSpace(existing.AppGuid))
        {
            existing.AppGuid = appGuid;
            changed = true;
        }

        return changed;
    }

    private async Task WarmManagedAppNameCacheAsync()
    {
        _cimResolvedInstalledGuids.Clear();

        var targetDevice = GetEffectiveTargetDeviceName();
        if (string.IsNullOrWhiteSpace(targetDevice))
        {
            return;
        }

        var registryAppGuids = ExtractRegistryAppGuids(Win32AppsRegistryEntries);
        if (registryAppGuids.Count == 0)
        {
            return;
        }

        var appWorkloadMetadataMap = ExtractAppWorkloadMetadataMap(AppWorkloadEntries);
        var inventoryMetadataMap = ExtractInventoryMetadataMap(Win321AppInventoryEntries, registryAppGuids);

        var changed = false;
        foreach (var item in inventoryMetadataMap)
        {
            appWorkloadMetadataMap.TryGetValue(item.Key, out var metadata);
            changed |= UpsertAppNameCacheEntry(item.Key, metadata?.PackageId, item.Value.AppName);
        }

        foreach (var item in appWorkloadMetadataMap)
        {
            changed |= UpsertAppNameCacheEntry(item.Key, item.Value.PackageId, item.Value.AppName);
        }

        var unresolvedForCim = registryAppGuids
            .Where(guid => !_appNameCache.TryGetValue(guid, out var cachedEntry) || !IsMeaningfulAppName(cachedEntry.PackageName))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (unresolvedForCim.Length > 0)
        {
            var resolvedNames = await _intuneSupportService.ResolveAppNamesAsync(targetDevice, unresolvedForCim);
            foreach (var item in resolvedNames)
            {
                _cimResolvedInstalledGuids.Add(item.Key);
                appWorkloadMetadataMap.TryGetValue(item.Key, out var metadata);
                changed |= UpsertAppNameCacheEntry(item.Key, metadata?.PackageId, item.Value);
            }
        }

        if (changed)
        {
            SaveAppNameCache();
            NotifyDashboardStateChanged();
        }
    }

    private Dictionary<string, LogEntry> ExtractLatestRelevantEntryMap(IEnumerable<LogEntry> entries, IEnumerable<string> appGuids)
    {
        var guidSet = new HashSet<string>(appGuids, StringComparer.OrdinalIgnoreCase);
        var result = new Dictionary<string, LogEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries.OrderByDescending(item => item.Timestamp))
        {
            foreach (Match match in GuidRegex.Matches(entry.Message ?? string.Empty))
            {
                if (!match.Success || !guidSet.Contains(match.Value) || result.ContainsKey(match.Value))
                {
                    continue;
                }

                result[match.Value] = entry;
            }
        }

        return result;
    }

    private static Dictionary<string, LogEntry> ExtractLatestAppWorkloadErrorMap(IEnumerable<LogEntry> entries)
    {
        var result = new Dictionary<string, LogEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries.OrderByDescending(item => item.Timestamp))
        {
            if (!string.Equals(entry.Severity, "Error", StringComparison.OrdinalIgnoreCase)
                && !ContainsAny(entry.Message, new[] { "failed", "error", "0x", "exception", "not compliant", "enforcement failed" }))
            {
                continue;
            }

            foreach (Match match in GuidRegex.Matches(entry.Message ?? string.Empty))
            {
                if (match.Success && !result.ContainsKey(match.Value))
                {
                    result[match.Value] = entry;
                }
            }
        }

        return result;
    }

    private sealed class RegistryAppStateSnapshot
    {
        public string AppGuid { get; set; } = string.Empty;
        public string ComputerId { get; set; } = string.Empty;
        public string UserTargetingGuid { get; set; } = string.Empty;
        public string TargetingMethod { get; set; } = string.Empty;
        public bool HasGrsFailure { get; set; }
        public string ErrorCodeHex { get; set; } = string.Empty;
        public string ComplianceState { get; set; } = string.Empty;
        public string Applicability { get; set; } = string.Empty;
        public string DesiredState { get; set; } = string.Empty;
        public string EnforcementState { get; set; } = string.Empty;
        public string InstallContext { get; set; } = string.Empty;
        public string TargetType { get; set; } = string.Empty;
        public string ComplianceStateMessage { get; set; } = string.Empty;
        public string EnforcementStateMessage { get; set; } = string.Empty;
        public string ProductVersion { get; set; } = string.Empty;
        public string RebootStatus { get; set; } = string.Empty;
        public string RebootReason { get; set; } = string.Empty;
        public string SourceLog { get; set; } = string.Empty;
        public string LastSeen { get; set; } = string.Empty;
        public LogEntry? SourceEntry { get; set; }
    }

    private sealed class AppPayloadSnapshot
    {
        public string AppGuid { get; set; } = string.Empty;
        public string PackageId { get; set; } = string.Empty;
        public string InternalVersion { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public string DeviceId { get; set; } = string.Empty;
        public string ExitCode { get; set; } = string.Empty;
        public string ComplianceStateMessage { get; set; } = string.Empty;
        public string EnforcementState { get; set; } = string.Empty;
        public string TargetMethod { get; set; } = string.Empty;
        public string RebootStatus { get; set; } = string.Empty;
        public string RebootReason { get; set; } = string.Empty;
        public string SourceLog { get; set; } = string.Empty;
        public string LastSeen { get; set; } = string.Empty;
        public string RawMessage { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public LogEntry? SourceEntry { get; set; }
    }

    private static Dictionary<string, AppPayloadSnapshot> ExtractLatestAppPayloadMap(IEnumerable<LogEntry> entries)
    {
        var result = new Dictionary<string, AppPayloadSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries.OrderByDescending(item => item.Timestamp))
        {
            var message = entry.Message ?? string.Empty;
            if (string.IsNullOrWhiteSpace(message)
                || !ContainsAny(message, new[] { "sending results to service", "request payload", "session request payload" }))
            {
                continue;
            }

            var payload = BuildPayloadSnapshot(entry);
            if (payload is null || string.IsNullOrWhiteSpace(payload.AppGuid) || result.ContainsKey(payload.AppGuid))
            {
                continue;
            }

            result[payload.AppGuid] = payload;
        }

        return result;
    }

    private static AppPayloadSnapshot? BuildPayloadSnapshot(LogEntry entry)
    {
        var message = entry.Message ?? string.Empty;
        if (string.IsNullOrWhiteSpace(message))
        {
            return null;
        }

        var appGuid = ExtractPayloadValue(message, new[] { "AppId", "appId", "ApplicationId", "applicationId", "Id", "id" });
        if (!GuidRegex.IsMatch(appGuid ?? string.Empty))
        {
            var guidMatch = GuidRegex.Match(message);
            appGuid = guidMatch.Success ? guidMatch.Value : string.Empty;
        }

        if (string.IsNullOrWhiteSpace(appGuid))
        {
            return null;
        }

        return new AppPayloadSnapshot
        {
            AppGuid = appGuid,
            PackageId = ExtractPayloadValue(message, new[] { "PackageId", "packageId", "PackageIdentifier", "packageIdentifier" }),
            InternalVersion = ExtractPayloadValue(message, new[] { "InternalVersion", "internalVersion", "Version", "version" }),
            UserId = ExtractPayloadValue(message, new[] { "UserId", "userId" }),
            DeviceId = ExtractPayloadValue(message, new[] { "DeviceId", "deviceId" }),
            ExitCode = ExtractPayloadValue(message, new[] { "ExitCode", "exitCode" }),
            ComplianceStateMessage = ExtractPayloadValue(message, new[] { "ComplianceStateMessage", "complianceStateMessage", "ComplianceMessage", "complianceMessage" }),
            EnforcementState = ExtractPayloadValue(message, new[] { "EnforcementState", "enforcementState" }),
            TargetMethod = ExtractPayloadValue(message, new[] { "TargetMethod", "targetMethod" }),
            RebootStatus = ExtractPayloadValue(message, new[] { "RebootStatus", "rebootStatus" }),
            RebootReason = ExtractPayloadValue(message, new[] { "RebootReason", "rebootReason" }),
            SourceLog = entry.SourceFile,
            LastSeen = entry.DisplayTimestamp,
            RawMessage = message,
            Timestamp = entry.Timestamp,
            SourceEntry = entry
        };
    }

    private static string ExtractPayloadValue(string message, IEnumerable<string> keys)
    {
        foreach (var key in keys)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var jsonPattern = "(?is)\\\"" + Regex.Escape(key) + "\\\"\\s*:\\s*(?<value>\\\"(?:\\\\.|[^\\\"])*\\\"|-?\\d+|true|false|null)";
            var jsonMatch = Regex.Match(message, jsonPattern);
            if (jsonMatch.Success)
            {
                var candidate = NormalizePayloadValue(jsonMatch.Groups["value"].Value);
                if (!string.IsNullOrWhiteSpace(candidate))
                {
                    return candidate;
                }
            }

            var plainPattern = @"(?is)\b" + Regex.Escape(key) + @"\b\s*[:=]\s*(?<value>[^,;\r\n\]}]+)";
            var plainMatch = Regex.Match(message, plainPattern);
            if (plainMatch.Success)
            {
                var candidate = NormalizePayloadValue(plainMatch.Groups["value"].Value);
                if (!string.IsNullOrWhiteSpace(candidate))
                {
                    return candidate;
                }
            }
        }

        return string.Empty;
    }

    private static string ExtractRegistryTopLevelValue(string message, IEnumerable<string> keys)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return string.Empty;
        }

        foreach (var key in keys)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var pattern = @"(?is)(?:^|;\s*|\]\s*)" + Regex.Escape(key) + @"=(?<value>.*?)(?=(?:;\s*[A-Za-z][A-Za-z0-9]*=)|$)";
            var match = Regex.Match(message, pattern);
            if (match.Success)
            {
                var candidate = NormalizePayloadValue(match.Groups["value"].Value);
                if (!string.IsNullOrWhiteSpace(candidate))
                {
                    return candidate;
                }
            }
        }

        return string.Empty;
    }

    private string ResolveRegistryRecommendationsPath()
    {
        var baseDirectory = AppContext.BaseDirectory;
        var configPath = Path.Combine(baseDirectory, "Config", "MSRegRecomm.json");
        if (File.Exists(configPath))
        {
            return configPath;
        }

        var legacyPath = Path.Combine(baseDirectory, "MSRegRecomm.json");
        return legacyPath;
    }

    private Dictionary<string, string> LoadRegistryRecommendations()
    {
        var recommendations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!File.Exists(_registryRecommendationsPath))
            {
                return recommendations;
            }

            var json = File.ReadAllText(_registryRecommendationsPath);
            var entries = JsonSerializer.Deserialize<List<RegistryRecommendationDefinition>>(json, _jsonOptions) ?? new List<RegistryRecommendationDefinition>();
            foreach (var entry in entries)
            {
                if (string.IsNullOrWhiteSpace(entry.SettingName) || string.IsNullOrWhiteSpace(entry.Recommendation))
                {
                    continue;
                }

                var category = entry.Category?.Trim() ?? string.Empty;
                var settingName = entry.SettingName.Trim();
                var recommendation = entry.Recommendation.Trim();

                if (!string.IsNullOrWhiteSpace(category))
                {
                    recommendations[$"{category}|{settingName}"] = recommendation;
                }

                recommendations[settingName] = recommendation;
            }
        }
        catch (Exception ex)
        {
            _logger.Warn(
                "RegistryRecommendationsLoadFailed",
                "MSRegRecomm.json konnte nicht geladen werden.",
                DeviceName,
                "-",
                "REG-RECOMM-LOAD",
                AppErrorClass.CONFIG.ToString(),
                "CONFIG-REGRECOMM-001",
                "Die Empfehlungsdatei für Registry-Settings konnte nicht verarbeitet werden.",
                ex.Message,
                nameof(MainViewModel));
        }

        return recommendations;
    }

    private static string ResolveRegistryRecommendation(IReadOnlyDictionary<string, string> recommendations, string category, string settingName)
    {
        if (recommendations.Count == 0)
        {
            return string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(category)
            && !string.IsNullOrWhiteSpace(settingName)
            && recommendations.TryGetValue($"{category}|{settingName}", out var categoryMatch)
            && !string.IsNullOrWhiteSpace(categoryMatch))
        {
            return categoryMatch;
        }

        if (!string.IsNullOrWhiteSpace(settingName)
            && recommendations.TryGetValue(settingName, out var directMatch)
            && !string.IsNullOrWhiteSpace(directMatch))
        {
            return directMatch;
        }

        return string.Empty;
    }

    private static string NormalizePackageIdValue(string? value)
    {
        var normalized = NormalizePayloadValue(value);
        return normalized.Trim().TrimEnd('.', ',', ';');
    }

    private static string NormalizePayloadValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim().Trim(',', ';');
        if (normalized.StartsWith('"') && normalized.EndsWith('"') && normalized.Length >= 2)
        {
            normalized = normalized[1..^1];
        }

        normalized = normalized.Replace("\\\"", "\"").Replace("\\/", "/").Trim();
        if (string.Equals(normalized, "null", StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        return Regex.Replace(normalized, @"\s+", " ").Trim();
    }

    private string ResolveAppNameCachePath()
    {
        try
        {
            var logDirectory = Environment.ExpandEnvironmentVariables(_config.LocalLogDirectory ?? string.Empty);
            var appDataDirectory = !string.IsNullOrWhiteSpace(logDirectory)
                ? Path.GetDirectoryName(logDirectory)
                : null;

            if (string.IsNullOrWhiteSpace(appDataDirectory))
            {
                appDataDirectory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    string.IsNullOrWhiteSpace(_config.AppDataFolderName) ? LanguageManager.Instance.GetAppDisplayName() : _config.AppDataFolderName.Trim());
            }

            Directory.CreateDirectory(appDataDirectory!);
            return Path.Combine(appDataDirectory!, "AppNameCache.json");
        }
        catch
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), LanguageManager.Instance.GetAppDisplayName(), "AppNameCache.json");
        }
    }

    private void LoadAppNameCache()
    {
        try
        {
            if (!File.Exists(_appNameCachePath))
            {
                return;
            }

            var json = File.ReadAllText(_appNameCachePath);
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!GuidRegex.IsMatch(property.Name))
                {
                    continue;
                }

                if (property.Value.ValueKind == JsonValueKind.String)
                {
                    var legacyName = NormalizeAppNameCandidate(property.Value.GetString());
                    if (IsMeaningfulAppName(legacyName))
                    {
                        _appNameCache[property.Name] = new AppNameCacheEntry
                        {
                            AppGuid = property.Name,
                            PackageName = legacyName,
                            PackageId = string.Empty
                        };
                    }

                    continue;
                }

                if (property.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var packageName = NormalizeAppNameCandidate(GetJsonStringProperty(property.Value, "PackageName"));
                var packageId = NormalizePayloadValue(GetJsonStringProperty(property.Value, "PackageId"));
                if (!IsMeaningfulAppName(packageName) && !IsMeaningfulPackageId(packageId))
                {
                    continue;
                }

                _appNameCache[property.Name] = new AppNameCacheEntry
                {
                    AppGuid = property.Name,
                    PackageName = IsMeaningfulAppName(packageName) ? packageName : string.Empty,
                    PackageId = IsMeaningfulPackageId(packageId) ? packageId : string.Empty
                };
            }
        }
        catch
        {
            _appNameCache.Clear();
        }
    }

    private void SaveAppNameCache()
    {
        try
        {
            var cacheDirectory = Path.GetDirectoryName(_appNameCachePath);
            if (!string.IsNullOrWhiteSpace(cacheDirectory))
            {
                Directory.CreateDirectory(cacheDirectory);
            }

            var ordered = _appNameCache
                .Where(item => GuidRegex.IsMatch(item.Key) && (IsMeaningfulAppName(item.Value.PackageName) || IsMeaningfulPackageId(item.Value.PackageId)))
                .OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    item => item.Key,
                    item => new AppNameCacheEntry
                    {
                        AppGuid = item.Key,
                        PackageId = IsMeaningfulPackageId(item.Value.PackageId) ? item.Value.PackageId : string.Empty,
                        PackageName = IsMeaningfulAppName(item.Value.PackageName) ? item.Value.PackageName : string.Empty
                    },
                    StringComparer.OrdinalIgnoreCase);

            File.WriteAllText(_appNameCachePath, JsonSerializer.Serialize(ordered, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
        }
    }

    private static string TrimForDashboard(string? value, int maxLength = 180)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "-";
        }

        var normalized = value.Replace(Environment.NewLine, " ").Trim();
        return normalized.Length <= maxLength ? normalized : normalized[..maxLength] + "...";
    }

    private static string ResolveAppName(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "App-Name nicht aufgelöst";
        }

        var patterns = new[]
        {
            @"(?i)""(?:displayname|display name|appname|app name|applicationname|application name|packagename|package name|name)""\s*:\s*""(?<name>[^""\r\n]{3,160})""",
            @"(?i)(?:display ?name|app ?name|application ?name|package ?name|friendly ?name|product ?name)\s*[:=]\s*[""']?(?<name>[^,;|""'\r\n]{3,160})",
            @"(?i)(?:detected|installing|installed|processing|evaluating|assignment for|applicable app|selected app)\s+[""'](?<name>[^""']{3,160})[""']",
            @"(?i)(?:detected|installing|installed|processing|evaluating|assignment for|applicable app|selected app)\s+(?<name>[A-Za-z0-9][A-Za-z0-9 _\-.()\[\]]{2,160})"
        };

        foreach (var pattern in patterns)
        {
            var match = Regex.Match(message, pattern);
            if (!match.Success)
            {
                continue;
            }

            var candidate = NormalizeAppNameCandidate(match.Groups["name"].Value);
            if (IsMeaningfulAppName(candidate))
            {
                return candidate;
            }
        }

        foreach (Match quoted in Regex.Matches(message, "\"(?<name>[^\"]{3,160})\""))
        {
            var candidate = NormalizeAppNameCandidate(quoted.Groups["name"].Value);
            if (IsMeaningfulAppName(candidate))
            {
                return candidate;
            }
        }

        return "App-Name nicht aufgelöst";
    }

    private static string NormalizeAppNameCandidate(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return string.Empty;
        }

        var normalized = candidate.Trim().Trim('"', '\'', ':', ';');
        normalized = Regex.Replace(normalized, @"\s+", " ").Trim();
        return normalized;
    }

    private static bool IsMeaningfulAppName(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        if (candidate.Length < 3)
        {
            return false;
        }

        if (GuidRegex.IsMatch(candidate))
        {
            return false;
        }

        var lowered = candidate.Trim().ToLowerInvariant();
        if (lowered is "applicationid" or "application id" or "app id" or "appid" or "guid" or "applicationguid" or "application guid"
            or "name" or "displayname" or "display name" or "packagename" or "package name" or "id")
        {
            return false;
        }

        if (lowered.Contains("applicationid") || lowered.Contains("application guid") || lowered.Contains("app guid")
            || lowered.Contains("\"name\"") || lowered.Contains("\"id\"") || lowered.Contains("{") || lowered.Contains("}"))
        {
            return false;
        }

        if (lowered.StartsWith("win32 app") || lowered == "application" || lowered == "app" || lowered == "package")
        {
            return false;
        }

        if (lowered.Contains("install enforcement actions for app with id")
            || lowered.Contains("app with id")
            || lowered.Contains("enforcement actions"))
        {
            return false;
        }

        return true;
    }

    private static int GetAppNameQuality(string? candidate)
    {
        if (string.Equals(candidate, "App-Name nicht aufgelöst", StringComparison.OrdinalIgnoreCase))
        {
            return 1;
        }

        if (!IsMeaningfulAppName(candidate))
        {
            return 0;
        }

        var score = candidate!.Length;
        if (candidate.Any(char.IsWhiteSpace))
        {
            score += 30;
        }

        if (candidate.Any(char.IsLetter))
        {
            score += 20;
        }

        return score;
    }


    private static bool IsMeaningfulPackageId(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        var normalized = candidate.Trim();
        if (normalized.Length < 3)
        {
            return false;
        }

        var lowered = normalized.ToLowerInvariant();
        if (lowered is "packageid" or "package id" or "identifier" or "packageidentifier" or "null" or "-")
        {
            return false;
        }

        return normalized.Any(char.IsLetterOrDigit);
    }

    private static int GetPackageIdQuality(string? candidate)
    {
        if (!IsMeaningfulPackageId(candidate))
        {
            return 0;
        }

        var score = candidate!.Length;
        if (candidate.Any(char.IsLetter))
        {
            score += 10;
        }

        if (candidate.Any(char.IsDigit))
        {
            score += 10;
        }

        return score;
    }

    private static string ResolveAppStatus(string? message, AppPayloadSnapshot? payload = null)
    {
        var effectiveMessage = string.Join(" | ", new[]
        {
            payload?.EnforcementState,
            payload?.ComplianceStateMessage,
            payload?.ExitCode,
            payload?.RebootStatus,
            payload?.RebootReason,
            message
        }.Where(value => !string.IsNullOrWhiteSpace(value)));

        if (string.IsNullOrWhiteSpace(effectiveMessage))
        {
            return "Unbekannt";
        }

        if (ContainsAny(effectiveMessage, new[] { "failed", "error", "nicht erfolgreich", "0x", "noncompliant", "not compliant", "enforcement failed" })) return "Fehler";
        if (ContainsAny(effectiveMessage, new[] { "pending", "queued", "waiting", "restart required", "reboot required", "pending reboot" })) return "Pending";
        if (ContainsAny(effectiveMessage, new[] { "download", "installing", "processing", "executing", "in progress", "running" })) return "In Bearbeitung";
        if (ContainsAny(effectiveMessage, new[] { "installed", "successfully", "completed", "detected", "compliant", "success", "succeeded" })) return "Installiert";
        return "Unbekannt";
    }

    private static string ResolveErrorHint(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return string.Empty;
        }

        return ContainsAny(message, new[] { "failed", "error", "nicht erfolgreich", "0x" })
            ? TrimForDashboard(message, 120)
            : string.Empty;
    }

    private static bool ShouldReplaceStatus(string currentStatus, string candidateStatus)
    {
        static int Rank(string status) => status switch
        {
            "Fehler" => 4,
            "Pending" => 3,
            "In Bearbeitung" => 2,
            "Installiert" => 1,
            _ => 0
        };

        return Rank(candidateStatus) >= Rank(currentStatus);
    }

    private void NotifyDashboardStateChanged()
    {
        RebuildDashboardInsights();
        OnPropertyChanged(nameof(ImeHealthTargetDevice));
        OnPropertyChanged(nameof(ImeHealthConnectionState));
        OnPropertyChanged(nameof(ImeHealthRemoteLogStats));
        OnPropertyChanged(nameof(ImeHealthLatestSignal));
        OnPropertyChanged(nameof(ImeHealthRemediationSignal));
        OnPropertyChanged(nameof(ImeHealthRemediationSummary));
        OnPropertyChanged(nameof(ImeHealthPendingRestartText));
        OnPropertyChanged(nameof(ImeHealthManagedAppsSummary));
        OnPropertyChanged(nameof(ImeHealthEnrollmentSummary));
        OnPropertyChanged(nameof(ImeHealthIssueSummary));
        OnPropertyChanged(nameof(CompanyPortalSummaryText));
        OnPropertyChanged(nameof(EnrollmentSummaryText));
        OnPropertyChanged(nameof(MdmDiagnosticsSummaryText));
        OnPropertyChanged(nameof(EventLogChannelsSummaryText));
        OnPropertyChanged(nameof(InstallAgentEventsSummaryText));
        OnPropertyChanged(nameof(CompanyPortalOverviewText));
        OnPropertyChanged(nameof(CompanyPortalOverviewSignalText));
        OnPropertyChanged(nameof(IntuneLogsOverviewText));
        OnPropertyChanged(nameof(IntuneLogsOverviewSignalText));
        OnPropertyChanged(nameof(LocalAppLogsOverviewText));
        OnPropertyChanged(nameof(LocalAppLogsOverviewSignalText));
        OnPropertyChanged(nameof(RemediationSummaryText));
        OnPropertyChanged(nameof(IntuneRelevantRegistrySettingsSummaryText));
    }

private void RefreshLocalProgramLogs(bool forceFullReload = false)
{
    try
    {
        var effectiveGuid = string.IsNullOrWhiteSpace(AppGuid) ? null : AppGuid.Trim();
        var localLogs = _intuneSupportService.ReadLocalProgramLogs(DeviceName.Trim(), effectiveGuid);
        var changedCollections = new List<string>();
        if (UpdateLocalLogCollection(localLogs, nameof(LocalAppLogEntries), "LocalAppLog", forceFullReload)) changedCollections.Add(nameof(LocalAppLogEntries));
        if (UpdateLocalLogCollection(localLogs, nameof(AppDataLogsEntries), "AppDataLogs", forceFullReload)) changedCollections.Add(nameof(AppDataLogsEntries));
        if (UpdateLocalLogCollection(localLogs, nameof(TrustLogEntries), "TrustLog", forceFullReload)) changedCollections.Add(nameof(TrustLogEntries));
        if (changedCollections.Count > 0)
        {
            RefreshViews(changedCollections);
        }
    }
    catch
    {
        // Lokale Log-Aktualisierung darf die Hauptfunktionalität nicht stören.
    }
}

private void InitializeLogCollection(string key)
    {
        var collection = new ObservableCollection<LogEntry>();
        _entryCollections[key] = collection;
        var view = CollectionViewSource.GetDefaultView(collection);
        view.Filter = item => FilterEntry(key, item);
        view.SortDescriptions.Clear();
        view.SortDescriptions.Add(new SortDescription(nameof(LogEntry.Timestamp), ListSortDirection.Descending));
        _entryViews[key] = view;
    }

    private bool FilterEntry(string collectionName, object item)
    {
        if (item is not LogEntry entry)
        {
            return false;
        }

        var searchTerm = GetSearchTermForCollection(collectionName);
        var selectedFilter = GetSelectedFilterForCollection(collectionName);

        var matchesSearch = string.IsNullOrWhiteSpace(searchTerm)
            || entry.Message.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
            || entry.SourceFile.Contains(searchTerm, StringComparison.OrdinalIgnoreCase);

        var matchesFilter = selectedFilter switch
        {
            "Info" => entry.Severity.Equals("Info", StringComparison.OrdinalIgnoreCase),
            "Success" => entry.Severity.Equals("Success", StringComparison.OrdinalIgnoreCase),
            "Warning" => entry.Severity.Equals("Warning", StringComparison.OrdinalIgnoreCase),
            "Error" => entry.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase),
            _ => true
        };

        return matchesSearch && matchesFilter;
    }

    private void RefreshViews(IEnumerable<string>? collectionNames = null)
    {
        var keys = collectionNames?.ToArray() ?? _entryViews.Keys.ToArray();
        foreach (var key in keys)
        {
            if (_entryViews.TryGetValue(key, out var view))
            {
                view.Refresh();
            }
        }

        NotifyDashboardStateChanged();
    }

    private void ReplaceEntries(string collectionName, LogBundle bundle, string logKey)
    {
        var target = _entryCollections[collectionName];
        target.Clear();
        if (!bundle.EntriesByKey.TryGetValue(logKey, out var entries))
        {
            return;
        }
        foreach (var entry in entries)
        {
            target.Add(entry);
        }
    }

    private void ClearEntries()
    {
        foreach (var collection in _entryCollections.Values)
        {
            collection.Clear();
        }
        _remoteLogStates.Clear();
        RefreshViews();
        NotifyDashboardStateChanged();
    }

    private void RaiseCommands()
    {
        AnalyzeCommand.RaiseCanExecuteChanged();
        RefreshCommand.RaiseCanExecuteChanged();
        ResetImeLogsCommand.RaiseCanExecuteChanged();
        RestartImeServiceCommand.RaiseCanExecuteChanged();
        ResetAppInstallCommand.RaiseCanExecuteChanged();
        WsResetCommand.RaiseCanExecuteChanged();
        ExportLogBundleCommand.RaiseCanExecuteChanged();
    }
}
