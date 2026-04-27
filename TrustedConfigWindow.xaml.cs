using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using DapIntuneSupportSuite.Models;
using DapIntuneSupportSuite.Services;
using DapIntuneSupportSuite.ViewModels;

namespace DapIntuneSupportSuite;

public partial class TrustedConfigWindow : Window
{
    private readonly AppConfig _originalConfig;
    private readonly ConfigBootstrapper _configBootstrapper;
    private readonly Action<AppConfig>? _onSaved;

    public TrustedConfigWindow(AppConfig config, ConfigBootstrapper configBootstrapper, Action<AppConfig>? onSaved = null)
    {
        InitializeComponent();
        _originalConfig = config;
        _configBootstrapper = configBootstrapper;
        _onSaved = onSaved;

        Title = LanguageManager.Instance.ComposeWindowTitle("Trusted Config");
        WindowLocalizationHelper.Attach(this);
        DataContext = new OptionsViewModel(_originalConfig.Clone());
        Loaded += TrustedConfigWindow_Loaded;
    }

    private async void TrustedConfigWindow_Loaded(object sender, RoutedEventArgs e)
    {
        await LoadTrustStatusAsync(forceFullValidation: false, operationId: "TRUSTEDCONFIG-LOAD");
    }

    private async Task LoadTrustStatusAsync(bool forceFullValidation, string operationId)
    {
        if (DataContext is not OptionsViewModel viewModel)
        {
            return;
        }

        var perfLogger = new AuditLogger(_originalConfig);
        using var perf = PerformanceTrace.Start(perfLogger, forceFullValidation ? "TrustedConfigTrustRevalidate" : "TrustedConfigFingerprintRefresh", operationId, "-", "-", nameof(TrustedConfigWindow));
        viewModel.BeginTrustStatusLoading();
        var progressTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(120)
        };
        progressTimer.Tick += (_, _) =>
        {
            if (viewModel.TrustStatusLoadProgress < 90)
            {
                viewModel.UpdateTrustStatusLoadProgress(viewModel.TrustStatusLoadProgress + 6);
            }
        };
        progressTimer.Start();

        try
        {
            var refreshed = await Task.Run(() =>
            {
                var clone = _originalConfig.Clone();
                if (forceFullValidation)
                {
                    _configBootstrapper.ForceRevalidateRuntimeTrustStatePreservingUserSettings(clone, operationId);
                }
                else
                {
                    _configBootstrapper.RefreshRuntimeTrustStateUsingFingerprintCachePreservingUserSettings(clone, operationId);
                }
                return clone;
            });

            viewModel.ApplyRuntimeTrustStatus(refreshed);
        }
        catch (Exception ex)
        {
            var error = AppErrorCatalog.OptionsOperationFailed(ex.ToString());
            var logger = new AuditLogger(_originalConfig);
            logger.Error("TrustedConfigLoad", error.UserMessage, "-", "-", operationId, error.ErrorClass.ToString(), error.ErrorCode, error.UserMessage, error.TechnicalDetails, error.Component);
            viewModel.CompleteTrustStatusLoadingWithError(LanguageManager.Instance.TranslateText("Trust-Status konnte nicht geladen werden."));
            AppErrorPresenter.Show(_originalConfig.WindowTitle, error, MessageBoxImage.Warning);
        }
        finally
        {
            progressTimer.Stop();
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is not OptionsViewModel viewModel)
        {
            DialogResult = false;
            Close();
            return;
        }

        if (!viewModel.CanSaveTrustedConfig)
        {
            return;
        }

        try
        {
            var updatedConfig = viewModel.ToTrustedSettingsConfig(_originalConfig);
            var saveResult = _configBootstrapper.SaveTrustedConfiguration(updatedConfig);
            _originalConfig.CopyFrom(updatedConfig);
            _onSaved?.Invoke(_originalConfig);

            if (saveResult.HasWarnings)
            {
                MessageBox.Show(
                    LanguageManager.Instance.TranslateText("TrustedConfig gespeichert. Es liegen Validierungswarnungen vor:\n\n") + saveResult.Message,
                    _originalConfig.WindowTitle,
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else
            {
                MessageBox.Show(
                    LanguageManager.Instance.TranslateText("TrustedConfig gespeichert. Externe Neuerzeugung und Signierung des Catalogs sind weiterhin erforderlich. Simulationsmodus ist erzwungen."),
                    _originalConfig.WindowTitle,
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            DialogResult = true;
            Close();
        }
        catch (Exception ex)
        {
            var error = ex is InvalidOperationException
                ? AppErrorCatalog.ConfigSaveBlocked(ex.Message)
                : AppErrorCatalog.OptionsOperationFailed(ex.ToString());
            var logger = new AuditLogger(_originalConfig);
            logger.Error("TrustedConfigSave", error.UserMessage, "-", "-", "TRUSTEDCONFIG-SAVE", error.ErrorClass.ToString(), error.ErrorCode, error.UserMessage, error.TechnicalDetails, error.Component);
            AppErrorPresenter.Show(_originalConfig.WindowTitle, error, MessageBoxImage.Error);
        }
    }

    private void ResetTrust_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is not OptionsViewModel viewModel)
        {
            return;
        }

        viewModel.MarkTrustedConfigAsUntrusted();
        MessageBox.Show(
            LanguageManager.Instance.TranslateText("TrustedConfig wurde für die weitere Bearbeitung auf nicht vertrauenswürdig gesetzt. Simulationsmodus ist nun erzwungen, bis der Catalog extern neu erzeugt und signiert wurde."),
            _originalConfig.WindowTitle,
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private async void RevalidateTrust_Click(object sender, RoutedEventArgs e)
    {
        await LoadTrustStatusAsync(forceFullValidation: true, operationId: "TRUSTEDCONFIG-REVALIDATE");
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
