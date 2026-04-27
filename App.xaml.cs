using System;
using System.Windows.Threading;
using System.Windows;
using DapIntuneSupportSuite.Models;
using DapIntuneSupportSuite.Services;
using DapIntuneSupportSuite.ViewModels;

namespace DapIntuneSupportSuite;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var configBootstrapper = new ConfigBootstrapper();
        var bootstrapResult = configBootstrapper.EnsureAndLoad();
        var appConfig = bootstrapResult.Config;
        LanguageManager.Instance.Load(AppContext.BaseDirectory, appConfig.Language, null);
        LanguageManager.Instance.ApplyLanguageDrivenConfigFields(appConfig);
        appConfig.WindowTitle = LanguageManager.Instance.ComposeWindowTitle();

        if (bootstrapResult.ExitApplication)
        {
            var startupError = AppErrorCatalog.ConfigStartupBlocked(bootstrapResult.StartupMessage);
            AppErrorPresenter.Show(appConfig.WindowTitle, startupError, MessageBoxImage.Error);
            Shutdown();
            return;
        }

        var logger = new AuditLogger(appConfig);

        DispatcherUnhandledException += (_, args) =>
        {
            var unhandledError = AppErrorCatalog.Unknown("DispatcherUnhandledException", args.Exception.ToString(), "App");
            logger.Error("DispatcherUnhandledException", unhandledError.UserMessage, "-", "-", "APP-UNHANDLED", unhandledError.ErrorClass.ToString(), unhandledError.ErrorCode, unhandledError.UserMessage, unhandledError.TechnicalDetails, unhandledError.Component);
            AppErrorPresenter.Show(appConfig.WindowTitle, unhandledError, MessageBoxImage.Error);
            args.Handled = true;
        };
        logger.Info("ShortDestinationLogsLoaded", $"shortDestinationLogs geladen: {appConfig.ShortDestinationLogs}", "-", "-", "STARTUP");
        var dependencyService = new PsExecDependencyService(logger, appConfig, configBootstrapper);
        var powerShellRunner = new PowerShellRunner(logger, appConfig);
        var intuneService = new IntuneSupportService(powerShellRunner, logger, appConfig);
        var securityGuardService = new SecurityGuardService(configBootstrapper);
        var appInputValidator = new AppInputValidator(logger);

        var viewModel = new MainViewModel(intuneService, logger, appConfig, dependencyService, configBootstrapper, securityGuardService, appInputValidator);
        var window = new MainWindow(appConfig, configBootstrapper)
        {
            DataContext = viewModel,
            Title = appConfig.WindowTitle
        };

        window.Loaded += async (_, _) =>
        {
            try
            {
                if (bootstrapResult.ShowWarningPopup)
                {
                    var startupWarning = appConfig.TrustState == TrustState.Trusted
                        ? AppErrorCatalog.ConfigStartupBlocked(bootstrapResult.StartupMessage)
                        : AppErrorCatalog.TrustBlocked(bootstrapResult.StartupMessage);
                    AppErrorPresenter.Show(appConfig.WindowTitle, startupWarning, MessageBoxImage.Warning);
                }
                else if (bootstrapResult.ShowTrustedInfoPopup)
                {
                    MessageBox.Show(
                        LanguageManager.Instance.TranslateText("TrustedConfig wurde erfolgreich als vertrauenswürdig erkannt."),
                        appConfig.WindowTitle,
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }

                if (!appConfig.IsProductiveModeAvailable)
                {
                    return;
                }

                var startupResult = await dependencyService.InitializeForStartupAsync();
                if (!startupResult.Success)
                {
                    var psExecError = AppErrorCatalog.PsExecBlocked(startupResult.ErrorMessage);
                    logger.Error("PsExecStartup", psExecError.UserMessage, "-", "-", "STARTUP-PSEXEC", psExecError.ErrorClass.ToString(), psExecError.ErrorCode, psExecError.UserMessage, psExecError.TechnicalDetails, psExecError.Component);
                    AppErrorPresenter.Show(appConfig.WindowTitle, psExecError, MessageBoxImage.Error);
                    return;
                }

                if (startupResult.ShowDirectInstallHint)
                {
                    MessageBox.Show(
                        LanguageManager.Instance.TranslateText("winget wurde nicht gefunden. PsExec wurde im Programmverzeichnis von {AppDisplayName} bereitgestellt und wird von dort verwendet."),
                        appConfig.WindowTitle,
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                var startupError = AppErrorCatalog.Unknown("StartupPsExecInitialization", ex.ToString(), "App");
                logger.Error("StartupPsExecInitialization", startupError.UserMessage, "-", "-", "STARTUP-PSEXEC", startupError.ErrorClass.ToString(), startupError.ErrorCode, startupError.UserMessage, startupError.TechnicalDetails, startupError.Component);
                AppErrorPresenter.Show(appConfig.WindowTitle, startupError, MessageBoxImage.Error);
            }
        };

        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        AsyncLogDispatcher.Shutdown(TimeSpan.FromSeconds(3));
        base.OnExit(e);
    }
}
