using System;
using System.Windows;
using DapIntuneSupportSuite.Models;
using DapIntuneSupportSuite.Services;
using DapIntuneSupportSuite.ViewModels;

namespace DapIntuneSupportSuite;

public partial class OptionsWindow : Window
{
    private readonly AppConfig _originalConfig;
    private readonly ConfigBootstrapper _configBootstrapper;
    private readonly Action<AppConfig>? _onSaved;

    public OptionsWindow(AppConfig config, ConfigBootstrapper configBootstrapper, Action<AppConfig>? onSaved = null)
    {
        InitializeComponent();
        _originalConfig = config;
        _configBootstrapper = configBootstrapper;
        _onSaved = onSaved;

        Title = LanguageManager.Instance.ComposeWindowTitle("Optionen");
        WindowLocalizationHelper.Attach(this);
        DataContext = new OptionsViewModel(_originalConfig.Clone());
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is not OptionsViewModel viewModel)
        {
            DialogResult = false;
            Close();
            return;
        }

        try
        {
            var updatedConfig = viewModel.ToUserSettingsConfig(_originalConfig);
            var saveResult = _configBootstrapper.SaveUserConfiguration(updatedConfig);
            _originalConfig.CopyFrom(updatedConfig);
            _onSaved?.Invoke(_originalConfig);

            if (saveResult.HasWarnings)
            {
                MessageBox.Show(
                    LanguageManager.Instance.TranslateText("Konfiguration gespeichert. Es liegen Validierungswarnungen vor:\n\n") + saveResult.Message,
                    _originalConfig.WindowTitle,
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
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
            logger.Error("OptionsSave", error.UserMessage, "-", "-", "OPTIONS-SAVE", error.ErrorClass.ToString(), error.ErrorCode, error.UserMessage, error.TechnicalDetails, error.Component);
            AppErrorPresenter.Show(_originalConfig.WindowTitle, error, MessageBoxImage.Error);
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
