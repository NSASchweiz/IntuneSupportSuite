using System;
using System.Linq;
using System.Windows;
using DapIntuneSupportSuite.Models;
using DapIntuneSupportSuite.Services;

namespace DapIntuneSupportSuite;

public partial class LanguageWindow : Window
{
    private readonly AppConfig _originalConfig;
    private readonly ConfigBootstrapper _configBootstrapper;
    private readonly Action<AppConfig>? _onSaved;

    public LanguageWindow(AppConfig config, ConfigBootstrapper configBootstrapper, Action<AppConfig>? onSaved = null)
    {
        InitializeComponent();
        _originalConfig = config;
        _configBootstrapper = configBootstrapper;
        _onSaved = onSaved;

        Title = LanguageManager.Instance.ComposeWindowTitle("Language");
        WindowLocalizationHelper.Attach(this);
        LoadLanguages();
    }

    private void LoadLanguages()
    {
        var available = LanguageManager.Instance
            .DiscoverLanguages(AppContext.BaseDirectory)
            .Where(item => item.ShowInGui)
            .OrderBy(item => item.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        LanguageComboBox.ItemsSource = available;
        LanguageComboBox.SelectedItem = available.FirstOrDefault(item => string.Equals(item.LanguageId, _originalConfig.Language, StringComparison.OrdinalIgnoreCase))
                                       ?? available.FirstOrDefault();
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (LanguageComboBox.SelectedItem is not LanguageOption option)
        {
            MessageBox.Show(
                LanguageManager.Instance.TranslateText("Es wurde keine Sprache ausgewählt."),
                LanguageManager.Instance.ComposeWindowTitle(),
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        try
        {
            var updatedConfig = _originalConfig.Clone();
            updatedConfig.Language = option.LanguageId;
            LanguageManager.Instance.Load(AppContext.BaseDirectory, updatedConfig.Language, new AuditLogger(updatedConfig));
            updatedConfig.WindowTitle = LanguageManager.Instance.ComposeWindowTitle();

            var saveResult = _configBootstrapper.SaveUserConfiguration(updatedConfig);
            _originalConfig.CopyFrom(updatedConfig);
            _originalConfig.WindowTitle = LanguageManager.Instance.ComposeWindowTitle();
            _onSaved?.Invoke(_originalConfig);

            if (saveResult.HasWarnings)
            {
                MessageBox.Show(
                    LanguageManager.Instance.TranslateText("Sprache gespeichert. Es liegen Validierungswarnungen vor:\n\n") + saveResult.Message,
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
            logger.Error("LanguageSave", error.UserMessage, "-", "-", "LANGUAGE-SAVE", error.ErrorClass.ToString(), error.ErrorCode, error.UserMessage, error.TechnicalDetails, error.Component);
            AppErrorPresenter.Show(_originalConfig.WindowTitle, error, MessageBoxImage.Error);
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
