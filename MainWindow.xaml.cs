
using System.ComponentModel;
using System.Windows;
using DapIntuneSupportSuite.Models;
using DapIntuneSupportSuite.Services;
using DapIntuneSupportSuite.ViewModels;

namespace DapIntuneSupportSuite;

public partial class MainWindow : Window
{
    private readonly AppConfig _config;
    private readonly ConfigBootstrapper _configBootstrapper;

    public MainWindow(AppConfig config, ConfigBootstrapper configBootstrapper)
    {
        InitializeComponent();
        _config = config;
        _configBootstrapper = configBootstrapper;
        Title = LanguageManager.Instance.ComposeWindowTitle();
        WindowLocalizationHelper.Attach(this);
        Closing += OnClosingAsync;
    }

    private async void OnClosingAsync(object? sender, CancelEventArgs e)
    {
        if (DataContext is MainViewModel viewModel)
        {
            await viewModel.ShutdownAsync();
        }
    }

    private void Options_Click(object sender, RoutedEventArgs e)
    {
        var optionsWindow = new OptionsWindow(_config, _configBootstrapper, _ =>
        {
            _config.WindowTitle = LanguageManager.Instance.ComposeWindowTitle();
            Title = _config.WindowTitle;
            if (DataContext is MainViewModel viewModel)
            {
                viewModel.ApplyConfigurationChanges();
            }
            WindowLocalizationHelper.Apply(this);
        })
        {
            Owner = this,
            Title = LanguageManager.Instance.ComposeWindowTitle("Optionen")
        };
        optionsWindow.ShowDialog();
    }


    private void TrustedConfig_Click(object sender, RoutedEventArgs e)
    {
        var trustedConfigWindow = new TrustedConfigWindow(_config, _configBootstrapper, _ =>
        {
            _config.WindowTitle = LanguageManager.Instance.ComposeWindowTitle();
            Title = _config.WindowTitle;
            if (DataContext is MainViewModel viewModel)
            {
                viewModel.ApplyConfigurationChanges();
                viewModel.NotifySecurityContextChanged();
            }
            WindowLocalizationHelper.Apply(this);
        })
        {
            Owner = this,
            Title = LanguageManager.Instance.ComposeWindowTitle("Trusted Config")
        };
        trustedConfigWindow.ShowDialog();
    }

    private void Language_Click(object sender, RoutedEventArgs e)
    {
        var languageWindow = new LanguageWindow(_config, _configBootstrapper, _ =>
        {
            _config.WindowTitle = LanguageManager.Instance.ComposeWindowTitle();
            Title = _config.WindowTitle;
            if (DataContext is MainViewModel viewModel)
            {
                viewModel.ApplyConfigurationChanges();
            }
            WindowLocalizationHelper.Apply(this);
        })
        {
            Owner = this,
            Title = LanguageManager.Instance.ComposeWindowTitle("Language")
        };
        languageWindow.ShowDialog();
    }

    private void Exit_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
