namespace DapIntuneSupportSuite.Models;

public sealed class ConfigurationBootstrapResult
{
    public AppConfig Config { get; init; } = new();
    public UserConfigData UserConfig { get; init; } = new();
    public TrustedConfig TrustedConfig { get; init; } = new();
    public string UserConfigPath { get; init; } = string.Empty;
    public string TrustedConfigPath { get; init; } = string.Empty;
    public TrustState TrustState { get; init; }
    public string StartupMessage { get; init; } = string.Empty;
    public bool ExitApplication { get; init; }
    public bool ShowWarningPopup { get; init; }
    public bool ShowTrustedInfoPopup { get; init; }
}
