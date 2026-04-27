using System.Windows;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public static class AppErrorPresenter
{
    public static string BuildGuiMessage(AppErrorInfo error)
    {
        if (error.IsKnown)
        {
            return LanguageManager.Instance.TranslateText($"{error.UserMessage}{Environment.NewLine}{Environment.NewLine}Fehlerklasse: {error.ErrorClass}{Environment.NewLine}Fehlercode: {error.ErrorCode}");
        }

        var technical = string.IsNullOrWhiteSpace(error.TechnicalDetails)
            ? "Keine technischen Details verfügbar."
            : error.TechnicalDetails.Trim();

        return LanguageManager.Instance.TranslateText($"{error.UserMessage}{Environment.NewLine}{Environment.NewLine}Fehlerklasse: {error.ErrorClass}{Environment.NewLine}Fehlercode: {error.ErrorCode}{Environment.NewLine}{Environment.NewLine}Technische Details: {technical}");
    }

    public static void Show(string windowTitle, AppErrorInfo error, MessageBoxImage image = MessageBoxImage.Error)
    {
        MessageBox.Show(BuildGuiMessage(error), windowTitle, MessageBoxButton.OK, image);
    }
}
