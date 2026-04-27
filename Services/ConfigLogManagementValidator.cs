using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class ConfigLogManagementValidator
{
    public LogManagementValidationResult ValidateForSave(AppConfig config)
    {
        var result = new LogManagementValidationResult();
        ValidateBoolBackedInt(result, nameof(AppConfig.MaxManagedLogSizeMb), config.MaxManagedLogSizeMb, 1, 500, 2, 100, "Sehr kleine Loggrößen führen zu häufiger Rotation.", "Sehr große Loggrößen können Performance und Lesbarkeit verschlechtern.");
        ValidateBoolBackedInt(result, nameof(AppConfig.MaxManagedLogHistoryFiles), config.MaxManagedLogHistoryFiles, 1, 90, 3, 30, "Sehr wenige Rotationen reduzieren die Historie stark.", "Sehr viele Rotationen erhöhen die Datenträgernutzung.");
        ValidateBoolBackedInt(result, nameof(AppConfig.MaxKeptLocalLogs), config.MaxKeptLocalLogs, 1, 90, 3, 30, "Sehr wenige lokale Rotationen reduzieren die Historie stark.", "Sehr viele lokale Rotationen erhöhen die Datenträgernutzung.");
        return result;
    }

    private static void ValidateBoolBackedInt(LogManagementValidationResult result, string attributeName, int value, int min, int max, int infoMin, int infoMax, string lowInfo, string highInfo)
    {
        if (value < min || value > max)
        {
            result.Issues.Add(new LogManagementValidationIssue { Severity = LogManagementValidationSeverity.Critical, AttributeName = attributeName, Value = value.ToString(), Message = $"{attributeName} liegt außerhalb des zulässigen Bereichs {min} bis {max}." });
            return;
        }
        if (value < infoMin)
        {
            result.Issues.Add(new LogManagementValidationIssue { Severity = LogManagementValidationSeverity.Informational, AttributeName = attributeName, Value = value.ToString(), Message = lowInfo });
        }
        else if (value > infoMax)
        {
            result.Issues.Add(new LogManagementValidationIssue { Severity = LogManagementValidationSeverity.Informational, AttributeName = attributeName, Value = value.ToString(), Message = highInfo });
        }
    }
}
