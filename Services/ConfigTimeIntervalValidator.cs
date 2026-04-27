using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class ConfigTimeIntervalValidator
{
    public TimeIntervalValidationResult ValidateForSave(AppConfig config)
    {
        var result = new TimeIntervalValidationResult();

        ValidateRange(result, "config.json", nameof(AppConfig.ConnectionTimeoutSeconds), config.ConnectionTimeoutSeconds, min: 1, max: 600, hintMin: 5, hintMax: 120,
            lowHintMessage: "Sehr niedriger ConnectionTimeoutSeconds-Wert kann zu unnötigen Verbindungsabbrüchen führen.",
            highHintMessage: "Sehr hoher ConnectionTimeoutSeconds-Wert kann zu trägem Verhalten führen.");

        ValidateRange(result, "config.json", nameof(AppConfig.ConnectionStatusIntervalSeconds), config.ConnectionStatusIntervalSeconds, min: 1, max: 300, hintMin: 2, hintMax: 60,
            lowHintMessage: "Sehr niedriger ConnectionStatusIntervalSeconds-Wert kann unnötige Last erzeugen.",
            highHintMessage: "Sehr hoher ConnectionStatusIntervalSeconds-Wert verzögert Statusrückmeldungen.");

        ValidateRange(result, "config.json", nameof(AppConfig.AutoRefreshTargetLogs), config.AutoRefreshTargetLogs, min: 1, max: 3600, hintMin: 2, hintMax: 300,
            lowHintMessage: "Sehr niedriger autoRefreshTargetLogs-Wert kann unnötige Last erzeugen.",
            highHintMessage: "Sehr hoher autoRefreshTargetLogs-Wert macht den automatischen Remote-Log-Refresh träge.");

        ValidateRange(result, "config.json", nameof(AppConfig.FallbackTaskDelayMinutes), config.FallbackTaskDelayMinutes, min: 1, max: 1440, hintMin: 2, hintMax: 120,
            lowHintMessage: "Sehr niedriger FallbackTaskDelayMinutes-Wert kann unerwünschte Betriebsfolgen verursachen.",
            highHintMessage: "Sehr hoher FallbackTaskDelayMinutes-Wert verzögert den Fallback unnötig.");

        ValidateRange(result, "config.json", nameof(AppConfig.PsExecTimeoutSeconds), config.PsExecTimeoutSeconds, min: 1, max: 600, hintMin: 5, hintMax: 120,
            lowHintMessage: "Sehr niedriger PsExecTimeoutSeconds-Wert kann zu unnötigen Abbrüchen führen.",
            highHintMessage: "Sehr hoher PsExecTimeoutSeconds-Wert kann die Rückmeldung stark verzögern.");

        if (config.ConnectionStatusIntervalSeconds > config.ConnectionTimeoutSeconds)
        {
            AddIssue(result, TimeIntervalValidationSeverity.Critical, "config.json", nameof(AppConfig.ConnectionStatusIntervalSeconds),
                config.ConnectionStatusIntervalSeconds.ToString(),
                "ConnectionStatusIntervalSeconds darf nicht größer als ConnectionTimeoutSeconds sein.");
        }

        return result;
    }

    private static void ValidateRange(
        TimeIntervalValidationResult result,
        string scope,
        string attributeName,
        int value,
        int min,
        int max,
        int hintMin,
        int hintMax,
        string lowHintMessage,
        string highHintMessage)
    {
        if (value < min || value > max)
        {
            AddIssue(result, TimeIntervalValidationSeverity.Critical, scope, attributeName, value.ToString(),
                $"{attributeName} liegt außerhalb des zulässigen Bereichs {min} bis {max}.");
            return;
        }

        if (value < hintMin)
        {
            AddIssue(result, TimeIntervalValidationSeverity.Hint, scope, attributeName, value.ToString(), lowHintMessage);
        }
        else if (value > hintMax)
        {
            AddIssue(result, TimeIntervalValidationSeverity.Hint, scope, attributeName, value.ToString(), highHintMessage);
        }
    }

    private static void AddIssue(TimeIntervalValidationResult result, TimeIntervalValidationSeverity severity, string scope, string attributeName, string value, string message)
    {
        result.Issues.Add(new TimeIntervalValidationIssue
        {
            Severity = severity,
            ConfigurationScope = scope,
            AttributeName = attributeName,
            Value = value,
            Message = message
        });
    }
}
