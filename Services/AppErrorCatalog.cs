using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public static class AppErrorCatalog
{
    public static AppErrorInfo ConfigStartupBlocked(string technicalDetails)
        => Create(AppErrorClass.CONFIG, "CONFIG-001", "Die Konfiguration konnte beim Start nicht sicher geladen werden.", technicalDetails, "Startup", "ConfigBootstrapper");

    public static AppErrorInfo ConfigSaveBlocked(string technicalDetails)
        => Create(AppErrorClass.CONFIG, "CONFIG-002", "Die Konfiguration konnte nicht gespeichert werden.", technicalDetails, "OptionsSave", "ConfigBootstrapper");

    public static AppErrorInfo TrustBlocked(string technicalDetails)
        => Create(AppErrorClass.TRUST, "TRUST-001", "Die TrustedConfig ist nicht vertrauenswürdig oder fehlerhaft. Produktive Funktionen bleiben gesperrt.", technicalDetails, "Trust", "ConfigBootstrapper");

    public static AppErrorInfo InvalidGuid(string? guidValue)
        => Create(AppErrorClass.VALIDATION, "VALIDATION-001", "Die angegebene Intune App GUID ist ungültig. Die Aktion wurde blockiert.", guidValue, "GuidValidation", "AppInputValidator", severity: "Warning");

    public static AppErrorInfo ConnectionFailed(string targetDevice, string technicalDetails)
        => Create(AppErrorClass.CONNECTION, "CONNECTION-001", $"Zum Zielgerät '{targetDevice}' konnte keine Verbindung aufgebaut werden.", technicalDetails, "Connect", "IntuneSupportService");

    public static AppErrorInfo RemoteActionFailed(string actionName, string technicalDetails)
        => Create(AppErrorClass.CONNECTION, "CONNECTION-002", $"Die Aktion '{actionName}' konnte nicht erfolgreich ausgeführt werden.", technicalDetails, actionName, "IntuneSupportService");

    public static AppErrorInfo PsExecBlocked(string technicalDetails)
        => Create(AppErrorClass.PSEXEC, "PSEXEC-001", "PsExec ist nicht verfügbar, nicht vertrauenswürdig oder versionsseitig nicht zulässig.", technicalDetails, "PsExec", "PsExecDependencyService");

    public static AppErrorInfo LiveViewFailed(string technicalDetails)
        => Create(AppErrorClass.GUI, "GUI-001", "Die Live-Ansicht konnte nicht weitergeführt werden. Die Verbindung wurde beendet.", technicalDetails, "LiveView", "MainViewModel", severity: "Warning");

    public static AppErrorInfo OptionsOperationFailed(string technicalDetails)
        => Create(AppErrorClass.GUI, "GUI-002", "Die Aktion im Optionenfenster konnte nicht abgeschlossen werden.", technicalDetails, "Options", "OptionsWindow");

    public static AppErrorInfo LogParsingUnavailable(string technicalDetails)
        => Create(AppErrorClass.LOGGING, "LOGGING-001", "Ein oder mehrere Logs konnten nicht vollständig eingelesen werden.", technicalDetails, "LogParsing", "IntuneSupportService", severity: "Warning");

    public static AppErrorInfo Unknown(string actionContext, string? technicalDetails = null, string? component = null)
        => Create(AppErrorClass.UNKNOWN, "UNKNOWN-001", "Ein unerwarteter Fehler ist aufgetreten.", technicalDetails, actionContext, component);

    public static AppErrorInfo Create(
        AppErrorClass errorClass,
        string errorCode,
        string userMessage,
        string? technicalDetails = null,
        string? actionContext = null,
        string? component = null,
        string severity = "Error")
    {
        return new AppErrorInfo
        {
            ErrorClass = errorClass,
            ErrorCode = errorCode,
            UserMessage = userMessage,
            TechnicalDetails = technicalDetails,
            ActionContext = actionContext,
            Component = component,
            Severity = severity
        };
    }
}
