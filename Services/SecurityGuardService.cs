using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class SecurityGuardService
{
    private readonly ConfigBootstrapper _configBootstrapper;

    public SecurityGuardService(ConfigBootstrapper configBootstrapper)
    {
        _configBootstrapper = configBootstrapper;
    }

    public RuntimeTrustCheckResult EnsureProductiveActionAllowed(AppConfig config, string actionName, string targetDeviceName, string? activeSessionTargetDeviceName = null)
    {
        var operationId = $"GUARD-{NormalizeOperation(actionName)}";
        var trustLogger = new TrustLogger(config.TrustLogPath, config);
        var sourceHost = Environment.MachineName;
        trustLogger.Info("SecurityGuard", "Started", "Zentraler Security-Guard aufgerufen.", operationId, sourceHost, targetDeviceName, actionName);

        if (!string.IsNullOrWhiteSpace(activeSessionTargetDeviceName) &&
            !string.IsNullOrWhiteSpace(targetDeviceName) &&
            !string.Equals(activeSessionTargetDeviceName.Trim(), targetDeviceName.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            var mismatchMessage = $"Bestehende Session gehört nicht mehr zum aktuell ausgewählten Zielgerät. SessionTarget='{activeSessionTargetDeviceName}', GUI-Ziel='{targetDeviceName}'.";
            trustLogger.Warn("SecurityGuard", "Blocked", mismatchMessage, operationId, sourceHost, targetDeviceName, actionName);
            trustLogger.Warn("SessionContextMismatch", "Failed", mismatchMessage, operationId, sourceHost, targetDeviceName, actionName);
            return new RuntimeTrustCheckResult
            {
                Allowed = false,
                Message = mismatchMessage,
                SessionShouldClose = true,
                SourceHost = sourceHost,
                DestinationHost = targetDeviceName,
                ExistingSessionTarget = activeSessionTargetDeviceName
            };
        }

        var checkResult = _configBootstrapper.RecheckBeforeProductiveAction(config, actionName, targetDeviceName);
        trustLogger.Info("SecurityGuard", checkResult.Allowed ? "Success" : "Blocked", checkResult.Message, operationId, sourceHost, targetDeviceName, actionName,
            sourceIps: checkResult.SourceIps, destinationIps: checkResult.DestinationIps, matchedAllowEntry: checkResult.MatchedAllowEntry);

        return checkResult.Allowed
            ? checkResult
            : new RuntimeTrustCheckResult
            {
                Allowed = false,
                Message = checkResult.Message,
                SessionShouldClose = !string.IsNullOrWhiteSpace(activeSessionTargetDeviceName),
                SourceHost = checkResult.SourceHost,
                SourceIps = checkResult.SourceIps,
                DestinationHost = checkResult.DestinationHost,
                DestinationIps = checkResult.DestinationIps,
                MatchedAllowEntry = checkResult.MatchedAllowEntry,
                ExistingSessionTarget = activeSessionTargetDeviceName ?? string.Empty
            };
    }

    public RuntimeTrustCheckResult RevalidateActiveSession(AppConfig config, string actionName, string selectedTargetDeviceName, string? activeSessionTargetDeviceName)
    {
        var operationId = $"SESSION-{NormalizeOperation(actionName)}";
        var trustLogger = new TrustLogger(config.TrustLogPath, config);
        var sourceHost = Environment.MachineName;
        var destinationHost = activeSessionTargetDeviceName ?? selectedTargetDeviceName;
        trustLogger.Info("SessionRevalidation", "Started", "Session-Revalidierung gestartet.", operationId, sourceHost, destinationHost, actionName);

        if (string.IsNullOrWhiteSpace(activeSessionTargetDeviceName))
        {
            const string noSessionMessage = "Keine aktive Session vorhanden.";
            trustLogger.Warn("SessionRevalidation", "Failed", noSessionMessage, operationId, sourceHost, selectedTargetDeviceName, actionName);
            return new RuntimeTrustCheckResult
            {
                Allowed = false,
                Message = noSessionMessage,
                SourceHost = sourceHost,
                DestinationHost = selectedTargetDeviceName
            };
        }

        if (!string.IsNullOrWhiteSpace(selectedTargetDeviceName) &&
            !string.Equals(activeSessionTargetDeviceName.Trim(), selectedTargetDeviceName.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            var message = $"Session nicht mehr zulässig: aktives Ziel='{activeSessionTargetDeviceName}', aktuell ausgewähltes Ziel='{selectedTargetDeviceName}'.";
            trustLogger.Warn("SessionRevalidation", "Failed", message, operationId, sourceHost, selectedTargetDeviceName, actionName);
            return new RuntimeTrustCheckResult
            {
                Allowed = false,
                Message = message,
                SessionShouldClose = true,
                SourceHost = sourceHost,
                DestinationHost = selectedTargetDeviceName,
                ExistingSessionTarget = activeSessionTargetDeviceName
            };
        }

        var result = EnsureProductiveActionAllowed(config, actionName, activeSessionTargetDeviceName, activeSessionTargetDeviceName);
        if (result.Allowed)
        {
            trustLogger.Info("SessionRevalidation", "Success", "Session-Revalidierung erfolgreich.", operationId, sourceHost, activeSessionTargetDeviceName, actionName,
                sourceIps: result.SourceIps, destinationIps: result.DestinationIps, matchedAllowEntry: result.MatchedAllowEntry);
            return result;
        }

        trustLogger.Warn("SessionRevalidation", "Failed", result.Message, operationId, sourceHost, activeSessionTargetDeviceName, actionName,
            sourceIps: result.SourceIps, destinationIps: result.DestinationIps, matchedAllowEntry: result.MatchedAllowEntry);
        trustLogger.Warn("SessionSecurityTermination", "Required", "Session muss aus Sicherheitsgründen beendet werden.", operationId, sourceHost, activeSessionTargetDeviceName, actionName,
            sourceIps: result.SourceIps, destinationIps: result.DestinationIps, matchedAllowEntry: result.MatchedAllowEntry);
        return new RuntimeTrustCheckResult
        {
            Allowed = false,
            Message = result.Message,
            SessionShouldClose = true,
            SourceHost = result.SourceHost,
            SourceIps = result.SourceIps,
            DestinationHost = result.DestinationHost,
            DestinationIps = result.DestinationIps,
            MatchedAllowEntry = result.MatchedAllowEntry,
            ExistingSessionTarget = activeSessionTargetDeviceName
        };
    }

    private static string NormalizeOperation(string actionName)
    {
        if (string.IsNullOrWhiteSpace(actionName))
        {
            return "UNKNOWN";
        }

        return actionName.Trim().ToUpperInvariant().Replace(' ', '-');
    }
}
