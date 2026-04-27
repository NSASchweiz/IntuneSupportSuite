using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class AppInputValidator
{
    private readonly AuditLogger _logger;

    public AppInputValidator(AuditLogger logger)
    {
        _logger = logger;
    }

    public AppGuidValidationResult ValidateOptionalGuid(string? rawValue, string actionName, string deviceName, string operationId)
    {
        _logger.Info("GuidValidation", $"GUID-Validierung gestartet. Action={actionName}", deviceName, rawValue ?? "-", operationId);

        var trimmed = rawValue?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            _logger.Info("GuidValidation", $"GUID leer und zulässig. Action={actionName}", deviceName, "-", operationId);
            return new AppGuidValidationResult
            {
                IsValid = true,
                IsEmpty = true,
                NormalizedValue = string.Empty,
                Message = "GUID leer und zulässig."
            };
        }

        if (Guid.TryParse(trimmed, out var parsedGuid))
        {
            var normalized = parsedGuid.ToString("D");
            _logger.Info("GuidValidation", $"GUID gültig. Action={actionName}", deviceName, normalized, operationId);
            return new AppGuidValidationResult
            {
                IsValid = true,
                IsEmpty = false,
                NormalizedValue = normalized,
                Message = "GUID gültig."
            };
        }

        _logger.Warn("GuidValidation", $"GUID ungültig. Action={actionName}", deviceName, trimmed, operationId);
        return new AppGuidValidationResult
        {
            IsValid = false,
            IsEmpty = false,
            NormalizedValue = string.Empty,
            Message = "Die eingegebene Intune App GUID ist ungültig. Bitte eine gültige GUID eingeben oder das Feld leer lassen."
        };
    }
}
