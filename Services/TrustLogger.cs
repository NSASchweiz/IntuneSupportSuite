using DapIntuneSupportSuite.Models;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;

namespace DapIntuneSupportSuite.Services;

public sealed class TrustLogger
{
    private readonly string _logPath;
    private readonly LogFileManager? _logFileManager;

    public TrustLogger(string logPath, AppConfig? config = null)
    {
        _logPath = logPath;
        var directory = Path.GetDirectoryName(_logPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
        _logFileManager = config is null ? null : new LogFileManager(config);
    }

    public void Info(string action, string result, string details, string operationId = "BOOT", string? sourceHost = null, string? destinationHost = null, string? requestedAction = null, IEnumerable<string>? sourceIps = null, IEnumerable<string>? destinationIps = null, string? matchedAllowEntry = null, string? psExecPath = null, string? psExecVersion = null, string? signer = null, string? thumbprint = null, string? downloadSource = null, string? redirectChain = null, string? configurationScope = null, string? attributeName = null, string? pathValue = null, string? errorClass = null, string? errorCode = null, string? userMessage = null, string? technicalDetails = null, string? component = null)
        => Write("INFO", action, result, details, operationId, sourceHost, destinationHost, requestedAction, sourceIps, destinationIps, matchedAllowEntry, psExecPath, psExecVersion, signer, thumbprint, downloadSource, redirectChain, configurationScope, attributeName, pathValue, errorClass, errorCode, userMessage, technicalDetails, component);

    public void Warn(string action, string result, string details, string operationId = "BOOT", string? sourceHost = null, string? destinationHost = null, string? requestedAction = null, IEnumerable<string>? sourceIps = null, IEnumerable<string>? destinationIps = null, string? matchedAllowEntry = null, string? psExecPath = null, string? psExecVersion = null, string? signer = null, string? thumbprint = null, string? downloadSource = null, string? redirectChain = null, string? configurationScope = null, string? attributeName = null, string? pathValue = null, string? errorClass = null, string? errorCode = null, string? userMessage = null, string? technicalDetails = null, string? component = null)
        => Write("WARNING", action, result, details, operationId, sourceHost, destinationHost, requestedAction, sourceIps, destinationIps, matchedAllowEntry, psExecPath, psExecVersion, signer, thumbprint, downloadSource, redirectChain, configurationScope, attributeName, pathValue, errorClass, errorCode, userMessage, technicalDetails, component);

    public void Error(string action, string result, string details, string operationId = "BOOT", string? sourceHost = null, string? destinationHost = null, string? requestedAction = null, IEnumerable<string>? sourceIps = null, IEnumerable<string>? destinationIps = null, string? matchedAllowEntry = null, string? psExecPath = null, string? psExecVersion = null, string? signer = null, string? thumbprint = null, string? downloadSource = null, string? redirectChain = null, string? configurationScope = null, string? attributeName = null, string? pathValue = null, string? errorClass = null, string? errorCode = null, string? userMessage = null, string? technicalDetails = null, string? component = null)
        => Write("ERROR", action, result, details, operationId, sourceHost, destinationHost, requestedAction, sourceIps, destinationIps, matchedAllowEntry, psExecPath, psExecVersion, signer, thumbprint, downloadSource, redirectChain, configurationScope, attributeName, pathValue, errorClass, errorCode, userMessage, technicalDetails, component);

    private void Write(string severity, string action, string result, string details, string operationId, string? sourceHost, string? destinationHost, string? requestedAction, IEnumerable<string>? sourceIps, IEnumerable<string>? destinationIps, string? matchedAllowEntry, string? psExecPath, string? psExecVersion, string? signer, string? thumbprint, string? downloadSource, string? redirectChain, string? configurationScope, string? attributeName, string? pathValue, string? errorClass, string? errorCode, string? userMessage, string? technicalDetails, string? component)
    {
        var user = Environment.UserName;
        var machine = Environment.MachineName;
        var parts = new List<string>
        {
            $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}",
            severity,
            $"OperationId={operationId}",
            $"User={user}",
            $"Machine={machine}",
            $"Action={action}",
            $"Result={result}"
        };

        if (!string.IsNullOrWhiteSpace(sourceHost)) parts.Add($"SourceHost={sourceHost}");
        if (!string.IsNullOrWhiteSpace(destinationHost)) parts.Add($"DestinationHost={destinationHost}");
        if (!string.IsNullOrWhiteSpace(requestedAction)) parts.Add($"RequestedAction={requestedAction}");

        var normalizedSourceIps = sourceIps?.Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ?? [];
        if (normalizedSourceIps.Length > 0) parts.Add($"SourceIPs={string.Join(',', normalizedSourceIps)}");
        var normalizedDestinationIps = destinationIps?.Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ?? [];
        if (normalizedDestinationIps.Length > 0) parts.Add($"DestinationIPs={string.Join(',', normalizedDestinationIps)}");

        if (!string.IsNullOrWhiteSpace(matchedAllowEntry)) parts.Add($"MatchedAllowEntry={matchedAllowEntry}");
        if (!string.IsNullOrWhiteSpace(psExecPath)) parts.Add($"PsExecPath={psExecPath}");
        if (!string.IsNullOrWhiteSpace(psExecVersion)) parts.Add($"PsExecVersion={psExecVersion}");
        if (!string.IsNullOrWhiteSpace(signer)) parts.Add($"Signer={signer}");
        if (!string.IsNullOrWhiteSpace(thumbprint)) parts.Add($"Thumbprint={thumbprint}");
        if (!string.IsNullOrWhiteSpace(downloadSource)) parts.Add($"DownloadSource={downloadSource}");
        if (!string.IsNullOrWhiteSpace(redirectChain)) parts.Add($"RedirectChain={redirectChain}");
        if (!string.IsNullOrWhiteSpace(configurationScope)) parts.Add($"ConfigurationScope={configurationScope}");
        if (!string.IsNullOrWhiteSpace(attributeName)) parts.Add($"AttributeName={attributeName}");
        if (!string.IsNullOrWhiteSpace(pathValue)) parts.Add($"PathValue={pathValue}");
        if (!string.IsNullOrWhiteSpace(errorClass)) parts.Add($"ErrorClass={errorClass}");
        if (!string.IsNullOrWhiteSpace(errorCode)) parts.Add($"ErrorCode={errorCode}");
        if (!string.IsNullOrWhiteSpace(userMessage)) parts.Add($"UserMessage={userMessage}");
        if (!string.IsNullOrWhiteSpace(technicalDetails)) parts.Add($"TechnicalDetails={technicalDetails}");
        if (!string.IsNullOrWhiteSpace(component)) parts.Add($"Component={component}");

        parts.Add($"Details={details}");
        var line = string.Join("	", parts) + Environment.NewLine;

        AsyncLogDispatcher.Enqueue(() =>
        {
            var builder = new StringBuilder();
            var events = _logFileManager?.PrepareForWrite("TrustLog", _logPath, Encoding.UTF8.GetByteCount(line)) ?? [];
            foreach (var evt in events)
            {
                builder.Append($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}	INFO	OperationId={operationId}	User={user}	Machine={machine}	Action=LogRotation	Result=Info	Details={evt}{Environment.NewLine}");
            }
            builder.Append(line);
            var payload = builder.ToString();
            File.AppendAllText(_logPath, payload);
            _logFileManager?.NotifyWriteComplete(_logPath, Encoding.UTF8.GetByteCount(payload));
        });
    }
}
