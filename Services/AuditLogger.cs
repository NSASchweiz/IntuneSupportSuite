using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.Text;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class AuditLogger
{
    private readonly string _localLogFilePath;
    private readonly LogFileManager _logFileManager;

    public AuditLogger(AppConfig config)
    {
        var directory = Environment.ExpandEnvironmentVariables(config.LocalLogDirectory);
        Directory.CreateDirectory(directory);
        _localLogFilePath = Path.Combine(directory, "DAP-Intune-Support.log");
        _logFileManager = new LogFileManager(config);
    }

    public void Info(string action, string message, string targetDevice = "-", string guid = "-", string operationId = "APP", string? errorClass = null, string? errorCode = null, string? userMessage = null, string? technicalDetails = null, string? component = null)
        => Write("INFO", action, message, targetDevice, guid, operationId, errorClass, errorCode, userMessage, technicalDetails, component);

    public void Warn(string action, string message, string targetDevice = "-", string guid = "-", string operationId = "APP", string? errorClass = null, string? errorCode = null, string? userMessage = null, string? technicalDetails = null, string? component = null)
        => Write("WARN", action, message, targetDevice, guid, operationId, errorClass, errorCode, userMessage, technicalDetails, component);

    public void Error(string action, string message, string targetDevice = "-", string guid = "-", string operationId = "APP", string? errorClass = null, string? errorCode = null, string? userMessage = null, string? technicalDetails = null, string? component = null)
        => Write("ERROR", action, message, targetDevice, guid, operationId, errorClass, errorCode, userMessage, technicalDetails, component);

    private void Write(string level, string action, string message, string targetDevice, string guid, string operationId, string? errorClass, string? errorCode, string? userMessage, string? technicalDetails, string? component)
    {
        var jumpHost = Environment.MachineName;
        var user = WindowsIdentity.GetCurrent().Name;
        var parts = new List<string>
        {
            $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}",
            level,
            $"OperationId={operationId}",
            $"JumpHost={jumpHost}",
            $"User={user}",
            $"Target={targetDevice}",
            $"Action={action}",
            $"Guid={guid}",
            $"Message={message}"
        };

        if (!string.IsNullOrWhiteSpace(errorClass)) parts.Add($"ErrorClass={errorClass}");
        if (!string.IsNullOrWhiteSpace(errorCode)) parts.Add($"ErrorCode={errorCode}");
        if (!string.IsNullOrWhiteSpace(userMessage)) parts.Add($"UserMessage={userMessage}");
        if (!string.IsNullOrWhiteSpace(technicalDetails)) parts.Add($"TechnicalDetails={technicalDetails}");
        if (!string.IsNullOrWhiteSpace(component)) parts.Add($"Component={component}");

        var line = string.Join("	", parts) + Environment.NewLine;
        AsyncLogDispatcher.Enqueue(() =>
        {
            var rotationEvents = _logFileManager.PrepareForWrite("LocalAppLog", _localLogFilePath, Encoding.UTF8.GetByteCount(line));
            var builder = new StringBuilder();
            foreach (var evt in rotationEvents)
            {
                builder.Append($"{DateTime.Now:yyyy-MM-dd HH:mm:ss}	INFO	OperationId={operationId}	JumpHost={jumpHost}	User={user}	Target={targetDevice}	Action=LogRotation	Guid={guid}	Message={evt}{Environment.NewLine}");
            }
            builder.Append(line);
            var payload = builder.ToString();
            using (var stream = new FileStream(_localLogFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
            {
                writer.Write(payload);
            }
            _logFileManager.NotifyWriteComplete(_localLogFilePath, Encoding.UTF8.GetByteCount(payload));
        });
    }
}
