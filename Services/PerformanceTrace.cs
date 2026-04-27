using System.Diagnostics;

namespace DapIntuneSupportSuite.Services;

public sealed class PerformanceTrace : IDisposable
{
    private readonly Stopwatch _stopwatch;
    private readonly AuditLogger? _auditLogger;
    private readonly TrustLogger? _trustLogger;
    private readonly string _metricName;
    private readonly string _operationId;
    private readonly string _targetDevice;
    private readonly string _guid;
    private readonly string _component;
    private readonly string _details;
    private bool _disposed;

    private PerformanceTrace(AuditLogger logger, string metricName, string operationId, string targetDevice, string guid, string component, string details)
    {
        _auditLogger = logger;
        _metricName = metricName;
        _operationId = operationId;
        _targetDevice = string.IsNullOrWhiteSpace(targetDevice) ? "-" : targetDevice;
        _guid = string.IsNullOrWhiteSpace(guid) ? "-" : guid;
        _component = component;
        _details = details;
        _stopwatch = Stopwatch.StartNew();
    }

    private PerformanceTrace(TrustLogger logger, string metricName, string operationId, string component, string details)
    {
        _trustLogger = logger;
        _metricName = metricName;
        _operationId = operationId;
        _targetDevice = "-";
        _guid = "-";
        _component = component;
        _details = details;
        _stopwatch = Stopwatch.StartNew();
    }

    public static PerformanceTrace Start(AuditLogger logger, string metricName, string operationId, string targetDevice = "-", string guid = "-", string component = "PerformanceTrace", string details = "")
        => new(logger, metricName, operationId, targetDevice, guid, component, details);

    public static PerformanceTrace Start(TrustLogger logger, string metricName, string operationId, string component = "PerformanceTrace", string details = "")
        => new(logger, metricName, operationId, component, details);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _stopwatch.Stop();
        var technicalDetails = string.IsNullOrWhiteSpace(_details)
            ? $"Metric={_metricName};ElapsedMs={_stopwatch.ElapsedMilliseconds}"
            : $"Metric={_metricName};ElapsedMs={_stopwatch.ElapsedMilliseconds};{_details}";

        if (_auditLogger is not null)
        {
            _auditLogger.Info("Performance", $"{_metricName} abgeschlossen in {_stopwatch.ElapsedMilliseconds} ms.", _targetDevice, _guid, _operationId, null, null, null, technicalDetails, _component);
        }
        else if (_trustLogger is not null)
        {
            _trustLogger.Info("Performance", "Success", $"{_metricName} abgeschlossen in {_stopwatch.ElapsedMilliseconds} ms.", _operationId, technicalDetails: technicalDetails, component: _component);
        }
    }
}
