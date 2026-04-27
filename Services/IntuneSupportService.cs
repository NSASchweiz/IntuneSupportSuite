using System.Linq;
using System.IO;
using System.Text.Json;
using System.Threading;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class IntuneSupportService
{
    public bool HasPreparedFallback { get; private set; }
    public bool HasActiveConnection { get; private set; }

    private static readonly Dictionary<string, string> BootstrapStatusMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["FallbackDirectory"] = "Fallback-Verzeichnis wird vorbereitet...",
        ["FallbackScript"] = "Fallback-Skript wird übertragen...",
        ["FallbackConfig"] = "Fallback-Konfiguration wird erstellt...",
        ["ScheduledTask"] = "Geplanter Task wird erstellt...",
        ["ScheduledTaskRetry"] = "Geplanter Task wird erneut geprüft...",
        ["RunOnce"] = "RunOnce wird gesetzt...",
        ["FallbackArm"] = "Fallback wird scharf geschaltet...",
        ["VerifyPsRemoting"] = "PSRemoting wird geprüft...",
        ["EnablePsRemoting"] = "PSRemoting wird aktiviert...",
        ["RestoreRemoting"] = "PSRemoting-Ursprungszustand wird wiederhergestellt..."
    };
    private IReadOnlyDictionary<string, string> LogKeyToFileMap => new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["AgentExecutor"] = "AgentExecutor.log",
        ["AppActionProcessor"] = "AppActionProcessor.log",
        ["AppWorkload"] = "AppWorkload.log",
        ["ClientCertCheck"] = "ClientCertCheck.log",
        ["ClientHealth"] = "ClientHealth.log",
        ["DeviceHealthMonitoring"] = "DeviceHealthMonitoring.log",
        ["HealthScripts"] = "HealthScripts.log",
        ["IntuneManagementExtension"] = "IntuneManagementExtension.log",
        ["CompanyPortal"] = "Company Portal",
        ["Enrollment"] = "Enrollment",
        ["MdmDiagnostics"] = "MDM Diagnoseartefakte",
        ["EventLogChannels"] = "Event-Log-Kanäle",
        ["InstallAgentEvents"] = "Install-Agent Events",
        ["DeviceRegistrySettings"] = "Intune Registry Settings",
        ["NotificationInfraLogs"] = "NotificationInfraLogs.log",
        ["Sensor"] = "Sensor.log",
        ["Win321AppInventory"] = "Win32AppInventory.log",
        ["Win32AppsRegistry"] = "Win32Apps Registry",
        ["LocalAppLog"] = LanguageManager.Instance.GetLocalAppLogLabel(),
        ["AppDataLogs"] = "Log Verlauf",
        ["RemoteAuditLog"] = LanguageManager.Instance.GetRemoteAuditLogLabel(),
        ["FallbackLog"] = LanguageManager.Instance.GetFallbackLogLabel(),
        ["TrustLog"] = "Trust Log"
    };

    private static readonly HashSet<string> LocalLogKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "LocalAppLog",
        "AppDataLogs",
        "TrustLog"
    };

    private readonly PowerShellRunner _powerShellRunner;
    private readonly AuditLogger _logger;
    private readonly AppConfig _config;
    private readonly LogParser _logParser;
    private readonly string _sourceHost;
    private readonly string _expectedAppSignerThumbprint;
    private readonly string _expectedAppSignerPublicKey;

    public IntuneSupportService(PowerShellRunner powerShellRunner, AuditLogger logger, AppConfig config)
    {
        _powerShellRunner = powerShellRunner;
        _logger = logger;
        _config = config;
        _logParser = new LogParser(config, logger);
        _sourceHost = Environment.MachineName;
        var appSignature = ResolveCurrentExecutableSignature();
        _expectedAppSignerThumbprint = appSignature.Thumbprint ?? string.Empty;
        _expectedAppSignerPublicKey = appSignature.PublicKey ?? string.Empty;
    }

    public async Task<RemoteOperationResult> TestConnectionAsync(string deviceName, int? timeoutSeconds = null)
    {
        _logger.Info("Connect", "Verbindungsaufbau gestartet.", deviceName);
        var script = ResolveScript("Test-RemoteConnection.ps1");
        var result = await _powerShellRunner.ExecuteScriptAsync(script, BuildTestConnectionArguments(deviceName, Guid.NewGuid().ToString()), timeoutSeconds ?? _config.ConnectionTimeoutSeconds);

        if (result.Success)
        {
            HasPreparedFallback = result.StandardOutput.Contains("FallbackPrepared=True", StringComparison.OrdinalIgnoreCase);
            HasActiveConnection = true;
            _logger.Info("Connect", string.IsNullOrWhiteSpace(result.StandardOutput) ? "Verbindung erfolgreich etabliert." : result.StandardOutput, deviceName);
        }
        else
        {
            HasActiveConnection = false;
            _logger.Error("Connect", string.IsNullOrWhiteSpace(result.StandardError) ? result.Message : result.StandardError, deviceName);
        }

        return result;
    }

    public async Task<bool> TestActiveConnectionAsync(string deviceName)
    {
        var script = ResolveScript("Verify-Connection.ps1");
        var result = await _powerShellRunner.ExecuteScriptAsync(script, new Dictionary<string, string?>
        {
            ["ComputerName"] = deviceName,
            ["SimulationMode"] = _config.SimulationMode.ToString()
        }, Math.Max(5, _config.ConnectionStatusIntervalSeconds));

        HasActiveConnection = result.Success;
        return result.Success;
    }

    public async Task<RemoteOperationResult> TriggerFallbackAsync(string deviceName)
    {
        var script = ResolveScript("Trigger-Fallback.ps1");
        var result = await _powerShellRunner.ExecuteScriptAsync(script, BuildTriggerFallbackArguments(deviceName), Math.Max(10, _config.ConnectionStatusIntervalSeconds));
        if (result.Success)
        {
            HasPreparedFallback = false;
            HasActiveConnection = false;
        }
        return result;
    }


    public async Task<LogBundle> ReadRelevantLogsAsync(string deviceName, string? appGuid, bool suppressAudit = false, IReadOnlyDictionary<string, RemoteLogReadState>? previousStates = null)
    {
        using var perf = PerformanceTrace.Start(_logger, "ReadRelevantLogsAsync", "READLOGS", deviceName, appGuid ?? "-", nameof(IntuneSupportService), $"SuppressAudit={suppressAudit}");
        if (!suppressAudit)
        {
            _logger.Info("ReadLogs", "IME Logs werden ausgelesen.", deviceName, appGuid ?? "-");
        }
        var script = ResolveScript("Get-ImeLogs.ps1");
        var result = await _powerShellRunner.ExecuteScriptAsync(script, BuildReadLogsArguments(deviceName, appGuid, Guid.NewGuid().ToString(), suppressAudit, previousStates));

        if (!result.Success)
        {
            if (!suppressAudit)
            {
                _logger.Error("ReadLogs", string.IsNullOrWhiteSpace(result.StandardError) ? result.Message : result.StandardError, deviceName, appGuid ?? "-");
            }
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.StandardError) ? result.Message : result.StandardError);
        }

        return ParseLogBundle(result.StandardOutput, deviceName, appGuid);
    }

    public async Task<RemoteOperationResult> ResetImeLogsAsync(string deviceName)
    {
        _logger.Warn("ImeLogReset", "IME Log Reset wurde ausgelöst.", deviceName);
        var script = ResolveScript("Reset-ImeLogs.ps1");
        var result = await _powerShellRunner.ExecuteScriptAsync(script, BuildResetImeLogsArguments(deviceName, Guid.NewGuid().ToString()));
        LogOperationResult("ImeLogReset", result, deviceName);
        return CreateUserMessageResult(result);
    }

    public async Task<RemoteOperationResult> ResetAppInstallAsync(string deviceName, string appGuid)
    {
        _logger.Warn("ResetAppInstall", "Reset App Install wurde ausgelöst.", deviceName, appGuid);
        var script = ResolveScript("Reset-AppInstall.ps1");
        var result = await _powerShellRunner.ExecuteScriptAsync(script, BuildResetAppInstallArguments(deviceName, appGuid, Guid.NewGuid().ToString()));
        LogOperationResult("ResetAppInstall", result, deviceName, appGuid);
        return CreateUserMessageResult(result);
    }

    public async Task<RemoteOperationResult> RestartImeServiceAsync(string deviceName)
    {
        _logger.Warn("ImeRestart", "IME Restart wurde ausgelöst.", deviceName);
        var script = ResolveScript("Reset-ImeService.ps1");
        var result = await _powerShellRunner.ExecuteScriptAsync(script, BuildRestartImeArguments(deviceName, Guid.NewGuid().ToString()));
        LogOperationResult("ImeRestart", result, deviceName);
        return CreateUserMessageResult(result);
    }

    public async Task<RemoteOperationResult> ExecuteWsResetAsync(string deviceName)
    {
        _logger.Warn("WSReset", "WSReset wurde ausgelöst. Danach wird der IME-Dienst neu gestartet.", deviceName);
        var script = ResolveScript("Invoke-WSReset.ps1");
        var result = await _powerShellRunner.ExecuteScriptAsync(script, BuildWsResetArguments(deviceName, Guid.NewGuid().ToString()), Math.Max(240, _config.ConnectionTimeoutSeconds));
        LogOperationResult("WSReset", result, deviceName);
        return CreateUserMessageResult(result);
    }

    public async Task<IReadOnlyDictionary<string, string>> ResolveAppNamesAsync(string deviceName, IEnumerable<string> appGuids)
    {
        var distinctGuids = appGuids?
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray() ?? [];

        if (distinctGuids.Length == 0)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        var script = ResolveScript("Resolve-AppNames.ps1");
        var result = await _powerShellRunner.ExecuteScriptAsync(
            script,
            BuildResolveAppNamesArguments(deviceName, distinctGuids, Guid.NewGuid().ToString()),
            Math.Max(20, _config.ConnectionTimeoutSeconds));

        if (!result.Success || string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        try
        {
            using var document = JsonDocument.Parse(result.StandardOutput);
            if (!document.RootElement.TryGetProperty("Names", out var namesElement)
                || namesElement.ValueKind != JsonValueKind.Object)
            {
                return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }

            var resolved = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in namesElement.EnumerateObject())
            {
                var value = property.Value.GetString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    resolved[property.Name] = value.Trim();
                }
            }

            return resolved;
        }
        catch (JsonException)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private Dictionary<string, string?> BuildTestConnectionArguments(string deviceName, string operationId)
    {
        var arguments = CreateBootstrapArguments(deviceName, operationId);
        arguments["RemoteAuditLogDirectory"] = _config.RemoteAuditLogDirectory;
        arguments["FallbackTaskDelayMinutes"] = _config.FallbackTaskDelayMinutes.ToString();
        return arguments;
    }

    private Dictionary<string, string?> BuildReadLogsArguments(string deviceName, string? appGuid, string operationId, bool suppressAudit, IReadOnlyDictionary<string, RemoteLogReadState>? previousStates = null)
    {
        var arguments = CreateBootstrapArguments(deviceName, operationId);
        AddIfHasValue(arguments, "AppGuid", appGuid);
        arguments["ImeLogPath"] = _config.RemoteImeLogDirectory;
        arguments["ServiceName"] = _config.ImeServiceName;
        arguments["RemoteAuditLogDirectory"] = _config.RemoteAuditLogDirectory;
        arguments["RemoteTempDirectory"] = _config.RemoteTempDirectory;
        arguments["LogFilesCsv"] = string.Join(';', _config.DefaultLogFiles);
        arguments["FallbackTaskDelayMinutes"] = _config.FallbackTaskDelayMinutes.ToString();
        arguments["SuppressReadAudit"] = suppressAudit.ToString();
        arguments["ShortDestinationLogs"] = _config.ShortDestinationLogs.ToString();
        arguments["DestinationLogMaxAgeDays"] = "10";
        if (previousStates is not null && previousStates.Count > 0)
        {
            arguments["PreviousLogStatesJson"] = JsonSerializer.Serialize(previousStates);
        }
        return arguments;
    }

    private Dictionary<string, string?> BuildResetImeLogsArguments(string deviceName, string operationId)
    {
        var arguments = CreateBootstrapArguments(deviceName, operationId);
        arguments["ImeLogPath"] = _config.RemoteImeLogDirectory;
        arguments["RemoteAuditLogDirectory"] = _config.RemoteAuditLogDirectory;
        arguments["ServiceName"] = _config.ImeServiceName;
        arguments["FallbackTaskDelayMinutes"] = _config.FallbackTaskDelayMinutes.ToString();
        return arguments;
    }

    private Dictionary<string, string?> BuildResetAppInstallArguments(string deviceName, string appGuid, string operationId)
    {
        var arguments = CreateBootstrapArguments(deviceName, operationId);
        arguments["AppGuid"] = appGuid;
        arguments["ServiceName"] = _config.ImeServiceName;
        arguments["RegistryPathsCsv"] = string.Join(';', _config.RegistryPathsForAppReset);
        arguments["RemoteAuditLogDirectory"] = _config.RemoteAuditLogDirectory;
        arguments["FallbackTaskDelayMinutes"] = _config.FallbackTaskDelayMinutes.ToString();
        return arguments;
    }


    private Dictionary<string, string?> BuildRestartImeArguments(string deviceName, string operationId)
    {
        var arguments = CreateBootstrapArguments(deviceName, operationId);
        arguments["RemoteAuditLogDirectory"] = _config.RemoteAuditLogDirectory;
        arguments["ServiceName"] = _config.ImeServiceName;
        arguments["FallbackTaskDelayMinutes"] = _config.FallbackTaskDelayMinutes.ToString();
        return arguments;
    }

    private Dictionary<string, string?> BuildWsResetArguments(string deviceName, string operationId)
    {
        var arguments = CreateBootstrapArguments(deviceName, operationId);
        arguments["RemoteAuditLogDirectory"] = _config.RemoteAuditLogDirectory;
        arguments["ServiceName"] = _config.ImeServiceName;
        arguments["FallbackTaskDelayMinutes"] = _config.FallbackTaskDelayMinutes.ToString();
        return arguments;
    }

    private Dictionary<string, string?> BuildResolveAppNamesArguments(string deviceName, IEnumerable<string> appGuids, string operationId)
    {
        return new Dictionary<string, string?>
        {
            ["ComputerName"] = deviceName,
            ["AppGuidsCsv"] = string.Join(';', appGuids),
            ["OperationId"] = operationId,
            ["SimulationMode"] = _config.SimulationMode.ToString()
        };
    }

    private Dictionary<string, string?> BuildTriggerFallbackArguments(string deviceName)
    {
        return new Dictionary<string, string?>
        {
            ["ComputerName"] = deviceName,
            ["SupportClientDirectory"] = _config.SupportClientDirectory,
            ["FallbackScriptFileName"] = _config.FallbackScriptFileName,
            ["SimulationMode"] = _config.SimulationMode.ToString()
        };
    }

    private Dictionary<string, string?> CreateBootstrapArguments(string deviceName, string operationId)
    {
        return new Dictionary<string, string?>
        {
            ["ComputerName"] = deviceName,
            ["SimulationMode"] = _config.SimulationMode.ToString(),
            ["PowerShellExecutable"] = _config.PowerShellExecutable,
            ["OperationId"] = operationId,
            ["PsExecPath"] = _config.PsExecPath,
            ["SupportClientDirectory"] = _config.SupportClientDirectory,
            ["FallbackConfigFileName"] = _config.FallbackConfigFileName,
            ["FallbackScriptFileName"] = _config.FallbackScriptFileName,
            ["FallbackScheduledTaskName"] = _config.FallbackScheduledTaskName,
            ["FallbackRunOnceValueName"] = _config.FallbackRunOnceValueName,
            ["RemoteAuditLogFileName"] = LanguageManager.Instance.GetRemoteAuditLogFileName(),
            ["RemoteFallbackLogFileName"] = _config.RemoteFallbackLogFileName,
            ["ConnectionFallback"] = _config.ConnectionFallback.ToString(),
            ["RestoreRemotingState"] = _config.RestoreRemotingState.ToString(),
            ["FallbackTaskDelayMinutes"] = _config.FallbackTaskDelayMinutes.ToString(),
            ["SourceHost"] = _sourceHost,
            ["ExpectedAppSignerThumbprint"] = _expectedAppSignerThumbprint,
            ["ExpectedAppSignerPublicKey"] = _expectedAppSignerPublicKey
        };
    }


    private static SignatureVerificationResult ResolveCurrentExecutableSignature()
    {
        try
        {
            var executablePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
            {
                return SignatureVerificationResult.Failed("Aktueller EXE-Pfad konnte nicht bestimmt werden.");
            }

            var verifier = new AuthentiCodeVerifier();
            return verifier.Verify(executablePath);
        }
        catch (Exception ex)
        {
            return SignatureVerificationResult.Failed(ex.Message);
        }
    }

    private static void AddIfHasValue(IDictionary<string, string?> arguments, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            arguments[key] = value;
        }
    }

    private void LogOperationResult(string action, RemoteOperationResult result, string deviceName, string guid = "-")
    {
        if (result.Success)
        {
            _logger.Info(action, string.IsNullOrWhiteSpace(result.StandardOutput) ? result.Message : result.StandardOutput, deviceName, guid);
        }
        else
        {
            _logger.Error(action, string.IsNullOrWhiteSpace(result.StandardError) ? result.Message : result.StandardError, deviceName, guid);
        }
    }

    private static RemoteOperationResult CreateUserMessageResult(RemoteOperationResult result)
    {
        var combined = string.Join(Environment.NewLine,
            new[] { result.StandardOutput.Trim(), result.StandardError.Trim() }.Where(static x => !string.IsNullOrWhiteSpace(x)));

        return new RemoteOperationResult
        {
            Success = result.Success,
            Message = result.Success ? "Operation erfolgreich abgeschlossen." : "Operation fehlgeschlagen.",
            StandardOutput = combined,
            StandardError = result.StandardError
        };
    }


    public string? GetLatestBootstrapStatus(string deviceName)
    {
        try
        {
            var lines = ReadRemoteBootstrapLogLines(deviceName, 80);
            for (var i = lines.Count - 1; i >= 0; i--)
            {
                var line = lines[i];
                var action = ExtractTokenValue(line, "Action");
                if (string.IsNullOrWhiteSpace(action))
                {
                    continue;
                }

                if (!BootstrapStatusMap.TryGetValue(action, out var status))
                {
                    continue;
                }

                if (line.Contains("	ERROR	", StringComparison.OrdinalIgnoreCase))
                {
                    return status.Replace("...", string.Empty, StringComparison.Ordinal) + " fehlgeschlagen...";
                }

                return status;
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractTokenValue(string line, string key)
    {
        var marker = key + "=";
        var index = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return null;
        }

        index += marker.Length;
        var endIndex = line.IndexOf('	', index);
        if (endIndex < 0)
        {
            endIndex = line.Length;
        }

        return line[index..endIndex].Trim();
    }

    public string? GetConnectionTimeoutDiagnostic(string deviceName)
    {
        try
        {
            var lines = ReadRemoteBootstrapLogLines(deviceName, 120);
            if (lines.Count == 0)
            {
                return null;
            }

            var latestError = lines.LastOrDefault(static line => line.Contains("	ERROR	", StringComparison.OrdinalIgnoreCase));
            var runOnceOk = lines.Any(static line => line.Contains("Action=RunOnce", StringComparison.OrdinalIgnoreCase) && line.Contains("erfolgreich erstellt", StringComparison.OrdinalIgnoreCase));
            var taskError = lines.LastOrDefault(static line => line.Contains("Action=ScheduledTask", StringComparison.OrdinalIgnoreCase) && line.Contains("konnte nicht erstellt werden", StringComparison.OrdinalIgnoreCase));
            var runOnceError = lines.LastOrDefault(static line => line.Contains("Action=RunOnce", StringComparison.OrdinalIgnoreCase) && line.Contains("konnte nicht erstellt werden", StringComparison.OrdinalIgnoreCase));
            var scriptError = lines.LastOrDefault(static line => line.Contains("Action=FallbackScript", StringComparison.OrdinalIgnoreCase) && line.Contains("konnte nicht", StringComparison.OrdinalIgnoreCase));
            var configError = lines.LastOrDefault(static line => line.Contains("Action=FallbackConfig", StringComparison.OrdinalIgnoreCase) && line.Contains("konnte nicht", StringComparison.OrdinalIgnoreCase));
            var remotingError = lines.LastOrDefault(static line => line.Contains("Action=EnablePsRemoting", StringComparison.OrdinalIgnoreCase) && line.Contains("	ERROR	", StringComparison.OrdinalIgnoreCase));
            var restoreError = lines.LastOrDefault(static line => line.Contains("Restore fehlgeschlagen", StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrWhiteSpace(runOnceError))
            {
                return $"Interpretation: RunOnce konnte auf dem Zielgerät nicht erstellt werden.{Environment.NewLine}{runOnceError}";
            }

            if (!string.IsNullOrWhiteSpace(scriptError))
            {
                return $"Interpretation: fallbackcore.ps1 konnte auf dem Zielgerät nicht sauber bereitgestellt werden.{Environment.NewLine}{scriptError}";
            }

            if (!string.IsNullOrWhiteSpace(configError))
            {
                return $"Interpretation: fallbackconfig.json konnte auf dem Zielgerät nicht erstellt werden.{Environment.NewLine}{configError}";
            }

            if (!string.IsNullOrWhiteSpace(taskError) && runOnceOk)
            {
                return $"Interpretation: Der geplante Task konnte nicht erstellt werden. RunOnce wurde laut Ziel-Log jedoch erfolgreich erstellt; darauf wird als Fallback weitergebaut.{Environment.NewLine}{taskError}";
            }

            if (!string.IsNullOrWhiteSpace(taskError))
            {
                return $"Interpretation: Der geplante Task konnte auf dem Zielgerät nicht erstellt werden.{Environment.NewLine}{taskError}";
            }

            if (!string.IsNullOrWhiteSpace(remotingError))
            {
                return $"Interpretation: PSRemoting konnte im Bootstrap nicht sauber aktiviert werden.{Environment.NewLine}{remotingError}";
            }

            if (!string.IsNullOrWhiteSpace(restoreError))
            {
                return $"Interpretation: Der Restore des ursprünglichen PSRemoting-Zustands ist fehlgeschlagen.{Environment.NewLine}{restoreError}";
            }

            if (!string.IsNullOrWhiteSpace(latestError))
            {
                return $"Interpretation: Auf dem Zielgerät wurde vor dem Timeout ein Fehler geloggt.{Environment.NewLine}{latestError}";
            }

            var latestInteresting = lines.LastOrDefault(static line => line.Contains("Action=RunOnce", StringComparison.OrdinalIgnoreCase) || line.Contains("Action=ScheduledTask", StringComparison.OrdinalIgnoreCase) || line.Contains("Action=EnablePsRemoting", StringComparison.OrdinalIgnoreCase));
            return string.IsNullOrWhiteSpace(latestInteresting) ? null : $"Letzter Zielgerätehinweis vor Timeout:{Environment.NewLine}{latestInteresting}";
        }
        catch (Exception ex)
        {
            _logger.Warn("ConnectTimeoutDiagnosis", $"Timeout-Diagnose konnte nicht gelesen werden: {ex.Message}", deviceName);
            return null;
        }
    }

    private List<string> ReadRemoteBootstrapLogLines(string deviceName, int maxLines)
    {
        var lines = new List<string>();
        foreach (var fileName in LanguageManager.Instance.GetKnownFallbackLogFileNameVariants().Concat(LanguageManager.Instance.GetKnownRemoteAuditLogFileNameVariants()).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var uncPath = BuildRemoteUncPath(deviceName, Path.Combine(_config.RemoteAuditLogDirectory, fileName));
            if (!File.Exists(uncPath))
            {
                continue;
            }

            lines.AddRange(File.ReadLines(uncPath).TakeLast(maxLines));
        }

        return lines;
    }

    private static string BuildRemoteUncPath(string deviceName, string localPath)
    {
        var normalized = localPath.Replace('/', '\\');
        if (normalized.Length < 3 || normalized[1] != ':' || normalized[2] != '\\')
        {
            throw new InvalidOperationException($"Ungültiger lokaler Pfad für UNC-Umwandlung: {localPath}");
        }

        var driveLetter = char.ToUpperInvariant(normalized[0]);
        var relative = normalized.Substring(3);
        return $@"\\{deviceName}\{driveLetter}$\{relative}";
    }

    private string? ResolveLatestLocalAppLogPath()
    {
        var directory = Environment.ExpandEnvironmentVariables(_config.LocalLogDirectory);
        if (!Directory.Exists(directory))
        {
            return null;
        }

        var activePath = Path.Combine(directory, LanguageManager.Instance.GetLocalAppLogFileName());
        if (File.Exists(activePath))
        {
            return activePath;
        }

        return LanguageManager.Instance.GetKnownLocalAppLogFileNameVariants()
            .SelectMany(fileName => Directory.GetFiles(directory, Path.GetFileNameWithoutExtension(fileName) + "*.log"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }

    private static string[] ReadTailLinesShared(string path, int maxLines)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        for (var attempt = 0; attempt < 4; attempt++)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream);
                var queue = new Queue<string>();
                while (!reader.EndOfStream)
                {
                    var line = reader.ReadLine() ?? string.Empty;
                    queue.Enqueue(line);
                    if (queue.Count > maxLines)
                    {
                        queue.Dequeue();
                    }
                }

                return queue.ToArray();
            }
            catch (IOException) when (attempt < 3)
            {
                Thread.Sleep(40 * (attempt + 1));
            }
        }

        return [];
    }

    private string[] ReadAppDataLogLines()
    {
        var directory = Environment.ExpandEnvironmentVariables(_config.LocalLogDirectory);
        if (!Directory.Exists(directory))
        {
            return [];
        }

        return LanguageManager.Instance.GetKnownLocalAppLogFileNameVariants()
            .SelectMany(fileName => Directory.GetFiles(directory, Path.GetFileNameWithoutExtension(fileName) + "*.log"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .SelectMany(path => ReadTailLinesShared(path, 200))
            .TakeLast(1000)
            .ToArray();
    }


    public LogBundle ReadLocalProgramLogs(string deviceName, string? appGuid)
    {
        var entriesByKey = new Dictionary<string, List<LogEntry>>(StringComparer.OrdinalIgnoreCase);
        var failures = new List<LogParseFailure>();

        foreach (var mapping in LogKeyToFileMap.Where(item => LocalLogKeys.Contains(item.Key)))
        {
            try
            {
                var lines = GetLocalLogLines(mapping.Key);
                var parseResult = _logParser.Parse(mapping.Key, mapping.Value, lines, "LOCAL-REFRESH");
                entriesByKey[mapping.Key] = parseResult.Entries;
            }
            catch (Exception ex)
            {
                failures.Add(new LogParseFailure { LogKey = mapping.Key, LogName = mapping.Value, Reason = ex.Message });
                entriesByKey[mapping.Key] = [];
            }
        }

        return new LogBundle { EntriesByKey = entriesByKey, FailedLogs = failures, ReadStates = new Dictionary<string, RemoteLogReadState>(StringComparer.OrdinalIgnoreCase) };
    }

    private string[] GetLocalLogLines(string logKey)
    {
        if (logKey.Equals("TrustLog", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(_config.TrustLogPath) && File.Exists(_config.TrustLogPath))
            {
                return ReadTailLinesShared(_config.TrustLogPath, 500);
            }

            return [];
        }

        if (logKey.Equals("LocalAppLog", StringComparison.OrdinalIgnoreCase))
        {
            var localAppLogPath = ResolveLatestLocalAppLogPath();
            if (!string.IsNullOrWhiteSpace(localAppLogPath) && File.Exists(localAppLogPath))
            {
                return ReadTailLinesShared(localAppLogPath, 500);
            }

            return [];
        }

        if (logKey.Equals("AppDataLogs", StringComparison.OrdinalIgnoreCase))
        {
            return ReadAppDataLogLines();
        }

        return [];
    }

    private string? GetProcessedRunDirectory(string? appGuid)
    {
        var processedDirectory = Environment.ExpandEnvironmentVariables(_config.LocalProcessingDirectory ?? string.Empty);
        if (string.IsNullOrWhiteSpace(processedDirectory))
        {
            return null;
        }

        var runDirectory = Path.Combine(processedDirectory, string.IsNullOrWhiteSpace(appGuid) ? "latest_all" : ("latest_" + appGuid));
        Directory.CreateDirectory(runDirectory);
        return runDirectory;
    }

    private void PersistProcessedRemoteLogSnapshot(string? runDirectory, string fileName, string[] lines, string updateMode)
    {
        if (string.IsNullOrWhiteSpace(runDirectory) || string.Equals(updateMode, "Unchanged", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var path = Path.Combine(runDirectory, fileName);
        if (string.Equals(updateMode, "Append", StringComparison.OrdinalIgnoreCase) && File.Exists(path))
        {
            File.AppendAllLines(path, lines);
            return;
        }

        File.WriteAllLines(path, lines);
    }

    private LogBundle ParseLogBundle(string jsonPayload, string deviceName, string? appGuid)
    {
        using var perf = PerformanceTrace.Start(_logger, "ParseLogBundle", "READLOGS", deviceName, appGuid ?? "-", nameof(IntuneSupportService));
        if (string.IsNullOrWhiteSpace(jsonPayload))
        {
            throw new InvalidOperationException("Leere Antwort beim Auslesen der Remote-Logs.");
        }

        using var document = JsonDocument.Parse(jsonPayload);
        var root = document.RootElement;
        if (!root.TryGetProperty("Success", out var successElement) || !successElement.GetBoolean())
        {
            var errorMessage = root.TryGetProperty("ErrorMessage", out var errorElement)
                ? errorElement.GetString()
                : "Remote-Logauslese fehlgeschlagen.";
            throw new InvalidOperationException(errorMessage);
        }

        var entriesByKey = new Dictionary<string, List<LogEntry>>(StringComparer.OrdinalIgnoreCase);
        var failures = new List<LogParseFailure>();
        var readStates = new Dictionary<string, RemoteLogReadState>(StringComparer.OrdinalIgnoreCase);
        string? runDirectory = null;

        foreach (var mapping in LogKeyToFileMap)
        {
            try
            {
                var lines = Array.Empty<string>();
                var readState = new RemoteLogReadState { UpdateMode = "Full", Exists = true };
                if (mapping.Key.Equals("TrustLog", StringComparison.OrdinalIgnoreCase))
                {
                    if (!string.IsNullOrWhiteSpace(_config.TrustLogPath) && File.Exists(_config.TrustLogPath))
                    {
                        lines = ReadTailLinesShared(_config.TrustLogPath, 500);
                    }
                    readState.FilteredLineCount = lines.Length;
                }
                else if (mapping.Key.Equals("LocalAppLog", StringComparison.OrdinalIgnoreCase))
                {
                    var localAppLogPath = ResolveLatestLocalAppLogPath();
                    if (!string.IsNullOrWhiteSpace(localAppLogPath) && File.Exists(localAppLogPath))
                    {
                        lines = ReadTailLinesShared(localAppLogPath, 500);
                    }
                    readState.FilteredLineCount = lines.Length;
                }
                else if (mapping.Key.Equals("AppDataLogs", StringComparison.OrdinalIgnoreCase))
                {
                    lines = ReadAppDataLogLines();
                    readState.FilteredLineCount = lines.Length;
                }
                else if (root.TryGetProperty("Logs", out var logsElement) && logsElement.ValueKind == JsonValueKind.Object)
                {
                    if (logsElement.TryGetProperty(mapping.Key, out var logNode))
                    {
                        if (logNode.ValueKind == JsonValueKind.Object && logNode.TryGetProperty("Lines", out var linesNode))
                        {
                            lines = ExtractLogLines(linesNode).ToArray();
                            if (logNode.TryGetProperty("UpdateMode", out var modeNode) && modeNode.ValueKind == JsonValueKind.String)
                            {
                                readState.UpdateMode = modeNode.GetString() ?? "Full";
                            }
                            if (logNode.TryGetProperty("LastWriteUtc", out var lastWriteNode) && lastWriteNode.ValueKind == JsonValueKind.String)
                            {
                                readState.LastWriteUtc = lastWriteNode.GetString() ?? string.Empty;
                            }
                            if (logNode.TryGetProperty("FilteredLineCount", out var lineCountNode) && lineCountNode.ValueKind == JsonValueKind.Number)
                            {
                                readState.FilteredLineCount = lineCountNode.GetInt32();
                            }
                            if (logNode.TryGetProperty("Exists", out var existsNode) && (existsNode.ValueKind == JsonValueKind.True || existsNode.ValueKind == JsonValueKind.False))
                            {
                                readState.Exists = existsNode.GetBoolean();
                            }
                        }
                        else
                        {
                            lines = ExtractLogLines(logNode).ToArray();
                            readState.FilteredLineCount = lines.Length;
                        }
                    }
                }

                if (readState.FilteredLineCount == 0 && lines.Length > 0)
                {
                    readState.FilteredLineCount = lines.Length;
                }

                lines = ApplyDestinationLogShorteningIfEnabled(mapping.Key, lines);
                readState.FilteredLineCount = Math.Max(readState.FilteredLineCount, lines.Length);
                readStates[mapping.Key] = readState;
                if (!string.Equals(readState.UpdateMode, "Unchanged", StringComparison.OrdinalIgnoreCase))
                {
                    runDirectory ??= GetProcessedRunDirectory(appGuid);
                    PersistProcessedRemoteLogSnapshot(runDirectory, mapping.Value, lines, readState.UpdateMode ?? "Full");
                }
                using var parsePerf = PerformanceTrace.Start(_logger, $"ParseLog:{mapping.Key}", "READLOGS", deviceName, appGuid ?? "-", nameof(IntuneSupportService), $"UpdateMode={readState.UpdateMode};Lines={lines.Length}");
                var parseResult = _logParser.Parse(mapping.Key, mapping.Value, lines, "READLOGS");
                if (parseResult.LineFallbackCount > 0)
                {
                    _logger.Warn("LogParsing", $"Log {mapping.Key} wurde teilweise mit Fallback verarbeitet.", deviceName, appGuid ?? "-", "READLOGS", AppErrorClass.LOGGING.ToString(), "LOGGING-001", "Das Log konnte nur teilweise strukturiert geparsed werden.", $"LineFallbacks={parseResult.LineFallbackCount}", nameof(IntuneSupportService));
                }
                entriesByKey[mapping.Key] = parseResult.Entries;
            }
            catch (Exception ex)
            {
                _logger.Error("LogParsing", $"Log {mapping.Key} konnte nicht vollständig eingelesen werden.", deviceName, appGuid ?? "-", "READLOGS", AppErrorClass.LOGGING.ToString(), "LOGGING-001", "Ein Log konnte nicht eingelesen werden.", ex.Message, nameof(IntuneSupportService));
                failures.Add(new LogParseFailure { LogKey = mapping.Key, LogName = mapping.Value, Reason = ex.Message });
                entriesByKey[mapping.Key] = [];
                readStates[mapping.Key] = new RemoteLogReadState { UpdateMode = "Full", Exists = false };
            }
        }

        return new LogBundle { EntriesByKey = entriesByKey, FailedLogs = failures, ReadStates = readStates };
    }



    private string[] ApplyDestinationLogShorteningIfEnabled(string logKey, string[] lines)
    {
        if (logKey.Equals("TrustLog", StringComparison.OrdinalIgnoreCase)
            || logKey.Equals("LocalAppLog", StringComparison.OrdinalIgnoreCase)
            || logKey.Equals("AppDataLogs", StringComparison.OrdinalIgnoreCase))
        {
            return lines;
        }

        if (!_config.ShortDestinationLogs)
        {
            _logger.Info("DestinationLogParsingMode", $"Zielgeräte-Log {logKey} wird vollständig geparsed.", "-", "-", "READLOGS");
            return lines;
        }

        var threshold = DateTime.Now.AddDays(-10);
        var kept = new List<string>(lines.Length);
        var removed = 0;
        foreach (var line in lines)
        {
            if (_logParser.TryExtractTimestamp(line, out var timestamp) && timestamp != DateTime.MinValue && timestamp < threshold)
            {
                removed++;
                continue;
            }
            kept.Add(line);
        }

        _logger.Info("DestinationLogParsingMode", $"Zielgeräte-Log {logKey} wird gekürzt geparsed.", "-", "-", "READLOGS", null, null, null, $"shortDestinationLogs={_config.ShortDestinationLogs}; RemovedLines={removed}", nameof(IntuneSupportService));
        return kept.ToArray();
    }

    private static IEnumerable<string> ExtractLogLines(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    foreach (var line in ExtractLogLines(item))
                    {
                        yield return line;
                    }
                }
                yield break;

            case JsonValueKind.String:
                yield return element.GetString() ?? string.Empty;
                yield break;

            case JsonValueKind.Object:
                if (element.TryGetProperty("value", out var valueElement))
                {
                    foreach (var line in ExtractLogLines(valueElement))
                    {
                        yield return line;
                    }
                }
                else if (element.TryGetProperty("Line", out var lineElement))
                {
                    foreach (var line in ExtractLogLines(lineElement))
                    {
                        yield return line;
                    }
                }
                else if (element.TryGetProperty("Message", out var messageElement))
                {
                    foreach (var line in ExtractLogLines(messageElement))
                    {
                        yield return line;
                    }
                }
                else
                {
                    yield return element.GetRawText();
                }
                yield break;

            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
                yield break;

            default:
                yield return element.ToString();
                yield break;
        }
    }

    private static string ResolveScript(string fileName)
        => Path.Combine(AppContext.BaseDirectory, "Scripts", fileName);
}
