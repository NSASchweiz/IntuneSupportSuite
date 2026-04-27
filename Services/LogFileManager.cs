using System.Globalization;
using System.IO;
using System.Collections.Generic;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class LogFileManager
{
    private readonly AppConfig _config;
    private readonly Dictionary<string, ManagedLogState> _states = new(StringComparer.OrdinalIgnoreCase);

    public LogFileManager(AppConfig config)
    {
        _config = config;
    }

    public List<string> PrepareForWrite(string logType, string logPath, int anticipatedBytes = 0)
    {
        var events = new List<string>();
        var directory = Path.GetDirectoryName(logPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        if (!_config.EnableAppLogRotation || _config.MaxManagedLogSizeMb <= 0)
        {
            return events;
        }

        var state = GetOrCreateState(logPath);
        var keepCount = ResolveKeepCountForLog(logPath);
        var retentionDeleted = EnforceRetentionLimit(logPath, keepCount, state);
        foreach (var item in retentionDeleted)
        {
            events.Add($"Action=LogRotationCleanup	LogType={logType}	Result=Deleted	Path={item}	Details=Alte Logrotation gemäß maxkeptlocalLogs/maxManagedLogHistoryFiles bereinigt.");
        }

        var maxBytes = Math.Max(1, _config.MaxManagedLogSizeMb) * 1024L * 1024L;
        var skipPhysicalCheck = state.LastKnownSize > 0 && state.WritesSinceLastCheck < 12 && (state.LastKnownSize + Math.Max(anticipatedBytes, 256)) < (long)(maxBytes * 0.85);
        if (skipPhysicalCheck)
        {
            return events;
        }

        state.WritesSinceLastCheck = 0;
        events.Add($"Action=LogSizeCheck	LogType={logType}	Result=Started	Path={logPath}	Details=Größenprüfung gestartet.");
        if (!File.Exists(logPath))
        {
            state.LastKnownSize = 0;
            return events;
        }

        var info = new FileInfo(logPath);
        state.LastKnownSize = info.Length;
        if (info.Length < maxBytes)
        {
            return events;
        }

        var datePart = DateTime.Now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var baseName = Path.GetFileNameWithoutExtension(logPath);
        var extension = Path.GetExtension(logPath);
        var rotatedPath = Path.Combine(directory ?? string.Empty, $"{baseName}_{datePart}{extension}");
        var suffix = 1;
        while (File.Exists(rotatedPath))
        {
            rotatedPath = Path.Combine(directory ?? string.Empty, $"{baseName}_{datePart}_{suffix}{extension}");
            suffix++;
        }

        File.Move(logPath, rotatedPath);
        events.Add($"Action=LogRotation	LogType={logType}	Result=Started	Path={logPath}	OriginalSize={info.Length}	Details=Größenlimit überschritten, Rotation gestartet.");
        events.Add($"Action=LogRotation	LogType={logType}	Result=Renamed	Path={rotatedPath}	OriginalSize={info.Length}	Details=Logdatei wurde rotiert.");

        File.WriteAllText(logPath, string.Empty);
        state.LastKnownSize = 0;
        events.Add($"Action=LogRotation	LogType={logType}	Result=Created	Path={logPath}	Details=Neue aktive Logdatei erstellt.");

        var deleted = CleanupOldRotations(logPath, keepCount);
        foreach (var item in deleted)
        {
            events.Add($"Action=LogRotationCleanup	LogType={logType}	Result=Deleted	Path={item}	Details=Alte Logrotation bereinigt.");
        }

        events.Add($"Action=LogRotation	LogType={logType}	Result=Success	Path={logPath}	Details=Rotation erfolgreich abgeschlossen.");
        return events;
    }

    public void NotifyWriteComplete(string logPath, int bytesWritten)
    {
        var state = GetOrCreateState(logPath);
        state.LastKnownSize = Math.Max(0, state.LastKnownSize) + Math.Max(0, bytesWritten);
        state.WritesSinceLastCheck++;
    }

    private ManagedLogState GetOrCreateState(string logPath)
    {
        if (!_states.TryGetValue(logPath, out var state))
        {
            state = new ManagedLogState();
            _states[logPath] = state;
        }

        return state;
    }


    private int ResolveKeepCountForLog(string logPath)
    {
        var defaultKeep = Math.Max(1, _config.MaxManagedLogHistoryFiles);
        var localKeep = Math.Max(1, _config.MaxKeptLocalLogs);

        try
        {
            var fullLogPath = Path.GetFullPath(logPath);
            var appDataLocalDir = ExpandPath(_config.LocalLogDirectory);
            var executableAppLogDir = Path.Combine(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), "AppLog");

            if (IsUnderDirectory(fullLogPath, appDataLocalDir) || IsUnderDirectory(fullLogPath, executableAppLogDir))
            {
                return localKeep;
            }
        }
        catch
        {
        }

        return defaultKeep;
    }

    private static string ExpandPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        return Path.GetFullPath(Environment.ExpandEnvironmentVariables(value));
    }

    private static bool IsUnderDirectory(string filePath, string directoryPath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(directoryPath)) return false;
        var normalizedDirectory = Path.GetFullPath(directoryPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var normalizedFile = Path.GetFullPath(filePath);
        return normalizedFile.StartsWith(normalizedDirectory, StringComparison.OrdinalIgnoreCase);
    }

    private static List<string> EnforceRetentionLimit(string activeLogPath, int keepCount, ManagedLogState state)
    {
        if (state.RetentionCleanupCompleted && (DateTime.UtcNow - state.LastRetentionCleanupUtc) < TimeSpan.FromSeconds(20))
        {
            return [];
        }

        state.LastRetentionCleanupUtc = DateTime.UtcNow;
        state.RetentionCleanupCompleted = true;
        return CleanupOldRotations(activeLogPath, keepCount);
    }

    private static List<string> CleanupOldRotations(string activeLogPath, int keepCount)
    {
        var deleted = new List<string>();
        var directory = Path.GetDirectoryName(activeLogPath);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory)) return deleted;
        var baseName = Path.GetFileNameWithoutExtension(activeLogPath);
        var extension = Path.GetExtension(activeLogPath);
        var historyKeepCount = Math.Max(0, keepCount - (File.Exists(activeLogPath) ? 1 : 0));
        var candidates = Directory.GetFiles(directory, $"{baseName}_*{extension}")
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .Skip(historyKeepCount)
            .ToArray();
        foreach (var candidate in candidates)
        {
            try
            {
                File.Delete(candidate);
                deleted.Add(candidate);
            }
            catch
            {
            }
        }
        return deleted;
    }

    private sealed class ManagedLogState
    {
        public long LastKnownSize { get; set; }
        public int WritesSinceLastCheck { get; set; }
        public DateTime LastRetentionCleanupUtc { get; set; }
        public bool RetentionCleanupCompleted { get; set; }
    }
}
