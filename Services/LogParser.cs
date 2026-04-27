using System.IO;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Media;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class LogParser
{
    private readonly AuditLogger _logger;
    private readonly AppConfig _config;

    private static readonly Regex CmTraceRegex = new(
        @"<!\[LOG\[(?<message>.*?)\]LOG\]!><time=""(?<time>[^""]+)""\s+date=""(?<date>[^""]+)""(?:\s+component=""(?<component>[^""]*)"")?(?:\s+context=""(?<context>[^""]*)"")?(?:\s+type=""(?<type>[^""]+)"")?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

    private static readonly Regex TimestampPrefixRegex = new(
        @"^(?:\d{4}-\d{2}-\d{2}|\d{2}\.\d{2}\.\d{4}|\d{1,2}-\d{1,2}-\d{4})\s+\d{2}:\d{2}:\d{2}",
        RegexOptions.Compiled);

    private static readonly Regex SourcePrefixRegex = new(
        @"^\[(?<source>[^\]]+)\]\s*",
        RegexOptions.Compiled);

    public LogParser(AppConfig config, AuditLogger logger)
    {
        _config = config;
        _logger = logger;
    }

    public LogParseExecutionResult Parse(string logKey, string sourceFile, IEnumerable<string> lines, string operationId)
    {
        var entries = new List<LogEntry>();
        var lineFallbackCount = 0;

        foreach (var logicalEntry in FrameLogicalEntries(lines))
        {
            try
            {
                entries.Add(ParseEntry(sourceFile, logicalEntry));
            }
            catch (Exception ex)
            {
                lineFallbackCount++;
                _logger.Warn(
                    "LogParsingLineFallback",
                    $"Zeilenfallback für {logKey} verwendet.",
                    "-",
                    "-",
                    operationId,
                    AppErrorClass.LOGGING.ToString(),
                    "LOGGING-001",
                    "Eine Logzeile konnte nicht strukturiert geparsed werden.",
                    ex.Message,
                    nameof(LogParser));

                var fallbackSeverity = DetermineSeverity(sourceFile, logicalEntry);
                entries.Add(new LogEntry
                {
                    Timestamp = DateTime.MinValue,
                    Severity = fallbackSeverity,
                    SourceFile = sourceFile,
                    Message = CleanupMessage(sourceFile, logicalEntry),
                    SeverityBrush = DetermineBrush(fallbackSeverity)
                });
            }
        }

        return new LogParseExecutionResult { Entries = entries, LineFallbackCount = lineFallbackCount };
    }

    public bool TryExtractTimestamp(string line, out DateTime timestamp)
    {
        timestamp = ExtractTimestamp(line);
        return timestamp != DateTime.MinValue;
    }

    private LogEntry ParseEntry(string sourceFile, string rawEntry)
    {
        var normalizedEntry = NormalizeRawLine(rawEntry);
        var parsedTimestamp = ExtractTimestamp(normalizedEntry);
        var parsedMessage = SimplifyMessage(sourceFile, normalizedEntry);
        var parsedSeverity = DetermineSeverity(sourceFile, normalizedEntry);

        return new LogEntry
        {
            Timestamp = parsedTimestamp,
            Severity = parsedSeverity,
            SourceFile = sourceFile,
            Message = parsedMessage,
            SeverityBrush = DetermineBrush(parsedSeverity)
        };
    }

    private IEnumerable<string> FrameLogicalEntries(IEnumerable<string> lines)
    {
        var framedEntries = new List<string>();
        var buffer = new StringBuilder();
        var bufferIsCmTrace = false;

        foreach (var rawLine in lines ?? Enumerable.Empty<string>())
        {
            var line = NormalizeRawLine(rawLine);
            if (string.IsNullOrWhiteSpace(line))
            {
                if (bufferIsCmTrace && buffer.Length > 0)
                {
                    buffer.AppendLine();
                }

                continue;
            }

            var startsCmTrace = IsCmTraceStart(line);
            var startsNewPlainEntry = LooksLikePlainEntryStart(line);

            if (buffer.Length == 0)
            {
                buffer.Append(line);
                bufferIsCmTrace = startsCmTrace;

                if (bufferIsCmTrace && IsCompleteCmTraceEntry(buffer.ToString()))
                {
                    framedEntries.Add(buffer.ToString());
                    buffer.Clear();
                    bufferIsCmTrace = false;
                }

                continue;
            }

            if (bufferIsCmTrace)
            {
                if (startsCmTrace && IsCompleteCmTraceEntry(buffer.ToString()))
                {
                    framedEntries.Add(buffer.ToString());
                    buffer.Clear();
                    buffer.Append(line);
                    bufferIsCmTrace = true;
                }
                else
                {
                    buffer.AppendLine();
                    buffer.Append(line);
                }

                if (bufferIsCmTrace && IsCompleteCmTraceEntry(buffer.ToString()))
                {
                    framedEntries.Add(buffer.ToString());
                    buffer.Clear();
                    bufferIsCmTrace = false;
                }

                continue;
            }

            if (startsCmTrace || startsNewPlainEntry)
            {
                framedEntries.Add(buffer.ToString());
                buffer.Clear();
                buffer.Append(line);
                bufferIsCmTrace = startsCmTrace;

                if (bufferIsCmTrace && IsCompleteCmTraceEntry(buffer.ToString()))
                {
                    framedEntries.Add(buffer.ToString());
                    buffer.Clear();
                    bufferIsCmTrace = false;
                }

                continue;
            }

            buffer.AppendLine();
            buffer.Append(line);
        }

        if (buffer.Length > 0)
        {
            framedEntries.Add(buffer.ToString());
        }

        return framedEntries;
    }

    private DateTime ExtractTimestamp(string line)
    {
        var normalizedLine = NormalizeRawLine(line);
        var match = CmTraceRegex.Match(normalizedLine);
        if (match.Success)
        {
            var dateValue = match.Groups["date"].Value.Trim();
            var timeValue = NormalizeCmTraceTime(match.Groups["time"].Value.Trim());
            if (TryParseCmTraceTimestamp(dateValue, timeValue, out var parsed))
            {
                return parsed;
            }
        }

        var firstLine = normalizedLine
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)
            .FirstOrDefault()?
            .Trim() ?? string.Empty;

        return DateTime.TryParse(firstLine[..Math.Min(19, firstLine.Length)], out var fallback)
            ? fallback
            : DateTime.MinValue;
    }

    private static bool TryParseCmTraceTimestamp(string dateValue, string timeValue, out DateTime timestamp)
    {
        var combined = $"{dateValue} {timeValue}";
        var formats = new[]
        {
            "M-d-yyyy HH:mm:ss.fffffff",
            "M-d-yyyy HH:mm:ss.ffffff",
            "M-d-yyyy HH:mm:ss.fffff",
            "M-d-yyyy HH:mm:ss.ffff",
            "M-d-yyyy HH:mm:ss.fff",
            "M-d-yyyy HH:mm:ss",
            "MM-dd-yyyy HH:mm:ss.fffffff",
            "MM-dd-yyyy HH:mm:ss.ffffff",
            "MM-dd-yyyy HH:mm:ss.fff",
            "MM-dd-yyyy HH:mm:ss",
            "yyyy-MM-dd HH:mm:ss.fffffff",
            "yyyy-MM-dd HH:mm:ss.ffffff",
            "yyyy-MM-dd HH:mm:ss.fff",
            "yyyy-MM-dd HH:mm:ss",
            "dd.MM.yyyy HH:mm:ss.fffffff",
            "dd.MM.yyyy HH:mm:ss.ffffff",
            "dd.MM.yyyy HH:mm:ss.fff",
            "dd.MM.yyyy HH:mm:ss"
        };

        return DateTime.TryParseExact(combined, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out timestamp)
            || DateTime.TryParse(combined, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out timestamp);
    }

    private static string NormalizeCmTraceTime(string timeValue)
    {
        var plusIndex = timeValue.IndexOf('+');
        if (plusIndex > 0)
        {
            return timeValue[..plusIndex];
        }

        var minusIndex = timeValue.LastIndexOf('-');
        if (minusIndex > 7)
        {
            return timeValue[..minusIndex];
        }

        return timeValue;
    }

    private string SimplifyMessage(string sourceFile, string line)
    {
        var normalizedLine = NormalizeRawLine(line);
        var match = CmTraceRegex.Match(normalizedLine);
        if (match.Success)
        {
            var message = match.Groups["message"].Value
                .Replace("\r", " ")
                .Replace("\n", " ")
                .Trim();

            return CleanupMessage(sourceFile, message);
        }

        return CleanupMessage(sourceFile, normalizedLine);
    }

    private string CleanupMessage(string sourceFile, string message)
    {
        var cleaned = NormalizeRawLine(message)
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Trim();

        if (string.IsNullOrWhiteSpace(cleaned))
        {
            return string.Empty;
        }

        while (true)
        {
            var match = SourcePrefixRegex.Match(cleaned);
            if (!match.Success)
            {
                break;
            }

            var prefix = match.Groups["source"].Value.Trim();
            if (!MatchesSourcePrefix(prefix, sourceFile))
            {
                break;
            }

            cleaned = cleaned[match.Length..].TrimStart();
        }

        cleaned = StripSyntheticStructuredPrefix(sourceFile, cleaned);

        return cleaned;
    }

    private static string StripSyntheticStructuredPrefix(string sourceFile, string message)
    {
        if (string.IsNullOrWhiteSpace(sourceFile) || string.IsNullOrWhiteSpace(message))
        {
            return message;
        }

        var shouldStrip = sourceFile.Equals("Install-Agent Events", StringComparison.OrdinalIgnoreCase)
            || sourceFile.Equals("Intune Registry Settings", StringComparison.OrdinalIgnoreCase)
            || sourceFile.Equals("Win32Apps Registry", StringComparison.OrdinalIgnoreCase)
            || sourceFile.Equals("Company Portal", StringComparison.OrdinalIgnoreCase)
            || sourceFile.Equals("Enrollment", StringComparison.OrdinalIgnoreCase)
            || sourceFile.Equals("Event-Log-Kanäle", StringComparison.OrdinalIgnoreCase)
            || sourceFile.Equals("MDM Diagnoseartefakte", StringComparison.OrdinalIgnoreCase);

        if (!shouldStrip)
        {
            return message;
        }

        return Regex.Replace(
                message,
                @"^(?:\d{4}-\d{2}-\d{2}|\d{2}\.\d{2}\.\d{4}|\d{1,2}-\d{1,2}-\d{4})\s+\d{2}:\d{2}:\d{2}\s+\[(?:Info|Information|Informationen|Warning|Warnung|Error|Fehler|Success|Erfolg)\]\s+\[[^\]]+\]\s*",
                string.Empty,
                RegexOptions.IgnoreCase)
            .Trim();
    }

    private static bool MatchesSourcePrefix(string prefix, string sourceFile)
    {
        if (string.IsNullOrWhiteSpace(prefix) || string.IsNullOrWhiteSpace(sourceFile))
        {
            return false;
        }

        var sourceName = Path.GetFileName(sourceFile);
        var sourceWithoutExtension = Path.GetFileNameWithoutExtension(sourceFile);
        return prefix.Equals(sourceName, StringComparison.OrdinalIgnoreCase)
            || prefix.Equals(sourceWithoutExtension, StringComparison.OrdinalIgnoreCase);
    }

    private string DetermineSeverity(string sourceFile, string line)
    {
        var normalizedLine = NormalizeRawLine(line);
        var simplifiedMessage = SimplifyMessage(sourceFile, normalizedLine);

        var explicitSeverity = DetermineExplicitSeverity(normalizedLine);
        var keywordSeverity = DetermineKeywordSeverity(simplifiedMessage, normalizedLine);

        return GetSeverityRank(keywordSeverity) > GetSeverityRank(explicitSeverity)
            ? keywordSeverity
            : explicitSeverity;
    }

    private static string DetermineExplicitSeverity(string line)
    {
        var match = CmTraceRegex.Match(line);
        if (match.Success)
        {
            var typeValue = match.Groups["type"].Value.Trim();
            if (typeValue == "3") return "Error";
            if (typeValue == "2") return "Warning";
            if (typeValue == "0") return "Info";
            if (typeValue == "1") return "Info";
        }

        if (line.Contains("\tERROR\t", StringComparison.OrdinalIgnoreCase)
            || line.Contains("[Error]", StringComparison.OrdinalIgnoreCase)
            || line.Contains(" level=error", StringComparison.OrdinalIgnoreCase))
        {
            return "Error";
        }

        if (line.Contains("\tWARN", StringComparison.OrdinalIgnoreCase)
            || line.Contains("[Warning]", StringComparison.OrdinalIgnoreCase)
            || line.Contains(" level=warning", StringComparison.OrdinalIgnoreCase))
        {
            return "Warning";
        }

        if (line.Contains("\tINFO\t", StringComparison.OrdinalIgnoreCase)
            || line.Contains("[Info]", StringComparison.OrdinalIgnoreCase)
            || line.Contains("[Information]", StringComparison.OrdinalIgnoreCase)
            || line.Contains("[Informationen]", StringComparison.OrdinalIgnoreCase))
        {
            return "Info";
        }

        return "Info";
    }

    private string DetermineKeywordSeverity(string simplifiedMessage, string rawLine)
    {
        var message = $"{simplifiedMessage} {rawLine}".ToLowerInvariant();

        if (ContainsAny(message, _config.ErrorKeywords))
        {
            return "Error";
        }

        if (ContainsAny(message, _config.WarningKeywords))
        {
            return "Warning";
        }

        if (ContainsAny(message, _config.SuccessKeywords))
        {
            return "Success";
        }

        return "Info";
    }

    private static bool ContainsAny(string message, IEnumerable<string>? keywords)
    {
        if (string.IsNullOrWhiteSpace(message) || keywords is null)
        {
            return false;
        }

        foreach (var keyword in keywords)
        {
            if (string.IsNullOrWhiteSpace(keyword))
            {
                continue;
            }

            if (message.Contains(keyword.Trim().ToLowerInvariant(), StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static int GetSeverityRank(string severity)
        => severity switch
        {
            "Error" => 3,
            "Warning" => 2,
            "Success" => 1,
            _ => 0
        };

    private static Brush DetermineBrush(string severity)
        => severity switch
        {
            "Error" => Brushes.MistyRose,
            "Warning" => Brushes.LightGoldenrodYellow,
            "Success" => Brushes.Honeydew,
            _ => Brushes.White
        };

    private static string NormalizeRawLine(string? line)
        => (line ?? string.Empty)
            .Replace("\0", string.Empty)
            .Replace("\uFEFF", string.Empty)
            .TrimEnd();

    private static bool IsCmTraceStart(string line)
        => line.Contains("<![LOG[", StringComparison.OrdinalIgnoreCase);

    private static bool IsCompleteCmTraceEntry(string entry)
        => entry.Contains("<![LOG[", StringComparison.OrdinalIgnoreCase)
            && entry.Contains("]LOG]!><time=", StringComparison.OrdinalIgnoreCase)
            && entry.Contains(" date=\"", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikePlainEntryStart(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        return TimestampPrefixRegex.IsMatch(line)
            || line.Contains("\tERROR\t", StringComparison.OrdinalIgnoreCase)
            || line.Contains("\tINFO\t", StringComparison.OrdinalIgnoreCase)
            || line.Contains("\tWARN", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("ERROR", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("WARN", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("INFO", StringComparison.OrdinalIgnoreCase);
    }
}
