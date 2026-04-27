using System.Windows.Media;

namespace DapIntuneSupportSuite.Models;

public sealed class LogEntry
{
    public DateTime Timestamp { get; set; }
    public string DisplayTimestamp => Timestamp == DateTime.MinValue ? string.Empty : Timestamp.ToString("dd.MM.yyyy HH:mm:ss");
    public string Severity { get; set; } = "Info";
    public string SourceFile { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public Brush SeverityBrush { get; set; } = Brushes.White;
}
