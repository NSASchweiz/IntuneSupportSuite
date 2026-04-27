namespace DapIntuneSupportSuite.Models;

public sealed class RemoteLogReadState
{
    public string LastWriteUtc { get; set; } = string.Empty;
    public int FilteredLineCount { get; set; }
    public string UpdateMode { get; set; } = "Full";
    public bool Exists { get; set; } = true;
}
