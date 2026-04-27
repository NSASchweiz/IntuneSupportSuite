using System.Collections.Generic;

namespace DapIntuneSupportSuite.Models;

public sealed class LanguageMetadata
{
    public string LanguageId { get; set; } = "Language-DEV";
    public string DisplayName { get; set; } = "Language DEV";
    public bool ShowInGui { get; set; } = true;
    public string AppPrefix { get; set; } = string.Empty;
    public string AppName { get; set; } = "Intune Support Suite";
}

public sealed class LanguageFile
{
    public LanguageMetadata Meta { get; set; } = new();
    public Dictionary<string, string> Strings { get; set; } = new();
}

public sealed class LanguageOption
{
    public string LanguageId { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public bool ShowInGui { get; set; } = true;

    public override string ToString() => DisplayName;
}
