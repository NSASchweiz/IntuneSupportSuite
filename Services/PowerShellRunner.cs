using System.Diagnostics;
using System.IO;
using System.Text;
using DapIntuneSupportSuite.Models;

namespace DapIntuneSupportSuite.Services;

public sealed class PowerShellRunner
{
    private readonly AuditLogger _logger;
    private readonly AppConfig _config;

    public PowerShellRunner(AuditLogger logger, AppConfig config)
    {
        _logger = logger;
        _config = config;
    }

    public async Task<RemoteOperationResult> ExecuteScriptAsync(string scriptPath, IDictionary<string, string?> arguments, int? timeoutSeconds = null)
    {
        var effectiveArguments = new Dictionary<string, string?>(arguments, StringComparer.OrdinalIgnoreCase);
        if (effectiveArguments.TryGetValue("PsExecPath", out var configuredPsExecPath))
        {
            effectiveArguments["PsExecPath"] = ResolvePsExecRuntimeValue(configuredPsExecPath);
        }

        var psi = new ProcessStartInfo
        {
            FileName = _config.PowerShellExecutable,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        var builder = new StringBuilder();
        builder.Append($"-NoProfile -ExecutionPolicy Bypass -File {Quote(scriptPath)}");
        foreach (var argument in effectiveArguments)
        {
            if (string.IsNullOrWhiteSpace(argument.Key) || argument.Value is null)
            {
                continue;
            }

            builder.Append($" -{argument.Key} {Quote(argument.Value)}");
        }

        psi.Arguments = builder.ToString();
        _logger.Info("PowerShellExecute", $"Executing script {Path.GetFileName(scriptPath)}");

        using var process = new Process { StartInfo = psi };
        process.Start();

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        var waitTask = process.WaitForExitAsync();
        var effectiveTimeout = timeoutSeconds.GetValueOrDefault(0) > 0 ? timeoutSeconds!.Value : 0;

        if (effectiveTimeout > 0)
        {
            var completedTask = await Task.WhenAny(waitTask, Task.Delay(TimeSpan.FromSeconds(effectiveTimeout)));
            if (completedTask != waitTask)
            {
                TryKill(process);
                var timedOutOutput = await outputTask;
                var timedOutError = await errorTask;
                return new RemoteOperationResult
                {
                    Success = false,
                    Message = $"Remote script timed out after {effectiveTimeout} seconds.",
                    StandardOutput = timedOutOutput,
                    StandardError = string.IsNullOrWhiteSpace(timedOutError) ? $"Timeout nach {effectiveTimeout} Sekunden." : timedOutError
                };
            }
        }
        else
        {
            await waitTask;
        }

        var output = await outputTask;
        var error = await errorTask;

        return new RemoteOperationResult
        {
            Success = process.ExitCode == 0,
            Message = process.ExitCode == 0 ? "Remote script executed." : "Remote script failed.",
            StandardOutput = output,
            StandardError = error
        };
    }

    private string ResolvePsExecRuntimeValue(string? configuredValue)
    {
        if (string.IsNullOrWhiteSpace(configuredValue))
        {
            return "PsExec.exe";
        }

        return Environment.ExpandEnvironmentVariables(configuredValue);
    }

    private static string Quote(string value)
        => $"\"{value.Replace("\"", "`\"")}\"";

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
        }
    }
}
