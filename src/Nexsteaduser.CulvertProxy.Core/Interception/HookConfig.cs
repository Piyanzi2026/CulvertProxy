using System.Text;
using Nexsteaduser.CulvertProxy.Core.Configuration;

namespace Nexsteaduser.CulvertProxy.Core.Interception;

/// <summary>注入端与引擎共享的接管参数。</summary>
internal sealed record HookSettings(
    bool Enabled,
    int Port,
    int PortV6,
    string Token,
    bool FailOpen,
    IReadOnlyList<string> Excludes);

/// <summary>hook.conf 的原子写入；文件路径必须能被同用户的注入进程读取。</summary>
internal static class HookConfig
{
    /// <summary>测试用路径覆盖，避免污染真实用户目录。</summary>
    internal static string? FilePathOverride { get; set; }

    /// <summary>注入进程按环境变量定位的固定配置路径。</summary>
    public static string FilePath
    {
        get
        {
            if (FilePathOverride is not null)
            {
                return FilePathOverride;
            }

            // 与原生 Hook 的 GetEnvironmentVariableW("LOCALAPPDATA") 保持完全一致。
            var root = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrWhiteSpace(root))
            {
                root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            }

            return Path.Combine(root, "Nexsteaduser", "CulvertProxy", "hook.conf");
        }
    }

    /// <summary>写入启用配置；先写临时文件再替换，避免注入端读到半截内容。</summary>
    public static void Write(HookSettings settings)
    {
        var directory = Path.GetDirectoryName(FilePath)!;
        Directory.CreateDirectory(directory);

        var excludes = settings.Excludes
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Replace('\r', ' ').Replace('\n', ' ').Replace(';', ' ').Trim())
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase);

        var builder = new StringBuilder(256);
        builder.AppendLine("# 由 CulvertProxy 自动生成，请勿手工编辑。");
        builder.AppendLine("version=1");
        builder.AppendLine($"enabled={(settings.Enabled ? 1 : 0)}");
        builder.AppendLine($"port={settings.Port}");
        builder.AppendLine($"port6={settings.PortV6}");
        builder.AppendLine($"token={settings.Token}");
        builder.AppendLine($"failopen={(settings.FailOpen ? 1 : 0)}");
        builder.AppendLine($"exclude={string.Join(';', excludes)}");

        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, builder.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(temp, FilePath, overwrite: true);
    }

    /// <summary>关闭接管；已注入进程会在下一次连接时放行。</summary>
    public static void WriteDisabled()
    {
        try
        {
            var directory = Path.GetDirectoryName(FilePath)!;
            Directory.CreateDirectory(directory);
            var contents = "# 由 CulvertProxy 自动生成，请勿手工编辑。\nversion=1\nenabled=0\nport=0\nport6=0\ntoken=\nfailopen=0\nexclude=\n";
            var temp = FilePath + ".tmp";
            File.WriteAllText(temp, contents, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(temp, FilePath, overwrite: true);
        }
        catch
        {
            // 退出阶段或受限目录下关闭失败不阻断引擎停止。
        }
    }
}

/// <summary>界面展示的注入进程。</summary>
public sealed record InjectedProcessInfo(int ProcessId, string Name, string? Path, DateTimeOffset InjectedAt);

/// <summary>一次进程扫描的结果。</summary>
public sealed record InjectionReport(
    int Scanned,
    int Injected,
    int AlreadyInjected,
    int Skipped,
    int Failed,
    string? LastError)
{
    public static InjectionReport Empty { get; } = new(0, 0, 0, 0, 0, null);
}

/// <summary>接管运行状态快照。</summary>
public sealed record InterceptionSnapshot(
    bool Enabled,
    bool Active,
    int Port,
    int PortV6,
    bool HookAvailable,
    bool Elevated,
    int InjectedProcesses,
    int FailedInjections,
    string? Error,
    string? LastInjectionError,
    IReadOnlyList<InjectedProcessInfo> Processes);
