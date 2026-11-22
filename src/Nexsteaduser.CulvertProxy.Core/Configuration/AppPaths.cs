namespace Nexsteaduser.CulvertProxy.Core.Configuration;

/// <summary>集中管理配置与日志落盘位置，支持便携模式。</summary>
public static class AppPaths
{
    private static readonly Lazy<string> RootLazy = new(ResolveRoot);

    public static string Root => RootLazy.Value;

    public static string ConfigFile => Path.Combine(Root, "config.json");

    public static string LogsDirectory => Path.Combine(Root, "logs");

    /// <summary>确保数据目录存在。</summary>
    public static void EnsureCreated()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(LogsDirectory);
    }

    private static string ResolveRoot()
    {
        // 程序目录存在 portable.flag 时使用便携模式，所有数据跟随程序。
        var portableFlag = Path.Combine(AppContext.BaseDirectory, "portable.flag");
        if (File.Exists(portableFlag))
        {
            return Path.Combine(AppContext.BaseDirectory, "data");
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Nexsteaduser",
            "CulvertProxy");
    }
}
