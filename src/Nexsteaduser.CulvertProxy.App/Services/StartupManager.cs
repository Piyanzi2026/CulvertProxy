using Microsoft.Win32;

namespace Nexsteaduser.CulvertProxy.App.Services;

/// <summary>管理当前用户的登录启动项。</summary>
public static class StartupManager
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "CulvertProxy";

    public static bool IsEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue(ValueName) is string;
    }

    public static void Apply(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
        if (key is null)
        {
            return;
        }

        if (enabled)
        {
            var executable = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(executable))
            {
                key.SetValue(ValueName, $"\"{executable}\" --startup", RegistryValueKind.String);
            }
        }
        else
        {
            key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
    }
}
