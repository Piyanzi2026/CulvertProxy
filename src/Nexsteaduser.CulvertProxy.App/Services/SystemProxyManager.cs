using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;

namespace Nexsteaduser.CulvertProxy.App.Services;

/// <summary>通过注册表接管 WinINET 系统代理，指向本地 PAC。</summary>
public sealed class SystemProxyManager
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int InternetOptionRefresh = 37;
    private const int InternetOptionSettingsChanged = 39;
    private readonly LogHub _log;
    private readonly string _backupPath;
    private readonly JsonSerializerOptions _json = new() { WriteIndented = true };

    public SystemProxyManager(LogHub log)
    {
        _log = log;
        _backupPath = Path.Combine(AppPaths.Root, "system-proxy-backup.json");
        IsEnabled = DetectEnabled();
    }

    public bool IsEnabled { get; private set; }

    /// <summary>启用 PAC 系统代理；重复调用保持幂等。</summary>
    public bool Enable(int port)
    {
        try
        {
            if (!File.Exists(_backupPath))
            {
                var backup = CaptureBackup();
                File.WriteAllText(_backupPath, JsonSerializer.Serialize(backup, _json));
            }

            using var key = Registry.CurrentUser.CreateSubKey(InternetSettingsKey, writable: true)
                ?? throw new InvalidOperationException("无法打开 Internet Settings 注册表项。");
            key.SetValue("AutoConfigURL", $"http://127.0.0.1:{port}/proxy.pac", RegistryValueKind.String);
            key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            NotifyWinInet();
            IsEnabled = true;
            _log.Info("SystemProxy", $"系统代理已启用，PAC 指向 127.0.0.1:{port}。");
            return true;
        }
        catch (Exception ex)
        {
            _log.Error("SystemProxy", $"启用系统代理失败：{ex.Message}", ex);
            return false;
        }
    }

    /// <summary>恢复启用前的设置。</summary>
    public void Disable()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true);
            if (key is null)
            {
                IsEnabled = false;
                return;
            }

            if (File.Exists(_backupPath))
            {
                var backup = JsonSerializer.Deserialize<ProxyBackup>(File.ReadAllText(_backupPath), _json);
                RestoreValue(key, "AutoConfigURL", backup?.AutoConfigUrl, RegistryValueKind.String);
                RestoreValue(key, "ProxyServer", backup?.ProxyServer, RegistryValueKind.String);
                RestoreValue(key, "ProxyOverride", backup?.ProxyOverride, RegistryValueKind.String);
                if (backup?.ProxyEnable is { } proxyEnable)
                {
                    key.SetValue("ProxyEnable", proxyEnable, RegistryValueKind.DWord);
                }
                else
                {
                    key.DeleteValue("ProxyEnable", throwOnMissingValue: false);
                }

                File.Delete(_backupPath);
            }
            else if (key.GetValue("AutoConfigURL") is string pac
                && pac.Contains("127.0.0.1", StringComparison.Ordinal)
                && pac.EndsWith("/proxy.pac", StringComparison.OrdinalIgnoreCase))
            {
                key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
            }

            NotifyWinInet();
            IsEnabled = false;
            _log.Info("SystemProxy", "系统代理设置已恢复。");
        }
        catch (Exception ex)
        {
            _log.Error("SystemProxy", $"恢复系统代理失败：{ex.Message}", ex);
        }
    }

    private ProxyBackup CaptureBackup()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
        return new ProxyBackup(
            key?.GetValue("AutoConfigURL") as string,
            key?.GetValue("ProxyEnable") is int enable ? enable : null,
            key?.GetValue("ProxyServer") as string,
            key?.GetValue("ProxyOverride") as string);
    }

    private bool DetectEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
            var pac = key?.GetValue("AutoConfigURL") as string;
            return File.Exists(_backupPath)
                && pac is not null
                && pac.Contains("127.0.0.1", StringComparison.Ordinal)
                && pac.EndsWith("/proxy.pac", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static void RestoreValue(RegistryKey key, string name, string? value, RegistryValueKind kind)
    {
        if (value is null)
        {
            key.DeleteValue(name, throwOnMissingValue: false);
        }
        else
        {
            key.SetValue(name, value, kind);
        }
    }

    private static void NotifyWinInet()
    {
        _ = InternetSetOptionW(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
        _ = InternetSetOptionW(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
    }

    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOptionW(IntPtr hInternet, int option, IntPtr buffer, int bufferLength);

    private sealed record ProxyBackup(string? AutoConfigUrl, int? ProxyEnable, string? ProxyServer, string? ProxyOverride);
}
