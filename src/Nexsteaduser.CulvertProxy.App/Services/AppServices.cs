using Microsoft.UI.Dispatching;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;
using Nexsteaduser.CulvertProxy.Core.Engine;

namespace Nexsteaduser.CulvertProxy.App.Services;

/// <summary>界面进程内的服务集合：配置、引擎、系统代理。</summary>
public sealed class AppServices : IAsyncDisposable
{
    private readonly SemaphoreSlim _saveLock = new(1, 1);
    private readonly DispatcherQueue? _dispatcher = DispatcherQueue.GetForCurrentThread();
    private volatile AppConfig _config;

    public AppServices()
    {
        AppPaths.EnsureCreated();
        Log = new LogHub(AppPaths.LogsDirectory);
        Store = new ConfigStore(Log);
        _config = Store.Load();
        if (!_config.Interception.Enabled)
        {
            ProxyEngine.DisableStaleInterception();
        }

        Engine = new ProxyEngine(Log, _config);
        SystemProxy = new SystemProxyManager(Log);
        StartupManager.Apply(_config.Ui.StartWithWindows);
    }

    public LogHub Log { get; }

    public ConfigStore Store { get; }

    public AppConfig Config => _config;

    public ProxyEngine Engine { get; }

    public SystemProxyManager SystemProxy { get; }

    public event EventHandler? ConfigChanged;

    public string ConfigPath => Store.FilePath;

    public string LogsPath => AppPaths.LogsDirectory;

    /// <summary>PAC 不支持携带 SOCKS5 用户名密码，启用入口认证时不能开系统代理。</summary>
    public bool LocalAuthenticationEnabled => _config.Listener.RequiresAuthentication;

    /// <summary>保存配置并热加载引擎。</summary>
    public async Task SaveConfigAsync(AppConfig config)
    {
        await _saveLock.WaitAsync().ConfigureAwait(false);
        try
        {
            var clone = ConfigCloner.Clone(config);
            ConfigStore.Normalize(clone);
            Store.Save(clone);
            _config = clone;
            await Engine.ReloadAsync(clone).ConfigureAwait(false);
            StartupManager.Apply(clone.Ui.StartWithWindows);

            // 入口端口或开关可能已变化，PAC 必须跟着刷新，否则浏览器会指向失效端口。
            if (SystemProxy.IsEnabled)
            {
                var snapshot = Engine.GetSnapshot();
                if (snapshot.ListenerRunning && !clone.Listener.RequiresAuthentication)
                {
                    SystemProxy.Enable(snapshot.ListenPort);
                }
                else
                {
                    SystemProxy.Disable();
                }
            }

            RaiseConfigChanged();
        }
        finally
        {
            _saveLock.Release();
        }
    }

    /// <summary>记录上次访问页面；只落盘界面状态，不触发引擎重载。</summary>
    public void SetLastPage(string page)
    {
        var config = _config;
        if (string.Equals(config.Ui.LastPage, page, StringComparison.Ordinal))
        {
            return;
        }

        config.Ui.LastPage = page;
        _ = PersistUiStateAsync();
    }

    private async Task PersistUiStateAsync()
    {
        await _saveLock.WaitAsync().ConfigureAwait(false);
        try
        {
            Store.Save(_config);
        }
        catch (Exception ex)
        {
            Log.Warn("Config", $"保存界面状态失败：{ex.Message}");
        }
        finally
        {
            _saveLock.Release();
        }
    }

    /// <summary>配置事件固定回到界面线程，避免后台线程直接触碰 XAML。</summary>
    private void RaiseConfigChanged()
    {
        var handler = ConfigChanged;
        if (handler is null)
        {
            return;
        }

        if (_dispatcher is null || _dispatcher.HasThreadAccess)
        {
            handler(this, EventArgs.Empty);
            return;
        }

        _dispatcher.TryEnqueue(() => handler(this, EventArgs.Empty));
    }

    /// <summary>启动或停止本地代理。</summary>
    public async Task ToggleEngineAsync()
    {
        if (Engine.IsRunning)
        {
            if (SystemProxy.IsEnabled)
            {
                SystemProxy.Disable();
            }

            await Engine.StopAsync().ConfigureAwait(false);
        }
        else
        {
            await Engine.StartAsync().ConfigureAwait(false);
        }
    }

    public async Task StartEngineAsync()
    {
        if (!Engine.IsRunning)
        {
            await Engine.StartAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (SystemProxy.IsEnabled)
            {
                SystemProxy.Disable();
            }

            await Engine.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            await Log.DisposeAsync().ConfigureAwait(false);
            _saveLock.Dispose();
        }
    }
}
