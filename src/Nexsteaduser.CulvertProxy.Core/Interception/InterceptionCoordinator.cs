using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;
using Nexsteaduser.CulvertProxy.Core.Engine;
using Nexsteaduser.CulvertProxy.Core.Server;

namespace Nexsteaduser.CulvertProxy.Core.Interception;

/// <summary>透明接管生命周期：入口、共享配置与进程注入器的编排。</summary>
internal sealed class InterceptionCoordinator : IAsyncDisposable
{
    internal const string OwnershipSemaphoreName = @"Local\Nexsteaduser.CulvertProxy.Intercept";

    private readonly ProxyEngine _engine;
    private readonly LogHub _log;
    private readonly string _hookPath;
    private InterceptServer? _server;
    private ProcessInjector? _injector;
    private Semaphore? _ownership;
    private byte[]? _token;
    private string? _error;
    private bool _active;
    private bool _injectRunning;
    private bool _autoInject;
    private bool _failOpen;
    private IReadOnlyList<string> _excludes = [];

    public InterceptionCoordinator(ProxyEngine engine, LogHub log, string? hookPath = null)
    {
        _engine = engine;
        _log = log;
        _hookPath = hookPath ?? Path.Combine(AppContext.BaseDirectory, "CulvertHook.dll");
    }

    public string HookPath => _hookPath;

    public bool IsActive => _active;

    public bool IsHookAvailable => File.Exists(_hookPath);

    public string? TokenHex => _token is null ? null : InterceptProtocol.ToHex(_token);

    /// <summary>按当前配置启动或更新接管；配置关闭时确保注入端放行。</summary>
    public async Task ApplyAsync(AppConfig config, CancellationToken engineToken)
    {
        var settings = config.Interception;
        if (!settings.Enabled)
        {
            if (_active)
            {
                await StopAsync().ConfigureAwait(false);
            }
            else
            {
                DisableIfOwner();
            }

            _error = null;
            return;
        }

        _excludes = NormalizeExcludes(settings.ExcludeProcesses);
        _failOpen = settings.FailOpen;
        _autoInject = settings.AutoInjectNewProcesses;

        if (!IsHookAvailable)
        {
            _error = "未找到 CulvertHook.dll；请先运行 native/build.ps1 或使用完整发行包。";
            if (_active)
            {
                await StopAsync().ConfigureAwait(false);
            }
            else
            {
                DisableIfOwner();
            }

            _log.Error("Intercept", _error);
            return;
        }

        if (_active)
        {
            WriteSettings(_token!);
            _injector?.UpdateOptions(_autoInject, _excludes);
            if (settings.InjectRunningProcesses && !_injectRunning)
            {
                _ = _injector?.InjectNowAsync();
            }

            _injectRunning = settings.InjectRunningProcesses;
            return;
        }

        await StartAsync(settings, engineToken).ConfigureAwait(false);
    }

    /// <summary>立即扫描并注入当前用户进程。</summary>
    public Task<InjectionReport> InjectNowAsync()
    {
        if (!_active || _injector is null)
        {
            return Task.FromResult(new InjectionReport(0, 0, 0, 0, 0, "透明接管尚未启动。"));
        }

        return _injector.InjectNowAsync();
    }

    /// <summary>向指定进程注入；用于启动器或诊断。</summary>
    public Task<InjectionReport> InjectProcessAsync(int processId)
    {
        if (!_active || _injector is null)
        {
            return Task.FromResult(new InjectionReport(0, 0, 0, 0, 0, "透明接管尚未启动。"));
        }

        return _injector.InjectProcessAsync(processId);
    }

    public InterceptionSnapshot Snapshot(AppConfig config)
    {
        return new InterceptionSnapshot(
            config.Interception.Enabled,
            _active,
            _server?.Port ?? 0,
            _server?.PortV6 ?? 0,
            IsHookAvailable,
            _injector?.IsElevated ?? false,
            _injector?.InjectedCount ?? 0,
            _injector?.FailedCount ?? 0,
            _error,
            _injector?.LastError,
            _injector?.InjectedProcesses ?? []);
    }

    private async Task StartAsync(InterceptionConfig settings, CancellationToken engineToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _error = null;
        _injectRunning = settings.InjectRunningProcesses;
        _autoInject = settings.AutoInjectNewProcesses;

        if (!AcquireOwnership())
        {
            _error = "另一个 CulvertProxy 实例正在使用透明接管。";
            _log.Warn("Intercept", _error);
            return;
        }

        _token = InterceptProtocol.CreateToken();

        try
        {
            _server = new InterceptServer(_engine, _token);
            _server.Start(engineToken);
        }
        catch (Exception ex)
        {
            _error = $"接管入口启动失败：{ex.Message}";
            _log.Error("Intercept", _error, ex);
            HookConfig.WriteDisabled();
            await StopServerAsync().ConfigureAwait(false);
            ReleaseOwnership();
            return;
        }

        try
        {
            WriteSettings(_token);
        }
        catch (Exception ex)
        {
            _error = $"写入接管配置失败：{ex.Message}";
            _log.Error("Intercept", _error, ex);
            HookConfig.WriteDisabled();
            await StopServerAsync().ConfigureAwait(false);
            ReleaseOwnership();
            return;
        }

        _injector = new ProcessInjector(_log, _hookPath);
        _injector.Start(_injectRunning, _autoInject, _excludes);
        _active = true;
        var ipv6 = _server.PortV6 > 0 ? $" / [::1]:{_server.PortV6}" : string.Empty;
        _log.Info("Intercept",
            $"透明接管已启用，入口 127.0.0.1:{_server.Port}{ipv6}；注入当前进程={_injectRunning}，跟随新进程={_autoInject}。");
        if (!_injector.IsElevated)
        {
            _log.Info("Intercept", "当前未提升权限，高完整性进程将被跳过。");
        }
    }

    private void WriteSettings(byte[] token)
    {
        HookConfig.Write(new HookSettings(
            Enabled: true,
            Port: _server?.Port ?? 0,
            PortV6: _server?.PortV6 ?? 0,
            Token: InterceptProtocol.ToHex(token),
            FailOpen: _failOpen,
            Excludes: _excludes));
    }

    public async Task StopAsync()
    {
        if (!_active)
        {
            return;
        }

        HookConfig.WriteDisabled();
        if (_injector is not null)
        {
            await _injector.DisposeAsync().ConfigureAwait(false);
            _injector = null;
        }

        await StopServerAsync().ConfigureAwait(false);
        _active = false;
        _injectRunning = false;
        _token = null;
        ReleaseOwnership();
        _log.Info("Intercept", "透明接管已停用。");
    }

    /// <summary>只在没有其他实例持有接管时清理配置，避免误伤正在运行的接管。</summary>
    private void DisableIfOwner()
    {
        if (AcquireOwnership())
        {
            HookConfig.WriteDisabled();
            ReleaseOwnership();
        }
    }

    private bool AcquireOwnership()
    {
        if (_ownership is not null)
        {
            return true;
        }

        // 命名信号量按计数互斥，不会像 Mutex 那样被同一线程递归获取。
        var semaphore = new Semaphore(1, 1, OwnershipSemaphoreName);
        if (semaphore.WaitOne(0))
        {
            _ownership = semaphore;
            return true;
        }

        semaphore.Dispose();
        return false;
    }

    private void ReleaseOwnership()
    {
        if (_ownership is null)
        {
            return;
        }

        try
        {
            _ownership.Release();
        }
        catch
        {
            // 信号量已满时忽略。
        }

        _ownership.Dispose();
        _ownership = null;
    }

    private async Task StopServerAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync().ConfigureAwait(false);
            _server = null;
        }
    }

    private static IReadOnlyList<string> NormalizeExcludes(IEnumerable<string> excludes)
    {
        return excludes
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Where(value => value.Length is > 0 and <= 260)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(256)
            .ToArray();
    }

    private bool _disposed;

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_active)
        {
            await StopAsync().ConfigureAwait(false);
        }
        else if (IsHookAvailable)
        {
            DisableIfOwner();
        }
    }
}
