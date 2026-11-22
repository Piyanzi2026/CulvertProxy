using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI;
using Windows.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Media;
using Nexsteaduser.CulvertProxy.App.Services;
using Nexsteaduser.CulvertProxy.Core.Engine;
using Nexsteaduser.CulvertProxy.Core.Routing;

namespace Nexsteaduser.CulvertProxy.App.Pages;

/// <summary>仪表盘轮询引擎快照并格式化展示。</summary>
public sealed partial class DashboardViewModel : ObservableObject, IDisposable
{
    private static readonly SolidColorBrush RunningBrush = new(Color.FromArgb(255, 52, 211, 153));
    private static readonly SolidColorBrush StoppedBrush = new(Color.FromArgb(255, 248, 113, 113));
    private readonly AppServices _services;
    private readonly DispatcherQueueTimer _timer;
    private bool _refreshing;

    [ObservableProperty] private bool isRunning;
    [ObservableProperty] private string statusHeadline = "已停止";
    [ObservableProperty] private string statusDetail = "本地代理未运行";
    [ObservableProperty] private string listenText = "—";
    [ObservableProperty] private string activeText = "0";
    [ObservableProperty] private string upText = "0 B/s";
    [ObservableProperty] private string downText = "0 B/s";
    [ObservableProperty] private string totalText = "0 B";
    [ObservableProperty] private string uptimeText = "—";
    [ObservableProperty] private string dnsText = "—";
    [ObservableProperty] private string interceptText = "未启用";
    [ObservableProperty] private string toggleLabel = "启动代理";
    [ObservableProperty] private bool systemProxyEnabled;
    [ObservableProperty] private bool hasError;
    [ObservableProperty] private string? errorText;
    [ObservableProperty] private Brush statusBrush = StoppedBrush;

    public DashboardViewModel(AppServices services)
    {
        _services = services;
        _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
        _timer.Interval = TimeSpan.FromSeconds(1);
        _timer.Tick += (_, _) => Refresh();
        Refresh();
    }

    public ObservableCollection<HealthRow> Health { get; } = [];

    public event Action<IReadOnlyList<RateSample>>? SamplesUpdated;

    public void Start() => _timer.Start();

    public void Stop() => _timer.Stop();

    public async Task ToggleAsync()
    {
        try
        {
            await _services.ToggleEngineAsync();
        }
        catch (Exception ex)
        {
            ErrorText = ex.Message;
            HasError = true;
        }

        Refresh();
    }

    public async Task SetSystemProxyAsync(bool enabled)
    {
        try
        {
            if (enabled)
            {
                if (_services.LocalAuthenticationEnabled)
                {
                    ErrorText = "本地入口启用了用户名密码，PAC 无法携带 SOCKS5 凭据；请先关闭入口认证，或手动配置代理。";
                    HasError = true;
                    SystemProxyEnabled = false;
                    return;
                }

                if (!_services.Engine.IsRunning)
                {
                    await _services.StartEngineAsync();
                }

                var snapshot = _services.Engine.GetSnapshot();
                if (!snapshot.ListenerRunning)
                {
                    ErrorText = snapshot.ListenerError ?? "本地入口未运行，无法启用系统代理。";
                    HasError = true;
                    SystemProxyEnabled = false;
                    return;
                }

                if (!_services.SystemProxy.Enable(snapshot.ListenPort))
                {
                    SystemProxyEnabled = false;
                    ErrorText = "写入系统代理设置失败，请查看日志。";
                    HasError = true;
                    return;
                }
            }
            else
            {
                _services.SystemProxy.Disable();
            }

            SystemProxyEnabled = _services.SystemProxy.IsEnabled;
            HasError = false;
            ErrorText = null;
        }
        catch (Exception ex)
        {
            ErrorText = ex.Message;
            HasError = true;
        }

        Refresh();
    }

    public void Refresh()
    {
        if (_refreshing)
        {
            return;
        }

        _refreshing = true;
        try
        {
            var snapshot = _services.Engine.GetSnapshot();
            var traffic = snapshot.Traffic;
            IsRunning = snapshot.IsRunning;
            StatusHeadline = snapshot.IsRunning ? "代理运行中" : "代理已停止";
            StatusBrush = snapshot.IsRunning ? RunningBrush : StoppedBrush;
            ListenText = $"{(snapshot.ListenerRunning ? snapshot.ListenAddress : "未监听")}:{(snapshot.ListenerRunning ? snapshot.ListenPort : 0)}";
            StatusDetail = snapshot.Interception.Active
                ? $"透明接管已注入 {snapshot.Interception.InjectedProcesses} 个进程；SOCKS5 与 HTTP 仍共用本地入口。"
                : snapshot.ListenerRunning
                    ? "SOCKS5 与 HTTP 共用同一入口，进程规则按连接自动归属。"
                    : (snapshot.ListenerError ?? "启动代理后会监听本地端口。");
            ActiveText = snapshot.ActiveConnections.ToString();
            UpText = FormatRate(traffic.UploadBytesPerSecond);
            DownText = FormatRate(traffic.DownloadBytesPerSecond);
            TotalText = FormatBytes(traffic.TotalUploadedBytes + traffic.TotalDownloadedBytes);
            UptimeText = snapshot.StartedAt is { } started
                ? FormatDuration(DateTimeOffset.Now - started)
                : "—";
            DnsText = snapshot.DnsRunning ? $"{snapshot.DnsAddress}:{snapshot.DnsPort}" : "未启用";
            InterceptText = snapshot.Interception switch
            {
                { Active: true } interception => $"{interception.InjectedProcesses} 进程 · :{interception.Port}",
                { Enabled: true } => "已配置，未运行",
                _ => "未启用",
            };
            ToggleLabel = snapshot.IsRunning ? "停止代理" : "启动代理";
            SystemProxyEnabled = _services.SystemProxy.IsEnabled;
            var currentError = !string.IsNullOrEmpty(snapshot.ListenerError)
                ? snapshot.ListenerError
                : snapshot.Interception.Error;
            if (!string.IsNullOrEmpty(currentError))
            {
                ErrorText = currentError;
                HasError = true;
            }
            else if (HasError)
            {
                ErrorText = null;
                HasError = false;
            }

            UpdateHealth(snapshot.Health);
            SamplesUpdated?.Invoke(traffic.Samples);
        }
        finally
        {
            _refreshing = false;
        }
    }

    private void UpdateHealth(IReadOnlyList<EndpointHealthSnapshot> health)
    {
        var changed = health.Count != Health.Count;
        if (!changed)
        {
            for (var i = 0; i < health.Count; i++)
            {
                if (Health[i].Name != health[i].Name || Health[i].Latency != DescribeLatency(health[i]))
                {
                    changed = true;
                    break;
                }
            }
        }

        if (!changed)
        {
            return;
        }

        Health.Clear();
        foreach (var item in health)
        {
            Health.Add(new HealthRow(
                item.Name,
                DescribeLatency(item),
                item.IsBlocked ? "熔断" : item.ConsecutiveFailures > 0 ? "重试中" : "可用",
                item.LastError ?? string.Empty,
                !item.IsBlocked && item.ConsecutiveFailures == 0));
        }
    }

    private static string DescribeLatency(EndpointHealthSnapshot health) =>
        health.LatencyMs < 0 ? "未测速" : $"{health.LatencyMs:F0} ms";

    private static string FormatRate(double bytesPerSecond)
    {
        if (bytesPerSecond >= 1024 * 1024)
        {
            return $"{bytesPerSecond / (1024 * 1024):F1} MiB/s";
        }

        if (bytesPerSecond >= 1024)
        {
            return $"{bytesPerSecond / 1024:F1} KiB/s";
        }

        return $"{bytesPerSecond:F0} B/s";
    }

    private static string FormatBytes(double bytes)
    {
        if (bytes >= 1024d * 1024 * 1024)
        {
            return $"{bytes / (1024d * 1024 * 1024):F2} GiB";
        }

        if (bytes >= 1024d * 1024)
        {
            return $"{bytes / (1024d * 1024):F2} MiB";
        }

        if (bytes >= 1024)
        {
            return $"{bytes / 1024:F1} KiB";
        }

        return $"{bytes:F0} B";
    }

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalDays >= 1)
        {
            return $"{(int)duration.TotalDays} 天 {duration.Hours} 小时";
        }

        return duration.TotalHours >= 1
            ? $"{(int)duration.TotalHours} 小时 {duration.Minutes} 分"
            : $"{duration.Minutes} 分 {duration.Seconds} 秒";
    }

    public void Dispose()
    {
        _timer.Stop();
    }
}

/// <summary>健康度列表行。</summary>
public sealed class HealthRow
{
    public HealthRow(string name, string latency, string status, string error, bool healthy)
    {
        Name = name;
        Latency = latency;
        Status = status;
        Error = error;
        DotBrush = new SolidColorBrush(healthy
            ? Color.FromArgb(255, 52, 211, 153)
            : Color.FromArgb(255, 251, 191, 36));
    }

    public string Name { get; }

    public string Latency { get; }

    public string Status { get; }

    public string Error { get; }

    public Brush DotBrush { get; }
}
