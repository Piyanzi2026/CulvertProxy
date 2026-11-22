using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;
using Nexsteaduser.CulvertProxy.Core.Engine;

namespace CulvertProxy.SmokeTest;

/// <summary>端到端验证：注入原生探针 → fake-IP → 接管入口 → 规则 → 回显。</summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        await using var echo = new EchoServer();
        await echo.StartAsync();

        var config = AppConfig.CreateDefault();
        config.Rules.Clear();
        config.Listener.Enabled = true;
        config.Listener.BindAddress = "127.0.0.1";
        config.Listener.Port = FreePort();
        config.Dns.Mode = DnsResolutionMode.System;
        config.Dns.Hosts.Add(new HostMapping { Host = "probe.test", Address = "127.0.0.1" });
        config.Interception.Enabled = true;
        config.Interception.InjectRunningProcesses = false;
        config.Interception.AutoInjectNewProcesses = false;
        ConfigStore.Normalize(config);

        await using var log = new LogHub(writeToDisk: false);
        log.EntryAdded += entry => Console.WriteLine($"LOG [{entry.Severity}] {entry.Category}: {entry.Message}");

        await using var engine = new ProxyEngine(log, config);
        await engine.StartAsync();

        var snapshot = engine.GetSnapshot();
        if (!snapshot.Interception.Active || snapshot.Interception.Port <= 0)
        {
            Console.Error.WriteLine($"接管未启动：{snapshot.Interception.Error}");
            return 1;
        }

        var probePath = Path.Combine(AppContext.BaseDirectory, "probe.exe");
        if (!File.Exists(probePath))
        {
            Console.Error.WriteLine($"缺少探针：{probePath}");
            return 1;
        }

        var startInfo = new ProcessStartInfo(probePath, $"probe.test {echo.Port} 3000")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var probe = Process.Start(startInfo);
        if (probe is null)
        {
            Console.Error.WriteLine("无法启动探针。");
            return 1;
        }

        var stdoutTask = probe.StandardOutput.ReadToEndAsync();
        var stderrTask = probe.StandardError.ReadToEndAsync();
        await Task.Delay(300);
        var report = await engine.InjectProcessAsync(probe.Id);
        Console.WriteLine($"注入 PID {probe.Id}：新注入 {report.Injected}，已在管 {report.AlreadyInjected}，失败 {report.Failed}，{report.LastError}");

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            await probe.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            probe.Kill(entireProcessTree: true);
            Console.Error.WriteLine("探针超时。");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        Console.WriteLine("--- probe stdout ---");
        Console.Write(stdout);
        if (!string.IsNullOrWhiteSpace(stderr))
        {
            Console.WriteLine("--- probe stderr ---");
            Console.Write(stderr);
        }

        var connections = engine.GetConnections();
        foreach (var connection in connections)
        {
            Console.WriteLine($"连接：{connection.Protocol} {connection.Target} 规则={connection.RuleName} 路由={connection.Route} 状态={connection.State} 上={connection.BytesUp} 下={connection.BytesDown} 错误={connection.Error}");
        }

        var passed = probe.ExitCode == 0
            && stdout.Contains("OK probe-ping", StringComparison.Ordinal)
            && stdout.Contains("WIDE 198.19.", StringComparison.Ordinal)
            && stdout.Contains("WIDE6 ::ffff:198.19.", StringComparison.Ordinal)
            && connections.Any(item => item.Protocol == "TCP 接管");

        if (passed && args.Length > 0 && File.Exists(args[0]))
        {
            passed = await RunDotnetProbeAsync(engine, echo.Port, args[0]);
        }

        if (passed && args.Contains("--release-test", StringComparer.OrdinalIgnoreCase))
        {
            passed = await RunReleaseFallbackAsync(engine, echo.Port, probePath, config, log);
        }

        Console.WriteLine(passed ? "SMOKE PASS" : $"SMOKE FAIL (exit={probe.ExitCode})");
        return passed ? 0 : 1;
    }

    /// <summary>关闭透明接管后，验证已缓存 fake-IP 能在 Hook 内还原域名并直连。</summary>
    private static async Task<bool> RunReleaseFallbackAsync(
        ProxyEngine engine,
        int echoPort,
        string probePath,
        AppConfig config,
        LogHub log)
    {
        const string host = "127.0.0.1.sslip.io";
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host);
            if (!addresses.Contains(IPAddress.Loopback))
            {
                Console.WriteLine("RELEASE TEST SKIPPED：通配 DNS 未返回回环地址。");
                return true;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"RELEASE TEST SKIPPED：通配 DNS 不可用（{ex.Message}）。");
            return true;
        }

        var startInfo = new ProcessStartInfo(probePath, $"{host} {echoPort} 3000 hold")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var probe = Process.Start(startInfo);
        if (probe is null)
        {
            Console.WriteLine("RELEASE TEST FAIL：无法启动探针。");
            return false;
        }

        var stdout = new StringBuilder();
        var holdSignal = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var stdoutTask = Task.Run(async () =>
        {
            while (await probe.StandardOutput.ReadLineAsync() is { } line)
            {
                stdout.AppendLine(line);
                if (line.Contains("HOLD_FAKE", StringComparison.Ordinal))
                {
                    holdSignal.TrySetResult(true);
                }
            }
        });
        var stderrTask = probe.StandardError.ReadToEndAsync();

        await Task.Delay(250);
        await engine.InjectProcessAsync(probe.Id);
        try
        {
            await holdSignal.Task.WaitAsync(TimeSpan.FromSeconds(20));
        }
        catch (TimeoutException)
        {
            Console.WriteLine("RELEASE TEST FAIL：探针未进入等待阶段。");
            probe.Kill(entireProcessTree: true);
            return false;
        }

        config.Interception.Enabled = false;
        await engine.ReloadAsync(config);
        log.Info("Smoke", "已关闭透明接管，等待缓存 fake-IP 连接。");

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            await probe.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            probe.Kill(entireProcessTree: true);
            Console.WriteLine("RELEASE TEST FAIL：探针超时。");
            return false;
        }

        await stdoutTask;
        var output = stdout.ToString();
        var stderr = await stderrTask;
        Console.WriteLine($"--- release probe stdout ---\n{output}");
        if (!string.IsNullOrWhiteSpace(stderr))
        {
            Console.WriteLine($"--- release probe stderr ---\n{stderr}");
        }

        var ok = probe.ExitCode == 0
            && output.Contains("HOLD_FAKE", StringComparison.Ordinal)
            && output.Contains("OK probe-ping", StringComparison.Ordinal)
            && output.Contains("ADDR 198.19.", StringComparison.Ordinal);
        Console.WriteLine(ok ? "RELEASE TEST PASS" : "RELEASE TEST FAIL");
        return ok;
    }

    /// <summary>用非回环局域网地址验证 .NET Socket 的异步 ConnectEx 路径。</summary>
    private static async Task<bool> RunDotnetProbeAsync(ProxyEngine engine, int echoPort, string probePath)
    {
        var lan = FindLanAddress();
        if (lan is null)
        {
            Console.WriteLine("DOTNET PROBE SKIPPED：未找到非回环 IPv4 地址。");
            return true;
        }

        var startInfo = new ProcessStartInfo(probePath, $"{lan} {echoPort} 2000 async")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var probe = Process.Start(startInfo);
        if (probe is null)
        {
            Console.WriteLine("DOTNET PROBE FAIL：无法启动。");
            return false;
        }

        var stdoutTask = probe.StandardOutput.ReadToEndAsync();
        var stderrTask = probe.StandardError.ReadToEndAsync();
        await Task.Delay(200);
        var report = await engine.InjectProcessAsync(probe.Id);
        Console.WriteLine($"注入 .NET 探针 PID {probe.Id}：新注入 {report.Injected}，失败 {report.Failed}，{report.LastError}");

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            await probe.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            probe.Kill(entireProcessTree: true);
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        Console.WriteLine($"--- .NET probe stdout ---\n{stdout}");
        if (!string.IsNullOrWhiteSpace(stderr))
        {
            Console.WriteLine($"--- .NET probe stderr ---\n{stderr}");
        }

        var intercepted = engine.GetConnections()
            .Any(item => item.Protocol == "TCP 接管"
                && item.Target.StartsWith($"{lan}:{echoPort}", StringComparison.Ordinal));
        var ok = probe.ExitCode == 0 && stdout.Contains("OK dotnet-ping", StringComparison.Ordinal) && intercepted;
        Console.WriteLine(ok ? "DOTNET PROBE PASS" : "DOTNET PROBE FAIL");
        return ok;
    }

    private static IPAddress? FindLanAddress()
    {
        foreach (var network in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (network.OperationalStatus != OperationalStatus.Up
                || network.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var unicast in network.GetIPProperties().UnicastAddresses)
            {
                var address = unicast.Address;
                if (address.AddressFamily == AddressFamily.InterNetwork
                    && !IPAddress.IsLoopback(address)
                    && !address.ToString().StartsWith("169.254.", StringComparison.Ordinal))
                {
                    return address;
                }
            }
        }

        return null;
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}

/// <summary>单线程 TCP 回显服务，仅用于冒烟验证。</summary>
internal sealed class EchoServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Any, 0);
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public int Port { get; private set; }

    public Task StartAsync()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _loop = Task.Run(AcceptLoopAsync);
        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch
            {
                break;
            }

            _ = HandleAsync(client);
        }
    }

    private static async Task HandleAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var buffer = new byte[4096];
                while (true)
                {
                    var read = await stream.ReadAsync(buffer);
                    if (read <= 0)
                    {
                        break;
                    }

                    await stream.WriteAsync(buffer.AsMemory(0, read));
                }
            }
            catch
            {
                // 探针退出时连接被重置属于正常现象。
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        if (_loop is not null)
        {
            try
            {
                await _loop.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch
            {
                // 忽略停止阶段异常。
            }
        }

        _cts.Dispose();
    }
}
