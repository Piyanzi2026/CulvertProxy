using System.Net;
using System.Net.Sockets;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Engine;
using Nexsteaduser.CulvertProxy.Core.Interception;
using Nexsteaduser.CulvertProxy.Core.Net;
using Nexsteaduser.CulvertProxy.Core.Routing;
using Nexsteaduser.CulvertProxy.Core.Transport;

namespace Nexsteaduser.CulvertProxy.Core.Server;

/// <summary>接收注入端重定向的 TCP 连接，按前导中的原始目标走统一路由。</summary>
internal sealed class InterceptServer : IAsyncDisposable
{
    private static readonly TimeSpan PreambleTimeout = TimeSpan.FromSeconds(5);
    private readonly ProxyEngine _engine;
    private readonly byte[] _token;
    private readonly List<Socket> _listeners = [];
    private readonly List<Task> _acceptLoops = [];
    private CancellationTokenSource? _cts;

    public InterceptServer(ProxyEngine engine, byte[] token)
    {
        _engine = engine;
        _token = token;
    }

    public bool IsRunning => _listeners.Count > 0;

    public int Port { get; private set; }

    /// <summary>IPv6 回环入口；绑定失败时为 0，IPv6-only 应用将失败关闭。</summary>
    public int PortV6 { get; private set; }

    /// <summary>同时监听 IPv4 与 IPv6 回环，端口尽量保持一致。</summary>
    public void Start(CancellationToken engineToken)
    {
        if (_listeners.Count > 0)
        {
            return;
        }

        var cts = CancellationTokenSource.CreateLinkedTokenSource(engineToken);
        var ipv4 = SocketFactory.CreateListener(new IPEndPoint(IPAddress.Loopback, 0));
        Port = ((IPEndPoint)ipv4.LocalEndPoint!).Port;
        _listeners.Add(ipv4);
        _acceptLoops.Add(Task.Run(() => AcceptLoopAsync(ipv4, cts.Token)));

        try
        {
            var ipv6 = SocketFactory.CreateListener(new IPEndPoint(IPAddress.IPv6Loopback, Port));
            PortV6 = Port;
            _listeners.Add(ipv6);
            _acceptLoops.Add(Task.Run(() => AcceptLoopAsync(ipv6, cts.Token)));
        }
        catch
        {
            try
            {
                var ipv6 = SocketFactory.CreateListener(new IPEndPoint(IPAddress.IPv6Loopback, 0));
                PortV6 = ((IPEndPoint)ipv6.LocalEndPoint!).Port;
                _listeners.Add(ipv6);
                _acceptLoops.Add(Task.Run(() => AcceptLoopAsync(ipv6, cts.Token)));
            }
            catch (Exception ex)
            {
                PortV6 = 0;
                _engine.Log.Warn("Intercept", $"IPv6 接管入口不可用：{ex.Message}");
            }
        }

        _cts = cts;
        _engine.Log.Info("Intercept", PortV6 > 0
            ? $"接管入口已监听 127.0.0.1:{Port} 与 [::1]:{PortV6}。"
            : $"接管入口已监听 127.0.0.1:{Port}（IPv6 不可用）。");
    }

    private async Task AcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                _engine.Log.Debug("Intercept", $"accept 失败：{ex.SocketErrorCode}");
                try
                {
                    await Task.Delay(50, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                continue;
            }

            _ = HandleClientAsync(client, cancellationToken);
        }
    }

    private async Task HandleClientAsync(Socket client, CancellationToken cancellationToken)
    {
        ActiveConnection? entry = null;
        string? failure = null;
        var failureCounted = false;
        var blockedCounted = false;
        try
        {
            SocketFactory.ConfigureAccepted(client);
            var request = await InterceptProtocol.ReadAsync(client, _token, PreambleTimeout, cancellationToken)
                .ConfigureAwait(false);
            if (request is null)
            {
                ResetAndClose(client);
                return;
            }

            var process = ResolveProcess(client) ?? _engine.Processes.Lookup(request.ProcessId);
            var (target, decision) = _engine.ResolveRoute(request.Target, RuleTransport.Tcp, process);
            var policyName = decision.PolicyId is not null
                ? _engine.Routes.GetPolicy(decision.PolicyId)?.Name
                : null;
            entry = _engine.Connections.Begin(
                new ConnectionInit("TCP 接管", target.ToString(), process?.Name, process?.Pid, decision.RuleName, policyName),
                cancellationToken);
            _engine.Stats.RecordConnection();

            Tunnel tunnel;
            try
            {
                var access = _engine.Access;
                tunnel = await _engine.Connector.ConnectAsync(
                    decision,
                    target,
                    access.ConnectTimeout,
                    access.HandshakeTimeout,
                    access.OutboundBindAddress,
                    access.MaxAttempts,
                    entry.CancellationToken).ConfigureAwait(false);
            }
            catch (ConnectionBlockedException ex)
            {
                _engine.Stats.RecordBlocked();
                blockedCounted = true;
                failure = ex.Message;
                ResetAndClose(client);
                return;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                failure = "引擎停止。";
                ResetAndClose(client);
                return;
            }
            catch (Exception ex)
            {
                _engine.Stats.RecordFailure();
                failureCounted = true;
                failure = ex.Message;
                _engine.Log.Debug("Intercept", $"{target} 连接失败：{ex.Message}");
                ResetAndClose(client);
                return;
            }

            await using (tunnel)
            {
                entry.SetRoute(tunnel.Description);
                entry.SetState("relaying");
                await using var stream = new NetworkStream(client, ownsSocket: true);
                var result = await StreamRelay.RunAsync(
                    stream,
                    client,
                    tunnel.Stream,
                    tunnel.HalfCloseSocket,
                    bytes =>
                    {
                        entry.AddUploaded(bytes);
                        _engine.Stats.AddUploaded(bytes);
                    },
                    bytes =>
                    {
                        entry.AddDownloaded(bytes);
                        _engine.Stats.AddDownloaded(bytes);
                    },
                    entry.CancellationToken).ConfigureAwait(false);

                if (result.Error is not null and not OperationCanceledException)
                {
                    _engine.Log.Debug("Intercept", $"{target} 中继结束：{result.Error.Message}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            ResetAndClose(client);
        }
        catch (Exception ex)
        {
            _engine.Log.Debug("Intercept", $"接管会话异常：{ex.Message}");
            ResetAndClose(client);
        }
        finally
        {
            if (entry is not null)
            {
                if (failure is not null && !failureCounted && !blockedCounted)
                {
                    _engine.Stats.RecordFailure();
                }

                _engine.Connections.Complete(entry, failure);
            }
        }
    }

    private ProcessIdentity? ResolveProcess(Socket client)
    {
        return client.RemoteEndPoint is IPEndPoint remote && client.LocalEndPoint is IPEndPoint local
            ? _engine.Processes.Resolve(remote, local)
            : null;
    }

    private static void ResetAndClose(Socket socket)
    {
        try
        {
            socket.LingerState = new LingerOption(true, 0);
        }
        catch
        {
            // 已断开时忽略。
        }

        socket.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        foreach (var listener in _listeners)
        {
            listener.Dispose();
        }

        foreach (var loop in _acceptLoops)
        {
            try
            {
                await loop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch
            {
                // 停止阶段允许超时。
            }
        }

        _listeners.Clear();
        _acceptLoops.Clear();
        _cts?.Dispose();
        _cts = null;
        _engine.Log.Info("Intercept", "接管入口已停止。");
    }
}
