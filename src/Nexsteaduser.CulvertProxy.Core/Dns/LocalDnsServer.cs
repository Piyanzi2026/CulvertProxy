using System.Buffers;
using System.Net;
using System.Net.Sockets;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;

namespace Nexsteaduser.CulvertProxy.Core.Dns;

/// <summary>本地 UDP DNS 服务：可返回 fake-IP，或把查询转发到 DoH/系统解析。</summary>
public sealed class LocalDnsServer : IAsyncDisposable
{
    private readonly LogHub _log;
    private readonly DohResolver _resolver;
    private readonly FakeIpPool? _fakeIp;
    private readonly Func<bool>? _fakeIpAllowed;
    private readonly IPEndPoint _endpoint;
    private readonly SemaphoreSlim _concurrency = new(64, 64);
    private Socket? _socket;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private int _fakeUnavailableWarned;

    public LocalDnsServer(
        LogHub log,
        DohResolver resolver,
        FakeIpPool? fakeIp,
        DnsConfig config,
        Func<bool>? fakeIpAllowed = null)
    {
        _log = log;
        _resolver = resolver;
        _fakeIp = config.FakeIpEnabled ? fakeIp : null;
        _fakeIpAllowed = fakeIpAllowed;
        _endpoint = new IPEndPoint(IPAddress.Parse(config.BindAddress), config.Port);
    }

    public IPEndPoint Endpoint => _endpoint;

    public bool IsRunning => _socket is not null;

    /// <summary>绑定并启动接收循环；端口冲突时抛出，由引擎记录并继续运行。</summary>
    public void Start(CancellationToken engineToken)
    {
        if (_socket is not null)
        {
            return;
        }

        var socket = new Socket(_endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Bind(_endpoint);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(engineToken);
        _socket = socket;
        _loop = Task.Run(() => ReceiveLoopAsync(socket, _cts.Token));
        _log.Info("DNS", $"本地 DNS 已监听 {_endpoint}（fake-IP：{(_fakeIp is not null ? "开启" : "关闭")}）。");
    }

    private async Task ReceiveLoopAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            var anyEndPoint = new IPEndPoint(
                socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any,
                0);
            while (!cancellationToken.IsCancellationRequested)
            {
                SocketReceiveFromResult result;
                try
                {
                    result = await socket.ReceiveFromAsync(buffer.AsMemory(0, 4096), SocketFlags.None, anyEndPoint, cancellationToken).ConfigureAwait(false);
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
                    _log.Debug("DNS", $"接收 DNS 查询失败：{ex.SocketErrorCode}");
                    continue;
                }

                if (result.ReceivedBytes <= 0)
                {
                    continue;
                }

                var packet = buffer.AsSpan(0, result.ReceivedBytes).ToArray();
                _ = HandleQueryAsync(socket, packet, result.RemoteEndPoint, cancellationToken);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task HandleQueryAsync(Socket socket, byte[] packet, EndPoint remote, CancellationToken cancellationToken)
    {
        try
        {
            await _concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        try
        {
            if (!DnsWire.TryParseQuery(packet, out _, out var host, out var qtype, out var questionEnd))
            {
                return;
            }

            IReadOnlyList<IPAddress> addresses;
            var ttl = 60;
            byte rcode = 0;
            var fakeIp = ResolveFakeEligibility();
            if (qtype is not (DnsWire.TypeA or DnsWire.TypeAaaa))
            {
                addresses = [];
            }
            else if (fakeIp is not null && qtype == DnsWire.TypeA && !DohResolver.IsLocalName(host))
            {
                addresses = [fakeIp.GetOrAdd(host)];
            }
            else if (fakeIp is not null && qtype == DnsWire.TypeAaaa && !DohResolver.IsLocalName(host))
            {
                // fake-IP 模式下屏蔽 AAAA，避免应用绕过 IPv4 假地址。
                addresses = [];
            }
            else
            {
                var resolution = await _resolver.QueryAsync(host, qtype, cancellationToken).ConfigureAwait(false);
                addresses = resolution.Addresses;
                ttl = resolution.TtlSeconds;
                if (!resolution.IsSuccess)
                {
                    rcode = resolution.RCode == 3 ? (byte)3 : (byte)2;
                    _log.Debug("DNS", $"{host} 解析失败：{resolution.Error}");
                }
            }

            var response = DnsWire.BuildResponse(packet, questionEnd, addresses, ttl, qtype, rcode);
            try
            {
                await socket.SendToAsync(response, SocketFlags.None, remote, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                // 客户端已放弃查询。
            }
        }
        catch (OperationCanceledException)
        {
            // 引擎停止。
        }
        catch (Exception ex)
        {
            _log.Debug("DNS", $"处理 DNS 查询异常：{ex.Message}");
        }
        finally
        {
            _concurrency.Release();
        }
    }

    /// <summary>fake-IP 只有在透明接管真正可用时才能返回，否则连接无法被还原。</summary>
    private FakeIpPool? ResolveFakeEligibility()
    {
        if (_fakeIp is null)
        {
            return null;
        }

        if (_fakeIpAllowed is null || _fakeIpAllowed())
        {
            return _fakeIp;
        }

        if (Interlocked.Exchange(ref _fakeUnavailableWarned, 1) == 0)
        {
            _log.Warn("DNS", "已配置 fake-IP，但透明接管未运行；本次改为返回真实解析结果，避免应用拿到无法连接的假地址。");
        }

        return null;
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _socket?.Dispose();
        if (_loop is not null)
        {
            try
            {
                await _loop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch
            {
                // 停止阶段允许超时。
            }
        }

        _cts?.Dispose();
        _concurrency.Dispose();
        _socket = null;
        _loop = null;
        _log.Info("DNS", "本地 DNS 已停止。");
    }
}
