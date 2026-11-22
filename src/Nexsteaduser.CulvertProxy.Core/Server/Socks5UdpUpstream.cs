using System.Buffers;
using System.Net;
using System.Net.Sockets;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Net;
using Nexsteaduser.CulvertProxy.Core.Protocols;

namespace Nexsteaduser.CulvertProxy.Core.Server;

/// <summary>与单个 SOCKS5 上游建立的 UDP ASSOCIATE 通道。</summary>
internal sealed class Socks5UdpUpstream : IAsyncDisposable
{
    private readonly Socket _udp;
    private readonly Stream _control;
    private readonly CancellationTokenSource _closed = new();
    private readonly Task _watcher;
    private int _disposed;

    private Socks5UdpUpstream(Socket udp, Stream control)
    {
        _udp = udp;
        _control = control;
        _watcher = Task.Run(WatchControlAsync);
    }

    public bool IsAlive => !_closed.IsCancellationRequested;

    public CancellationToken ClosedToken => _closed.Token;

    public static async ValueTask<Socks5UdpUpstream> ConnectAsync(
        ProxyEndpoint hop,
        TimeSpan connectTimeout,
        TimeSpan handshakeTimeout,
        CancellationToken cancellationToken)
    {
        var tcp = await SocketFactory.ConnectAsync(hop.Host, hop.Port, connectTimeout, null, cancellationToken).ConfigureAwait(false);
        Stream stream = new NetworkStream(tcp, ownsSocket: true);
        try
        {
            if (hop.UseTls)
            {
                stream = await TlsStreamFactory.WrapAsync(stream, hop, cancellationToken).ConfigureAwait(false);
            }

            await Socks5Protocol.NegotiateAsync(stream, hop, handshakeTimeout, cancellationToken).ConfigureAwait(false);

            // UDP ASSOCIATE，客户端地址填 0.0.0.0:0 由服务器决定。
            byte[] request =
            [
                Socks5Protocol.Version,
                Socks5Protocol.CmdUdpAssociate,
                0x00,
                Socks5Protocol.AddressIpv4,
                0, 0, 0, 0,
                0, 0,
            ];
            await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);

            var head = new byte[4];
            await stream.ReadExactlyAsync(head, cancellationToken).ConfigureAwait(false);
            if (head[0] != Socks5Protocol.Version)
            {
                throw new ProxyHandshakeException($"UDP ASSOCIATE 版本异常：0x{head[0]:X2}。");
            }

            if (head[1] != 0)
            {
                throw new ProxyHandshakeException($"UDP ASSOCIATE 被拒绝：{Socks5Protocol.DescribeReply(head[1])}。", head[1]);
            }

            var advertised = await Socks5Protocol.ReadEndpointAsync(stream, head[3], cancellationToken).ConfigureAwait(false);
            var relayEndPoint = await ResolveRelayAsync(hop, advertised, cancellationToken).ConfigureAwait(false);

            var udp = new Socket(relayEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                udp.Connect(relayEndPoint);
            }
            catch
            {
                udp.Dispose();
                throw;
            }

            return new Socks5UdpUpstream(udp, stream);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            tcp.Dispose();
            throw;
        }
    }

    public async ValueTask SendAsync(ProxyTarget target, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (!IsAlive)
        {
            throw new IOException("UDP 上游控制连接已关闭。");
        }

        var header = new byte[Socks5UdpCodec.MaxHeaderLength];
        var headerLength = Socks5UdpCodec.WriteHeader(target, header);
        var total = headerLength + payload.Length;
        if (total > 65507)
        {
            throw new IOException("UDP 负载超过 65507 字节上限。");
        }

        var buffer = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            header.AsSpan(0, headerLength).CopyTo(buffer);
            payload.Span.CopyTo(buffer.AsSpan(headerLength));
            await _udp.SendAsync(buffer.AsMemory(0, total), SocketFlags.None, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>接收并去掉 SOCKS5 UDP 头，负载前移到缓冲区起始位置。</summary>
    public async ValueTask<(ProxyTarget Source, int Length)> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (true)
        {
            var received = await _udp.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if (Socks5UdpCodec.TryParseHeader(buffer.Span[..received], out var source, out var offset))
            {
                var length = received - offset;
                buffer.Span.Slice(offset, length).CopyTo(buffer.Span);
                return (source, length);
            }
        }
    }

    private async Task WatchControlAsync()
    {
        var buffer = new byte[256];
        try
        {
            while (!_closed.IsCancellationRequested)
            {
                var read = await _control.ReadAsync(buffer, _closed.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
            }
        }
        catch
        {
            // 控制连接异常即视为通道关闭。
        }
        finally
        {
            _closed.Cancel();
        }
    }

    private static async ValueTask<IPEndPoint> ResolveRelayAsync(ProxyEndpoint hop, ProxyTarget advertised, CancellationToken cancellationToken)
    {
        if (advertised.Port == 0)
        {
            throw new ProxyHandshakeException("上游返回的 UDP 中继端口为 0。");
        }

        IPAddress address;
        if (IPAddress.TryParse(advertised.Host, out var parsed))
        {
            address = parsed;
        }
        else
        {
            var resolved = await System.Net.Dns.GetHostAddressesAsync(advertised.Host, cancellationToken).ConfigureAwait(false);
            address = resolved.FirstOrDefault() ?? throw new ProxyHandshakeException("无法解析 UDP 中继地址。");
        }

        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            var family = address.AddressFamily;
            IReadOnlyList<IPAddress> hopAddresses = IPAddress.TryParse(hop.Host, out var literal)
                ? [literal]
                : await System.Net.Dns.GetHostAddressesAsync(hop.Host, cancellationToken).ConfigureAwait(false);
            address = hopAddresses.FirstOrDefault(a => a.AddressFamily == family)
                ?? hopAddresses.FirstOrDefault()
                ?? throw new ProxyHandshakeException("无法确定 UDP 中继地址。");
        }

        return new IPEndPoint(address, advertised.Port);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _closed.Cancel();
        try
        {
            await _control.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
            // 忽略关闭异常。
        }

        _udp.Dispose();
        try
        {
            await _watcher.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        }
        catch
        {
            // 关闭阶段允许超时。
        }

        _closed.Dispose();
    }
}
