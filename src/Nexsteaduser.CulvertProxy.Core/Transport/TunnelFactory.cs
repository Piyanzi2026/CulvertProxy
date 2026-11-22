using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Net;
using Nexsteaduser.CulvertProxy.Core.Protocols;

namespace Nexsteaduser.CulvertProxy.Core.Transport;

/// <summary>把已解析的主机名转换为地址集合。</summary>
public delegate ValueTask<IReadOnlyList<IPAddress>> HostResolver(string host, CancellationToken cancellationToken);

/// <summary>按顺序逐跳建立隧道，支持 SOCKS5、HTTP CONNECT 与 TLS 包装。</summary>
public sealed class TunnelFactory
{
    private readonly HostResolver _hostResolver;

    public TunnelFactory(HostResolver hostResolver)
    {
        _hostResolver = hostResolver;
    }

    /// <summary>直连目标；域名通过自定义解析器（可走 DoH 或代理）解析。</summary>
    public async ValueTask<Tunnel> OpenDirectAsync(
        ProxyTarget target,
        TimeSpan connectTimeout,
        IPAddress? bindAddress,
        CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        Socket socket;
        if (target.IsIpLiteral)
        {
            socket = await SocketFactory.ConnectAnyAsync([target.AsAddress()!], target.Port, connectTimeout, bindAddress, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var addresses = await _hostResolver(target.Host, cancellationToken).ConfigureAwait(false);
            socket = await SocketFactory.ConnectAnyAsync(addresses, target.Port, connectTimeout, bindAddress, cancellationToken).ConfigureAwait(false);
        }

        sw.Stop();
        return new Tunnel(new NetworkStream(socket, ownsSocket: true), socket, $"直连 {target} ({sw.ElapsedMilliseconds} ms)");
    }

    /// <summary>建立完整链路；hops 为空表示直连。</summary>
    public async ValueTask<Tunnel> OpenAsync(
        IReadOnlyList<ProxyEndpoint> hops,
        ProxyTarget target,
        TimeSpan connectTimeout,
        TimeSpan handshakeTimeout,
        IPAddress? bindAddress,
        CancellationToken cancellationToken,
        string? policyName = null)
    {
        if (hops.Count == 0)
        {
            return await OpenDirectAsync(target, connectTimeout, bindAddress, cancellationToken).ConfigureAwait(false);
        }

        if (hops.Count > 8)
        {
            throw new ArgumentException("链路跳数不能超过 8。", nameof(hops));
        }

        var first = hops[0];
        var sw = Stopwatch.StartNew();
        // 入口代理地址使用系统解析，避免 DoH 与代理策略形成自举依赖。
        // 同时过滤 fake-IP：系统 DNS 指向本机 fake-IP 服务时，上游主机必须用 IP。
        var socket = await ConnectFirstHopAsync(first, connectTimeout, bindAddress, cancellationToken).ConfigureAwait(false);
        Stream stream = new NetworkStream(socket, ownsSocket: true);
        var plainTcp = true;
        try
        {
            if (first.UseTls)
            {
                stream = await TlsStreamFactory.WrapAsync(stream, first, cancellationToken).ConfigureAwait(false);
                plainTcp = false;
            }

            for (var i = 0; i < hops.Count; i++)
            {
                var hop = hops[i];
                var nextTarget = i == hops.Count - 1
                    ? target
                    : new ProxyTarget(hops[i + 1].Host, hops[i + 1].Port);

                try
                {
                    stream = hop.Protocol switch
                    {
                        ProxyProtocol.Socks5 => await OpenSocksAsync(stream, hop, nextTarget, handshakeTimeout, cancellationToken).ConfigureAwait(false),
                        ProxyProtocol.HttpConnect => await OpenHttpAsync(stream, hop, nextTarget, handshakeTimeout, cancellationToken).ConfigureAwait(false),
                        _ => throw new ProxyHandshakeException($"未知上游协议：{hop.Protocol}。"),
                    };
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    throw new ChainConnectException(i, hop, ex);
                }

                if (i + 1 < hops.Count && hops[i + 1].UseTls)
                {
                    stream = await TlsStreamFactory.WrapAsync(stream, hops[i + 1], cancellationToken).ConfigureAwait(false);
                    plainTcp = false;
                }
            }

            sw.Stop();
            var description = string.Join(" → ", hops.Select(h => h.Name)) + $" → {target} ({sw.ElapsedMilliseconds} ms)";
            return new Tunnel(stream, plainTcp ? socket : null, description, policyName);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            socket.Dispose();
            throw;
        }
    }

    private static async ValueTask<Socket> ConnectFirstHopAsync(
        ProxyEndpoint first,
        TimeSpan connectTimeout,
        IPAddress? bindAddress,
        CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(first.Host, out var literal))
        {
            return await SocketFactory.ConnectAnyAsync([literal], first.Port, connectTimeout, bindAddress, cancellationToken)
                .ConfigureAwait(false);
        }

        var addresses = await System.Net.Dns.GetHostAddressesAsync(first.Host, cancellationToken).ConfigureAwait(false);
        var usable = addresses.Where(address => !IsFakeIpAddress(address)).ToArray();
        if (usable.Length == 0)
        {
            throw new ProxyHandshakeException(
                $"上游主机 {first.Host} 被 fake-IP 解析。启用本地 DNS + fake-IP 时，请把上游地址改为 IP，SNI 单独填写域名。");
        }

        return await SocketFactory.ConnectAnyAsync(usable, first.Port, connectTimeout, bindAddress, cancellationToken)
            .ConfigureAwait(false);
    }

    private static bool IsFakeIpAddress(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19);
    }

    private static async ValueTask<Stream> OpenSocksAsync(
        Stream stream,
        ProxyEndpoint hop,
        ProxyTarget target,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        await Socks5Protocol.ConnectAsync(stream, hop, target, timeout, cancellationToken).ConfigureAwait(false);
        return stream;
    }

    private static async ValueTask<Stream> OpenHttpAsync(
        Stream stream,
        ProxyEndpoint hop,
        ProxyTarget target,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        return await HttpConnectClient.ConnectAsync(stream, hop, target, timeout, cancellationToken).ConfigureAwait(false);
    }
}
