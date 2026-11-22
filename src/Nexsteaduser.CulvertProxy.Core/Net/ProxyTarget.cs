using System.Net;
using System.Net.Sockets;

namespace Nexsteaduser.CulvertProxy.Core.Net;

/// <summary>一次连接请求的目标，主机名可以是域名或 IP 字面量。</summary>
public readonly record struct ProxyTarget(string Host, int Port)
{
    public bool IsIpLiteral => IPAddress.TryParse(Host, out _);

    public bool IsIpv6Literal => IPAddress.TryParse(Host, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6;

    public IPAddress? AsAddress() => IPAddress.TryParse(Host, out var address) ? address : null;

    /// <summary>将 host:port 或 [ipv6]:port 解析为目标。</summary>
    public static ProxyTarget Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        value = value.Trim();
        if (value.StartsWith('['))
        {
            var close = value.IndexOf(']');
            if (close < 0 || close + 2 > value.Length || value[close + 1] != ':')
            {
                throw new FormatException($"无法解析目标地址：{value}");
            }

            return new ProxyTarget(value[1..close], int.Parse(value[(close + 2)..]));
        }

        var lastColon = value.LastIndexOf(':');
        if (lastColon <= 0 || lastColon == value.Length - 1)
        {
            throw new FormatException($"无法解析目标地址：{value}");
        }

        var host = value[..lastColon];
        var port = int.Parse(value[(lastColon + 1)..]);
        return new ProxyTarget(host.Trim('[', ']'), port);
    }

    public override string ToString() => IsIpv6Literal ? $"[{Host}]:{Port}" : $"{Host}:{Port}";
}
