using System.Net;
using System.Net.Sockets;

namespace Nexsteaduser.CulvertProxy.Core.Routing;

/// <summary>紧凑的 CIDR 匹配，IPv4 映射地址自动归一。</summary>
public readonly struct CidrRange
{
    private readonly byte[] _network;
    private readonly int _prefixLength;
    private readonly AddressFamily _family;

    private CidrRange(byte[] network, int prefixLength, AddressFamily family)
    {
        _network = network;
        _prefixLength = prefixLength;
        _family = family;
    }

    public int PrefixLength => _prefixLength;

    public AddressFamily AddressFamily => _family;

    public static bool TryParse(string text, out CidrRange range)
    {
        range = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var slash = text.IndexOf('/');
        var addressPart = slash < 0 ? text.Trim() : text[..slash].Trim();
        if (!IPAddress.TryParse(addressPart, out var address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        var maxPrefix = bytes.Length * 8;
        var prefix = maxPrefix;
        if (slash >= 0 && (!int.TryParse(text[(slash + 1)..].Trim(), out prefix) || prefix < 0 || prefix > maxPrefix))
        {
            return false;
        }

        var network = new byte[bytes.Length];
        var fullBytes = prefix / 8;
        var remainder = prefix % 8;
        Array.Copy(bytes, network, fullBytes);
        if (remainder > 0)
        {
            network[fullBytes] = (byte)(bytes[fullBytes] & (0xFF << (8 - remainder)));
        }

        range = new CidrRange(network, prefix, address.AddressFamily);
        return true;
    }

    public bool Contains(IPAddress address)
    {
        if (_network is null)
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != _family)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        if (bytes.Length != _network.Length)
        {
            return false;
        }

        var fullBytes = _prefixLength / 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (bytes[i] != _network[i])
            {
                return false;
            }
        }

        var remainder = _prefixLength % 8;
        if (remainder == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainder));
        return (bytes[fullBytes] & mask) == (_network[fullBytes] & mask);
    }
}
