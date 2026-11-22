using System.Collections.Concurrent;
using System.Net;

namespace Nexsteaduser.CulvertProxy.Core.Dns;

/// <summary>为域名分配固定假地址，配合本地 DNS 把连接还原成域名。</summary>
public sealed class FakeIpPool
{
    private readonly object _sync = new();
    private readonly uint _base;
    private readonly int _capacity;
    private readonly ConcurrentDictionary<string, IPAddress> _byHost = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<IPAddress, string> _byAddress = new();
    private readonly ConcurrentQueue<(string Host, IPAddress Address)> _allocationOrder = new();
    private int _next;

    public FakeIpPool(string cidr)
    {
        if (!Routing.CidrRange.TryParse(cidr, out var range))
        {
            throw new FormatException($"fake-IP 网段无效：{cidr}");
        }

        var sample = ParseBase(cidr);
        if (sample.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            throw new FormatException("fake-IP 仅支持 IPv4 网段。");
        }

        var bytes = sample.GetAddressBytes();
        if (bytes[0] == 198 && bytes[1] == 19)
        {
            throw new FormatException("198.19.0.0/16 保留给透明接管，请使用其他 fake-IP 网段。");
        }

        _base = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        var prefix = ParsePrefix(cidr);
        if (prefix is < 8 or > 30)
        {
            throw new FormatException("fake-IP 网段前缀必须在 /8 到 /30 之间。");
        }

        var size = 1L << (32 - prefix);
        _capacity = (int)Math.Min(Math.Max(size - 2, 2), 262_144);
    }

    public int Count => _byHost.Count;

    /// <summary>取或分配域名对应的假地址。</summary>
    public IPAddress GetOrAdd(string host)
    {
        var key = host.Trim().TrimEnd('.').ToLowerInvariant();
        lock (_sync)
        {
            if (_byHost.TryGetValue(key, out var existing))
            {
                return existing;
            }

            var address = AllocateAddress();
            _byHost[key] = address;
            _byAddress[address] = key;
            _allocationOrder.Enqueue((key, address));
            Trim();
            return address;
        }
    }

    /// <summary>反查假地址对应的域名。</summary>
    public bool TryGetHost(IPAddress address, out string host)
    {
        if (_byAddress.TryGetValue(address, out var value))
        {
            host = value;
            return true;
        }

        host = string.Empty;
        return false;
    }

    public void Clear()
    {
        lock (_sync)
        {
            _byHost.Clear();
            _byAddress.Clear();
            while (_allocationOrder.TryDequeue(out _))
            {
            }
        }
    }

    private IPAddress AllocateAddress()
    {
        for (var attempt = 0; attempt < _capacity; attempt++)
        {
            var offset = (uint)((Interlocked.Increment(ref _next) - 1) % (_capacity - 1)) + 1;
            var address = FromUInt(_base + offset);
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 198 && bytes[1] == 19)
            {
                // 注入层保留段，跳过，避免与进程内 fake-IP 发生域名错配。
                continue;
            }

            if (!_byAddress.ContainsKey(address))
            {
                return address;
            }
        }

        // 容量耗尽时整体回收，旧连接会自然失效。
        Clear();
        return AllocateAddress();
    }

    private void Trim()
    {
        while (_allocationOrder.Count > _capacity && _allocationOrder.TryDequeue(out var oldest))
        {
            if (_byAddress.TryGetValue(oldest.Address, out var mapped) && mapped == oldest.Host)
            {
                _byAddress.TryRemove(oldest.Address, out _);
                _byHost.TryRemove(oldest.Host, out _);
            }
        }
    }

    private static IPAddress FromUInt(uint value) => new(new[]
    {
        (byte)(value >> 24),
        (byte)(value >> 16),
        (byte)(value >> 8),
        (byte)value,
    });

    private static IPAddress ParseBase(string cidr)
    {
        var slash = cidr.IndexOf('/');
        var text = slash < 0 ? cidr : cidr[..slash];
        return IPAddress.Parse(text.Trim());
    }

    private static int ParsePrefix(string cidr)
    {
        var slash = cidr.IndexOf('/');
        return slash < 0 || !int.TryParse(cidr[(slash + 1)..], out var prefix) ? 32 : prefix;
    }
}
