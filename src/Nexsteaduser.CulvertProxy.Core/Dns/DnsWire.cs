using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Nexsteaduser.CulvertProxy.Core.Dns;

/// <summary>最小但完整的 DNS 报文构造与解析，只处理 A/AAAA 记录。</summary>
public static class DnsWire
{
    public const ushort TypeA = 1;
    public const ushort TypeCname = 5;
    public const ushort TypeAaaa = 28;
    public const ushort ClassIn = 1;

    /// <summary>构造递归查询报文。</summary>
    public static byte[] BuildQuery(string host, ushort qtype, ushort id)
    {
        var nameBytes = EncodeName(host);
        var packet = new byte[12 + nameBytes.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0), id);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), 1);
        nameBytes.CopyTo(packet, 12);
        var offset = 12 + nameBytes.Length;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset), qtype);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 2), ClassIn);
        return packet;
    }

    /// <summary>解析查询报文的 id、名称、类型与问题段结束位置。</summary>
    public static bool TryParseQuery(ReadOnlySpan<byte> packet, out ushort id, out string host, out ushort qtype, out int questionEnd)
    {
        id = 0;
        host = string.Empty;
        qtype = 0;
        questionEnd = 0;
        if (packet.Length < 12)
        {
            return false;
        }

        id = BinaryPrimitives.ReadUInt16BigEndian(packet);
        var questions = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
        if (questions < 1)
        {
            return false;
        }

        if (!TryReadName(packet, 12, out host, out var next))
        {
            return false;
        }

        if (next + 4 > packet.Length)
        {
            return false;
        }

        qtype = BinaryPrimitives.ReadUInt16BigEndian(packet[next..]);
        questionEnd = next + 4;
        return true;
    }

    /// <summary>解析应答报文中的 A/AAAA 地址与最小 TTL。</summary>
    public static DnsResolution ParseAnswer(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 12)
        {
            return DnsResolution.Failure("DNS 应答过短。");
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        var rcode = flags & 0x000F;
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);
        var truncated = (flags & 0x0200) != 0;

        var offset = 12;
        for (var i = 0; i < questionCount; i++)
        {
            if (!TryReadName(packet, offset, out _, out offset) || offset + 4 > packet.Length)
            {
                return DnsResolution.Failure("DNS 问题段损坏。");
            }

            offset += 4;
        }

        if (rcode == 3)
        {
            return new DnsResolution(false, [], 0, rcode, "域名不存在（NXDOMAIN）。");
        }

        if (rcode != 0)
        {
            return DnsResolution.Failure($"DNS 服务器返回错误码 {rcode}。", rcode);
        }

        if (truncated)
        {
            return DnsResolution.Failure("DNS 应答被截断。");
        }

        var addresses = new List<IPAddress>(Math.Min((int)answerCount, 8));
        var minTtl = int.MaxValue;
        for (var i = 0; i < answerCount; i++)
        {
            if (!TryReadName(packet, offset, out _, out offset) || offset + 10 > packet.Length)
            {
                break;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]);
            var ttl = (int)BinaryPrimitives.ReadUInt32BigEndian(packet[(offset + 4)..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 8)..]);
            offset += 10;
            if (offset + length > packet.Length)
            {
                break;
            }

            if ((type == TypeA && length == 4) || (type == TypeAaaa && length == 16))
            {
                addresses.Add(new IPAddress(packet.Slice(offset, length)));
                minTtl = Math.Min(minTtl, ttl);
            }

            offset += length;
        }

        var effectiveTtl = minTtl == int.MaxValue ? 60 : Math.Clamp(minTtl, 30, 3600);
        return addresses.Count > 0
            ? new DnsResolution(true, addresses, effectiveTtl, 0, null)
            : new DnsResolution(true, [], effectiveTtl, 0, null);
    }

    /// <summary>基于原始查询构造响应，问题段原样复用。</summary>
    public static byte[] BuildResponse(
        ReadOnlySpan<byte> query,
        int questionEnd,
        IReadOnlyList<IPAddress> addresses,
        int ttlSeconds,
        ushort qtype,
        byte rcode = 0)
    {
        var queryFlags = BinaryPrimitives.ReadUInt16BigEndian(query[2..]);
        var answers = new List<IPAddress>(addresses.Count);
        foreach (var address in addresses)
        {
            if (qtype == TypeA && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                answers.Add(address);
            }
            else if (qtype == TypeAaaa && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                answers.Add(address);
            }
        }

        var flags = (ushort)(0x8000 | (queryFlags & 0x7900) | 0x0080 | (rcode & 0x0F));
        var size = 12 + (questionEnd - 12) + (answers.Count * 16);
        var packet = new byte[size];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0), BinaryPrimitives.ReadUInt16BigEndian(query));
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), (ushort)answers.Count);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(8), 0);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), 0);
        query[12..questionEnd].CopyTo(packet.AsSpan(12));

        var offset = 12 + (questionEnd - 12);
        foreach (var address in answers)
        {
            packet[offset] = 0xC0;
            packet[offset + 1] = 0x0C;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 2), qtype);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 4), ClassIn);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(offset + 6), (uint)Math.Clamp(ttlSeconds, 0, 3600));
            var bytes = address.GetAddressBytes();
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 10), (ushort)bytes.Length);
            bytes.CopyTo(packet, offset + 12);
            offset += 12 + bytes.Length;
        }

        return packet;
    }

    private static byte[] EncodeName(string host)
    {
        var normalized = host.Trim().TrimEnd('.');
        var output = new List<byte>(normalized.Length + 2);
        foreach (var label in normalized.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63)
            {
                throw new FormatException($"域名标签非法：{host}");
            }

            output.Add((byte)bytes.Length);
            output.AddRange(bytes);
        }

        output.Add(0);
        return [.. output];
    }

    private static bool TryReadName(ReadOnlySpan<byte> packet, int offset, out string name, out int nextOffset)
    {
        name = string.Empty;
        nextOffset = offset;
        var builder = new StringBuilder(64);
        var cursor = offset;
        var jumped = false;
        var jumps = 0;
        while (true)
        {
            if (cursor >= packet.Length)
            {
                return false;
            }

            var length = packet[cursor];
            if ((length & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= packet.Length)
                {
                    return false;
                }

                var pointer = ((length & 0x3F) << 8) | packet[cursor + 1];
                if (!jumped)
                {
                    nextOffset = cursor + 2;
                }

                jumped = true;
                if (++jumps > 16)
                {
                    return false;
                }

                cursor = pointer;
                continue;
            }

            if ((length & 0xC0) != 0)
            {
                return false;
            }

            cursor++;
            if (length == 0)
            {
                if (!jumped)
                {
                    nextOffset = cursor;
                }

                break;
            }

            if (cursor + length > packet.Length)
            {
                return false;
            }

            if (builder.Length > 0)
            {
                builder.Append('.');
            }

            builder.Append(Encoding.ASCII.GetString(packet.Slice(cursor, length)));
            cursor += length;
            if (builder.Length > 255)
            {
                return false;
            }
        }

        name = builder.ToString();
        return true;
    }
}

/// <summary>DNS 解析结果。</summary>
public readonly record struct DnsResolution(bool IsSuccess, IReadOnlyList<IPAddress> Addresses, int TtlSeconds, int RCode, string? Error)
{
    public static DnsResolution Failure(string error, int rcode = 2) => new(false, [], 0, rcode, error);
}
