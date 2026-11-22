using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Nexsteaduser.CulvertProxy.Core.Net;

namespace Nexsteaduser.CulvertProxy.Core.Interception;

/// <summary>注入端发送给接管入口的目标描述。</summary>
internal sealed record InterceptRequest(ProxyTarget Target, int ProcessId);

/// <summary>CPX1 前导协议：Magic、版本、PID、随机令牌与原始目标。</summary>
internal static class InterceptProtocol
{
    public const int Version = 1;
    public const int TokenLength = 16;
    public const int HeaderLength = 29;
    private const byte AddressTypeIpv4 = 1;
    private const byte AddressTypeDomain = 2;
    private const byte AddressTypeIpv6 = 3;

    /// <summary>生成一次引擎生命周期的入口令牌。</summary>
    public static byte[] CreateToken() => RandomNumberGenerator.GetBytes(TokenLength);

    /// <summary>判断地址是否落在注入层保留的 198.19.0.0/16。</summary>
    public static bool IsHookFakeAddress(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 198 && bytes[1] == 19;
    }

    /// <summary>把令牌编码为配置文件使用的十六进制字符串。</summary>
    public static string ToHex(ReadOnlySpan<byte> token) => Convert.ToHexStringLower(token);

    /// <summary>编码真实目标，供测试与诊断工具使用。</summary>
    public static byte[] Encode(ReadOnlySpan<byte> token, int processId, string host, int port)
    {
        if (token.Length != TokenLength)
        {
            throw new ArgumentException("令牌长度必须为 16 字节。", nameof(token));
        }

        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        if (IPAddress.TryParse(host, out var address))
        {
            var type = address.AddressFamily == AddressFamily.InterNetworkV6 ? AddressTypeIpv6 : AddressTypeIpv4;
            var addressBytes = address.GetAddressBytes();
            var buffer = new byte[HeaderLength + addressBytes.Length];
            WriteHeader(buffer, token, processId, type, port);
            addressBytes.CopyTo(buffer.AsSpan(HeaderLength));
            return buffer;
        }

        var domain = Encoding.ASCII.GetBytes(host);
        if (domain.Length is 0 or > 253)
        {
            throw new ArgumentException("域名长度必须在 1 到 253 之间。", nameof(host));
        }

        var domainBuffer = new byte[HeaderLength + 1 + domain.Length];
        WriteHeader(domainBuffer, token, processId, AddressTypeDomain, port);
        domainBuffer[HeaderLength] = (byte)domain.Length;
        domain.CopyTo(domainBuffer.AsSpan(HeaderLength + 1));
        return domainBuffer;
    }

    /// <summary>从套接字读取并校验前导；失败返回 null，不抛出给调用方。</summary>
    public static async ValueTask<InterceptRequest?> ReadAsync(
        Socket client,
        ReadOnlyMemory<byte> token,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);
        try
        {
            var header = new byte[HeaderLength];
            if (!await ReceiveExactAsync(client, header, timeoutCts.Token).ConfigureAwait(false))
            {
                return null;
            }

            if (header[0] != (byte)'C' || header[1] != (byte)'P'
                || header[2] != (byte)'X' || header[3] != (byte)'1'
                || header[4] != Version)
            {
                return null;
            }

            if (!CryptographicOperations.FixedTimeEquals(header.AsSpan(10, TokenLength), token.Span))
            {
                return null;
            }

            var processId = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(6, 4));
            var addressType = header[26];
            var port = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(27, 2));
            if (port == 0)
            {
                return null;
            }

            switch (addressType)
            {
                case AddressTypeIpv4:
                {
                    var address = new byte[4];
                    if (!await ReceiveExactAsync(client, address, timeoutCts.Token).ConfigureAwait(false))
                    {
                        return null;
                    }

                    return new InterceptRequest(new ProxyTarget(new IPAddress(address).ToString(), port), processId);
                }
                case AddressTypeIpv6:
                {
                    var address = new byte[16];
                    if (!await ReceiveExactAsync(client, address, timeoutCts.Token).ConfigureAwait(false))
                    {
                        return null;
                    }

                    return new InterceptRequest(new ProxyTarget(new IPAddress(address).ToString(), port), processId);
                }
                case AddressTypeDomain:
                {
                    var length = new byte[1];
                    if (!await ReceiveExactAsync(client, length, timeoutCts.Token).ConfigureAwait(false) || length[0] == 0)
                    {
                        return null;
                    }

                    var domain = new byte[length[0]];
                    if (!await ReceiveExactAsync(client, domain, timeoutCts.Token).ConfigureAwait(false))
                    {
                        return null;
                    }

                    foreach (var value in domain)
                    {
                        if (value is < 0x21 or > 0x7E)
                        {
                            return null;
                        }
                    }

                    var host = Encoding.ASCII.GetString(domain);
                    return new InterceptRequest(new ProxyTarget(host, port), processId);
                }
                default:
                    return null;
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException or ObjectDisposedException)
        {
            return null;
        }
    }

    private static void WriteHeader(Span<byte> buffer, ReadOnlySpan<byte> token, int processId, byte addressType, int port)
    {
        buffer[0] = (byte)'C';
        buffer[1] = (byte)'P';
        buffer[2] = (byte)'X';
        buffer[3] = (byte)'1';
        buffer[4] = Version;
        buffer[5] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(6, 4), processId);
        token.CopyTo(buffer.Slice(10, TokenLength));
        buffer[26] = addressType;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(27, 2), (ushort)port);
    }

    private static async ValueTask<bool> ReceiveExactAsync(Socket socket, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await socket.ReceiveAsync(buffer[offset..], SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }
}
