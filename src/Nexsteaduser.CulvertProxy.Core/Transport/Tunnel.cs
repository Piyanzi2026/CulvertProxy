using System.Net.Sockets;

namespace Nexsteaduser.CulvertProxy.Core.Transport;

/// <summary>一条已建立的出站流，附带半关闭所需的底层套接字。</summary>
public sealed class Tunnel : IAsyncDisposable
{
    public Tunnel(Stream stream, Socket? halfCloseSocket, string description, string? policyName = null)
    {
        Stream = stream;
        HalfCloseSocket = halfCloseSocket;
        Description = description;
        PolicyName = policyName;
    }

    public Stream Stream { get; }

    /// <summary>仅纯 TCP（无 TLS 包装）时可用，用于半关闭。</summary>
    public Socket? HalfCloseSocket { get; }

    public string Description { get; }

    public string? PolicyName { get; }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await Stream.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
            // 关闭阶段的异常不影响统计。
        }

        HalfCloseSocket?.Dispose();
    }
}
