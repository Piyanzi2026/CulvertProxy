using System.Net;
using System.Net.Sockets;

namespace Nexsteaduser.CulvertProxy.Core.Net;

/// <summary>创建与拨号：并行地址竞速、统一套接字调优。</summary>
public static class SocketFactory
{
    private static readonly TimeSpan HappyEyeballsStagger = TimeSpan.FromMilliseconds(200);

    /// <summary>创建带低延迟与 keep-alive 的 TCP 套接字。</summary>
    public static Socket CreateTcp()
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };

        TrySet(socket, () => socket.ReceiveBufferSize = 256 * 1024);
        TrySet(socket, () => socket.SendBufferSize = 256 * 1024);
        TrySet(socket, () => socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true));
        NativeSockets.TrySetKeepAlive(socket, 30, 5);
        return socket;
    }

    /// <summary>创建监听套接字并启用回环快速路径。</summary>
    public static Socket CreateListener(IPEndPoint endPoint, int backlog = 512)
    {
        var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        TrySet(socket, () => socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, false));
        TrySet(socket, () => socket.ReceiveBufferSize = 256 * 1024);
        TrySet(socket, () => socket.SendBufferSize = 256 * 1024);
        if (IPAddress.IsLoopback(endPoint.Address))
        {
            NativeSockets.TryEnableLoopbackFastPath(socket);
        }

        socket.Bind(endPoint);
        socket.Listen(backlog);
        return socket;
    }

    /// <summary>为 accept 得到的连接套接字应用统一的低延迟参数。</summary>
    public static void ConfigureAccepted(Socket socket)
    {
        TrySet(socket, () => socket.NoDelay = true);
        TrySet(socket, () => socket.ReceiveBufferSize = 256 * 1024);
        TrySet(socket, () => socket.SendBufferSize = 256 * 1024);
        TrySet(socket, () => socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true));
        NativeSockets.TrySetKeepAlive(socket, 30, 5);
        if (socket.LocalEndPoint is IPEndPoint local && IPAddress.IsLoopback(local.Address))
        {
            NativeSockets.TryEnableLoopbackFastPath(socket);
        }
    }

    /// <summary>拨号到目标，多个地址同时竞速；返回首个成功的套接字。</summary>
    public static async ValueTask<Socket> ConnectAsync(
        string host,
        int port,
        TimeSpan connectTimeout,
        IPAddress? bindAddress,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            throw new ArgumentException("目标主机为空。", nameof(host));
        }

        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        IPAddress[] addresses;
        if (IPAddress.TryParse(host, out var literal))
        {
            addresses = [literal];
        }
        else
        {
            addresses = await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        }

        return await ConnectAnyAsync(addresses, port, connectTimeout, bindAddress, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>在已解析的地址集合上竞速拨号，供自定义解析器复用。</summary>
    public static async ValueTask<Socket> ConnectAnyAsync(
        IReadOnlyList<IPAddress> addresses,
        int port,
        TimeSpan connectTimeout,
        IPAddress? bindAddress,
        CancellationToken cancellationToken)
    {
        if (addresses.Count == 0)
        {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(connectTimeout);

        var attempts = new List<Task<AttemptResult>>(addresses.Count);
        for (var i = 0; i < addresses.Count; i++)
        {
            attempts.Add(AttemptAsync(addresses[i], port, bindAddress, HappyEyeballsStagger * i, timeoutCts.Token));
        }

        Exception? lastError = null;
        while (attempts.Count > 0)
        {
            var finished = await Task.WhenAny(attempts).ConfigureAwait(false);
            attempts.Remove(finished);
            AttemptResult result;
            try
            {
                result = await finished.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                lastError = ex;
                continue;
            }

            if (result.Socket is not null)
            {
                timeoutCts.Cancel();
                foreach (var pending in attempts)
                {
                    _ = DisposeLateAsync(pending);
                }

                return result.Socket;
            }

            lastError = result.Error;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }

        if (timeoutCts.IsCancellationRequested)
        {
            throw new TimeoutException($"连接目标端口 {port} 超时。");
        }

        if (lastError is SocketException socketError)
        {
            throw socketError;
        }

        throw new SocketException((int)SocketError.HostUnreachable, lastError?.Message);
    }

    private static async Task<AttemptResult> AttemptAsync(
        IPAddress address,
        int port,
        IPAddress? bindAddress,
        TimeSpan stagger,
        CancellationToken cancellationToken)
    {
        try
        {
            if (stagger > TimeSpan.Zero)
            {
                await Task.Delay(stagger, cancellationToken).ConfigureAwait(false);
            }

            var socket = CreateTcp();
            try
            {
                if (bindAddress is not null)
                {
                    socket.Bind(new IPEndPoint(bindAddress, 0));
                }

                await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken).ConfigureAwait(false);
                return new AttemptResult(socket, null);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or IOException)
        {
            return new AttemptResult(null, ex);
        }
    }

    private static async Task DisposeLateAsync(Task<AttemptResult> pending)
    {
        try
        {
            var result = await pending.ConfigureAwait(false);
            result.Socket?.Dispose();
        }
        catch
        {
            // 竞速落败方直接丢弃。
        }
    }

    private static void TrySet(Socket socket, Action action)
    {
        try
        {
            action();
        }
        catch
        {
            // 某些选项在受限环境不可用。
        }
    }

    private readonly record struct AttemptResult(Socket? Socket, Exception? Error);
}
