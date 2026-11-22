using System.Buffers;
using System.Net.Sockets;

namespace Nexsteaduser.CulvertProxy.Core.Net;

/// <summary>双向字节泵：池化缓冲、半关闭、异常即断。</summary>
public static class StreamRelay
{
    private const int BufferSize = 64 * 1024;

    /// <summary>同时泵两个方向，直到两端结束或发生错误。</summary>
    public static async Task<RelayResult> RunAsync(
        Stream client,
        Socket? clientSocket,
        Stream upstream,
        Socket? upstreamSocket,
        Action<long>? clientToUpstreamBytes,
        Action<long>? upstreamToClientBytes,
        CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var upload = PumpAsync(client, upstream, upstreamSocket, clientToUpstreamBytes, cts.Token);
        var download = PumpAsync(upstream, client, clientSocket, upstreamToClientBytes, cts.Token);

        var first = await Task.WhenAny(upload, download).ConfigureAwait(false);
        if (first.IsFaulted)
        {
            Shutdown(clientSocket);
            Shutdown(upstreamSocket);
        }

        Exception? error = null;
        try
        {
            await Task.WhenAll(upload, download).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            error = ex;
        }

        return new RelayResult(error);
    }

    private static async Task PumpAsync(
        Stream source,
        Stream target,
        Socket? targetSocket,
        Action<long>? byteCounter,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                byteCounter?.Invoke(read);
            }

            try
            {
                await target.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                // 对端已关闭时忽略刷新错误。
            }

            if (targetSocket is not null)
            {
                Shutdown(targetSocket);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void Shutdown(Socket? socket)
    {
        if (socket is null)
        {
            return;
        }

        try
        {
            socket.Shutdown(SocketShutdown.Send);
        }
        catch
        {
            // 已断开或未连接时忽略。
        }
    }
}

/// <summary>中继结果。</summary>
public readonly record struct RelayResult(Exception? Error)
{
    public bool IsClean => Error is null;
}
