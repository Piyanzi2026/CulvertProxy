using System.Net;
using System.Net.Sockets;
using Nexsteaduser.CulvertProxy.Core.Engine;
using Nexsteaduser.CulvertProxy.Core.Net;

namespace Nexsteaduser.CulvertProxy.Core.Server;

/// <summary>本地混合入口：SOCKS5 与 HTTP 共用端口，按首字节分流。</summary>
internal sealed class LocalProxyServer : IAsyncDisposable
{
    private readonly ProxyEngine _engine;
    private readonly IPEndPoint _endpoint;
    private CancellationTokenSource? _cts;
    private Socket? _listener;
    private Task? _acceptLoop;

    public LocalProxyServer(ProxyEngine engine, IPEndPoint endpoint)
    {
        _engine = engine;
        _endpoint = endpoint;
    }

    public bool IsRunning => _listener is not null;

    public void Start(CancellationToken engineToken)
    {
        if (_listener is not null)
        {
            return;
        }

        var socket = SocketFactory.CreateListener(_endpoint);
        var cts = CancellationTokenSource.CreateLinkedTokenSource(engineToken);
        _listener = socket;
        _cts = cts;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(socket, engineToken, cts.Token));
        _engine.Log.Info("Listener", $"本地入口已监听 {_endpoint}（SOCKS5 / HTTP 混合）。");
    }

    private async Task AcceptLoopAsync(Socket listener, CancellationToken sessionToken, CancellationToken loopToken)
    {
        while (!loopToken.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(loopToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                _engine.Log.Debug("Listener", $"accept 失败：{ex.SocketErrorCode}");
                try
                {
                    await Task.Delay(50, loopToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                continue;
            }

            _ = HandleClientAsync(client, sessionToken);
        }
    }

    private async Task HandleClientAsync(Socket client, CancellationToken cancellationToken)
    {
        try
        {
            SocketFactory.ConfigureAccepted(client);
            var first = new byte[1];
            var read = await client.ReceiveAsync(first.AsMemory(0, 1), SocketFlags.Peek, cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                client.Dispose();
                return;
            }

            if (first[0] == 0x05)
            {
                await Socks5Session.RunAsync(client, _engine, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await HttpProxySession.RunAsync(client, _engine, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            client.Dispose();
        }
        catch (Exception ex)
        {
            _engine.Log.Debug("Listener", $"入口会话异常：{ex.Message}");
            client.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _listener?.Dispose();
        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch
            {
                // 停止阶段允许超时。
            }
        }

        _cts?.Dispose();
        _listener = null;
        _acceptLoop = null;
        _cts = null;
        _engine.Log.Info("Listener", "本地入口已停止。");
    }
}
