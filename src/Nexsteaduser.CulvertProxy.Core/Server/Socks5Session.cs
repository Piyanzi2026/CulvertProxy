using System.Net;
using System.Net.Sockets;
using System.Text;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Engine;
using Nexsteaduser.CulvertProxy.Core.Net;
using Nexsteaduser.CulvertProxy.Core.Protocols;
using Nexsteaduser.CulvertProxy.Core.Routing;
using Nexsteaduser.CulvertProxy.Core.Transport;

namespace Nexsteaduser.CulvertProxy.Core.Server;

/// <summary>本地 SOCKS5 会话：认证、CONNECT 与 UDP ASSOCIATE。</summary>
internal static class Socks5Session
{
    public static async Task RunAsync(Socket client, ProxyEngine engine, CancellationToken engineToken)
    {
        await using var stream = new NetworkStream(client, ownsSocket: true);
        ActiveConnection? entry = null;
        string? failure = null;
        var failureCounted = false;
        var blockedCounted = false;

        try
        {
            var access = engine.Access;
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(engineToken);
            handshakeCts.CancelAfter(access.HandshakeTimeout);
            var handshakeToken = handshakeCts.Token;

            if (!await NegotiateAsync(stream, engine, handshakeToken).ConfigureAwait(false))
            {
                return;
            }

            var header = new byte[4];
            if (!await ReadExactAsync(stream, header, handshakeToken).ConfigureAwait(false) || header[0] != Socks5Protocol.Version)
            {
                return;
            }

            var command = header[1];
            ProxyTarget requested;
            try
            {
                requested = await Socks5Protocol.ReadEndpointAsync(stream, header[3], handshakeToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is ProxyHandshakeException or EndOfStreamException or IOException)
            {
                await WriteReplyAsync(stream, 0x08, null, handshakeToken).ConfigureAwait(false);
                return;
            }

            var process = ResolveProcess(client, engine);

            if (command == Socks5Protocol.CmdUdpAssociate)
            {
                entry = engine.Connections.Begin(
                    new ConnectionInit("SOCKS5/UDP", $"UDP {requested}", process?.Name, process?.Pid, "按目标匹配", null),
                    engineToken);
                engine.Stats.RecordConnection();
                try
                {
                    Socks5UdpRelay relay;
                    try
                    {
                        relay = Socks5UdpRelay.Create(engine, client, requested, entry, process, engineToken);
                    }
                    catch (Exception ex)
                    {
                        failure = ex.Message;
                        await WriteReplyAsync(stream, 0x01, null, handshakeToken).ConfigureAwait(false);
                        return;
                    }

                    await WriteReplyAsync(stream, 0x00, relay.RelayEndPoint, handshakeToken).ConfigureAwait(false);
                    entry.SetState("udp-relay");
                    entry.SetRoute("每条数据报独立匹配规则");
                    await relay.RunAsync(stream, engineToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failure = ex.Message;
                    engine.Log.Debug("SOCKS5", $"UDP 关联结束：{ex.Message}");
                }

                return;
            }

            if (command != Socks5Protocol.CmdConnect)
            {
                await WriteReplyAsync(stream, 0x07, null, handshakeToken).ConfigureAwait(false);
                return;
            }

            var (target, decision) = engine.ResolveRoute(requested, RuleTransport.Tcp, process);
            var policyName = decision.PolicyId is not null ? engine.Routes.GetPolicy(decision.PolicyId)?.Name : null;
            entry = engine.Connections.Begin(
                new ConnectionInit("SOCKS5", target.ToString(), process?.Name, process?.Pid, decision.RuleName, policyName),
                engineToken);
            engine.Stats.RecordConnection();

            Tunnel tunnel;
            try
            {
                tunnel = await engine.Connector.ConnectAsync(
                    decision,
                    target,
                    access.ConnectTimeout,
                    access.HandshakeTimeout,
                    access.OutboundBindAddress,
                    access.MaxAttempts,
                    entry.CancellationToken).ConfigureAwait(false);
            }
            catch (ConnectionBlockedException ex)
            {
                engine.Stats.RecordBlocked();
                blockedCounted = true;
                failure = ex.Message;
                await WriteReplyAsync(stream, 0x02, null, handshakeToken).ConfigureAwait(false);
                return;
            }
            catch (OperationCanceledException) when (engineToken.IsCancellationRequested)
            {
                failure = "引擎停止。";
                return;
            }
            catch (Exception ex)
            {
                engine.Stats.RecordFailure();
                failureCounted = true;
                failure = ex.Message;
                // 上游握手可能已耗光本地握手超时，应答改用引擎令牌避免被误取消。
                await WriteReplyAsync(stream, MapError(ex), null, engineToken).ConfigureAwait(false);
                return;
            }

            await using (tunnel)
            {
                entry.SetRoute(tunnel.Description);
                entry.SetState("relaying");
                var bound = tunnel.HalfCloseSocket?.LocalEndPoint as IPEndPoint;
                await WriteReplyAsync(stream, 0x00, bound, engineToken).ConfigureAwait(false);

                var result = await StreamRelay.RunAsync(
                    stream,
                    client,
                    tunnel.Stream,
                    tunnel.HalfCloseSocket,
                    bytes =>
                    {
                        entry.AddUploaded(bytes);
                        engine.Stats.AddUploaded(bytes);
                    },
                    bytes =>
                    {
                        entry.AddDownloaded(bytes);
                        engine.Stats.AddDownloaded(bytes);
                    },
                    entry.CancellationToken).ConfigureAwait(false);

                if (result.Error is not null and not OperationCanceledException)
                {
                    engine.Log.Debug("SOCKS5", $"{target} 中继结束：{result.Error.Message}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 引擎停止或用户断开。
        }
        catch (Exception ex)
        {
            engine.Log.Debug("SOCKS5", $"会话异常：{ex.Message}");
        }
        finally
        {
            if (entry is not null)
            {
                if (failure is not null && !failureCounted && !blockedCounted)
                {
                    engine.Stats.RecordFailure();
                }

                engine.Connections.Complete(entry, failure);
            }
        }
    }

    private static async ValueTask<bool> NegotiateAsync(Stream stream, ProxyEngine engine, CancellationToken cancellationToken)
    {
        var head = new byte[2];
        if (!await ReadExactAsync(stream, head, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        if (head[0] != Socks5Protocol.Version || head[1] == 0)
        {
            return false;
        }

        var methods = new byte[head[1]];
        if (!await ReadExactAsync(stream, methods, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        var access = engine.Access;
        var offersNone = Array.IndexOf(methods, Socks5Protocol.AuthNone) >= 0;
        var offersUserPass = Array.IndexOf(methods, Socks5Protocol.AuthUserPassword) >= 0;
        if (access.AuthenticationRequired)
        {
            if (!offersUserPass)
            {
                await stream.WriteAsync(new byte[] { Socks5Protocol.Version, Socks5Protocol.AuthNoAcceptable }, cancellationToken).ConfigureAwait(false);
                return false;
            }

            await stream.WriteAsync(new byte[] { Socks5Protocol.Version, Socks5Protocol.AuthUserPassword }, cancellationToken).ConfigureAwait(false);

            var authHead = new byte[2];
            if (!await ReadExactAsync(stream, authHead, cancellationToken).ConfigureAwait(false) || authHead[0] != 0x01)
            {
                return false;
            }

            var userLength = authHead[1];
            if (userLength == 0)
            {
                await stream.WriteAsync(new byte[] { 0x01, 0x01 }, cancellationToken).ConfigureAwait(false);
                return false;
            }

            var userBytes = new byte[userLength];
            if (!await ReadExactAsync(stream, userBytes, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            var passLength = new byte[1];
            if (!await ReadExactAsync(stream, passLength, cancellationToken).ConfigureAwait(false) || passLength[0] == 0)
            {
                await stream.WriteAsync(new byte[] { 0x01, 0x01 }, cancellationToken).ConfigureAwait(false);
                return false;
            }

            var passBytes = new byte[passLength[0]];
            if (!await ReadExactAsync(stream, passBytes, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            var accepted = engine.ValidateLocalCredentials(
                Encoding.UTF8.GetString(userBytes),
                Encoding.UTF8.GetString(passBytes));
            await stream.WriteAsync(new byte[] { 0x01, (byte)(accepted ? 0 : 1) }, cancellationToken).ConfigureAwait(false);
            return accepted;
        }

        if (!offersNone)
        {
            await stream.WriteAsync(new byte[] { Socks5Protocol.Version, Socks5Protocol.AuthNoAcceptable }, cancellationToken).ConfigureAwait(false);
            return false;
        }

        await stream.WriteAsync(new byte[] { Socks5Protocol.Version, Socks5Protocol.AuthNone }, cancellationToken).ConfigureAwait(false);
        return true;
    }

    private static ProcessIdentity? ResolveProcess(Socket client, ProxyEngine engine)
    {
        return client.RemoteEndPoint is IPEndPoint remote && client.LocalEndPoint is IPEndPoint local
            ? engine.Processes.Resolve(remote, local)
            : null;
    }

    private static async ValueTask WriteReplyAsync(Stream stream, byte reply, IPEndPoint? bound, CancellationToken cancellationToken)
    {
        var target = bound is null
            ? new ProxyTarget("0.0.0.0", 0)
            : new ProxyTarget(bound.Address.ToString(), bound.Port);
        var buffer = new byte[3 + 19];
        buffer[0] = Socks5Protocol.Version;
        buffer[1] = reply;
        buffer[2] = 0;
        var length = Socks5Protocol.EncodeAddressAndPort(target, buffer.AsSpan(3));
        try
        {
            await stream.WriteAsync(buffer.AsMemory(0, 3 + length), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            // 客户端可能已经离开。
        }
    }

    private static async ValueTask<bool> ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        try
        {
            await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException or OperationCanceledException)
        {
            return false;
        }
    }

    private static byte MapError(Exception exception) => exception switch
    {
        ConnectionBlockedException => 0x02,
        ProxyUnavailableException => 0x01,
        ProxyConnectException => 0x01,
        TimeoutException => 0x04,
        SocketException socketException => socketException.SocketErrorCode switch
        {
            SocketError.HostNotFound or SocketError.NoData => 0x04,
            SocketError.ConnectionRefused => 0x05,
            SocketError.NetworkUnreachable or SocketError.NetworkDown => 0x03,
            SocketError.HostUnreachable => 0x04,
            SocketError.AccessDenied => 0x02,
            _ => 0x01,
        },
        _ => 0x01,
    };
}
