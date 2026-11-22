using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;
using Nexsteaduser.CulvertProxy.Core.Engine;
using Nexsteaduser.CulvertProxy.Core.Net;
using Nexsteaduser.CulvertProxy.Core.Protocols;

namespace Nexsteaduser.CulvertProxy.Tests;

internal static class TestNet
{
    public static int FreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public static int FreeUdpPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }
}

/// <summary>测试用 TCP 回显服务。</summary>
internal sealed class TcpEchoServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();

    public TcpEchoServer()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = AcceptLoopAsync();
    }

    public int Port { get; }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                _ = EchoAsync(client);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                break;
            }
        }
    }

    private async Task EchoAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var buffer = new byte[8192];
                while (true)
                {
                    var read = await stream.ReadAsync(buffer, _cts.Token);
                    if (read == 0)
                    {
                        break;
                    }

                    await stream.WriteAsync(buffer.AsMemory(0, read), _cts.Token);
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
            {
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>测试用 UDP 回显服务。</summary>
internal sealed class UdpEchoServer : IAsyncDisposable
{
    private readonly Socket _socket;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public UdpEchoServer()
    {
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Port = ((IPEndPoint)_socket.LocalEndPoint!).Port;
        _loop = Task.Run(ReceiveLoopAsync);
    }

    public int Port { get; }

    private async Task ReceiveLoopAsync()
    {
        var buffer = new byte[65535];
        var any = new IPEndPoint(IPAddress.Any, 0);
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, any, _cts.Token);
                await _socket.SendToAsync(buffer.AsMemory(0, result.ReceivedBytes), SocketFlags.None, result.RemoteEndPoint, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _socket.Dispose();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>独立实现的测试 SOCKS5 服务器，支持认证、域名映射与 UDP ASSOCIATE。</summary>
internal sealed class TestSocks5Server : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly string? _username;
    private readonly string? _password;
    private readonly Task _loop;

    public TestSocks5Server(string? username = null, string? password = null)
    {
        _username = username;
        _password = password;
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(32);
        Port = ((IPEndPoint)_listener.LocalEndPoint!).Port;
        _loop = Task.Run(AcceptLoopAsync);
    }

    public int Port { get; }

    public Func<string, int, IPEndPoint>? ResolveOverride { get; set; }

    public ConcurrentQueue<ProxyTarget> ConnectRequests { get; } = new();

    public int UdpAssociationCount;

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(_cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            _ = Task.Run(() => HandleAsync(client));
        }
    }

    private async Task HandleAsync(Socket client)
    {
        using (client)
        {
            try
            {
                var stream = new NetworkStream(client, ownsSocket: false);
                var head = new byte[2];
                await stream.ReadExactlyAsync(head, _cts.Token);
                if (head[0] != 5)
                {
                    return;
                }

                var methods = new byte[head[1]];
                await stream.ReadExactlyAsync(methods, _cts.Token);
                var requireAuth = _username is not null || _password is not null;
                if (requireAuth)
                {
                    if (Array.IndexOf(methods, (byte)2) < 0)
                    {
                        await stream.WriteAsync(new byte[] { 5, 0xFF }, _cts.Token);
                        return;
                    }

                    await stream.WriteAsync(new byte[] { 5, 2 }, _cts.Token);
                    var authHead = new byte[2];
                    await stream.ReadExactlyAsync(authHead, _cts.Token);
                    var user = new byte[authHead[1]];
                    await stream.ReadExactlyAsync(user, _cts.Token);
                    var passLength = new byte[1];
                    await stream.ReadExactlyAsync(passLength, _cts.Token);
                    var pass = new byte[passLength[0]];
                    await stream.ReadExactlyAsync(pass, _cts.Token);
                    var ok = Encoding.UTF8.GetString(user) == (_username ?? string.Empty)
                        && Encoding.UTF8.GetString(pass) == (_password ?? string.Empty);
                    await stream.WriteAsync(new byte[] { 1, (byte)(ok ? 0 : 1) }, _cts.Token);
                    if (!ok)
                    {
                        return;
                    }
                }
                else
                {
                    if (Array.IndexOf(methods, (byte)0) < 0)
                    {
                        await stream.WriteAsync(new byte[] { 5, 0xFF }, _cts.Token);
                        return;
                    }

                    await stream.WriteAsync(new byte[] { 5, 0 }, _cts.Token);
                }

                var request = new byte[4];
                await stream.ReadExactlyAsync(request, _cts.Token);
                var target = await ReadTargetAsync(stream, request[3]);
                if (request[1] == 3)
                {
                    Interlocked.Increment(ref UdpAssociationCount);
                    await HandleUdpAsync(stream, client, target);
                    return;
                }

                if (request[1] != 1)
                {
                    await WriteReplyAsync(stream, 7, null);
                    return;
                }

                ConnectRequests.Enqueue(target);
                IPEndPoint endpoint;
                var address = await ResolveAsync(target);
                endpoint = new IPEndPoint(address, target.Port);
                using var upstream = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await upstream.ConnectAsync(endpoint, _cts.Token);
                await WriteReplyAsync(stream, 0, (IPEndPoint)upstream.LocalEndPoint!);
                var upload = CopyAsync(stream, upstream);
                var download = CopyAsync(upstream, stream);
                await Task.WhenAll(upload, download);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException or EndOfStreamException)
            {
            }
        }
    }

    private async Task HandleUdpAsync(NetworkStream control, Socket tcpClient, ProxyTarget requested)
    {
        var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        var relayEndPoint = new IPEndPoint(IPAddress.Loopback, 0);
        udp.Bind(relayEndPoint);
        relayEndPoint = (IPEndPoint)udp.LocalEndPoint!;
        await WriteReplyAsync(control, 0, relayEndPoint);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
        var buffer = new byte[65535];
        var any = new IPEndPoint(IPAddress.Any, 0);
        var clientEndpoint = requested.IsIpLiteral && requested.Port != 0
            ? new IPEndPoint(IPAddress.Loopback, requested.Port)
            : (EndPoint?)null;
        var udpLoop = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var result = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, cts.Token);
                    if (result.RemoteEndPoint is not IPEndPoint remote)
                    {
                        continue;
                    }

                    if (clientEndpoint is null && remote.Address.Equals(IPAddress.Loopback))
                    {
                        // 第一个来自回环的数据报视为客户端，后续来自其他端口的视为目标回包。
                        clientEndpoint = remote;
                        if (Socks5UdpCodec.TryParseHeader(buffer.AsSpan(0, result.ReceivedBytes), out var target, out var offset))
                        {
                            var address = await ResolveAsync(target);
                            await udp.SendToAsync(
                                buffer.AsMemory(offset, result.ReceivedBytes - offset),
                                SocketFlags.None,
                                new IPEndPoint(address, target.Port),
                                cts.Token);
                        }

                        continue;
                    }

                    if (clientEndpoint is not null && remote.Equals(clientEndpoint))
                    {
                        if (Socks5UdpCodec.TryParseHeader(buffer.AsSpan(0, result.ReceivedBytes), out var target, out var offset))
                        {
                            var address = await ResolveAsync(target);
                            await udp.SendToAsync(
                                buffer.AsMemory(offset, result.ReceivedBytes - offset),
                                SocketFlags.None,
                                new IPEndPoint(address, target.Port),
                                cts.Token);
                        }
                    }
                    else if (clientEndpoint is not null)
                    {
                        var header = new byte[Socks5UdpCodec.MaxHeaderLength];
                        var headerLength = Socks5UdpCodec.WriteHeader(new ProxyTarget(remote.Address.ToString(), remote.Port), header);
                        var datagram = new byte[headerLength + result.ReceivedBytes];
                        header.AsSpan(0, headerLength).CopyTo(datagram);
                        buffer.AsSpan(0, result.ReceivedBytes).CopyTo(datagram.AsSpan(headerLength));
                        await udp.SendToAsync(datagram, SocketFlags.None, clientEndpoint, cts.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException)
                {
                }
            }
        });

        try
        {
            var drain = new byte[256];
            while (!_cts.IsCancellationRequested)
            {
                if (await control.ReadAsync(drain, _cts.Token) == 0)
                {
                    break;
                }
            }
        }
        catch
        {
        }

        cts.Cancel();
        try
        {
            await udpLoop;
        }
        catch
        {
        }

        udp.Dispose();
    }

    private async ValueTask<IPAddress> ResolveAsync(ProxyTarget target)
    {
        if (IPAddress.TryParse(target.Host, out var literal))
        {
            return literal;
        }

        if (ResolveOverride?.Invoke(target.Host, target.Port) is { } mapped)
        {
            return mapped.Address;
        }

        var addresses = await System.Net.Dns.GetHostAddressesAsync(target.Host, _cts.Token);
        return addresses.First();
    }

    private static async ValueTask<ProxyTarget> ReadTargetAsync(NetworkStream stream, byte atyp)
    {
        switch (atyp)
        {
            case 1:
            {
                var buffer = new byte[6];
                await stream.ReadExactlyAsync(buffer);
                return new ProxyTarget(new IPAddress(buffer.AsSpan(0, 4)).ToString(), (buffer[4] << 8) | buffer[5]);
            }
            case 4:
            {
                var buffer = new byte[18];
                await stream.ReadExactlyAsync(buffer);
                return new ProxyTarget(new IPAddress(buffer.AsSpan(0, 16)).ToString(), (buffer[16] << 8) | buffer[17]);
            }
            case 3:
            {
                var length = new byte[1];
                await stream.ReadExactlyAsync(length);
                var buffer = new byte[length[0] + 2];
                await stream.ReadExactlyAsync(buffer);
                return new ProxyTarget(Encoding.ASCII.GetString(buffer, 0, length[0]), (buffer[length[0]] << 8) | buffer[length[0] + 1]);
            }
            default:
                throw new IOException("未知地址类型。");
        }
    }

    private static async ValueTask WriteReplyAsync(NetworkStream stream, byte reply, IPEndPoint? bound)
    {
        var target = bound is null ? new ProxyTarget("0.0.0.0", 0) : new ProxyTarget(bound.Address.ToString(), bound.Port);
        var buffer = new byte[3 + 19];
        buffer[0] = 5;
        buffer[1] = reply;
        buffer[2] = 0;
        var length = Socks5Protocol.EncodeAddressAndPort(target, buffer.AsSpan(3));
        await stream.WriteAsync(buffer.AsMemory(0, 3 + length));
    }

    private async Task CopyAsync(Stream source, Socket destination)
    {
        var buffer = new byte[8192];
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(buffer, _cts.Token);
                if (read == 0)
                {
                    break;
                }

                await destination.SendAsync(buffer.AsMemory(0, read), SocketFlags.None, _cts.Token);
            }

            destination.Shutdown(SocketShutdown.Send);
        }
        catch
        {
        }
    }

    private async Task CopyAsync(Socket source, Stream destination)
    {
        var buffer = new byte[8192];
        try
        {
            while (true)
            {
                var read = await source.ReceiveAsync(buffer, SocketFlags.None, _cts.Token);
                if (read == 0)
                {
                    break;
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), _cts.Token);
            }
        }
        catch
        {
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Dispose();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>测试用 HTTP CONNECT 代理。</summary>
internal sealed class TestHttpProxyServer : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public TestHttpProxyServer()
    {
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(16);
        Port = ((IPEndPoint)_listener.LocalEndPoint!).Port;
        _loop = Task.Run(AcceptLoopAsync);
    }

    public int Port { get; }

    public Func<string, int, IPEndPoint>? ResolveOverride { get; set; }

    public ConcurrentQueue<string> ConnectTargets { get; } = new();

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(_cts.Token);
            }
            catch
            {
                break;
            }

            _ = Task.Run(() => HandleAsync(client));
        }
    }

    private async Task HandleAsync(Socket client)
    {
        using (client)
        {
            try
            {
                var stream = new NetworkStream(client, ownsSocket: false);
                var block = await HttpHeaderReader.ReadAsync(stream, 32 * 1024, _cts.Token);
                var firstLine = block.Text.Split('\n')[0].TrimEnd('\r');
                var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2 || !parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                {
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"), _cts.Token);
                    return;
                }

                var target = ProxyTarget.Parse(parts[1]);
                ConnectTargets.Enqueue(parts[1]);
                IPAddress address;
                if (IPAddress.TryParse(target.Host, out var literal))
                {
                    address = literal;
                }
                else if (ResolveOverride?.Invoke(target.Host, target.Port) is { } mapped)
                {
                    address = mapped.Address;
                }
                else
                {
                    address = (await System.Net.Dns.GetHostAddressesAsync(target.Host, _cts.Token))[0];
                }

                using var upstream = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await upstream.ConnectAsync(new IPEndPoint(address, target.Port), _cts.Token);
                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), _cts.Token);
                if (block.Leftover.Length > 0)
                {
                    await upstream.SendAsync(block.Leftover, SocketFlags.None, _cts.Token);
                }

                var up = PumpSocketToStreamAsync(upstream, stream, client);
                var down = PumpStreamToSocketAsync(stream, upstream);
                await Task.WhenAll(up, down);
            }
            catch
            {
            }
        }
    }

    private async Task PumpSocketToStreamAsync(Socket source, Stream destination, Socket clientSocket)
    {
        var buffer = new byte[8192];
        try
        {
            while (true)
            {
                var read = await source.ReceiveAsync(buffer, SocketFlags.None, _cts.Token);
                if (read == 0)
                {
                    break;
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), _cts.Token);
            }
        }
        catch
        {
        }
        finally
        {
            try
            {
                clientSocket.Shutdown(SocketShutdown.Send);
            }
            catch
            {
            }
        }
    }

    private async Task PumpStreamToSocketAsync(Stream source, Socket destination)
    {
        var buffer = new byte[8192];
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(buffer, _cts.Token);
                if (read == 0)
                {
                    break;
                }

                await destination.SendAsync(buffer.AsMemory(0, read), SocketFlags.None, _cts.Token);
            }

            destination.Shutdown(SocketShutdown.Send);
        }
        catch
        {
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Dispose();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>测试用最小 HTTP 源站，记录收到的请求行。</summary>
internal sealed class TestHttpOrigin : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();

    public TestHttpOrigin()
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = AcceptLoopAsync();
    }

    public int Port { get; }

    public string? LastRequestLine { get; private set; }

    public string? LastHostHeader { get; private set; }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                _ = HandleAsync(client);
            }
            catch
            {
                break;
            }
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var block = await HttpHeaderReader.ReadAsync(stream, 32 * 1024, _cts.Token);
                var lines = block.Text.Split('\n');
                LastRequestLine = lines[0].TrimEnd('\r');
                foreach (var line in lines.Skip(1))
                {
                    var trimmed = line.TrimEnd('\r');
                    if (trimmed.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                    {
                        LastHostHeader = trimmed[5..].Trim();
                        break;
                    }
                }

                const string body = "hello-from-origin";
                var response = Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}");
                await stream.WriteAsync(response, _cts.Token);
            }
            catch
            {
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>在随机端口启动被测引擎。</summary>
internal sealed class EngineHost : IAsyncDisposable
{
    private EngineHost(ProxyEngine engine, LogHub log, int port)
    {
        Engine = engine;
        Log = log;
        Port = port;
    }

    public ProxyEngine Engine { get; }

    public LogHub Log { get; }

    public int Port { get; }

    public static async Task<EngineHost> StartAsync(Action<AppConfig>? configure = null)
    {
        var config = AppConfig.CreateDefault();
        config.Listener.BindAddress = "127.0.0.1";
        config.Listener.Port = TestNet.FreeTcpPort();
        config.Listener.Enabled = true;
        config.Dns.Mode = DnsResolutionMode.System;
        config.Dns.EnableServer = false;
        config.Dns.FakeIpEnabled = false;
        configure?.Invoke(config);
        ConfigStore.Normalize(config);

        var log = new LogHub(writeToDisk: false);
        var engine = new ProxyEngine(log, config);
        await engine.StartAsync();
        var host = new EngineHost(engine, log, config.Listener.Port);
        await host.WaitReadyAsync();
        return host;
    }

    private async Task WaitReadyAsync()
    {
        for (var i = 0; i < 60; i++)
        {
            var snapshot = Engine.GetSnapshot();
            if (snapshot.ListenerRunning)
            {
                return;
            }

            if (snapshot.ListenerError is not null)
            {
                throw new InvalidOperationException($"监听失败：{snapshot.ListenerError}");
            }

            await Task.Delay(50);
        }

        throw new TimeoutException("本地入口未在 3 秒内就绪。");
    }

    public async ValueTask DisposeAsync()
    {
        await Engine.DisposeAsync();
        await Log.DisposeAsync();
    }
}
