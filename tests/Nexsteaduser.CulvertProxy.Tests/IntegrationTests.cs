using System.Net;
using System.Net.Sockets;
using System.Text;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;
using Nexsteaduser.CulvertProxy.Core.Dns;
using Nexsteaduser.CulvertProxy.Core.Net;
using Xunit;

namespace Nexsteaduser.CulvertProxy.Tests;

public sealed class IntegrationTests
{
    [Fact]
    public async Task Socks5_Direct_Echo_Roundtrip()
    {
        await using var echo = new TcpEchoServer();
        await using var host = await EngineHost.StartAsync(config => config.Rules.Clear());

        var (tcp, stream) = await OpenSocksAsync(host.Port, new ProxyTarget("127.0.0.1", echo.Port));
        using (tcp)
        {
            var payload = Encoding.UTF8.GetBytes("culvert-direct");
            await stream.WriteAsync(payload);
            var response = await ReadExactAsync(stream, payload.Length);
            Assert.Equal(payload, response);
        }
    }

    [Fact]
    public async Task Socks5_Direct_Honors_Static_Host_Mapping()
    {
        await using var echo = new TcpEchoServer();
        await using var host = await EngineHost.StartAsync(config =>
        {
            config.Rules.Clear();
            config.Dns.Mode = DnsResolutionMode.System;
            config.Dns.Hosts.Add(new HostMapping { Host = "mapped.test", Address = "127.0.0.1" });
        });

        var (tcp, stream) = await OpenSocksAsync(host.Port, new ProxyTarget("mapped.test", echo.Port));
        using (tcp)
        {
            var payload = Encoding.UTF8.GetBytes("static-host");
            await stream.WriteAsync(payload);
            Assert.Equal(payload, await ReadExactAsync(stream, payload.Length));
        }
    }

    [Fact]
    public async Task Unknown_Hook_FakeIp_Is_Blocked()
    {
        await using var host = await EngineHost.StartAsync(config =>
        {
            config.Rules.Clear();
            config.Listener.Username = "runner";
            config.Listener.SetPassword("s3cret");
        });
        var opened = await TryOpenSocksAsync(host.Port, new ProxyTarget("198.19.0.1", 443), "runner", "s3cret");
        Assert.False(opened);
        Assert.True(host.Engine.GetSnapshot().Traffic.BlockedConnections >= 1);
    }

    [Fact]
    public async Task Socks5_Via_Upstream_Preserves_Remote_Dns()
    {
        await using var echo = new TcpEchoServer();
        await using var upstream = new TestSocks5Server();
        upstream.ResolveOverride = (_, port) => new IPEndPoint(IPAddress.Loopback, port);

        await using var host = await EngineHost.StartAsync(config =>
        {
            config.Rules.Clear();
            var endpoint = new ProxyEndpoint
            {
                Name = "test-upstream",
                Protocol = ProxyProtocol.Socks5,
                Host = "127.0.0.1",
                Port = upstream.Port,
            };
            var policy = new RoutePolicy
            {
                Name = "test-policy",
                Mode = RoutePolicyMode.Failover,
                Chains = [new ProxyChainSpec { EndpointIds = [endpoint.Id] }],
            };
            config.Endpoints.Add(endpoint);
            config.Policies.Add(policy);
            config.Engine.DefaultPolicyId = policy.Id;
        });

        var target = new ProxyTarget("proxied.test", echo.Port);
        var (tcp, stream) = await OpenSocksAsync(host.Port, target);
        using (tcp)
        {
            var payload = Encoding.UTF8.GetBytes("through-upstream");
            await stream.WriteAsync(payload);
            var response = await ReadExactAsync(stream, payload.Length);
            Assert.Equal(payload, response);
        }

        Assert.Contains(upstream.ConnectRequests, request => request.Host == "proxied.test" && request.Port == echo.Port);
    }

    [Fact]
    public async Task Local_Dns_FakeIp_Requires_Active_Interception()
    {
        var dnsConfig = new DnsConfig
        {
            EnableServer = true,
            BindAddress = "127.0.0.1",
            Port = TestNet.FreeUdpPort(),
            Mode = DnsResolutionMode.System,
            FakeIpEnabled = true,
            FakeIpRange = "198.18.0.0/16",
        };
        dnsConfig.Hosts.Add(new HostMapping { Host = "mapped.test", Address = "127.0.0.1" });

        await using var log = new LogHub(writeToDisk: false);
        var resolver = new DohResolver(log, dnsConfig, null);
        var fakeIp = new FakeIpPool(dnsConfig.FakeIpRange);
        var allowed = false;
        var server = new LocalDnsServer(log, resolver, fakeIp, dnsConfig, () => allowed);
        server.Start(CancellationToken.None);
        try
        {
            var real = await QueryDnsAsync(server.Endpoint, "mapped.test");
            Assert.Contains(real, address => address.Equals(IPAddress.Loopback));

            allowed = true;
            var fake = await QueryDnsAsync(server.Endpoint, "mapped.test");
            Assert.Single(fake);
            Assert.StartsWith("198.18.", fake[0].ToString(), StringComparison.Ordinal);
        }
        finally
        {
            await server.DisposeAsync();
        }
    }

    private static async Task<IReadOnlyList<IPAddress>> QueryDnsAsync(IPEndPoint server, string host)
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var query = DnsWire.BuildQuery(host, DnsWire.TypeA, (ushort)Random.Shared.Next(1, ushort.MaxValue));
        await udp.SendAsync(query, server, timeout.Token);
        var response = await udp.ReceiveAsync(timeout.Token);
        var parsed = DnsWire.ParseAnswer(response.Buffer);
        Assert.True(parsed.IsSuccess, parsed.Error);
        return parsed.Addresses;
    }

    [Fact]
    public async Task Default_Policy_With_No_Usable_Chain_Fails_Closed()
    {
        await using var echo = new TcpEchoServer();
        await using var host = await EngineHost.StartAsync(config =>
        {
            config.Rules.Clear();
            config.Listener.Username = "runner";
            config.Listener.SetPassword("s3cret");
            config.Dns.Hosts.Add(new HostMapping { Host = "closed.test", Address = "127.0.0.1" });
            var endpoint = new ProxyEndpoint
            {
                Name = "disabled-upstream",
                Protocol = ProxyProtocol.Socks5,
                Host = "127.0.0.1",
                Port = 9,
                Enabled = false,
            };
            var policy = new RoutePolicy
            {
                Name = "no-chain",
                Mode = RoutePolicyMode.Failover,
                Chains = [new ProxyChainSpec { EndpointIds = [endpoint.Id] }],
            };
            config.Endpoints.Add(endpoint);
            config.Policies.Add(policy);
            config.Engine.DefaultPolicyId = policy.Id;
        });

        var opened = await TryOpenSocksAsync(host.Port, new ProxyTarget("closed.test", echo.Port), "runner", "s3cret");
        Assert.False(opened);
        Assert.True(host.Engine.GetSnapshot().Traffic.FailedConnections >= 1);
    }

    [Fact]
    public async Task Socks5_Local_Authentication_Enforced()
    {
        await using var echo = new TcpEchoServer();
        await using var host = await EngineHost.StartAsync(config =>
        {
            config.Rules.Clear();
            config.Listener.Username = "runner";
            config.Listener.SetPassword("s3cret");
        });

        var rejected = await TryOpenSocksAsync(host.Port, new ProxyTarget("127.0.0.1", echo.Port), "runner", "wrong");
        Assert.False(rejected);

        var (tcp, stream) = await OpenSocksAsync(host.Port, new ProxyTarget("127.0.0.1", echo.Port), "runner", "s3cret");
        using (tcp)
        {
            var payload = Encoding.UTF8.GetBytes("authorized");
            await stream.WriteAsync(payload);
            Assert.Equal(payload, await ReadExactAsync(stream, payload.Length));
        }
    }

    [Fact]
    public async Task Http_Connect_Direct_Roundtrip()
    {
        await using var echo = new TcpEchoServer();
        await using var host = await EngineHost.StartAsync(config => config.Rules.Clear());

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, host.Port);
        var stream = tcp.GetStream();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var request = $"CONNECT 127.0.0.1:{echo.Port} HTTP/1.1\r\nHost: 127.0.0.1:{echo.Port}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);
        var block = await HttpHeaderReader.ReadAsync(stream, 32 * 1024, cts.Token);
        Assert.Contains("200", block.Text.Split('\n')[0]);

        var payload = Encoding.UTF8.GetBytes("http-connect-direct");
        await stream.WriteAsync(payload, cts.Token);
        Assert.Equal(payload, await ReadExactAsync(stream, payload.Length, cts.Token));
    }

    [Fact]
    public async Task Http_Connect_Via_Http_Upstream()
    {
        await using var echo = new TcpEchoServer();
        await using var upstream = new TestHttpProxyServer();
        upstream.ResolveOverride = (_, port) => new IPEndPoint(IPAddress.Loopback, port);

        await using var host = await EngineHost.StartAsync(config =>
        {
            config.Rules.Clear();
            var endpoint = new ProxyEndpoint
            {
                Name = "http-upstream",
                Protocol = ProxyProtocol.HttpConnect,
                Host = "127.0.0.1",
                Port = upstream.Port,
            };
            var policy = new RoutePolicy
            {
                Name = "http-policy",
                Mode = RoutePolicyMode.Failover,
                Chains = [new ProxyChainSpec { EndpointIds = [endpoint.Id] }],
            };
            config.Endpoints.Add(endpoint);
            config.Policies.Add(policy);
            config.Engine.DefaultPolicyId = policy.Id;
        });

        using var cdp = new TcpClient();
        await cdp.ConnectAsync(IPAddress.Loopback, host.Port);
        var stream = cdp.GetStream();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var request = $"CONNECT proxied.test:{echo.Port} HTTP/1.1\r\nHost: proxied.test:{echo.Port}\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);
        var block = await HttpHeaderReader.ReadAsync(stream, 32 * 1024, cts.Token);
        Assert.Contains("200", block.Text.Split('\n')[0]);

        var payload = Encoding.UTF8.GetBytes("http-connect-upstream");
        await stream.WriteAsync(payload, cts.Token);
        Assert.Equal(payload, await ReadExactAsync(stream, payload.Length, cts.Token));
        Assert.Contains(upstream.ConnectTargets, value => value.StartsWith("proxied.test:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Http_Absolute_Form_Is_Rewritten_To_Origin_Form()
    {
        await using var origin = new TestHttpOrigin();
        await using var upstream = new TestHttpProxyServer();
        upstream.ResolveOverride = (_, port) => new IPEndPoint(IPAddress.Loopback, port);

        await using var host = await EngineHost.StartAsync(config =>
        {
            config.Rules.Clear();
            var endpoint = new ProxyEndpoint
            {
                Name = "http-upstream",
                Protocol = ProxyProtocol.HttpConnect,
                Host = "127.0.0.1",
                Port = upstream.Port,
            };
            var policy = new RoutePolicy
            {
                Name = "http-policy",
                Mode = RoutePolicyMode.Failover,
                Chains = [new ProxyChainSpec { EndpointIds = [endpoint.Id] }],
            };
            config.Endpoints.Add(endpoint);
            config.Policies.Add(policy);
            config.Engine.DefaultPolicyId = policy.Id;
        });

        using var cdp = new TcpClient();
        await cdp.ConnectAsync(IPAddress.Loopback, host.Port);
        var stream = cdp.GetStream();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var request = $"GET http://proxied.test:{origin.Port}/x?q=1 HTTP/1.1\r\nHost: proxied.test:{origin.Port}\r\nConnection: keep-alive\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token);

        var response = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cts.Token);
            if (read == 0)
            {
                break;
            }

            response.Write(buffer, 0, read);
        }

        var text = Encoding.ASCII.GetString(response.ToArray());
        Assert.Contains("200 OK", text);
        Assert.Contains("hello-from-origin", text);
        Assert.Equal("GET /x?q=1 HTTP/1.1", origin.LastRequestLine);
        Assert.Contains("proxied.test", origin.LastHostHeader);
    }

    [Fact]
    public async Task Udp_Associate_Direct_Echo()
    {
        await using var udpEcho = new UdpEchoServer();
        await using var host = await EngineHost.StartAsync(config => config.Rules.Clear());

        var (control, controlStream, relay) = await OpenSocksUdpAsync(host.Port);
        using (control)
        {
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var payload = Encoding.UTF8.GetBytes("udp-direct");
            var packet = BuildUdpPacket(new ProxyTarget("127.0.0.1", udpEcho.Port), payload);
            await udp.SendToAsync(packet, SocketFlags.None, relay);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var buffer = new byte[65535];
            var result = await udp.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cts.Token);
            Assert.True(TryParseUdpReply(buffer.AsSpan(0, result.ReceivedBytes), out var source, out var offset));
            Assert.Equal(payload, buffer.AsSpan(offset, result.ReceivedBytes - offset).ToArray());
            Assert.Equal(udpEcho.Port, source.Port);
        }
    }

    [Fact]
    public async Task Udp_Associate_Via_Socks5_Upstream()
    {
        await using var udpEcho = new UdpEchoServer();
        await using var upstream = new TestSocks5Server();
        upstream.ResolveOverride = (_, port) => new IPEndPoint(IPAddress.Loopback, port);

        await using var host = await EngineHost.StartAsync(config =>
        {
            config.Rules.Clear();
            var endpoint = new ProxyEndpoint
            {
                Name = "udp-upstream",
                Protocol = ProxyProtocol.Socks5,
                Host = "127.0.0.1",
                Port = upstream.Port,
            };
            var policy = new RoutePolicy
            {
                Name = "udp-policy",
                Mode = RoutePolicyMode.Failover,
                Chains = [new ProxyChainSpec { EndpointIds = [endpoint.Id] }],
            };
            config.Endpoints.Add(endpoint);
            config.Policies.Add(policy);
            config.Engine.DefaultPolicyId = policy.Id;
        });

        var (control, controlStream, relay) = await OpenSocksUdpAsync(host.Port);
        using (control)
        {
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var payload = Encoding.UTF8.GetBytes("udp-via-upstream");
            var packet = BuildUdpPacket(new ProxyTarget("udp.test", udpEcho.Port), payload);
            await udp.SendToAsync(packet, SocketFlags.None, relay);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            var buffer = new byte[65535];
            var result = await udp.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cts.Token);
            Assert.True(TryParseUdpReply(buffer.AsSpan(0, result.ReceivedBytes), out _, out var offset));
            Assert.Equal(payload, buffer.AsSpan(offset, result.ReceivedBytes - offset).ToArray());
        }

        Assert.True(Volatile.Read(ref upstream.UdpAssociationCount) >= 1);
    }

    [Fact]
    public async Task Pac_Is_Served_On_Proxy_Port()
    {
        await using var host = await EngineHost.StartAsync();
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, host.Port);
        var stream = tcp.GetStream();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await stream.WriteAsync(Encoding.ASCII.GetBytes("GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"), cts.Token);
        var block = await HttpHeaderReader.ReadAsync(stream, 64 * 1024, cts.Token);
        Assert.Contains("200", block.Text.Split('\n')[0]);
        var body = new MemoryStream();
        body.Write(block.Leftover);
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cts.Token);
            if (read == 0)
            {
                break;
            }

            body.Write(buffer, 0, read);
        }

        var text = Encoding.ASCII.GetString(body.ToArray());
        Assert.Contains("FindProxyForURL", text);
        Assert.Contains($":{host.Port}", text);
    }

    private static async Task<(TcpClient Tcp, NetworkStream Stream)> OpenSocksAsync(
        int localPort,
        ProxyTarget target,
        string? username = null,
        string? password = null)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, localPort);
        var stream = tcp.GetStream();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));

        if (username is null)
        {
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, cts.Token);
            var method = await ReadExactAsync(stream, 2, cts.Token);
            Assert.Equal(new byte[] { 5, 0 }, method);
        }
        else
        {
            await stream.WriteAsync(new byte[] { 5, 2, 0, 2 }, cts.Token);
            var method = await ReadExactAsync(stream, 2, cts.Token);
            Assert.Equal(new byte[] { 5, 2 }, method);
            var user = Encoding.UTF8.GetBytes(username);
            var pass = Encoding.UTF8.GetBytes(password ?? string.Empty);
            var auth = new byte[3 + user.Length + pass.Length];
            auth[0] = 1;
            auth[1] = (byte)user.Length;
            user.CopyTo(auth, 2);
            auth[2 + user.Length] = (byte)pass.Length;
            pass.CopyTo(auth, 3 + user.Length);
            await stream.WriteAsync(auth, cts.Token);
            var authReply = await ReadExactAsync(stream, 2, cts.Token);
            Assert.Equal(0, authReply[1]);
        }

        var request = BuildConnectRequest(target);
        await stream.WriteAsync(request, cts.Token);
        var reply = await ReadExactAsync(stream, 4, cts.Token);
        Assert.Equal(0, reply[1]);
        await SkipAddressAsync(stream, reply[3], cts.Token);
        return (tcp, stream);
    }

    private static async Task<bool> TryOpenSocksAsync(int localPort, ProxyTarget target, string username, string password)
    {
        try
        {
            var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, localPort);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var stream = tcp.GetStream();
            await stream.WriteAsync(new byte[] { 5, 2, 0, 2 }, cts.Token);
            var method = await ReadExactAsync(stream, 2, cts.Token);
            if (method[1] != 2)
            {
                tcp.Dispose();
                return false;
            }

            var user = Encoding.UTF8.GetBytes(username);
            var pass = Encoding.UTF8.GetBytes(password);
            var auth = new byte[3 + user.Length + pass.Length];
            auth[0] = 1;
            auth[1] = (byte)user.Length;
            user.CopyTo(auth, 2);
            auth[2 + user.Length] = (byte)pass.Length;
            pass.CopyTo(auth, 3 + user.Length);
            await stream.WriteAsync(auth, cts.Token);
            var authReply = await ReadExactAsync(stream, 2, cts.Token);
            if (authReply[1] != 0)
            {
                tcp.Dispose();
                return false;
            }

            await stream.WriteAsync(BuildConnectRequest(target), cts.Token);
            var reply = await ReadExactAsync(stream, 4, cts.Token);
            if (reply[1] != 0)
            {
                tcp.Dispose();
                return false;
            }

            await SkipAddressAsync(stream, reply[3], cts.Token);
            tcp.Dispose();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] BuildConnectRequest(ProxyTarget target)
    {
        var bytes = new List<byte> { 5, 1, 0 };
        if (IPAddress.TryParse(target.Host, out var address))
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                bytes.Add(1);
                bytes.AddRange(address.GetAddressBytes());
            }
            else
            {
                bytes.Add(4);
                bytes.AddRange(address.GetAddressBytes());
            }
        }
        else
        {
            var host = Encoding.ASCII.GetBytes(target.Host);
            bytes.Add(3);
            bytes.Add((byte)host.Length);
            bytes.AddRange(host);
        }

        bytes.Add((byte)(target.Port >> 8));
        bytes.Add((byte)target.Port);
        return bytes.ToArray();
    }

    private static async Task<(TcpClient Control, NetworkStream Stream, IPEndPoint Relay)> OpenSocksUdpAsync(int localPort)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, localPort);
        var stream = tcp.GetStream();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, cts.Token);
        Assert.Equal(new byte[] { 5, 0 }, await ReadExactAsync(stream, 2, cts.Token));
        await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, cts.Token);
        var reply = await ReadExactAsync(stream, 4, cts.Token);
        Assert.Equal(0, reply[1]);
        var relay = await ReadAddressAsync(stream, reply[3], cts.Token);
        return (tcp, stream, relay);
    }

    private static async Task SkipAddressAsync(NetworkStream stream, byte atyp, CancellationToken cancellationToken)
    {
        switch (atyp)
        {
            case 1:
                await ReadExactAsync(stream, 6, cancellationToken);
                break;
            case 4:
                await ReadExactAsync(stream, 18, cancellationToken);
                break;
            case 3:
                var length = await ReadExactAsync(stream, 1, cancellationToken);
                await ReadExactAsync(stream, length[0] + 2, cancellationToken);
                break;
            default:
                throw new InvalidOperationException($"未知地址类型 {atyp}");
        }
    }

    private static async Task<IPEndPoint> ReadAddressAsync(NetworkStream stream, byte atyp, CancellationToken cancellationToken)
    {
        switch (atyp)
        {
            case 1:
            {
                var data = await ReadExactAsync(stream, 6, cancellationToken);
                return new IPEndPoint(new IPAddress(data.AsSpan(0, 4)), (data[4] << 8) | data[5]);
            }
            case 4:
            {
                var data = await ReadExactAsync(stream, 18, cancellationToken);
                return new IPEndPoint(new IPAddress(data.AsSpan(0, 16)), (data[16] << 8) | data[17]);
            }
            case 3:
            {
                var length = await ReadExactAsync(stream, 1, cancellationToken);
                var data = await ReadExactAsync(stream, length[0] + 2, cancellationToken);
                var host = Encoding.ASCII.GetString(data, 0, length[0]);
                var port = (data[length[0]] << 8) | data[length[0] + 1];
                var addresses = await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken);
                return new IPEndPoint(addresses[0], port);
            }
            default:
                throw new InvalidOperationException($"未知地址类型 {atyp}");
        }
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int length, CancellationToken cancellationToken = default)
    {
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer, cancellationToken);
        return buffer;
    }

    private static byte[] BuildUdpPacket(ProxyTarget target, byte[] payload)
    {
        var bytes = new List<byte> { 0, 0, 0 };
        if (IPAddress.TryParse(target.Host, out var address))
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                bytes.Add(1);
                bytes.AddRange(address.GetAddressBytes());
            }
            else
            {
                bytes.Add(4);
                bytes.AddRange(address.GetAddressBytes());
            }
        }
        else
        {
            var host = Encoding.ASCII.GetBytes(target.Host);
            bytes.Add(3);
            bytes.Add((byte)host.Length);
            bytes.AddRange(host);
        }

        bytes.Add((byte)(target.Port >> 8));
        bytes.Add((byte)target.Port);
        bytes.AddRange(payload);
        return bytes.ToArray();
    }

    private static bool TryParseUdpReply(ReadOnlySpan<byte> packet, out ProxyTarget source, out int payloadOffset)
    {
        source = default;
        payloadOffset = 0;
        if (packet.Length < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || packet[3] != 1)
        {
            return false;
        }

        var address = new IPAddress(packet.Slice(4, 4));
        var port = (packet[8] << 8) | packet[9];
        source = new ProxyTarget(address.ToString(), port);
        payloadOffset = 10;
        return true;
    }
}
