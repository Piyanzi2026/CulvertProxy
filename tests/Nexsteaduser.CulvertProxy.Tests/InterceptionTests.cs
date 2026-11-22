using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Engine;
using Nexsteaduser.CulvertProxy.Core.Interception;
using Xunit;

namespace Nexsteaduser.CulvertProxy.Tests;

public sealed class InterceptionTests
{
    [Fact]
    public async Task Preamble_Roundtrips_Domain_And_Token()
    {
        var token = RandomNumberGenerator.GetBytes(InterceptProtocol.TokenLength);
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(1);
        var port = ((IPEndPoint)listener.LocalEndPoint!).Port;

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        var accept = listener.AcceptAsync();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using var server = await accept;

        var preamble = InterceptProtocol.Encode(token, 4242, "example.test", 443);
        await client.SendAsync(preamble);
        var request = await InterceptProtocol.ReadAsync(server, token, TimeSpan.FromSeconds(2), CancellationToken.None);

        Assert.NotNull(request);
        Assert.Equal("example.test", request!.Target.Host);
        Assert.Equal(443, request.Target.Port);
        Assert.Equal(4242, request.ProcessId);
    }

    [Fact]
    public async Task Preamble_Rejects_Wrong_Token()
    {
        var token = RandomNumberGenerator.GetBytes(InterceptProtocol.TokenLength);
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(1);
        var port = ((IPEndPoint)listener.LocalEndPoint!).Port;

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        var accept = listener.AcceptAsync();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using var server = await accept;

        var wrongToken = RandomNumberGenerator.GetBytes(InterceptProtocol.TokenLength);
        var preamble = InterceptProtocol.Encode(wrongToken, 1, "127.0.0.1", 80);
        await client.SendAsync(preamble);
        var request = await InterceptProtocol.ReadAsync(server, token, TimeSpan.FromSeconds(2), CancellationToken.None);
        Assert.Null(request);
    }

    [Fact]
    public async Task Intercept_Entry_Relays_To_Direct_Target()
    {
        await using var echo = new TcpEchoServer();
        var temp = Path.Combine(Path.GetTempPath(), "culvert-intercept-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        HookConfig.FilePathOverride = Path.Combine(temp, "hook.conf");
        EngineHost? host = null;
        try
        {
            host = await EngineHost.StartAsync(config =>
            {
                config.Rules.Clear();
                config.Interception.Enabled = true;
                config.Interception.InjectRunningProcesses = false;
                config.Interception.AutoInjectNewProcesses = false;
            });

            var snapshot = host.Engine.GetSnapshot();
            Assert.True(snapshot.Interception.Active, snapshot.Interception.Error);
            Assert.True(snapshot.Interception.Port > 0);
            Assert.True(snapshot.Interception.HookAvailable);
            Assert.NotNull(host.Engine.InterceptTokenHex);

            var contents = File.ReadAllText(HookConfig.FilePath);
            Assert.Contains("enabled=1", contents);
            Assert.Contains($"port={snapshot.Interception.Port}", contents);
            Assert.Contains($"port6={snapshot.Interception.PortV6}", contents);
            Assert.Contains(host.Engine.InterceptTokenHex!, contents);

            var token = Convert.FromHexString(host.Engine.InterceptTokenHex!);
            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await client.ConnectAsync(IPAddress.Loopback, snapshot.Interception.Port);
            var preamble = InterceptProtocol.Encode(token, Environment.ProcessId, "127.0.0.1", echo.Port);
            await client.SendAsync(preamble);

            var payload = Encoding.UTF8.GetBytes("intercepted-echo");
            await client.SendAsync(payload);
            var response = await ReceiveExactAsync(client, payload.Length, TimeSpan.FromSeconds(5));
            Assert.Equal(payload, response);
        }
        finally
        {
            if (host is not null)
            {
                await host.DisposeAsync();
            }

            HookConfig.FilePathOverride = TestAssemblyInit.HookConfigPath;
            try
            {
                Directory.Delete(temp, recursive: true);
            }
            catch
            {
                // 临时目录清理由系统兜底。
            }
        }
    }

    [Fact]
    public async Task Intercept_Entry_Relays_Via_IPv6_Loopback()
    {
        await using var echo = new TcpEchoServer();
        var temp = Path.Combine(Path.GetTempPath(), "culvert-intercept-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        HookConfig.FilePathOverride = Path.Combine(temp, "hook.conf");
        EngineHost? host = null;
        try
        {
            host = await EngineHost.StartAsync(config =>
            {
                config.Rules.Clear();
                config.Interception.Enabled = true;
                config.Interception.InjectRunningProcesses = false;
                config.Interception.AutoInjectNewProcesses = false;
            });

            var snapshot = host.Engine.GetSnapshot();
            Assert.True(snapshot.Interception.Active, snapshot.Interception.Error);
            Assert.True(snapshot.Interception.PortV6 > 0, "IPv6 回环接管入口不可用。");

            var token = Convert.FromHexString(host.Engine.InterceptTokenHex!);
            using var client = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            await client.ConnectAsync(IPAddress.IPv6Loopback, snapshot.Interception.PortV6);
            var preamble = InterceptProtocol.Encode(token, Environment.ProcessId, "127.0.0.1", echo.Port);
            await client.SendAsync(preamble);

            var payload = Encoding.UTF8.GetBytes("intercepted-ipv6");
            await client.SendAsync(payload);
            var response = await ReceiveExactAsync(client, payload.Length, TimeSpan.FromSeconds(5));
            Assert.Equal(payload, response);
        }
        finally
        {
            if (host is not null)
            {
                await host.DisposeAsync();
            }

            HookConfig.FilePathOverride = TestAssemblyInit.HookConfigPath;
            try
            {
                Directory.Delete(temp, recursive: true);
            }
            catch
            {
                // 临时目录清理由系统兜底。
            }
        }
    }

    [Fact]
    public async Task Second_Engine_Cannot_Overwrite_Active_Interception()
    {
        var temp = Path.Combine(Path.GetTempPath(), "culvert-intercept-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        HookConfig.FilePathOverride = Path.Combine(temp, "hook.conf");
        EngineHost? first = null;
        EngineHost? second = null;
        try
        {
            first = await EngineHost.StartAsync(config =>
            {
                config.Rules.Clear();
                config.Interception.Enabled = true;
                config.Interception.InjectRunningProcesses = false;
                config.Interception.AutoInjectNewProcesses = false;
            });
            var firstSnapshot = first.Engine.GetSnapshot();
            Assert.True(firstSnapshot.Interception.Active, firstSnapshot.Interception.Error);

            second = await EngineHost.StartAsync(config =>
            {
                config.Rules.Clear();
                config.Interception.Enabled = true;
                config.Interception.InjectRunningProcesses = false;
                config.Interception.AutoInjectNewProcesses = false;
            });
            var secondSnapshot = second.Engine.GetSnapshot();
            Assert.False(secondSnapshot.Interception.Active);
            Assert.Contains("另一个", secondSnapshot.Interception.Error);

            ProxyEngine.DisableStaleInterception();
            var contents = File.ReadAllText(HookConfig.FilePath);
            Assert.Contains("enabled=1", contents);
            Assert.Contains($"port={firstSnapshot.Interception.Port}", contents);
        }
        finally
        {
            if (second is not null)
            {
                await second.DisposeAsync();
            }

            if (first is not null)
            {
                await first.DisposeAsync();
            }

            HookConfig.FilePathOverride = TestAssemblyInit.HookConfigPath;
            try
            {
                Directory.Delete(temp, recursive: true);
            }
            catch
            {
                // 临时目录清理由系统兜底。
            }
        }
    }

    [Fact]
    public async Task Intercept_Entry_Rejects_Invalid_Token()
    {
        var temp = Path.Combine(Path.GetTempPath(), "culvert-intercept-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        HookConfig.FilePathOverride = Path.Combine(temp, "hook.conf");
        EngineHost? host = null;
        try
        {
            host = await EngineHost.StartAsync(config =>
            {
                config.Rules.Clear();
                config.Interception.Enabled = true;
                config.Interception.InjectRunningProcesses = false;
                config.Interception.AutoInjectNewProcesses = false;
            });

            var snapshot = host.Engine.GetSnapshot();
            Assert.True(snapshot.Interception.Active, snapshot.Interception.Error);
            var wrongToken = RandomNumberGenerator.GetBytes(InterceptProtocol.TokenLength);
            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await client.ConnectAsync(IPAddress.Loopback, snapshot.Interception.Port);
            var preamble = InterceptProtocol.Encode(wrongToken, Environment.ProcessId, "127.0.0.1", 9);
            await client.SendAsync(preamble);

            var buffer = new byte[1];
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var closed = false;
            try
            {
                closed = await client.ReceiveAsync(buffer, SocketFlags.None, cts.Token) == 0;
            }
            catch (SocketException)
            {
                closed = true;
            }

            Assert.True(closed, "错误令牌的连接应被关闭。");
        }
        finally
        {
            if (host is not null)
            {
                await host.DisposeAsync();
            }

            HookConfig.FilePathOverride = TestAssemblyInit.HookConfigPath;
            try
            {
                Directory.Delete(temp, recursive: true);
            }
            catch
            {
                // 临时目录清理由系统兜底。
            }
        }
    }

    private static async Task<byte[]> ReceiveExactAsync(Socket socket, int length, TimeSpan timeout)
    {
        var buffer = new byte[length];
        var offset = 0;
        using var cts = new CancellationTokenSource(timeout);
        while (offset < length)
        {
            var read = await socket.ReceiveAsync(buffer.AsMemory(offset), SocketFlags.None, cts.Token);
            if (read <= 0)
            {
                throw new EndOfStreamException();
            }

            offset += read;
        }

        return buffer;
    }
}
