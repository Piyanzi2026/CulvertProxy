using System.Buffers.Binary;
using System.Net;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Dns;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;
using Nexsteaduser.CulvertProxy.Core.Routing;
using Nexsteaduser.CulvertProxy.Core.Server;
using Xunit;

namespace Nexsteaduser.CulvertProxy.Tests;

public sealed class HostPatternTests
{
    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "www.example.com", false)]
    [InlineData("*.example.com", "a.example.com", true)]
    [InlineData("*.example.com", "a.b.example.com", true)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData(".example.com", "example.com", true)]
    [InlineData(".example.com", "api.example.com", true)]
    [InlineData("*google*", "www.google.com", true)]
    [InlineData("api?.example.com", "api1.example.com", true)]
    [InlineData("api?.example.com", "api12.example.com", false)]
    [InlineData("re:^ad[0-9]+\\.example\\.com$", "ad12.example.com", true)]
    [InlineData("*", "anything.at.all", true)]
    public void Patterns_Match_As_Expected(string patternText, string host, bool expected)
    {
        Assert.True(HostPattern.TryCreate(patternText, out var pattern, out var error), error);
        Assert.Equal(expected, pattern!.IsMatch(host));
    }

    [Fact]
    public void Invalid_Regex_Is_Rejected()
    {
        Assert.False(HostPattern.TryCreate("re:(", out _, out var error));
        Assert.NotNull(error);
    }
}

public sealed class CidrTests
{
    [Theory]
    [InlineData("192.168.0.0/16", "192.168.5.5", true)]
    [InlineData("192.168.0.0/16", "192.169.0.1", false)]
    [InlineData("10.0.0.0/8", "10.200.1.1", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("0.0.0.0/0", "223.5.5.5", true)]
    [InlineData("::1/128", "::1", true)]
    [InlineData("::1/128", "::2", false)]
    public void Contains_Works(string cidrText, string addressText, bool expected)
    {
        Assert.True(CidrRange.TryParse(cidrText, out var cidr));
        Assert.Equal(expected, cidr.Contains(IPAddress.Parse(addressText)));
    }

    [Fact]
    public void Ipv4_Mapped_Address_Is_Normalized()
    {
        Assert.True(CidrRange.TryParse("10.0.0.0/8", out var cidr));
        Assert.True(cidr.Contains(IPAddress.Parse("::ffff:10.1.2.3")));
    }

    [Fact]
    public void Invalid_Prefix_Is_Rejected()
    {
        Assert.False(CidrRange.TryParse("10.0.0.0/33", out _));
        Assert.False(CidrRange.TryParse("not-an-address/24", out _));
    }
}

public sealed class PortSetTests
{
    [Fact]
    public void Ranges_Are_Parsed()
    {
        Assert.True(PortSet.TryCreate(["80,443,8000-8002"], out var set, out var error), error);
        Assert.True(set!.Contains(80));
        Assert.True(set.Contains(443));
        Assert.True(set.Contains(8001));
        Assert.False(set.Contains(8003));
    }

    [Fact]
    public void Out_Of_Range_Is_Rejected()
    {
        Assert.False(PortSet.TryCreate(["70000"], out _, out _));
        Assert.False(PortSet.TryCreate(["9000-8000"], out _, out _));
    }
}

public sealed class DnsWireTests
{
    [Fact]
    public void Query_Roundtrip_And_Answer_Parse()
    {
        var query = DnsWire.BuildQuery("example.com", DnsWire.TypeA, 0x1234);
        Assert.True(DnsWire.TryParseQuery(query, out var id, out var host, out var qtype, out var questionEnd));
        Assert.Equal(0x1234, id);
        Assert.Equal("example.com", host);
        Assert.Equal(DnsWire.TypeA, qtype);
        Assert.Equal(query.Length, questionEnd);

        var ipv6 = IPAddress.Parse("2001:db8::1").GetAddressBytes();
        var response = new List<byte>();
        WriteU16(response, 0x1234);
        WriteU16(response, 0x8180);
        WriteU16(response, 1);
        WriteU16(response, 2);
        WriteU16(response, 0);
        WriteU16(response, 0);
        response.AddRange(query[12..]);
        response.AddRange([0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 1, 2, 3, 4]);
        response.AddRange([0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x10]);
        response.AddRange(ipv6);

        var parsed = DnsWire.ParseAnswer(response.ToArray());
        Assert.True(parsed.IsSuccess);
        Assert.Equal(2, parsed.Addresses.Count);
        Assert.Contains(IPAddress.Parse("1.2.3.4"), parsed.Addresses);
        Assert.Contains(IPAddress.Parse("2001:db8::1"), parsed.Addresses);
        Assert.Equal(300, parsed.TtlSeconds);
    }

    [Fact]
    public void Build_Response_Filters_Family_And_Copies_Question()
    {
        var query = DnsWire.BuildQuery("test.local", DnsWire.TypeA, 7);
        Assert.True(DnsWire.TryParseQuery(query, out _, out _, out _, out var questionEnd));
        var response = DnsWire.BuildResponse(
            query,
            questionEnd,
            [IPAddress.Parse("10.1.2.3"), IPAddress.Parse("2001:db8::5")],
            120,
            DnsWire.TypeA);
        var parsed = DnsWire.ParseAnswer(response);
        Assert.True(parsed.IsSuccess);
        Assert.Single(parsed.Addresses);
        Assert.Equal(IPAddress.Parse("10.1.2.3"), parsed.Addresses[0]);
        Assert.Equal(120, parsed.TtlSeconds);
    }

    [Fact]
    public void Nxdomain_Is_Reported()
    {
        var query = DnsWire.BuildQuery("missing.test", DnsWire.TypeA, 9);
        Assert.True(DnsWire.TryParseQuery(query, out _, out _, out _, out var questionEnd));
        var response = DnsWire.BuildResponse(query, questionEnd, [], 0, DnsWire.TypeA, 3);
        var parsed = DnsWire.ParseAnswer(response);
        Assert.False(parsed.IsSuccess);
        Assert.Equal(3, parsed.RCode);
    }

    private static void WriteU16(List<byte> buffer, int value)
    {
        buffer.Add((byte)(value >> 8));
        buffer.Add((byte)value);
    }
}

public sealed class FakeIpPoolTests
{
    [Fact]
    public void Allocation_Is_Stable_And_Reverse_Mappable()
    {
        var pool = new FakeIpPool("198.18.0.0/15");
        var first = pool.GetOrAdd("example.com");
        var again = pool.GetOrAdd("example.com");
        var other = pool.GetOrAdd("example.org");
        Assert.Equal(first, again);
        Assert.NotEqual(first, other);
        Assert.True(pool.TryGetHost(first, out var host));
        Assert.Equal("example.com", host);
        Assert.StartsWith("198.1", first.ToString());
        pool.Clear();
        Assert.Equal(0, pool.Count);
    }

    [Fact]
    public void Hook_Reserved_Range_Is_Rejected()
    {
        Assert.Throws<FormatException>(() => new FakeIpPool("198.19.0.0/16"));
    }
}

public sealed class RuleEngineTests
{
    [Fact]
    public async Task Process_Host_Port_Rules_And_Default()
    {
        await using var log = new LogHub(writeToDisk: false);
        var config = new AppConfig();
        config.Rules.Add(new RoutingRule
        {
            Name = "chrome-example",
            Action = RuleAction.Proxy,
            Processes = ["chrome.exe"],
            Hosts = ["*.example.com"],
            Ports = ["443"],
        });
        config.Rules.Add(new RoutingRule
        {
            Name = "block-ads",
            Action = RuleAction.Block,
            Hosts = ["ads.*"],
        });

        var engine = new RuleEngine(log);
        engine.Update(config);

        var hit = engine.Resolve(new RouteRequest(
            "api.example.com",
            443,
            RuleTransport.Tcp,
            "chrome.exe",
            @"C:\Program Files\Google\Chrome\chrome.exe"));
        Assert.Equal(RuleAction.Proxy, hit.Action);
        Assert.Equal("chrome-example", hit.RuleName);
        Assert.False(hit.IsDefault);

        var wrongPort = engine.Resolve(new RouteRequest("api.example.com", 80, RuleTransport.Tcp, "chrome.exe"));
        Assert.True(wrongPort.IsDefault);
        Assert.Equal(RuleAction.Direct, wrongPort.Action);

        var wrongProcess = engine.Resolve(new RouteRequest("api.example.com", 443, RuleTransport.Tcp, "firefox.exe"));
        Assert.True(wrongProcess.IsDefault);

        var blocked = engine.Resolve(new RouteRequest("ads.example.net", 443, RuleTransport.Tcp, "chrome.exe"));
        Assert.Equal(RuleAction.Block, blocked.Action);
    }

    [Fact]
    public async Task Cidr_And_Transport_Filters_Work()
    {
        await using var log = new LogHub(writeToDisk: false);
        var config = new AppConfig();
        config.Rules.Add(new RoutingRule
        {
            Name = "udp-private",
            Action = RuleAction.Block,
            IpRanges = ["10.0.0.0/8"],
            Transports = [RuleTransport.Udp],
        });

        var engine = new RuleEngine(log);
        engine.Update(config);

        Assert.Equal(RuleAction.Block, engine.Resolve(new RouteRequest("10.1.2.3", 53, RuleTransport.Udp)).Action);
        Assert.True(engine.Resolve(new RouteRequest("10.1.2.3", 53, RuleTransport.Tcp)).IsDefault);
        Assert.True(engine.Resolve(new RouteRequest("11.1.2.3", 53, RuleTransport.Udp)).IsDefault);
    }
}

public sealed class ConfigTests
{
    [Fact]
    public void Normalize_Creates_Policy_And_Clamps_Ports()
    {
        var config = new AppConfig();
        config.Listener.Port = 70000;
        config.Endpoints.Add(new ProxyEndpoint { Name = "up", Host = "1.2.3.4", Port = 1080 });
        ConfigStore.Normalize(config);
        Assert.Equal(65535, config.Listener.Port);
        Assert.Single(config.Policies);
        Assert.Equal(config.Policies[0].Id, config.Engine.DefaultPolicyId);
        Assert.Single(config.Policies[0].Chains);
    }

    [Fact]
    public void Normalize_Does_Not_Keep_Disabled_Default_Policy()
    {
        var config = new AppConfig();
        var policy = new RoutePolicy
        {
            Name = "disabled",
            Enabled = false,
            Chains = [new ProxyChainSpec { EndpointIds = ["missing"] }],
        };
        config.Policies.Add(policy);
        config.Engine.DefaultPolicyId = policy.Id;
        ConfigStore.Normalize(config);

        Assert.Null(config.Engine.DefaultPolicyId);
        Assert.False(policy.Enabled);
    }

    [Fact]
    public void Normalize_Treats_Zero_Ports_As_Default()
    {
        var config = new AppConfig();
        config.Listener.Port = 0;
        config.Dns.Port = 0;
        ConfigStore.Normalize(config);
        Assert.Equal(1080, config.Listener.Port);
        Assert.Equal(5353, config.Dns.Port);
    }

    [Theory]
    [InlineData("198.19.0.0/16")]
    [InlineData("198.18.0.0/31")]
    [InlineData("not-a-cidr")]
    [InlineData("fd00::/8")]
    public void Normalize_Repairs_Unusable_FakeIp_Range(string range)
    {
        var config = new AppConfig();
        config.Dns.FakeIpRange = range;
        ConfigStore.Normalize(config);
        Assert.Equal("198.18.0.0/16", config.Dns.FakeIpRange);
    }

    [Fact]
    public void Password_Is_Encrypted_At_Rest_And_Roundtrips()
    {
        var directory = Path.Combine(Path.GetTempPath(), "culvert-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var log = new LogHub(writeToDisk: false);
            var store = new ConfigStore(log, Path.Combine(directory, "config.json"));
            var config = new AppConfig();
            var endpoint = new ProxyEndpoint { Name = "up", Host = "127.0.0.1", Port = 1080, Username = "user" };
            endpoint.SetPassword("p@ssw0rd");
            config.Endpoints.Add(endpoint);
            store.Save(config);

            var json = File.ReadAllText(store.FilePath);
            Assert.DoesNotContain("p@ssw0rd", json);
            var loaded = store.Load();
            Assert.Equal("p@ssw0rd", loaded.Endpoints[0].PlainPassword);
            Assert.Equal("user", loaded.Endpoints[0].Username);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Corrupt_Config_Falls_Back_And_Is_Preserved()
    {
        var directory = Path.Combine(Path.GetTempPath(), "culvert-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "config.json");
            File.WriteAllText(path, "{ this is not json");
            var log = new LogHub(writeToDisk: false);
            var store = new ConfigStore(log, path);
            var config = store.Load();
            Assert.NotNull(store.LastLoadError);
            Assert.NotEmpty(config.Rules);
            Assert.True(Directory.GetFiles(directory, "config.corrupt-*.json").Length == 1);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}

public sealed class PacTests
{
    [Fact]
    public void Pac_Contains_Local_Proxy_And_Direct_Bypasses()
    {
        var config = new AppConfig();
        config.Listener.BindAddress = "127.0.0.1";
        config.Listener.Port = 1080;
        var pac = PacGenerator.Generate(config);
        Assert.Contains("FindProxyForURL", pac);
        Assert.Contains("SOCKS5 127.0.0.1:1080", pac);
        Assert.Contains("DIRECT", pac);
    }
}
