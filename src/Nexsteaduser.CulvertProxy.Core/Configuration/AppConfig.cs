using System.Text.Json.Serialization;
using Nexsteaduser.CulvertProxy.Core.Security;

namespace Nexsteaduser.CulvertProxy.Core.Configuration;

/// <summary>单个上游代理服务器定义。密码以 DPAPI 密文持久化。</summary>
public sealed class ProxyEndpoint
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public ProxyProtocol Protocol { get; set; } = ProxyProtocol.Socks5;
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 1080;
    public string? Username { get; set; }
    public string? Password { get; set; }
    public bool UseTls { get; set; }
    public string? TlsServerName { get; set; }
    public bool AllowInsecureTls { get; set; }

    /// <summary>可选的叶证书 SHA-256 指纹，用于抵抗 TLS 中间人。</summary>
    public string? PinnedCertSha256 { get; set; }
    public bool Enabled { get; set; } = true;
    public string? Note { get; set; }

    /// <summary>解密后的密码；不参与序列化。</summary>
    [JsonIgnore]
    public string? PlainPassword => SecretProtector.Unprotect(Password);

    /// <summary>写入明文密码并以 DPAPI 形式保存。</summary>
    public void SetPassword(string? plain)
    {
        Password = string.IsNullOrEmpty(plain) ? null : SecretProtector.Protect(plain);
    }

    /// <summary>用于日志与界面显示的上游描述。</summary>
    [JsonIgnore]
    public string Display => $"{Name} ({Protocol} {Host}:{Port}{(UseTls ? " +TLS" : string.Empty)})";
}

/// <summary>一条链路的组成，按顺序逐跳建立隧道。</summary>
public sealed class ProxyChainSpec
{
    public List<string> EndpointIds { get; set; } = [];
}

/// <summary>策略：若干条可用链路及选择算法，规则通过 Id 引用。</summary>
public sealed class RoutePolicy
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public RoutePolicyMode Mode { get; set; } = RoutePolicyMode.Latency;
    public List<ProxyChainSpec> Chains { get; set; } = [];
}

/// <summary>本地入口监听配置，SOCKS5 与 HTTP 共用同一端口自动识别。</summary>
public sealed class ListenerConfig
{
    public bool Enabled { get; set; } = true;
    public string BindAddress { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 1080;
    public bool AllowLan { get; set; }
    public string? Username { get; set; }
    public string? Password { get; set; }

    [JsonIgnore]
    public string? PlainPassword => SecretProtector.Unprotect(Password);

    [JsonIgnore]
    public bool RequiresAuthentication => !string.IsNullOrEmpty(Username) || !string.IsNullOrEmpty(Password);

    public void SetPassword(string? plain)
    {
        Password = string.IsNullOrEmpty(plain) ? null : SecretProtector.Protect(plain);
    }
}

/// <summary>内置 DNS 服务与解析器设置。</summary>
public sealed class DnsConfig
{
    public bool EnableServer { get; set; }
    public string BindAddress { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 5353;
    public DnsResolutionMode Mode { get; set; } = DnsResolutionMode.DnsOverHttps;
    public string DohUrl { get; set; } = "https://1.1.1.1/dns-query";
    public bool DohThroughProxy { get; set; } = true;
    public string? DohPolicyId { get; set; }
    public bool FakeIpEnabled { get; set; }
    public string FakeIpRange { get; set; } = "198.18.0.0/16";
    public int CacheMinutes { get; set; } = 10;
    public int QueryTimeoutMs { get; set; } = 5000;
    public bool SystemFallback { get; set; } = true;
    public List<HostMapping> Hosts { get; set; } = [];
}

/// <summary>静态 hosts 覆盖。</summary>
public sealed class HostMapping
{
    public string Host { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
}

/// <summary>按顺序匹配的转发规则；未命中时走默认策略。</summary>
public sealed class RoutingRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public RuleAction Action { get; set; } = RuleAction.Proxy;
    public string? PolicyId { get; set; }
    public List<string> Processes { get; set; } = [];
    public List<string> Hosts { get; set; } = [];
    public List<string> IpRanges { get; set; } = [];
    public List<string> Ports { get; set; } = [];
    public List<RuleTransport> Transports { get; set; } = [];
}

/// <summary>引擎行为参数。</summary>
public sealed class EngineSettings
{
    public string? DefaultPolicyId { get; set; }
    public int ConnectTimeoutMs { get; set; } = 8000;
    public int HandshakeTimeoutMs { get; set; } = 8000;
    public int MaxRouteAttempts { get; set; } = 3;
    public string? OutboundBindAddress { get; set; }
    public bool LogConnections { get; set; } = true;
    public int ConnectionHistoryLimit { get; set; } = 500;
    public bool StartProxyOnLaunch { get; set; } = true;
}

/// <summary>进程级透明接管：Winsock 注入与失败策略。</summary>
public sealed class InterceptionConfig
{
    public bool Enabled { get; set; }

    /// <summary>启用时接管已经在运行的当前用户进程。</summary>
    public bool InjectRunningProcesses { get; set; } = true;

    /// <summary>持续扫描并接管新启动的进程。</summary>
    public bool AutoInjectNewProcesses { get; set; } = true;

    /// <summary>接管入口不可达时是否允许应用直连；默认关闭以避免泄漏。</summary>
    public bool FailOpen { get; set; }

    /// <summary>进程名或完整路径通配符，每行一条。</summary>
    public List<string> ExcludeProcesses { get; set; } = [];
}

/// <summary>界面偏好。</summary>
public sealed class UiSettings
{
    public AppTheme Theme { get; set; } = AppTheme.System;
    public bool CloseToTray { get; set; } = true;
    public bool StartWithWindows { get; set; }
    public bool MinimizeToTray { get; set; } = true;
    public string LastPage { get; set; } = "dashboard";
    public int ChartWindowSeconds { get; set; } = 60;
}

/// <summary>完整应用配置。</summary>
public sealed class AppConfig
{
    public int SchemaVersion { get; set; } = 1;
    public ListenerConfig Listener { get; set; } = new();
    public DnsConfig Dns { get; set; } = new();
    public InterceptionConfig Interception { get; set; } = new();
    public EngineSettings Engine { get; set; } = new();
    public UiSettings Ui { get; set; } = new();
    public List<ProxyEndpoint> Endpoints { get; set; } = [];
    public List<RoutePolicy> Policies { get; set; } = [];
    public List<RoutingRule> Rules { get; set; } = [];

    [JsonIgnore]
    public string EffectiveListenAddress =>
        Listener.AllowLan ? (Listener.BindAddress is "127.0.0.1" or "localhost" ? "0.0.0.0" : Listener.BindAddress) : Listener.BindAddress;

    /// <summary>创建带内网直连规则的初始配置。</summary>
    public static AppConfig CreateDefault()
    {
        var cfg = new AppConfig();
        cfg.Rules.Add(new RoutingRule
        {
            Name = "本地与内网直连",
            Action = RuleAction.Direct,
            Hosts = ["localhost", "*.local", "*.lan", "*.home.arpa"],
            IpRanges = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"],
        });
        return cfg;
    }
}
