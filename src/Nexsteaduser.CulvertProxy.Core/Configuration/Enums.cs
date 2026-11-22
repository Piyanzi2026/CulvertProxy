namespace Nexsteaduser.CulvertProxy.Core.Configuration;

/// <summary>上游代理使用的协议。</summary>
public enum ProxyProtocol
{
    Socks5 = 0,
    HttpConnect = 1,
}

/// <summary>同一策略内多条链路的选择方式。</summary>
public enum RoutePolicyMode
{
    /// <summary>按配置顺序优先使用，失败后切换下一条。</summary>
    Failover = 0,
    /// <summary>按最近一次握手延迟从低到高选择。</summary>
    Latency = 1,
    /// <summary>随机选择，用于分散出口。</summary>
    Random = 2,
    /// <summary>同一目标固定命中同一条链路。</summary>
    Sticky = 3,
}

/// <summary>规则命中后的动作。</summary>
public enum RuleAction
{
    Direct = 0,
    Proxy = 1,
    Block = 2,
}

/// <summary>规则适用的传输层协议。</summary>
public enum RuleTransport
{
    Tcp = 0,
    Udp = 1,
}

/// <summary>DNS 解析方式。</summary>
public enum DnsResolutionMode
{
    System = 0,
    DnsOverHttps = 1,
}

/// <summary>应用主题。</summary>
public enum AppTheme
{
    System = 0,
    Dark = 1,
    Light = 2,
}
