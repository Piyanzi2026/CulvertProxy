using Nexsteaduser.CulvertProxy.Core.Net;

namespace Nexsteaduser.CulvertProxy.Core.Routing;

/// <summary>规则要求阻断该连接。</summary>
public sealed class ConnectionBlockedException : Exception
{
    public ConnectionBlockedException(ProxyTarget target)
        : base($"规则阻断了连接：{target}")
    {
        Target = target;
    }

    public ProxyTarget Target { get; }
}

/// <summary>需要代理但没有任何可用链路；宁可失败也不直连泄漏。</summary>
public sealed class ProxyUnavailableException : Exception
{
    public ProxyUnavailableException(string message)
        : base(message)
    {
    }
}

/// <summary>所有候选链路均连接失败。</summary>
public sealed class ProxyConnectException : Exception
{
    public ProxyConnectException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}
