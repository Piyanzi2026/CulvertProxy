using Nexsteaduser.CulvertProxy.Core.Configuration;

namespace Nexsteaduser.CulvertProxy.Core.Transport;

/// <summary>链路中某一跳失败，用于精确惩罚对应服务器。</summary>
public sealed class ChainConnectException : Exception
{
    public ChainConnectException(int hopIndex, ProxyEndpoint endpoint, Exception inner)
        : base($"第 {hopIndex + 1} 跳（{endpoint.Name}）失败：{inner.Message}", inner)
    {
        HopIndex = hopIndex;
        Endpoint = endpoint;
    }

    public int HopIndex { get; }

    public ProxyEndpoint Endpoint { get; }
}
