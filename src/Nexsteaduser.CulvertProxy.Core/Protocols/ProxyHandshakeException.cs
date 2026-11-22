namespace Nexsteaduser.CulvertProxy.Core.Protocols;

/// <summary>上游握手失败，携带协议状态码便于界面展示。</summary>
public sealed class ProxyHandshakeException : IOException
{
    public ProxyHandshakeException(string message, int statusCode = 0, Exception? inner = null)
        : base(message, inner)
    {
        StatusCode = statusCode;
    }

    /// <summary>SOCKS5 应答码或 HTTP 状态码；0 表示无。</summary>
    public int StatusCode { get; }
}
