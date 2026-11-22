using System.Text;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Net;

namespace Nexsteaduser.CulvertProxy.Core.Protocols;

/// <summary>通过上游 HTTP 代理建立 CONNECT 隧道。</summary>
public static class HttpConnectClient
{
    /// <summary>发送 CONNECT 并校验 2xx 应答；残余字节由 PrefixedStream 保留。</summary>
    public static async Task<Stream> ConnectAsync(
        Stream stream,
        ProxyEndpoint endpoint,
        ProxyTarget target,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var token = cts.Token;

        var hostHeader = target.ToString();
        var request = new StringBuilder(256);
        request.Append("CONNECT ").Append(hostHeader).Append(" HTTP/1.1\r\n");
        request.Append("Host: ").Append(hostHeader).Append("\r\n");
        request.Append("User-Agent: CulvertProxy/1.0\r\n");
        request.Append("Proxy-Connection: Keep-Alive\r\n");
        if (!string.IsNullOrEmpty(endpoint.Username) || !string.IsNullOrEmpty(endpoint.PlainPassword))
        {
            var raw = $"{endpoint.Username ?? string.Empty}:{endpoint.PlainPassword ?? string.Empty}";
            request.Append("Proxy-Authorization: Basic ")
                .Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)))
                .Append("\r\n");
        }

        request.Append("\r\n");
        var bytes = Encoding.ASCII.GetBytes(request.ToString());
        await stream.WriteAsync(bytes, token).ConfigureAwait(false);

        var block = await HttpHeaderReader.ReadAsync(stream, 64 * 1024, token).ConfigureAwait(false);
        var status = HttpHeaderReader.ParseStatusCode(block.Text);
        if (status is < 200 or > 299)
        {
            var reason = ExtractReason(block.Text);
            throw new ProxyHandshakeException(
                status == 407 ? "上游 HTTP 代理要求认证或凭据错误（407）。" : $"上游 HTTP CONNECT 失败：{status} {reason}",
                status);
        }

        return block.Leftover.Length == 0
            ? stream
            : new PrefixedStream(block.Leftover, 0, block.Leftover.Length, stream);
    }

    private static string ExtractReason(string headerText)
    {
        var lineEnd = headerText.IndexOf('\n');
        var line = (lineEnd < 0 ? headerText : headerText[..lineEnd]).TrimEnd('\r');
        var parts = line.Split(' ', 3, StringSplitOptions.TrimEntries);
        return parts.Length == 3 ? parts[2] : string.Empty;
    }
}
