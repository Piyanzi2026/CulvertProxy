using System.Net;
using System.Net.Sockets;
using System.Text;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Engine;
using Nexsteaduser.CulvertProxy.Core.Net;
using Nexsteaduser.CulvertProxy.Core.Routing;
using Nexsteaduser.CulvertProxy.Core.Transport;

namespace Nexsteaduser.CulvertProxy.Core.Server;

/// <summary>本地 HTTP 代理会话：CONNECT、绝对 URI 转发与 PAC 下发。</summary>
internal static class HttpProxySession
{
    public static async Task RunAsync(Socket client, ProxyEngine engine, CancellationToken engineToken)
    {
        await using var stream = new NetworkStream(client, ownsSocket: true);
        ActiveConnection? entry = null;
        string? failure = null;
        var failureCounted = false;
        var blockedCounted = false;

        try
        {
            var access = engine.Access;
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(engineToken);
            handshakeCts.CancelAfter(access.HandshakeTimeout);
            var handshakeToken = handshakeCts.Token;

            HttpHeaderReader.HeaderBlock block;
            try
            {
                block = await HttpHeaderReader.ReadAsync(stream, 64 * 1024, handshakeToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
                return;
            }

            if (!TryParseRequest(block.Text, out var method, out var targetText, out var version, out var headers))
            {
                await WriteResponseAsync(stream, 400, "Bad Request", "text/plain", "Invalid HTTP proxy request.", handshakeToken).ConfigureAwait(false);
                return;
            }

            if (method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                && targetText.EndsWith("/proxy.pac", StringComparison.OrdinalIgnoreCase))
            {
                await ServePacAsync(stream, engine, handshakeToken).ConfigureAwait(false);
                return;
            }

            if (!IsAuthorized(engine, headers))
            {
                await WriteResponseAsync(
                    stream,
                    407,
                    "Proxy Authentication Required",
                    "text/plain",
                    "Proxy authentication required.",
                    handshakeToken,
                    "Proxy-Authenticate: Basic realm=\"CulvertProxy\"\r\n").ConfigureAwait(false);
                return;
            }

            var process = ResolveProcess(client, engine);

            if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                ProxyTarget target;
                try
                {
                    target = ProxyTarget.Parse(targetText);
                }
                catch (Exception ex) when (ex is FormatException or OverflowException)
                {
                    await WriteResponseAsync(stream, 400, "Bad Request", "text/plain", "Invalid CONNECT target.", handshakeToken).ConfigureAwait(false);
                    return;
                }

                if (target.Port is < 1 or > 65535)
                {
                    await WriteResponseAsync(stream, 400, "Bad Request", "text/plain", "Invalid CONNECT port.", handshakeToken).ConfigureAwait(false);
                    return;
                }

                var (mapped, decision) = engine.ResolveRoute(target, RuleTransport.Tcp, process);
                var policyName = decision.PolicyId is not null ? engine.Routes.GetPolicy(decision.PolicyId)?.Name : null;
                entry = engine.Connections.Begin(
                    new ConnectionInit("HTTP CONNECT", mapped.ToString(), process?.Name, process?.Pid, decision.RuleName, policyName),
                    engineToken);
                engine.Stats.RecordConnection();

                Tunnel tunnel;
                try
                {
                    tunnel = await engine.Connector.ConnectAsync(
                        decision,
                        mapped,
                        access.ConnectTimeout,
                        access.HandshakeTimeout,
                        access.OutboundBindAddress,
                        access.MaxAttempts,
                        entry.CancellationToken).ConfigureAwait(false);
                }
                catch (ConnectionBlockedException ex)
                {
                    engine.Stats.RecordBlocked();
                    blockedCounted = true;
                    failure = ex.Message;
                    await WriteResponseAsync(stream, 403, "Forbidden", "text/plain", "Blocked by rule.", handshakeToken).ConfigureAwait(false);
                    return;
                }
                catch (OperationCanceledException) when (engineToken.IsCancellationRequested)
                {
                    failure = "引擎停止。";
                    return;
                }
                catch (Exception ex)
                {
                    engine.Stats.RecordFailure();
                    failureCounted = true;
                    failure = ex.Message;
                    await WriteResponseAsync(stream, 502, "Bad Gateway", "text/plain", "Upstream connection failed.", engineToken).ConfigureAwait(false);
                    return;
                }

                await using (tunnel)
                {
                    entry.SetRoute(tunnel.Description);
                    entry.SetState("relaying");
                    await WriteRawAsync(stream, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: CulvertProxy/1.0\r\n\r\n", engineToken).ConfigureAwait(false);

                    Stream clientStream = block.Leftover.Length > 0
                        ? new PrefixedStream(block.Leftover, 0, block.Leftover.Length, stream)
                        : stream;
                    var result = await StreamRelay.RunAsync(
                        clientStream,
                        client,
                        tunnel.Stream,
                        tunnel.HalfCloseSocket,
                        bytes =>
                        {
                            entry.AddUploaded(bytes);
                            engine.Stats.AddUploaded(bytes);
                        },
                        bytes =>
                        {
                            entry.AddDownloaded(bytes);
                            engine.Stats.AddDownloaded(bytes);
                        },
                        entry.CancellationToken).ConfigureAwait(false);

                    if (result.Error is not null and not OperationCanceledException)
                    {
                        engine.Log.Debug("HTTP", $"{mapped} 中继结束：{result.Error.Message}");
                    }
                }

                return;
            }

            if (!Uri.TryCreate(targetText, UriKind.Absolute, out var uri) || !uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
            {
                await WriteResponseAsync(
                    stream,
                    400,
                    "Bad Request",
                    "text/plain",
                    "CulvertProxy accepts CONNECT or absolute http:// requests. Configure this endpoint as an HTTP proxy.",
                    handshakeToken).ConfigureAwait(false);
                return;
            }

            var port = uri.IsDefaultPort ? 80 : uri.Port;
            var host = uri.IdnHost;
            var (mappedHttp, httpDecision) = engine.ResolveRoute(new ProxyTarget(host, port), RuleTransport.Tcp, process);
            var httpPolicyName = httpDecision.PolicyId is not null ? engine.Routes.GetPolicy(httpDecision.PolicyId)?.Name : null;
            entry = engine.Connections.Begin(
                new ConnectionInit("HTTP", mappedHttp.ToString(), process?.Name, process?.Pid, httpDecision.RuleName, httpPolicyName),
                engineToken);
            engine.Stats.RecordConnection();

            Tunnel httpTunnel;
            try
            {
                httpTunnel = await engine.Connector.ConnectAsync(
                    httpDecision,
                    mappedHttp,
                    access.ConnectTimeout,
                    access.HandshakeTimeout,
                    access.OutboundBindAddress,
                    access.MaxAttempts,
                    entry.CancellationToken).ConfigureAwait(false);
            }
            catch (ConnectionBlockedException ex)
            {
                engine.Stats.RecordBlocked();
                blockedCounted = true;
                failure = ex.Message;
                await WriteResponseAsync(stream, 403, "Forbidden", "text/plain", "Blocked by rule.", handshakeToken).ConfigureAwait(false);
                return;
            }
            catch (OperationCanceledException) when (engineToken.IsCancellationRequested)
            {
                failure = "引擎停止。";
                return;
            }
            catch (Exception ex)
            {
                engine.Stats.RecordFailure();
                failureCounted = true;
                failure = ex.Message;
                await WriteResponseAsync(stream, 502, "Bad Gateway", "text/plain", "Upstream connection failed.", engineToken).ConfigureAwait(false);
                return;
            }

            await using (httpTunnel)
            {
                entry.SetRoute(httpTunnel.Description);
                entry.SetState("relaying");

                var pathAndQuery = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
                var originHead = BuildOriginRequest(method, pathAndQuery, version, headers, uri, port);
                var headBytes = Encoding.ASCII.GetBytes(originHead);
                await httpTunnel.Stream.WriteAsync(headBytes, entry.CancellationToken).ConfigureAwait(false);
                entry.AddUploaded(headBytes.Length);
                engine.Stats.AddUploaded(headBytes.Length);

                Stream clientStream = block.Leftover.Length > 0
                    ? new PrefixedStream(block.Leftover, 0, block.Leftover.Length, stream)
                    : stream;
                var result = await StreamRelay.RunAsync(
                    clientStream,
                    client,
                    httpTunnel.Stream,
                    httpTunnel.HalfCloseSocket,
                    bytes =>
                    {
                        entry.AddUploaded(bytes);
                        engine.Stats.AddUploaded(bytes);
                    },
                    bytes =>
                    {
                        entry.AddDownloaded(bytes);
                        engine.Stats.AddDownloaded(bytes);
                    },
                    entry.CancellationToken).ConfigureAwait(false);

                if (result.Error is not null and not OperationCanceledException)
                {
                    engine.Log.Debug("HTTP", $"{mappedHttp} 中继结束：{result.Error.Message}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 正常结束。
        }
        catch (Exception ex)
        {
            engine.Log.Debug("HTTP", $"会话异常：{ex.Message}");
        }
        finally
        {
            if (entry is not null)
            {
                if (failure is not null && !failureCounted && !blockedCounted)
                {
                    engine.Stats.RecordFailure();
                }

                engine.Connections.Complete(entry, failure);
            }
        }
    }

    private static bool TryParseRequest(
        string headerText,
        out string method,
        out string target,
        out string version,
        out List<KeyValuePair<string, string>> headers)
    {
        method = string.Empty;
        target = string.Empty;
        version = "HTTP/1.1";
        headers = [];
        var lines = headerText.Split('\n');
        if (lines.Length == 0)
        {
            return false;
        }

        var first = lines[0].TrimEnd('\r');
        var parts = first.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            return false;
        }

        method = parts[0];
        target = parts[1];
        if (parts.Length >= 3)
        {
            version = parts[2];
        }

        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (line.Length == 0)
            {
                break;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            headers.Add(new KeyValuePair<string, string>(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }

        return true;
    }

    private static string? FindHeader(List<KeyValuePair<string, string>> headers, string name)
    {
        foreach (var header in headers)
        {
            if (header.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return header.Value;
            }
        }

        return null;
    }

    private static bool IsAuthorized(ProxyEngine engine, List<KeyValuePair<string, string>> headers)
    {
        if (!engine.Access.AuthenticationRequired)
        {
            return true;
        }

        var authorization = FindHeader(headers, "Proxy-Authorization");
        if (string.IsNullOrEmpty(authorization) || !authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            var raw = Convert.FromBase64String(authorization[6..].Trim());
            var text = Encoding.UTF8.GetString(raw);
            var colon = text.IndexOf(':');
            if (colon <= 0)
            {
                return false;
            }

            return engine.ValidateLocalCredentials(text[..colon], text[(colon + 1)..]);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string BuildOriginRequest(
        string method,
        string pathAndQuery,
        string version,
        List<KeyValuePair<string, string>> headers,
        Uri uri,
        int port)
    {
        var builder = new StringBuilder(512);
        builder.Append(method).Append(' ').Append(pathAndQuery).Append(' ').Append(version).Append("\r\n");
        var hasHost = false;
        foreach (var header in headers)
        {
            if (header.Key.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)
                || header.Key.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase)
                || header.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase)
                || header.Key.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                hasHost = true;
            }

            builder.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
        }

        if (!hasHost)
        {
            builder.Append("Host: ").Append(FormatAuthority(uri, port)).Append("\r\n");
        }

        builder.Append("Connection: close\r\n\r\n");
        return builder.ToString();
    }

    private static string FormatAuthority(Uri uri, int port)
    {
        var host = uri.Host;
        var isIpv6 = host.Contains(':');
        var formatted = isIpv6 && !host.StartsWith('[') ? $"[{host}]" : host;
        return port == 80 ? formatted : $"{formatted}:{port}";
    }

    private static ProcessIdentity? ResolveProcess(Socket client, ProxyEngine engine)
    {
        return client.RemoteEndPoint is IPEndPoint remote && client.LocalEndPoint is IPEndPoint local
            ? engine.Processes.Resolve(remote, local)
            : null;
    }

    private static async ValueTask ServePacAsync(Stream stream, ProxyEngine engine, CancellationToken cancellationToken)
    {
        var body = Encoding.ASCII.GetBytes(PacGenerator.Generate(engine.Config));
        var head = $"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {body.Length}\r\nCache-Control: no-cache, no-store\r\nConnection: close\r\n\r\n";
        await WriteRawAsync(stream, head, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(body, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask WriteResponseAsync(
        Stream stream,
        int status,
        string reason,
        string? contentType,
        string? body,
        CancellationToken cancellationToken,
        string? extraHeaders = null)
    {
        var payload = body is null ? [] : Encoding.UTF8.GetBytes(body);
        var builder = new StringBuilder(256)
            .Append("HTTP/1.1 ").Append(status).Append(' ').Append(reason).Append("\r\n")
            .Append("Proxy-Agent: CulvertProxy/1.0\r\n")
            .Append("Content-Length: ").Append(payload.Length).Append("\r\n")
            .Append("Connection: close\r\n");
        if (!string.IsNullOrEmpty(contentType))
        {
            builder.Append("Content-Type: ").Append(contentType).Append("\r\n");
        }

        if (!string.IsNullOrEmpty(extraHeaders))
        {
            builder.Append(extraHeaders);
        }

        builder.Append("\r\n");
        await WriteRawAsync(stream, builder.ToString(), cancellationToken).ConfigureAwait(false);
        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async ValueTask WriteRawAsync(Stream stream, string text, CancellationToken cancellationToken)
    {
        try
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes(text), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            // 客户端可能已经离开。
        }
    }
}
