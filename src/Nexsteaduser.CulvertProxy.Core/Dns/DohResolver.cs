using System.Buffers;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;
using Nexsteaduser.CulvertProxy.Core.Net;
using Nexsteaduser.CulvertProxy.Core.Transport;

namespace Nexsteaduser.CulvertProxy.Core.Dns;

/// <summary>DoH 解析器：支持走代理、缓存、静态 hosts 与系统解析回退。</summary>
public sealed class DohResolver
{
    private const int MaxCacheEntries = 4096;
    private readonly LogHub _log;
    private readonly Func<string, int, CancellationToken, ValueTask<Tunnel>>? _proxyTunnel;
    private readonly ConcurrentDictionary<CacheKey, CacheEntry> _cache = new();
    private volatile DnsConfig _config;
    private volatile HostMapping[] _hostMappings = [];

    public DohResolver(
        LogHub log,
        DnsConfig config,
        Func<string, int, CancellationToken, ValueTask<Tunnel>>? proxyTunnel)
    {
        _log = log;
        _proxyTunnel = proxyTunnel;
        _config = Clone(config);
        _hostMappings = config.Hosts.ToArray();
    }

    public int CacheCount => _cache.Count;

    /// <summary>热更新 DNS 设置，清空旧缓存避免解析口径混用。</summary>
    public void Update(DnsConfig config)
    {
        _config = Clone(config);
        _hostMappings = config.Hosts.ToArray();

        _cache.Clear();
    }

    /// <summary>解析主机的全部地址，供直连拨号使用。</summary>
    public async ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        var cfg = _config;
        var normalized = Normalize(host);
        if (IPAddress.TryParse(normalized, out var literal))
        {
            return [literal];
        }

        var mapping = FindHostMapping(normalized);
        if (mapping is not null && IPAddress.TryParse(mapping, out var mapped))
        {
            return [mapped];
        }

        if (cfg.Mode == DnsResolutionMode.System)
        {
            return await ResolveSystemAsync(normalized, cancellationToken).ConfigureAwait(false);
        }

        var aTask = QueryAsync(host, DnsWire.TypeA, cancellationToken).AsTask();
        var aaaaTask = QueryAsync(host, DnsWire.TypeAaaa, cancellationToken).AsTask();
        var answers = await Task.WhenAll(aTask, aaaaTask).ConfigureAwait(false);
        var addresses = answers
            .Where(x => x.IsSuccess)
            .SelectMany(x => x.Addresses)
            .Distinct()
            .ToArray();
        if (addresses.Length > 0)
        {
            return addresses;
        }

        var error = answers.Select(x => x.Error).FirstOrDefault(x => x is not null);
        throw new SocketException((int)SocketError.HostNotFound, error ?? $"无法解析 {host}。");
    }

    /// <summary>单类型查询，供本地 DNS 服务直接返回。</summary>
    public async ValueTask<DnsResolution> QueryAsync(string host, ushort qtype, CancellationToken cancellationToken)
    {
        var cfg = _config;
        var normalized = Normalize(host);
        if (normalized.Length == 0)
        {
            return DnsResolution.Failure("空域名。", 1);
        }

        if (qtype is not (DnsWire.TypeA or DnsWire.TypeAaaa))
        {
            return new DnsResolution(true, [], 60, 0, null);
        }

        if (IPAddress.TryParse(normalized, out var literal))
        {
            var matches = (qtype == DnsWire.TypeA && literal.AddressFamily == AddressFamily.InterNetwork)
                || (qtype == DnsWire.TypeAaaa && literal.AddressFamily == AddressFamily.InterNetworkV6);
            return new DnsResolution(true, matches ? [literal] : [], 3600, 0, null);
        }

        var mapping = FindHostMapping(normalized);
        if (mapping is not null && IPAddress.TryParse(mapping, out var mapped))
        {
            var matches = (qtype == DnsWire.TypeA && mapped.AddressFamily == AddressFamily.InterNetwork)
                || (qtype == DnsWire.TypeAaaa && mapped.AddressFamily == AddressFamily.InterNetworkV6);
            return new DnsResolution(true, matches ? [mapped] : [], 300, 0, null);
        }

        var key = new CacheKey(normalized, qtype);
        if (_cache.TryGetValue(key, out var cached) && cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return cached.Result;
        }

        DnsResolution result;
        try
        {
            result = cfg.Mode == DnsResolutionMode.System
                ? await QuerySystemAsync(normalized, qtype, cfg, cancellationToken).ConfigureAwait(false)
                : await ExchangeDohAsync(normalized, qtype, cfg, cancellationToken).ConfigureAwait(false);

            if (!result.IsSuccess && cfg.Mode == DnsResolutionMode.DnsOverHttps && cfg.SystemFallback)
            {
                _log.Warn("DNS", $"{normalized} 的 DoH 查询失败（{result.Error}），回退系统解析。");
                result = await QuerySystemAsync(normalized, qtype, cfg, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.Warn("DNS", $"{normalized} 解析异常：{ex.Message}");
            if (cfg.SystemFallback && cfg.Mode == DnsResolutionMode.DnsOverHttps)
            {
                try
                {
                    result = await QuerySystemAsync(normalized, qtype, cfg, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception fallbackError)
                {
                    result = DnsResolution.Failure(fallbackError.Message);
                }
            }
            else
            {
                result = DnsResolution.Failure(ex.Message);
            }
        }

        Cache(key, result, cfg);
        return result;
    }

    /// <summary>判断是否应当绕过 fake-IP（本地名称与局域网后缀）。</summary>
    public static bool IsLocalName(string host)
    {
        var value = host.Trim().TrimEnd('.');
        return value.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || value.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            || value.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
            || value.EndsWith(".lan", StringComparison.OrdinalIgnoreCase)
            || value.EndsWith(".home.arpa", StringComparison.OrdinalIgnoreCase)
            || value.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
            || !value.Contains('.');
    }

    private async ValueTask<DnsResolution> ExchangeDohAsync(string host, ushort qtype, DnsConfig cfg, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(cfg.DohUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            return DnsResolution.Failure("DoH 地址必须是 https URL。", 2);
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(cfg.QueryTimeoutMs);
        var token = timeoutCts.Token;

        var port = uri.IsDefaultPort ? 443 : uri.Port;
        var query = DnsWire.BuildQuery(host, qtype, (ushort)Random.Shared.Next(0, ushort.MaxValue + 1));

        Tunnel? tunnel = null;
        try
        {
            tunnel = cfg.DohThroughProxy && _proxyTunnel is not null
                ? await _proxyTunnel(uri.Host, port, token).ConfigureAwait(false)
                : await OpenDirectTunnelAsync(uri.Host, port, token).ConfigureAwait(false);

            await using var ssl = new SslStream(tunnel.Stream, leaveInnerStreamOpen: false);
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = uri.Host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            };
            await ssl.AuthenticateAsClientAsync(sslOptions, token).ConfigureAwait(false);

            var path = string.IsNullOrEmpty(uri.PathAndQuery) ? "/dns-query" : uri.PathAndQuery;
            var requestHead = new StringBuilder(256)
                .Append("POST ").Append(path).Append(" HTTP/1.1\r\n")
                .Append("Host: ").Append(uri.Authority).Append("\r\n")
                .Append("Accept: application/dns-message\r\n")
                .Append("Content-Type: application/dns-message\r\n")
                .Append("Content-Length: ").Append(query.Length).Append("\r\n")
                .Append("User-Agent: CulvertProxy/1.0\r\n")
                .Append("Connection: close\r\n\r\n");
            await ssl.WriteAsync(Encoding.ASCII.GetBytes(requestHead.ToString()), token).ConfigureAwait(false);
            await ssl.WriteAsync(query, token).ConfigureAwait(false);

            var headerBlock = await HttpHeaderReader.ReadAsync(ssl, 32 * 1024, token).ConfigureAwait(false);
            var status = HttpHeaderReader.ParseStatusCode(headerBlock.Text);
            if (status != 200)
            {
                return DnsResolution.Failure($"DoH 服务返回 HTTP {status}。", 2);
            }

            if (HttpHeaderReader.FindHeaderValue(headerBlock.Text, "Transfer-Encoding")?.Contains("chunked", StringComparison.OrdinalIgnoreCase) == true)
            {
                return DnsResolution.Failure("DoH 服务使用了不支持的分块编码。", 2);
            }

            var lengthText = HttpHeaderReader.FindHeaderValue(headerBlock.Text, "Content-Length");
            if (!int.TryParse(lengthText, out var length) || length is < 12 or > 65535)
            {
                return DnsResolution.Failure("DoH 响应长度无效。", 2);
            }

            var body = await ReadExactBodyAsync(ssl, headerBlock.Leftover, length, token).ConfigureAwait(false);
            return DnsWire.ParseAnswer(body);
        }
        finally
        {
            if (tunnel is not null)
            {
                await tunnel.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async ValueTask<DnsResolution> QuerySystemAsync(string host, ushort qtype, DnsConfig cfg, CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(cfg.QueryTimeoutMs);
        var addresses = await System.Net.Dns.GetHostAddressesAsync(host, timeoutCts.Token).ConfigureAwait(false);
        var filtered = addresses
            .Where(a => qtype == DnsWire.TypeA ? a.AddressFamily == AddressFamily.InterNetwork : a.AddressFamily == AddressFamily.InterNetworkV6)
            .Distinct()
            .ToArray();
        return new DnsResolution(true, filtered, 60, 0, null);
    }

    private async ValueTask<IReadOnlyList<IPAddress>> ResolveSystemAsync(string host, CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_config.QueryTimeoutMs);
        return await System.Net.Dns.GetHostAddressesAsync(host, timeoutCts.Token).ConfigureAwait(false);
    }

    private async ValueTask<Tunnel> OpenDirectTunnelAsync(string host, int port, CancellationToken cancellationToken)
    {
        // DoH 端点解析只能借助系统 DNS，默认配置使用 IP 以避免自举。
        var addresses = IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        var socket = await SocketFactory.ConnectAnyAsync(addresses, port, TimeSpan.FromSeconds(8), null, cancellationToken).ConfigureAwait(false);
        return new Tunnel(new NetworkStream(socket, ownsSocket: true), socket, $"DoH 直连 {host}:{port}");
    }

    private static async ValueTask<byte[]> ReadExactBodyAsync(Stream stream, byte[] leftover, int length, CancellationToken cancellationToken)
    {
        var body = new byte[length];
        var copied = Math.Min(leftover.Length, length);
        leftover.AsSpan(0, copied).CopyTo(body);
        var offset = copied;
        var buffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            while (offset < length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(8192, length - offset)), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new IOException("DoH 响应体提前结束。");
                }

                buffer.AsSpan(0, read).CopyTo(body.AsSpan(offset));
                offset += read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return body;
    }

    private void Cache(CacheKey key, DnsResolution result, DnsConfig cfg)
    {
        if (_cache.Count > MaxCacheEntries)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var entry in _cache.Where(kv => kv.Value.ExpiresAt <= now).Take(512))
            {
                _cache.TryRemove(entry.Key, out _);
            }

            if (_cache.Count > MaxCacheEntries)
            {
                foreach (var stale in _cache.Keys.Take(512))
                {
                    _cache.TryRemove(stale, out _);
                }
            }
        }

        var ttl = result.IsSuccess
            ? Math.Clamp(result.TtlSeconds, 30, cfg.CacheMinutes * 60)
            : 20;
        _cache[key] = new CacheEntry(result, DateTimeOffset.UtcNow.AddSeconds(ttl));
    }

    private string? FindHostMapping(string host)
    {
        var mappings = _hostMappings;
        foreach (var mapping in mappings)
        {
            if (string.Equals(mapping.Host, host, StringComparison.OrdinalIgnoreCase))
            {
                return mapping.Address;
            }
        }

        return null;
    }

    private static string Normalize(string host)
    {
        var value = host.Trim().TrimEnd('.');
        if (value.Any(c => c > 127))
        {
            try
            {
                value = new IdnMapping().GetAscii(value);
            }
            catch
            {
                // 保留原值，让查询失败并回退。
            }
        }

        return value.ToLowerInvariant();
    }

    private static DnsConfig Clone(DnsConfig source) => new()
    {
        EnableServer = source.EnableServer,
        BindAddress = source.BindAddress,
        Port = source.Port,
        Mode = source.Mode,
        DohUrl = source.DohUrl,
        DohThroughProxy = source.DohThroughProxy,
        DohPolicyId = source.DohPolicyId,
        FakeIpEnabled = source.FakeIpEnabled,
        FakeIpRange = source.FakeIpRange,
        CacheMinutes = source.CacheMinutes,
        QueryTimeoutMs = source.QueryTimeoutMs,
        SystemFallback = source.SystemFallback,
        Hosts = source.Hosts.Select(h => new HostMapping { Host = h.Host, Address = h.Address }).ToList(),
    };

    private readonly record struct CacheKey(string Host, ushort Type);

    private readonly record struct CacheEntry(DnsResolution Result, DateTimeOffset ExpiresAt);
}
