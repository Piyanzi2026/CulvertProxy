using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nexsteaduser.CulvertProxy.Core.Configuration;

namespace Nexsteaduser.CulvertProxy.Core.Protocols;

/// <summary>为上游链路套 TLS，充当混淆层、SNI 伪装或穿越强制 TLS 检查的环境。</summary>
public static class TlsStreamFactory
{
    /// <summary>用端点配置建立客户端 TLS，支持独立 SNI、宽松证书与证书指纹固定。</summary>
    public static async ValueTask<SslStream> WrapAsync(Stream inner, ProxyEndpoint endpoint, CancellationToken cancellationToken)
    {
        var sniHost = string.IsNullOrWhiteSpace(endpoint.TlsServerName) ? endpoint.Host : endpoint.TlsServerName.Trim();
        var pin = ParsePin(endpoint);
        var ssl = new SslStream(
            inner,
            leaveInnerStreamOpen: false,
            (_, certificate, _, errors) => Validate(endpoint, pin, certificate, errors));

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = sniHost,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            AllowRenegotiation = false,
        };

        try
        {
            await ssl.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        return ssl;
    }

    /// <summary>解析 64 位十六进制指纹；配置非法时拒绝连接而不是静默跳过。</summary>
    private static byte[]? ParsePin(ProxyEndpoint endpoint)
    {
        var text = endpoint.PinnedCertSha256;
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var normalized = text.Replace(":", string.Empty, StringComparison.Ordinal).Trim();
        if (normalized.Length != 64)
        {
            throw new ProxyHandshakeException("上游证书指纹必须是 64 位十六进制字符串。");
        }

        try
        {
            return Convert.FromHexString(normalized);
        }
        catch (FormatException ex)
        {
            throw new ProxyHandshakeException("上游证书指纹包含非法字符。", 0, ex);
        }
    }

    /// <summary>指纹优先；未配置指纹时沿用系统信任链或“允许不受信任证书”。</summary>
    private static bool Validate(
        ProxyEndpoint endpoint,
        byte[]? pin,
        X509Certificate? certificate,
        SslPolicyErrors errors)
    {
        if (pin is null)
        {
            return endpoint.AllowInsecureTls || errors == SslPolicyErrors.None;
        }

        if (certificate is null)
        {
            return false;
        }

        var actual = SHA256.HashData(certificate.GetRawCertData());
        return CryptographicOperations.FixedTimeEquals(actual, pin);
    }
}
