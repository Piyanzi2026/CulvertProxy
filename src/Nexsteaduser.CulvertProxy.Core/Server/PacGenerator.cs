using Nexsteaduser.CulvertProxy.Core.Configuration;

namespace Nexsteaduser.CulvertProxy.Core.Server;

/// <summary>生成指向本地入口的 PAC 脚本。</summary>
public static class PacGenerator
{
    public static string Generate(AppConfig config)
    {
        var address = config.Listener.BindAddress is "0.0.0.0" or "::" ? "127.0.0.1" : config.Listener.BindAddress;
        var port = config.Listener.Port;
        return $$"""
function FindProxyForURL(url, host) {
    if (isPlainHostName(host)
        || shExpMatch(host, "*.local")
        || shExpMatch(host, "*.lan")
        || shExpMatch(host, "*.home.arpa")
        || shExpMatch(host, "*.internal")
        || host == "localhost") {
        return "DIRECT";
    }
    if (isInNet(host, "127.0.0.0", "255.0.0.0")
        || isInNet(host, "10.0.0.0", "255.0.0.0")
        || isInNet(host, "172.16.0.0", "255.240.0.0")
        || isInNet(host, "192.168.0.0", "255.255.0.0")
        || isInNet(host, "169.254.0.0", "255.255.0.0")) {
        return "DIRECT";
    }
    return "SOCKS5 {{address}}:{{port}}; PROXY {{address}}:{{port}}";
}
""";
    }
}
