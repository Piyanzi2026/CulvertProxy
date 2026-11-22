using System.Text.Json;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;

namespace Nexsteaduser.CulvertProxy.Core.Configuration;

/// <summary>负责配置的读写、损坏恢复与结构归一化。</summary>
public sealed class ConfigStore
{
    private readonly string _path;
    private readonly LogHub _log;

    public ConfigStore(LogHub log, string? path = null)
    {
        _log = log;
        _path = path ?? AppPaths.ConfigFile;
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
    }

    public string FilePath => _path;

    public string? LastLoadError { get; private set; }

    /// <summary>加载配置；文件不存在或损坏时返回可用默认值。</summary>
    public AppConfig Load()
    {
        LastLoadError = null;
        if (!File.Exists(_path))
        {
            var fresh = AppConfig.CreateDefault();
            Normalize(fresh);
            return fresh;
        }

        try
        {
            var json = File.ReadAllText(_path);
            var config = JsonSerializer.Deserialize(json, ConfigJsonContext.Default.AppConfig);
            if (config is null)
            {
                throw new JsonException("配置反序列化结果为空。");
            }

            Normalize(config);
            return config;
        }
        catch (Exception ex)
        {
            LastLoadError = ex.Message;
            _log.Error("Config", $"配置文件无法读取：{ex.Message}", ex);
            TryPreserveCorruptFile();
            var fallback = AppConfig.CreateDefault();
            Normalize(fallback);
            return fallback;
        }
    }

    /// <summary>原子写入配置，避免中途崩溃留下半截文件。</summary>
    public void Save(AppConfig config)
    {
        Normalize(config);
        var json = JsonSerializer.Serialize(config, ConfigJsonContext.Default.AppConfig);
        var temp = _path + ".tmp";
        File.WriteAllText(temp, json);
        File.Move(temp, _path, overwrite: true);
    }

    /// <summary>修复重复 Id、悬空引用与越界端口，保证运行期不再做空值防御。</summary>
    public static void Normalize(AppConfig config)
    {
        config.Listener ??= new ListenerConfig();
        config.Dns ??= new DnsConfig();
        config.Interception ??= new InterceptionConfig();
        config.Engine ??= new EngineSettings();
        config.Ui ??= new UiSettings();
        config.Endpoints ??= [];
        config.Policies ??= [];
        config.Rules ??= [];
        config.Dns.Hosts ??= [];
        config.Interception.ExcludeProcesses ??= [];

        config.Engine.ConnectTimeoutMs = Math.Clamp(config.Engine.ConnectTimeoutMs, 500, 120_000);
        config.Engine.HandshakeTimeoutMs = Math.Clamp(config.Engine.HandshakeTimeoutMs, 500, 120_000);
        config.Engine.MaxRouteAttempts = Math.Clamp(config.Engine.MaxRouteAttempts, 1, 16);
        config.Engine.ConnectionHistoryLimit = Math.Clamp(config.Engine.ConnectionHistoryLimit, 20, 5000);
        config.Ui.ChartWindowSeconds = Math.Clamp(config.Ui.ChartWindowSeconds, 20, 600);
        config.Dns.QueryTimeoutMs = Math.Clamp(config.Dns.QueryTimeoutMs, 500, 60_000);
        config.Dns.CacheMinutes = Math.Clamp(config.Dns.CacheMinutes, 1, 1440);
        var fakeBase = config.Dns.FakeIpRange.Split('/')[0].Trim();
        var fakePrefix = 32;
        var fakeSlash = config.Dns.FakeIpRange.IndexOf('/');
        if (fakeSlash >= 0)
        {
            _ = int.TryParse(config.Dns.FakeIpRange[(fakeSlash + 1)..].Trim(), out fakePrefix);
        }

        if (!System.Net.IPAddress.TryParse(fakeBase, out var fakeAddress)
            || fakeAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || fakePrefix is < 8 or > 30
            || fakeBase.StartsWith("198.19.", StringComparison.Ordinal))
        {
            // 198.19.0.0/16 由进程注入层使用，引擎 fake-IP 必须避开。
            config.Dns.FakeIpRange = "198.18.0.0/16";
        }

        config.Interception.ExcludeProcesses = (config.Interception.ExcludeProcesses ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Where(value => value.Length <= 260)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(256)
            .ToList();

        if (string.IsNullOrWhiteSpace(config.Listener.BindAddress))
        {
            config.Listener.BindAddress = "127.0.0.1";
        }

        if (string.IsNullOrWhiteSpace(config.Dns.BindAddress))
        {
            config.Dns.BindAddress = "127.0.0.1";
        }

        // 端口为 0 时视为未配置，回到默认端口。
        if (config.Listener.Port == 0)
        {
            config.Listener.Port = 1080;
        }

        if (config.Dns.Port == 0)
        {
            config.Dns.Port = 5353;
        }

        config.Listener.Port = Math.Clamp(config.Listener.Port, 1, 65535);
        config.Dns.Port = Math.Clamp(config.Dns.Port, 1, 65535);

        var usedEndpointIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var endpoint in config.Endpoints)
        {
            endpoint.Name = string.IsNullOrWhiteSpace(endpoint.Name) ? $"{endpoint.Host}:{endpoint.Port}" : endpoint.Name.Trim();
            endpoint.Host = endpoint.Host.Trim();
            endpoint.Port = Math.Clamp(endpoint.Port, 1, 65535);
            endpoint.PinnedCertSha256 = string.IsNullOrWhiteSpace(endpoint.PinnedCertSha256)
                ? null
                : endpoint.PinnedCertSha256.Replace(":", string.Empty, StringComparison.Ordinal).Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(endpoint.Id) || !usedEndpointIds.Add(endpoint.Id))
            {
                endpoint.Id = Guid.NewGuid().ToString("N");
                usedEndpointIds.Add(endpoint.Id);
            }
        }

        var endpointIds = config.Endpoints.Select(e => e.Id).ToHashSet(StringComparer.Ordinal);
        var usedPolicyIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var policy in config.Policies)
        {
            if (string.IsNullOrEmpty(policy.Id) || !usedPolicyIds.Add(policy.Id))
            {
                policy.Id = Guid.NewGuid().ToString("N");
                usedPolicyIds.Add(policy.Id);
            }

            if (string.IsNullOrWhiteSpace(policy.Name))
            {
                policy.Name = "未命名策略";
            }

            foreach (var chain in policy.Chains)
            {
                chain.EndpointIds = chain.EndpointIds.Where(endpointIds.Contains).Distinct(StringComparer.Ordinal).ToList();
            }

            policy.Chains.RemoveAll(c => c.EndpointIds.Count == 0 || c.EndpointIds.Count > 8);
        }

        // 有可用服务器但没有任何策略时自动建立默认策略。
        if (config.Policies.Count == 0 && config.Endpoints.Count > 0)
        {
            var endpointChains = config.Endpoints
                .Where(e => e.Enabled)
                .Select(e => new ProxyChainSpec { EndpointIds = [e.Id] })
                .ToList();
            if (endpointChains.Count > 0)
            {
                var policy = new RoutePolicy
                {
                    Name = "默认代理",
                    Mode = RoutePolicyMode.Latency,
                    Chains = endpointChains,
                };
                config.Policies.Add(policy);
            }
        }

        var validPolicyIds = config.Policies.Where(p => p.Enabled).Select(p => p.Id).ToHashSet(StringComparer.Ordinal);
        if (config.Engine.DefaultPolicyId is null || !validPolicyIds.Contains(config.Engine.DefaultPolicyId))
        {
            config.Engine.DefaultPolicyId = config.Policies.FirstOrDefault(p => p.Enabled)?.Id;
        }

        foreach (var rule in config.Rules)
        {
            if (string.IsNullOrWhiteSpace(rule.Name))
            {
                rule.Name = "未命名规则";
            }

            if (rule.Action == RuleAction.Proxy && (rule.PolicyId is null || !validPolicyIds.Contains(rule.PolicyId)))
            {
                rule.PolicyId = config.Engine.DefaultPolicyId;
            }

            rule.Ports = rule.Ports.Where(p => !string.IsNullOrWhiteSpace(p)).ToList();
            rule.Hosts = rule.Hosts.Where(h => !string.IsNullOrWhiteSpace(h)).ToList();
            rule.IpRanges = rule.IpRanges.Where(r => !string.IsNullOrWhiteSpace(r)).ToList();
            rule.Processes = rule.Processes.Where(p => !string.IsNullOrWhiteSpace(p)).ToList();
        }

        config.Dns.Hosts.RemoveAll(h => string.IsNullOrWhiteSpace(h.Host) || string.IsNullOrWhiteSpace(h.Address));
    }

    private void TryPreserveCorruptFile()
    {
        try
        {
            var backup = Path.Combine(
                Path.GetDirectoryName(_path)!,
                $"config.corrupt-{DateTime.Now:yyyyMMdd-HHmmss}.json");
            File.Move(_path, backup, overwrite: true);
            _log.Warn("Config", $"已保留损坏配置副本：{backup}");
        }
        catch
        {
            // 保留失败时继续使用默认配置。
        }
    }
}
