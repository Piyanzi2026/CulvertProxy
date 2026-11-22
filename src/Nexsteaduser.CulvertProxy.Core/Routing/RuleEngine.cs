using System.Collections.Concurrent;
using System.Net;
using System.Text.RegularExpressions;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;

namespace Nexsteaduser.CulvertProxy.Core.Routing;

/// <summary>编译并执行有序规则集，带命中缓存与进程维度匹配。</summary>
public sealed class RuleEngine
{
    private const int MaxCacheEntries = 8192;
    private readonly LogHub _log;
    private readonly ConcurrentDictionary<RuleCacheKey, CacheEntry> _cache = new();
    private volatile CompiledSet _set = new([], null, 0);

    public RuleEngine(LogHub log)
    {
        _log = log;
    }

    /// <summary>根据配置重建规则集并清空缓存。</summary>
    public void Update(AppConfig config)
    {
        var compiled = new List<CompiledRule>(config.Rules.Count);
        foreach (var rule in config.Rules)
        {
            if (!rule.Enabled)
            {
                continue;
            }

            var hosts = new List<HostPattern>();
            var ruleValid = true;
            foreach (var hostPattern in rule.Hosts)
            {
                if (!HostPattern.TryCreate(hostPattern, out var pattern, out var error))
                {
                    _log.Warn("Rules", $"规则「{rule.Name}」的域名模式已忽略：{error}");
                    ruleValid = false;
                    break;
                }

                hosts.Add(pattern!);
            }

            if (!ruleValid)
            {
                continue;
            }

            var cidrs = new List<CidrRange>();
            foreach (var cidrText in rule.IpRanges)
            {
                if (!CidrRange.TryParse(cidrText, out var cidr))
                {
                    _log.Warn("Rules", $"规则「{rule.Name}」的 IP 段无效：{cidrText}，整条规则已跳过。");
                    ruleValid = false;
                    break;
                }

                cidrs.Add(cidr);
            }

            if (!ruleValid)
            {
                continue;
            }

            PortSet? ports = null;
            if (rule.Ports.Count > 0)
            {
                if (!PortSet.TryCreate(rule.Ports, out ports, out var portError))
                {
                    _log.Warn("Rules", $"规则「{rule.Name}」的端口设置无效：{portError}，整条规则已跳过。");
                    continue;
                }
            }

            var processPatterns = new List<ProcessPattern>();
            foreach (var process in rule.Processes)
            {
                if (ProcessPattern.TryCreate(process, out var compiledProcess, out var processError))
                {
                    processPatterns.Add(compiledProcess!);
                }
                else
                {
                    _log.Warn("Rules", $"规则「{rule.Name}」的进程模式无效：{processError}，整条规则已跳过。");
                    ruleValid = false;
                    break;
                }
            }

            if (!ruleValid)
            {
                continue;
            }

            compiled.Add(new CompiledRule(
                rule.Name,
                rule.Action,
                rule.PolicyId,
                hosts.Count > 0 ? hosts.ToArray() : null,
                cidrs.Count > 0 ? cidrs.ToArray() : null,
                ports,
                rule.Transports.Count > 0 ? rule.Transports.ToHashSet() : null,
                processPatterns.Count > 0 ? processPatterns.ToArray() : null));
        }

        _set = new CompiledSet(compiled.ToArray(), config.Engine.DefaultPolicyId, unchecked(_set.Version + 1));
        _cache.Clear();
        _log.Info("Rules", $"规则集已加载：{compiled.Count} 条启用规则。");
    }

    /// <summary>按顺序返回首个命中的决策；无命中时走默认策略。</summary>
    public RouteDecision Resolve(in RouteRequest request)
    {
        var set = _set;
        var key = new RuleCacheKey(request.Host, request.Port, request.Transport, request.ProcessName, request.ProcessPath);
        if (_cache.TryGetValue(key, out var cached) && cached.Version == set.Version)
        {
            return cached.Decision;
        }

        foreach (var rule in set.Rules)
        {
            if (rule.Matches(request))
            {
                var hit = new RouteDecision(rule.Action, rule.PolicyId, rule.Name);
                Store(set, key, hit);
                return hit;
            }
        }

        var fallback = set.DefaultPolicyId is { Length: > 0 } policyId
            ? new RouteDecision(RuleAction.Proxy, policyId, "默认策略", true)
            : new RouteDecision(RuleAction.Direct, null, "默认直连", true);
        Store(set, key, fallback);
        return fallback;
    }

    private void Store(CompiledSet set, RuleCacheKey key, RouteDecision decision)
    {
        if (_cache.Count > MaxCacheEntries)
        {
            _cache.Clear();
        }

        _cache[key] = new CacheEntry(set.Version, decision);
    }

    private sealed class CompiledSet(CompiledRule[] rules, string? defaultPolicyId, int version)
    {
        public CompiledRule[] Rules { get; } = rules;
        public string? DefaultPolicyId { get; } = defaultPolicyId;
        public int Version { get; } = version;
    }

    private sealed class CompiledRule(
        string name,
        RuleAction action,
        string? policyId,
        HostPattern[]? hosts,
        CidrRange[]? cidrs,
        PortSet? ports,
        HashSet<RuleTransport>? transports,
        ProcessPattern[]? processes)
    {
        public string Name { get; } = name;
        public RuleAction Action { get; } = action;
        public string? PolicyId { get; } = policyId;

        public bool Matches(in RouteRequest request)
        {
            if (ports is not null && !ports.Contains(request.Port))
            {
                return false;
            }

            if (transports is not null && !transports.Contains(request.Transport))
            {
                return false;
            }

            if (processes is not null)
            {
                var matchedProcess = false;
                foreach (var pattern in processes)
                {
                    if (pattern.Matches(request.ProcessName) || pattern.Matches(request.ProcessPath))
                    {
                        matchedProcess = true;
                        break;
                    }
                }

                if (!matchedProcess)
                {
                    return false;
                }
            }

            if (cidrs is not null)
            {
                var address = request.Address;
                if (address is null && !IPAddress.TryParse(request.Host, out address))
                {
                    return false;
                }

                var matchedCidr = false;
                foreach (var cidr in cidrs)
                {
                    if (cidr.Contains(address))
                    {
                        matchedCidr = true;
                        break;
                    }
                }

                if (!matchedCidr)
                {
                    return false;
                }
            }

            if (hosts is not null)
            {
                var matchedHost = false;
                foreach (var pattern in hosts)
                {
                    if (pattern.IsMatch(request.Host))
                    {
                        matchedHost = true;
                        break;
                    }
                }

                if (!matchedHost)
                {
                    return false;
                }
            }

            return true;
        }
    }

    private sealed class ProcessPattern
    {
        private readonly Regex _regex;
        private readonly bool _pathPattern;

        private ProcessPattern(string source, Regex regex)
        {
            Source = source;
            _regex = regex;
            _pathPattern = source.Contains('\\') || source.Contains('/');
        }

        public string Source { get; }

        public static bool TryCreate(string source, out ProcessPattern? pattern, out string? error)
        {
            pattern = null;
            error = null;
            if (string.IsNullOrWhiteSpace(source))
            {
                error = "进程模式为空。";
                return false;
            }

            var text = source.Trim();
            var escaped = Regex.Escape(text).Replace("\\*", ".*", StringComparison.Ordinal).Replace("\\?", ".", StringComparison.Ordinal);
            try
            {
                var regex = new Regex($"^{escaped}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(80));
                pattern = new ProcessPattern(text, regex);
                return true;
            }
            catch (ArgumentException ex)
            {
                error = ex.Message;
                return false;
            }
        }

        public bool Matches(string? candidate)
        {
            if (string.IsNullOrEmpty(candidate))
            {
                return false;
            }

            if (_pathPattern)
            {
                return _regex.IsMatch(candidate);
            }

            var fileName = Path.GetFileName(candidate.Replace('/', '\\'));
            return _regex.IsMatch(candidate) || _regex.IsMatch(fileName);
        }
    }

    private readonly record struct RuleCacheKey(
        string Host,
        int Port,
        RuleTransport Transport,
        string? ProcessName,
        string? ProcessPath);

    private readonly record struct CacheEntry(int Version, RouteDecision Decision);
}
