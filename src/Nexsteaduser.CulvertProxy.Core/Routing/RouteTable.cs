using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Net;

namespace Nexsteaduser.CulvertProxy.Core.Routing;

/// <summary>一条可尝试的链路。</summary>
public sealed record ResolvedChain(IReadOnlyList<ProxyEndpoint> Hops)
{
    public string Description => string.Join(" → ", Hops.Select(h => h.Name));
}

/// <summary>健康快照，供界面展示。</summary>
public sealed record EndpointHealthSnapshot(
    string EndpointId,
    string Name,
    double LatencyMs,
    int ConsecutiveFailures,
    bool IsBlocked,
    DateTimeOffset? BlockedUntil,
    string? LastError);

/// <summary>保存运行期服务器/策略副本与健康度，负责生成候选链路。</summary>
public sealed class RouteTable
{
    private readonly object _healthLock = new();
    private readonly Dictionary<string, HealthState> _health = new(StringComparer.Ordinal);
    private volatile Snapshot _snapshot = new(new Dictionary<string, ProxyEndpoint>(), new Dictionary<string, RoutePolicy>());

    /// <summary>用配置构建运行期快照，避免界面修改配置时影响正在处理的连接。</summary>
    public void Update(AppConfig config)
    {
        var endpoints = new Dictionary<string, ProxyEndpoint>(StringComparer.Ordinal);
        foreach (var endpoint in config.Endpoints)
        {
            endpoints[endpoint.Id] = Clone(endpoint);
        }

        var policies = new Dictionary<string, RoutePolicy>(StringComparer.Ordinal);
        foreach (var policy in config.Policies)
        {
            policies[policy.Id] = new RoutePolicy
            {
                Id = policy.Id,
                Name = policy.Name,
                Enabled = policy.Enabled,
                Mode = policy.Mode,
                Chains = policy.Chains
                    .Select(chain => new ProxyChainSpec { EndpointIds = [.. chain.EndpointIds] })
                    .ToList(),
            };
        }

        _snapshot = new Snapshot(endpoints, policies);

        lock (_healthLock)
        {
            foreach (var stale in _health.Keys.Where(id => !endpoints.ContainsKey(id)).ToList())
            {
                _health.Remove(stale);
            }
        }
    }

    public RoutePolicy? GetPolicy(string? policyId)
    {
        var snapshot = _snapshot;
        return policyId is not null && snapshot.Policies.TryGetValue(policyId, out var policy) && policy.Enabled ? policy : null;
    }

    public ProxyEndpoint? GetEndpoint(string endpointId)
    {
        var snapshot = _snapshot;
        return snapshot.Endpoints.GetValueOrDefault(endpointId);
    }

    /// <summary>根据策略模式排序候选链路，屏蔽暂时熔断的服务器。</summary>
    public IReadOnlyList<ResolvedChain> BuildCandidates(RoutePolicy policy, ProxyTarget target)
    {
        var snapshot = _snapshot;
        var now = DateTimeOffset.UtcNow;
        var chains = new List<ResolvedChain>();
        foreach (var spec in policy.Chains)
        {
            var hops = new List<ProxyEndpoint>(spec.EndpointIds.Count);
            var valid = true;
            foreach (var id in spec.EndpointIds)
            {
                if (!snapshot.Endpoints.TryGetValue(id, out var endpoint) || !endpoint.Enabled)
                {
                    valid = false;
                    break;
                }

                hops.Add(endpoint);
            }

            if (valid && hops.Count > 0)
            {
                chains.Add(new ResolvedChain(hops));
            }
        }

        if (chains.Count <= 1)
        {
            return chains;
        }

        var healthy = new List<ResolvedChain>();
        var blocked = new List<ResolvedChain>();
        foreach (var chain in chains)
        {
            var isHealthy = chain.Hops.All(hop => !IsBlocked(hop.Id, now));
            (isHealthy ? healthy : blocked).Add(chain);
        }

        var pool = healthy.Count > 0 ? healthy : chains;
        switch (policy.Mode)
        {
            case RoutePolicyMode.Failover:
            {
                var ordered = healthy.Count > 0 ? healthy.Concat(blocked).ToList() : chains;
                return ordered;
            }
            case RoutePolicyMode.Latency:
                pool.Sort((left, right) => Score(left).CompareTo(Score(right)));
                break;
            case RoutePolicyMode.Random:
                Shuffle(pool);
                break;
            case RoutePolicyMode.Sticky:
            {
                if (pool.Count > 0)
                {
                    var hash = (uint)StringComparer.OrdinalIgnoreCase.GetHashCode(target.Host);
                    hash = hash * 31 + (uint)target.Port;
                    var start = (int)(hash % (uint)pool.Count);
                    var rotated = pool.Skip(start).Concat(pool.Take(start)).ToList();
                    pool = rotated;
                }

                break;
            }
        }

        if (healthy.Count > 0 && blocked.Count > 0)
        {
            pool.AddRange(blocked);
        }

        return pool;
    }

    public void ReportSuccess(string endpointId, double latencyMs)
    {
        lock (_healthLock)
        {
            var state = GetOrCreate(endpointId);
            state.EwmaMs = double.IsNaN(state.EwmaMs) ? latencyMs : (state.EwmaMs * 0.7) + (latencyMs * 0.3);
            state.ConsecutiveFailures = 0;
            state.BlockedUntil = default;
            state.LastError = null;
        }
    }

    public void ReportFailure(string endpointId, string error)
    {
        lock (_healthLock)
        {
            var state = GetOrCreate(endpointId);
            state.ConsecutiveFailures++;
            state.LastError = error;
            state.LastFailureAt = DateTimeOffset.UtcNow;
            if (state.ConsecutiveFailures >= 3)
            {
                state.BlockedUntil = DateTimeOffset.UtcNow.AddSeconds(30);
            }
        }
    }

    public IReadOnlyList<EndpointHealthSnapshot> SnapshotHealth()
    {
        var snapshot = _snapshot;
        lock (_healthLock)
        {
            return snapshot.Endpoints.Values
                .Select(endpoint =>
                {
                    var state = _health.GetValueOrDefault(endpoint.Id);
                    var blocked = state is not null && state.BlockedUntil > DateTimeOffset.UtcNow;
                    return new EndpointHealthSnapshot(
                        endpoint.Id,
                        endpoint.Name,
                        state is null || double.IsNaN(state.EwmaMs) ? -1 : Math.Round(state.EwmaMs, 1),
                        state?.ConsecutiveFailures ?? 0,
                        blocked,
                        blocked ? state!.BlockedUntil : null,
                        state?.LastError);
                })
                .OrderBy(x => x.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();
        }
    }

    private bool IsBlocked(string endpointId, DateTimeOffset now)
    {
        lock (_healthLock)
        {
            return _health.TryGetValue(endpointId, out var state) && state.BlockedUntil > now;
        }
    }

    private double Score(ResolvedChain chain)
    {
        lock (_healthLock)
        {
            var sum = 0d;
            foreach (var hop in chain.Hops)
            {
                var state = _health.GetValueOrDefault(hop.Id);
                sum += state is null || double.IsNaN(state.EwmaMs) ? 250d : state.EwmaMs;
            }

            return sum / chain.Hops.Count;
        }
    }

    private HealthState GetOrCreate(string endpointId)
    {
        if (!_health.TryGetValue(endpointId, out var state))
        {
            state = new HealthState();
            _health[endpointId] = state;
        }

        return state;
    }

    private static void Shuffle<T>(IList<T> list)
    {
        for (var i = list.Count - 1; i > 0; i--)
        {
            var j = Random.Shared.Next(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
    }

    private static ProxyEndpoint Clone(ProxyEndpoint source) => new()
    {
        Id = source.Id,
        Name = source.Name,
        Protocol = source.Protocol,
        Host = source.Host,
        Port = source.Port,
        Username = source.Username,
        Password = source.Password,
        UseTls = source.UseTls,
        TlsServerName = source.TlsServerName,
        AllowInsecureTls = source.AllowInsecureTls,
        PinnedCertSha256 = source.PinnedCertSha256,
        Enabled = source.Enabled,
        Note = source.Note,
    };

    private sealed class HealthState
    {
        public double EwmaMs = double.NaN;
        public int ConsecutiveFailures;
        public DateTimeOffset BlockedUntil;
        public DateTimeOffset LastFailureAt;
        public string? LastError;
    }

    private sealed record Snapshot(
        IReadOnlyDictionary<string, ProxyEndpoint> Endpoints,
        IReadOnlyDictionary<string, RoutePolicy> Policies);
}
