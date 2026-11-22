using System.Diagnostics;
using System.Net;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;
using Nexsteaduser.CulvertProxy.Core.Net;
using Nexsteaduser.CulvertProxy.Core.Transport;

namespace Nexsteaduser.CulvertProxy.Core.Routing;

/// <summary>把路由决策落到实际链路，失败时按策略切换并记录健康度。</summary>
public sealed class OutboundConnector
{
    private readonly LogHub _log;
    private readonly RouteTable _routes;
    private readonly TunnelFactory _tunnels;

    public OutboundConnector(LogHub log, RouteTable routes, TunnelFactory tunnels)
    {
        _log = log;
        _routes = routes;
        _tunnels = tunnels;
    }

    public async ValueTask<Tunnel> ConnectAsync(
        RouteDecision decision,
        ProxyTarget target,
        TimeSpan connectTimeout,
        TimeSpan handshakeTimeout,
        IPAddress? bindAddress,
        int maxAttempts,
        CancellationToken cancellationToken)
    {
        switch (decision.Action)
        {
            case RuleAction.Block:
                throw new ConnectionBlockedException(target);
            case RuleAction.Direct:
                return await _tunnels.OpenDirectAsync(target, connectTimeout, bindAddress, cancellationToken).ConfigureAwait(false);
        }

        if (string.IsNullOrEmpty(decision.PolicyId))
        {
            throw new ProxyUnavailableException($"规则「{decision.RuleName}」要求走代理，但没有配置可用策略。");
        }

        var policy = _routes.GetPolicy(decision.PolicyId);
        if (policy is null)
        {
            throw new ProxyUnavailableException($"规则「{decision.RuleName}」引用的策略不存在或已禁用。");
        }

        var candidates = _routes.BuildCandidates(policy, target);
        if (candidates.Count == 0)
        {
            // 显式代理决策失败关闭。静默直连会在高审查网络中暴露真实地址。
            throw new ProxyUnavailableException($"策略「{policy.Name}」没有可用链路。");
        }

        var attempts = Math.Clamp(maxAttempts, 1, candidates.Count);
        Exception? lastError = null;
        for (var i = 0; i < attempts; i++)
        {
            var chain = candidates[i];
            var stopwatch = Stopwatch.StartNew();
            try
            {
                var tunnel = await _tunnels.OpenAsync(
                    chain.Hops,
                    target,
                    connectTimeout,
                    handshakeTimeout,
                    bindAddress,
                    cancellationToken,
                    policy.Name).ConfigureAwait(false);
                stopwatch.Stop();
                foreach (var hop in chain.Hops)
                {
                    _routes.ReportSuccess(hop.Id, stopwatch.Elapsed.TotalMilliseconds);
                }

                _log.Debug("Routing", $"{target} → {tunnel.Description}");
                return tunnel;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                if (ex is ChainConnectException chainError)
                {
                    _routes.ReportFailure(chainError.Endpoint.Id, chainError.InnerException?.Message ?? ex.Message);
                }
                else
                {
                    _routes.ReportFailure(chain.Hops[0].Id, ex.Message);
                }

                _log.Warn("Routing", $"链路「{chain.Description}」连接 {target} 失败：{ex.Message}");
                lastError = ex;
            }
        }

        throw new ProxyConnectException($"策略「{policy.Name}」的 {attempts} 条链路均连接失败。", lastError);
    }
}
