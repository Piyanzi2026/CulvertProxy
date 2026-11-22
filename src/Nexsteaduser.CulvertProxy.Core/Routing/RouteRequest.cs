using System.Net;
using Nexsteaduser.CulvertProxy.Core.Configuration;

namespace Nexsteaduser.CulvertProxy.Core.Routing;

/// <summary>一次路由判断的输入。</summary>
public readonly record struct RouteRequest(
    string Host,
    int Port,
    RuleTransport Transport,
    string? ProcessName = null,
    string? ProcessPath = null,
    IPAddress? Address = null);

/// <summary>路由判断的结果。</summary>
public readonly record struct RouteDecision(
    RuleAction Action,
    string? PolicyId,
    string RuleName,
    bool IsDefault = false);
