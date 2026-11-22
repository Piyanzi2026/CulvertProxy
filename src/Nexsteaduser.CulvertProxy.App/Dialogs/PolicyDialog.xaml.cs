using Microsoft.UI.Xaml.Controls;
using Nexsteaduser.CulvertProxy.Core.Configuration;

namespace Nexsteaduser.CulvertProxy.App.Dialogs;

/// <summary>编辑策略与多跳链路，链路使用可读的箭头语法。</summary>
public sealed partial class PolicyDialog : ContentDialog
{
    private static readonly RoutePolicyMode[] Modes =
    [
        RoutePolicyMode.Failover,
        RoutePolicyMode.Latency,
        RoutePolicyMode.Random,
        RoutePolicyMode.Sticky,
    ];

    private static readonly string[] ModeNames = ["故障转移", "延迟优先", "随机", "固定目标"];
    private readonly RoutePolicy _source;
    private readonly IReadOnlyList<ProxyEndpoint> _endpoints;

    public PolicyDialog(RoutePolicy? existing, IReadOnlyList<ProxyEndpoint> endpoints, bool makeDefault)
    {
        InitializeComponent();
        _source = existing ?? new RoutePolicy { Name = "新策略" };
        _endpoints = endpoints;
        ModeBox.ItemsSource = ModeNames;
        ModeBox.SelectedIndex = Math.Max(0, Array.IndexOf(Modes, _source.Mode));
        NameBox.Text = _source.Name;
        DefaultBox.IsChecked = makeDefault;
        ChainsBox.Text = string.Join(Environment.NewLine, _source.Chains.Select(FormatChain));
        EndpointHint.Text = endpoints.Count == 0
            ? "尚未配置服务器，请先在「代理服务器」中添加。"
            : "可用服务器：" + string.Join("、", endpoints.Select(e => e.Name));
        PrimaryButtonClick += OnPrimaryClick;
    }

    public RoutePolicy? Result { get; private set; }

    public bool MakeDefault { get; private set; }

    private string FormatChain(ProxyChainSpec chain)
    {
        var names = new List<string>();
        foreach (var id in chain.EndpointIds)
        {
            names.Add(_endpoints.FirstOrDefault(e => e.Id == id)?.Name ?? id);
        }

        return string.Join(" -> ", names);
    }

    private void OnPrimaryClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        ErrorText.Text = string.Empty;
        var name = NameBox.Text.Trim();
        if (name.Length == 0)
        {
            args.Cancel = true;
            ErrorText.Text = "策略名称不能为空。";
            return;
        }

        var chains = new List<ProxyChainSpec>();
        foreach (var rawLine in ChainsBox.Text.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            var tokens = line.Split(["->", "→", ",", "，"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var ids = new List<string>();
            var failed = false;
            foreach (var token in tokens)
            {
                var match = _endpoints.FirstOrDefault(e => e.Id.Equals(token, StringComparison.Ordinal))
                    ?? _endpoints.FirstOrDefault(e => e.Name.Equals(token, StringComparison.OrdinalIgnoreCase));
                if (match is null)
                {
                    ErrorText.Text = $"无法识别服务器「{token}」。请使用服务器名称或 Id。";
                    failed = true;
                    break;
                }

                if (ids.Count == 0 || ids[^1] != match.Id)
                {
                    ids.Add(match.Id);
                }
            }

            if (failed)
            {
                args.Cancel = true;
                return;
            }

            if (ids.Count > 8)
            {
                args.Cancel = true;
                ErrorText.Text = $"单条链路最多 8 跳，当前是 {ids.Count} 跳。";
                return;
            }

            if (ids.Count > 0)
            {
                chains.Add(new ProxyChainSpec { EndpointIds = ids });
            }
        }

        if (chains.Count == 0)
        {
            args.Cancel = true;
            ErrorText.Text = "至少需要一条链路。";
            return;
        }

        Result = new RoutePolicy
        {
            Id = _source.Id,
            Name = name,
            Mode = Modes[Math.Max(0, ModeBox.SelectedIndex)],
            Enabled = _source.Enabled,
            Chains = chains,
        };
        MakeDefault = DefaultBox.IsChecked == true;
    }
}
