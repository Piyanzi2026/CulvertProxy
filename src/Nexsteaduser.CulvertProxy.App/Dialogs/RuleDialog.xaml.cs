using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Routing;

namespace Nexsteaduser.CulvertProxy.App.Dialogs;

/// <summary>新增或编辑单条路由规则。</summary>
public sealed partial class RuleDialog : ContentDialog
{
    private static readonly RuleAction[] Actions = [RuleAction.Direct, RuleAction.Proxy, RuleAction.Block];
    private static readonly string[] ActionNames = ["直通（不走代理）", "走代理", "阻断"];
    private readonly RoutingRule _source;

    public RuleDialog(RoutingRule? existing, IReadOnlyList<RoutePolicy> policies)
    {
        InitializeComponent();
        _source = existing ?? new RoutingRule { Name = "新规则", Action = RuleAction.Proxy };
        ActionBox.ItemsSource = ActionNames;
        ActionBox.SelectedIndex = Math.Max(0, Array.IndexOf(Actions, _source.Action));

        var options = new List<PolicyOption> { new("使用默认策略", null) };
        options.AddRange(policies.Select(policy => new PolicyOption(policy.Name, policy.Id)));
        PolicyBox.ItemsSource = options;
        PolicyBox.SelectedItem = options.FirstOrDefault(option => option.Id == _source.PolicyId) ?? options[0];
        PolicyBox.IsEnabled = _source.Action == RuleAction.Proxy;

        NameBox.Text = _source.Name;
        ProcessesBox.Text = string.Join(Environment.NewLine, _source.Processes);
        HostsBox.Text = string.Join(Environment.NewLine, _source.Hosts);
        IpsBox.Text = string.Join(Environment.NewLine, _source.IpRanges);
        PortsBox.Text = string.Join(Environment.NewLine, _source.Ports);
        TcpBox.IsChecked = _source.Transports.Count == 0 || _source.Transports.Contains(RuleTransport.Tcp);
        UdpBox.IsChecked = _source.Transports.Contains(RuleTransport.Udp);
        PrimaryButtonClick += OnPrimaryClick;
    }

    public RoutingRule? Result { get; private set; }

    private void ActionBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PolicyBox is not null)
        {
            PolicyBox.IsEnabled = ActionBox.SelectedIndex == 1;
        }
    }

    private void OnPrimaryClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        ErrorText.Text = string.Empty;
        var name = NameBox.Text.Trim();
        if (name.Length == 0)
        {
            name = $"规则 {DateTime.Now:HHmmss}";
        }

        var action = Actions[Math.Max(0, ActionBox.SelectedIndex)];
        var policyId = (PolicyBox.SelectedItem as PolicyOption)?.Id;
        var tcp = TcpBox.IsChecked == true;
        var udp = UdpBox.IsChecked == true;
        List<RuleTransport> transports = tcp == udp ? [] : tcp ? [RuleTransport.Tcp] : [RuleTransport.Udp];
        var hosts = Split(HostsBox.Text);
        var cidrs = Split(IpsBox.Text);
        var ports = Split(PortsBox.Text);

        foreach (var host in hosts)
        {
            if (!HostPattern.TryCreate(host, out _, out var error))
            {
                args.Cancel = true;
                ErrorText.Text = $"域名模式「{host}」无效：{error}";
                return;
            }
        }

        foreach (var cidr in cidrs)
        {
            if (!CidrRange.TryParse(cidr, out _))
            {
                args.Cancel = true;
                ErrorText.Text = $"IP 段「{cidr}」无效，请使用 CIDR，例如 10.0.0.0/8。";
                return;
            }
        }

        if (ports.Count > 0 && !PortSet.TryCreate(ports, out _, out var portError))
        {
            args.Cancel = true;
            ErrorText.Text = $"端口设置无效：{portError}";
            return;
        }

        Result = new RoutingRule
        {
            Id = _source.Id,
            Name = name,
            Enabled = _source.Enabled,
            Action = action,
            PolicyId = action == RuleAction.Proxy ? policyId : null,
            Processes = Split(ProcessesBox.Text),
            Hosts = hosts,
            IpRanges = cidrs,
            Ports = ports,
            Transports = transports,
        };
    }

    private static List<string> Split(string text) =>
        text.Split(['\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private sealed record PolicyOption(string Name, string? Id);
}
