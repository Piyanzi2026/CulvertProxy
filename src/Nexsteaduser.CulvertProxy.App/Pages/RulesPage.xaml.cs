using System.Collections.ObjectModel;
using Microsoft.UI;
using Windows.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Nexsteaduser.CulvertProxy.App.Dialogs;
using Nexsteaduser.CulvertProxy.App.Services;
using Nexsteaduser.CulvertProxy.Core.Configuration;

namespace Nexsteaduser.CulvertProxy.App.Pages;

public sealed partial class RulesPage : Page
{
    private static readonly SolidColorBrush DirectBrush = new(Color.FromArgb(255, 148, 163, 184));
    private static readonly SolidColorBrush ProxyBrush = new(Color.FromArgb(255, 45, 212, 191));
    private static readonly SolidColorBrush BlockBrush = new(Color.FromArgb(255, 248, 113, 113));
    private AppConfig _config = null!;

    public RulesPage()
    {
        InitializeComponent();
        Reload();
    }

    public ObservableCollection<RuleRow> Rules { get; } = [];

    protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        Reload();
    }

    private void Reload()
    {
        _config = ConfigCloner.Clone(App.Services.Config);
        Rules.Clear();
        var policies = _config.Policies.ToDictionary(policy => policy.Id, policy => policy.Name);
        for (var i = 0; i < _config.Rules.Count; i++)
        {
            Rules.Add(new RuleRow(
                _config.Rules[i],
                i > 0,
                i < _config.Rules.Count - 1,
                policies,
                DirectBrush,
                ProxyBrush,
                BlockBrush));
        }

        EmptyRules.Visibility = Rules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async Task PersistAsync(string message)
    {
        try
        {
            await App.Services.SaveConfigAsync(_config);
            Reload();
            StatusBar.Severity = InfoBarSeverity.Success;
            StatusBar.Message = message;
            StatusBar.IsOpen = true;
        }
        catch (Exception ex)
        {
            StatusBar.Severity = InfoBarSeverity.Error;
            StatusBar.Message = ex.Message;
            StatusBar.IsOpen = true;
        }
    }

    private async void AddRule_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new RuleDialog(null, _config.Policies) { XamlRoot = XamlRoot };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary || dialog.Result is null)
        {
            return;
        }

        _config.Rules.Add(dialog.Result);
        await PersistAsync($"已添加规则「{dialog.Result.Name}」。");
    }

    private async void EditRule_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow(sender) is not { } row)
        {
            return;
        }

        var index = _config.Rules.FindIndex(rule => rule.Id == row.Model.Id);
        if (index < 0)
        {
            return;
        }

        var dialog = new RuleDialog(_config.Rules[index], _config.Policies) { XamlRoot = XamlRoot };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary || dialog.Result is null)
        {
            return;
        }

        _config.Rules[index] = dialog.Result;
        await PersistAsync($"已更新规则「{dialog.Result.Name}」。");
    }

    private async void DeleteRule_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow(sender) is not { } row)
        {
            return;
        }

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "删除规则",
            Content = $"确定删除「{row.Name}」吗？",
            PrimaryButtonText = "删除",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        _config.Rules.RemoveAll(rule => rule.Id == row.Model.Id);
        await PersistAsync($"已删除规则「{row.Name}」。");
    }

    private async void RuleEnabled_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox checkBox || checkBox.DataContext is not RuleRow row)
        {
            return;
        }

        var enabled = checkBox.IsChecked == true;
        if (enabled == row.Model.Enabled)
        {
            return;
        }

        var rule = _config.Rules.FirstOrDefault(item => item.Id == row.Model.Id);
        if (rule is null)
        {
            return;
        }

        rule.Enabled = enabled;
        await PersistAsync(enabled ? $"已启用「{rule.Name}」。" : $"已禁用「{rule.Name}」。");
    }

    private async void MoveUp_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow(sender) is not { } row)
        {
            return;
        }

        var index = _config.Rules.FindIndex(rule => rule.Id == row.Model.Id);
        if (index <= 0)
        {
            return;
        }

        (_config.Rules[index - 1], _config.Rules[index]) = (_config.Rules[index], _config.Rules[index - 1]);
        await PersistAsync("规则顺序已更新。");
    }

    private async void MoveDown_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow(sender) is not { } row)
        {
            return;
        }

        var index = _config.Rules.FindIndex(rule => rule.Id == row.Model.Id);
        if (index < 0 || index >= _config.Rules.Count - 1)
        {
            return;
        }

        (_config.Rules[index + 1], _config.Rules[index]) = (_config.Rules[index], _config.Rules[index + 1]);
        await PersistAsync("规则顺序已更新。");
    }

    private static RuleRow? GetRow(object sender) =>
        (sender as FrameworkElement)?.DataContext as RuleRow;
}

/// <summary>规则列表行。</summary>
public sealed class RuleRow
{
    public RuleRow(
        RoutingRule model,
        bool canMoveUp,
        bool canMoveDown,
        IReadOnlyDictionary<string, string> policies,
        Brush directBrush,
        Brush proxyBrush,
        Brush blockBrush)
    {
        Model = model;
        CanMoveUp = canMoveUp;
        CanMoveDown = canMoveDown;
        ActionBrush = model.Action switch
        {
            RuleAction.Proxy => proxyBrush,
            RuleAction.Block => blockBrush,
            _ => directBrush,
        };
        ActionText = model.Action switch
        {
            RuleAction.Proxy => "走代理",
            RuleAction.Block => "阻断",
            _ => "直通",
        };
        PolicyText = model.Action != RuleAction.Proxy
            ? "不经过上游"
            : model.PolicyId is { } id && policies.TryGetValue(id, out var name)
                ? $"策略：{name}"
                : "策略：使用默认";

        var conditions = new List<string>();
        if (model.Processes.Count > 0)
        {
            conditions.Add($"{model.Processes.Count} 个进程");
        }

        if (model.Hosts.Count > 0)
        {
            conditions.Add($"{model.Hosts.Count} 个域名");
        }

        if (model.IpRanges.Count > 0)
        {
            conditions.Add($"{model.IpRanges.Count} 个 IP 段");
        }

        if (model.Ports.Count > 0)
        {
            conditions.Add($"端口 {string.Join(",", model.Ports)}");
        }

        if (model.Transports.Count == 1)
        {
            conditions.Add(model.Transports[0] == RuleTransport.Tcp ? "仅 TCP" : "仅 UDP");
        }

        ConditionText = conditions.Count == 0 ? "任意目标" : string.Join(" · ", conditions);
    }

    public RoutingRule Model { get; }

    public string Name => Model.Name;

    public bool Enabled => Model.Enabled;

    public string ActionText { get; }

    public Brush ActionBrush { get; }

    public string PolicyText { get; }

    public string ConditionText { get; }

    public bool CanMoveUp { get; }

    public bool CanMoveDown { get; }
}
