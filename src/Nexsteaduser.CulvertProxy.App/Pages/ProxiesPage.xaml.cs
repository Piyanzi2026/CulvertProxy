using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Nexsteaduser.CulvertProxy.App.Dialogs;
using Nexsteaduser.CulvertProxy.App.Services;
using Nexsteaduser.CulvertProxy.Core.Configuration;
using Nexsteaduser.CulvertProxy.Core.Net;

namespace Nexsteaduser.CulvertProxy.App.Pages;

public sealed partial class ProxiesPage : Page
{
    private AppConfig _config = null!;

    public ProxiesPage()
    {
        InitializeComponent();
        Reload();
    }

    public ObservableCollection<EndpointRow> Endpoints { get; } = [];

    public ObservableCollection<PolicyRow> Policies { get; } = [];

    protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        Reload();
    }

    private void Reload()
    {
        _config = ConfigCloner.Clone(App.Services.Config);
        Endpoints.Clear();
        foreach (var endpoint in _config.Endpoints)
        {
            Endpoints.Add(new EndpointRow(endpoint));
        }

        Policies.Clear();
        foreach (var policy in _config.Policies)
        {
            Policies.Add(new PolicyRow(policy, policy.Id == _config.Engine.DefaultPolicyId, _config.Endpoints));
        }

        EmptyEndpoints.Visibility = Endpoints.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        EmptyPolicies.Visibility = Policies.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
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

    private async Task<bool> ConfirmAsync(string title, string content)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = title,
            Content = content,
            PrimaryButtonText = "删除",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async void AddEndpoint_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new EndpointDialog(null) { XamlRoot = XamlRoot };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary || dialog.Result is null)
        {
            return;
        }

        _config.Endpoints.Add(dialog.Result);
        await PersistAsync($"已添加服务器「{dialog.Result.Name}」。");
    }

    private async void EditEndpoint_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow<EndpointRow>(sender) is not { } row)
        {
            return;
        }

        var index = _config.Endpoints.FindIndex(item => item.Id == row.Model.Id);
        if (index < 0)
        {
            return;
        }

        var dialog = new EndpointDialog(_config.Endpoints[index]) { XamlRoot = XamlRoot };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary || dialog.Result is null)
        {
            return;
        }

        _config.Endpoints[index] = dialog.Result;
        await PersistAsync($"已更新服务器「{dialog.Result.Name}」。");
    }

    private async void DeleteEndpoint_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow<EndpointRow>(sender) is not { } row)
        {
            return;
        }

        if (!await ConfirmAsync("删除服务器", $"确定删除「{row.Name}」吗？引用它的链路会一并清理。"))
        {
            return;
        }

        _config.Endpoints.RemoveAll(item => item.Id == row.Model.Id);
        foreach (var policy in _config.Policies)
        {
            foreach (var chain in policy.Chains)
            {
                chain.EndpointIds.RemoveAll(id => id == row.Model.Id);
            }

            policy.Chains.RemoveAll(chain => chain.EndpointIds.Count == 0);
        }

        _config.Policies.RemoveAll(policy => policy.Chains.Count == 0);
        if (_config.Engine.DefaultPolicyId is { } defaultId && _config.Policies.All(p => p.Id != defaultId))
        {
            _config.Engine.DefaultPolicyId = _config.Policies.FirstOrDefault(p => p.Enabled)?.Id;
        }

        await PersistAsync($"已删除服务器「{row.Name}」。");
    }

    private async void EndpointEnabled_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox checkBox || checkBox.DataContext is not EndpointRow row)
        {
            return;
        }

        var enabled = checkBox.IsChecked == true;
        if (enabled == row.Model.Enabled)
        {
            return;
        }

        var endpoint = _config.Endpoints.FirstOrDefault(item => item.Id == row.Model.Id);
        if (endpoint is null)
        {
            return;
        }

        endpoint.Enabled = enabled;
        await PersistAsync(enabled ? $"已启用「{endpoint.Name}」。" : $"已禁用「{endpoint.Name}」。");
    }

    private async void TestEndpoint_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow<EndpointRow>(sender) is not { } row)
        {
            return;
        }

        row.IsTesting = true;
        row.TestResult = "正在握手…";
        try
        {
            var result = await App.Services.Engine.TestEndpointAsync(row.Model.Id, new ProxyTarget("1.1.1.1", 443));
            row.TestResult = result.Success
                ? $"握手成功 · {result.ElapsedMs:F0} ms"
                : $"失败 · {result.Error}";
        }
        catch (Exception ex)
        {
            row.TestResult = $"失败 · {ex.Message}";
        }
        finally
        {
            row.IsTesting = false;
        }
    }

    private async void AddPolicy_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new PolicyDialog(null, _config.Endpoints, makeDefault: _config.Policies.Count == 0)
        {
            XamlRoot = XamlRoot,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary || dialog.Result is null)
        {
            return;
        }

        _config.Policies.Add(dialog.Result);
        if (dialog.MakeDefault || _config.Engine.DefaultPolicyId is null)
        {
            _config.Engine.DefaultPolicyId = dialog.Result.Id;
        }

        await PersistAsync($"已创建策略「{dialog.Result.Name}」。");
    }

    private async void EditPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow<PolicyRow>(sender) is not { } row)
        {
            return;
        }

        var index = _config.Policies.FindIndex(item => item.Id == row.Model.Id);
        if (index < 0)
        {
            return;
        }

        var isDefault = _config.Engine.DefaultPolicyId == row.Model.Id;
        var dialog = new PolicyDialog(_config.Policies[index], _config.Endpoints, isDefault) { XamlRoot = XamlRoot };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary || dialog.Result is null)
        {
            return;
        }

        _config.Policies[index] = dialog.Result;
        if (dialog.MakeDefault)
        {
            _config.Engine.DefaultPolicyId = dialog.Result.Id;
        }
        else if (_config.Engine.DefaultPolicyId == dialog.Result.Id)
        {
            _config.Engine.DefaultPolicyId = _config.Policies.FirstOrDefault(p => p.Enabled)?.Id;
        }

        await PersistAsync($"已更新策略「{dialog.Result.Name}」。");
    }

    private async void DeletePolicy_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow<PolicyRow>(sender) is not { } row)
        {
            return;
        }

        if (!await ConfirmAsync("删除策略", $"确定删除「{row.Name}」吗？引用它的规则会回退到默认策略。"))
        {
            return;
        }

        _config.Policies.RemoveAll(policy => policy.Id == row.Model.Id);
        if (_config.Engine.DefaultPolicyId == row.Model.Id)
        {
            _config.Engine.DefaultPolicyId = _config.Policies.FirstOrDefault(p => p.Enabled)?.Id;
        }

        await PersistAsync($"已删除策略「{row.Name}」。");
    }

    private async void PolicyEnabled_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox checkBox || checkBox.DataContext is not PolicyRow row)
        {
            return;
        }

        var enabled = checkBox.IsChecked == true;
        if (enabled == row.Model.Enabled)
        {
            return;
        }

        var policy = _config.Policies.FirstOrDefault(item => item.Id == row.Model.Id);
        if (policy is null)
        {
            return;
        }

        policy.Enabled = enabled;
        if (!enabled && _config.Engine.DefaultPolicyId == policy.Id)
        {
            _config.Engine.DefaultPolicyId = _config.Policies.FirstOrDefault(p => p.Enabled)?.Id;
        }

        await PersistAsync(enabled ? $"已启用策略「{policy.Name}」。" : $"已禁用策略「{policy.Name}」。");
    }

    private async void SetDefaultPolicy_Click(object sender, RoutedEventArgs e)
    {
        if (GetRow<PolicyRow>(sender) is not { } row)
        {
            return;
        }

        _config.Engine.DefaultPolicyId = row.Model.Id;
        await PersistAsync($"已将「{row.Name}」设为默认策略。");
    }

    private static T? GetRow<T>(object sender) where T : class =>
        (sender as FrameworkElement)?.DataContext as T;
}

/// <summary>服务器列表行。</summary>
public sealed partial class EndpointRow : ObservableObject
{
    [ObservableProperty] private string testResult = string.Empty;
    [ObservableProperty] private bool isTesting;

    public EndpointRow(ProxyEndpoint model)
    {
        Model = model;
    }

    public ProxyEndpoint Model { get; }

    public string Name => Model.Name;

    public string Endpoint => $"{Model.Host}:{Model.Port}";

    public string Protocol => Model.Protocol == ProxyProtocol.Socks5 ? "SOCKS5" : "HTTP";

    public string Detail
    {
        get
        {
            var parts = new List<string>();
            parts.Add(Model.Protocol == ProxyProtocol.Socks5 ? "SOCKS5 握手" : "HTTP CONNECT");
            parts.Add(string.IsNullOrEmpty(Model.Username) ? "无认证" : $"认证用户 {Model.Username}");
            if (Model.UseTls)
            {
                parts.Add(string.IsNullOrWhiteSpace(Model.TlsServerName) ? "TLS 包装" : $"TLS SNI {Model.TlsServerName}");
            }

            if (!string.IsNullOrWhiteSpace(Model.Note))
            {
                parts.Add(Model.Note);
            }

            return string.Join(" · ", parts);
        }
    }

    public bool Enabled => Model.Enabled;

    public bool IsNotTesting => !IsTesting;

    public string TestButtonText => IsTesting ? "测试中" : "测试";

    public Visibility TestVisibility => string.IsNullOrEmpty(TestResult) ? Visibility.Collapsed : Visibility.Visible;

    partial void OnIsTestingChanged(bool value)
    {
        OnPropertyChanged(nameof(IsNotTesting));
        OnPropertyChanged(nameof(TestButtonText));
    }

    partial void OnTestResultChanged(string value)
    {
        OnPropertyChanged(nameof(TestButtonText));
        OnPropertyChanged(nameof(TestVisibility));
    }
}

/// <summary>策略列表行。</summary>
public sealed class PolicyRow
{
    public PolicyRow(RoutePolicy model, bool isDefault, IReadOnlyList<ProxyEndpoint> endpoints)
    {
        Model = model;
        IsDefault = isDefault;
        var names = endpoints.ToDictionary(e => e.Id, e => e.Name);
        ChainsText = string.Join("   |   ", model.Chains.Select(chain =>
            string.Join(" -> ", chain.EndpointIds.Select(id => names.GetValueOrDefault(id, id)))));
    }

    public RoutePolicy Model { get; }

    public bool IsDefault { get; }

    public string Name => Model.Name;

    public bool Enabled => Model.Enabled;

    public string ModeText => Model.Mode switch
    {
        RoutePolicyMode.Failover => $"故障转移 · {Model.Chains.Count} 条链路",
        RoutePolicyMode.Latency => $"延迟优先 · {Model.Chains.Count} 条链路",
        RoutePolicyMode.Random => $"随机出口 · {Model.Chains.Count} 条链路",
        _ => $"目标固定 · {Model.Chains.Count} 条链路",
    };

    public string ChainsText { get; }

    public Visibility DefaultVisibility => IsDefault ? Visibility.Visible : Visibility.Collapsed;

    public bool IsNotDefault => !IsDefault;
}
