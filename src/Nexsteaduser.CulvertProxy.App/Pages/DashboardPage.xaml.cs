using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Nexsteaduser.CulvertProxy.Core.Engine;

namespace Nexsteaduser.CulvertProxy.App.Pages;

public sealed partial class DashboardPage : Page
{
    private bool _syncingToggle;

    public DashboardPage()
    {
        ViewModel = new DashboardViewModel(App.Services);
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        ViewModel.SamplesUpdated += OnSamplesUpdated;
    }

    public DashboardViewModel ViewModel { get; }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ViewModel.Refresh();
        ViewModel.Start();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e) => ViewModel.Stop();

    private void OnSamplesUpdated(IReadOnlyList<RateSample> samples) => Chart.SetSamples(samples);

    private async void Toggle_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.ToggleAsync();
        _syncingToggle = true;
        SystemProxyToggle.IsOn = ViewModel.SystemProxyEnabled;
        _syncingToggle = false;
    }

    private async void SystemProxy_Toggled(object sender, RoutedEventArgs e)
    {
        if (_syncingToggle || sender is not ToggleSwitch toggle)
        {
            return;
        }

        if (toggle.IsOn == ViewModel.SystemProxyEnabled)
        {
            return;
        }

        await ViewModel.SetSystemProxyAsync(toggle.IsOn);
        _syncingToggle = true;
        toggle.IsOn = ViewModel.SystemProxyEnabled;
        _syncingToggle = false;
    }
}
