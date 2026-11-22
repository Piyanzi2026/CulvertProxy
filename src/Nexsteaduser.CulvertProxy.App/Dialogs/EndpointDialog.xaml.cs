using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Nexsteaduser.CulvertProxy.Core.Configuration;

namespace Nexsteaduser.CulvertProxy.App.Dialogs;

/// <summary>新增或编辑上游服务器。</summary>
public sealed partial class EndpointDialog : ContentDialog
{
    private readonly ProxyEndpoint _source;

    public EndpointDialog(ProxyEndpoint? existing)
    {
        InitializeComponent();
        _source = existing ?? new ProxyEndpoint();
        ProtocolBox.ItemsSource = new[] { "SOCKS5", "HTTP CONNECT" };
        ProtocolBox.SelectedIndex = _source.Protocol == ProxyProtocol.HttpConnect ? 1 : 0;
        NameBox.Text = _source.Name;
        HostBox.Text = _source.Host;
        PortBox.Value = _source.Port <= 0 ? 1080 : _source.Port;
        UsernameBox.Text = _source.Username ?? string.Empty;
        PasswordBox.PlaceholderText = string.IsNullOrEmpty(_source.Password) ? "无密码" : "留空表示保持原密码";
        ClearPasswordBox.Visibility = string.IsNullOrEmpty(_source.Password) ? Visibility.Collapsed : Visibility.Visible;
        TlsBox.IsChecked = _source.UseTls;
        SniBox.Text = _source.TlsServerName ?? string.Empty;
        InsecureBox.IsChecked = _source.AllowInsecureTls;
        PinBox.Text = _source.PinnedCertSha256 ?? string.Empty;
        EnabledBox.IsChecked = _source.Enabled;
        NoteBox.Text = _source.Note ?? string.Empty;
        PrimaryButtonClick += OnPrimaryClick;
    }

    public ProxyEndpoint? Result { get; private set; }

    private void OnPrimaryClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        ErrorText.Text = string.Empty;
        var host = HostBox.Text.Trim();
        if (host.Length == 0)
        {
            args.Cancel = true;
            ErrorText.Text = "主机不能为空。";
            return;
        }

        if (double.IsNaN(PortBox.Value) || PortBox.Value < 1 || PortBox.Value > 65535)
        {
            args.Cancel = true;
            ErrorText.Text = "端口必须在 1 到 65535 之间。";
            return;
        }

        var pin = PinBox.Text.Replace(":", string.Empty, StringComparison.Ordinal).Trim();
        if (pin.Length > 0 && (pin.Length != 64 || !pin.All(Uri.IsHexDigit)))
        {
            args.Cancel = true;
            ErrorText.Text = "证书指纹必须是 64 位十六进制字符，可带冒号分隔。";
            return;
        }

        var port = (int)PortBox.Value;
        var name = NameBox.Text.Trim();
        var result = new ProxyEndpoint
        {
            Id = _source.Id,
            Name = name.Length == 0 ? $"{host}:{port}" : name,
            Protocol = ProtocolBox.SelectedIndex == 1 ? ProxyProtocol.HttpConnect : ProxyProtocol.Socks5,
            Host = host,
            Port = port,
            Username = string.IsNullOrWhiteSpace(UsernameBox.Text) ? null : UsernameBox.Text.Trim(),
            UseTls = TlsBox.IsChecked == true,
            TlsServerName = string.IsNullOrWhiteSpace(SniBox.Text) ? null : SniBox.Text.Trim(),
            AllowInsecureTls = InsecureBox.IsChecked == true,
            PinnedCertSha256 = pin.Length == 0 ? null : pin.ToLowerInvariant(),
            Enabled = EnabledBox.IsChecked == true,
            Note = string.IsNullOrWhiteSpace(NoteBox.Text) ? null : NoteBox.Text.Trim(),
        };

        if (ClearPasswordBox.IsChecked == true)
        {
            result.Password = null;
        }
        else if (!string.IsNullOrEmpty(PasswordBox.Password))
        {
            result.SetPassword(PasswordBox.Password);
        }
        else
        {
            result.Password = _source.Password;
        }

        Result = result;
    }
}
