using Microsoft.UI;
using Windows.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Nexsteaduser.CulvertProxy.Core.Engine;
using Windows.Foundation;

namespace Nexsteaduser.CulvertProxy.App.Controls;

/// <summary>轻量吞吐折线图，避免引入图表依赖。</summary>
public sealed partial class TrafficChart : UserControl
{
    private static readonly SolidColorBrush UpStroke = new(Color.FromArgb(255, 45, 212, 191));
    private static readonly SolidColorBrush DownStroke = new(Color.FromArgb(255, 96, 165, 250));
    private static readonly SolidColorBrush GridStroke = new(Color.FromArgb(28, 128, 128, 128));
    private IReadOnlyList<RateSample> _samples = [];

    public TrafficChart()
    {
        InitializeComponent();
    }

    public void SetSamples(IReadOnlyList<RateSample> samples)
    {
        _samples = samples;
        Rebuild();
    }

    private void Root_SizeChanged(object sender, SizeChangedEventArgs e) => Rebuild();

    private void Rebuild()
    {
        Plot.Children.Clear();
        var width = Root.ActualWidth;
        var height = Root.ActualHeight;
        if (width < 20 || height < 20)
        {
            return;
        }

        var top = 6d;
        var bottom = height - 6;
        var plotHeight = Math.Max(bottom - top, 1);

        for (var i = 1; i <= 3; i++)
        {
            var y = top + plotHeight * i / 4;
            Plot.Children.Add(new Line
            {
                X1 = 0,
                X2 = width,
                Y1 = y,
                Y2 = y,
                Stroke = GridStroke,
                StrokeThickness = 1,
                StrokeDashArray = new DoubleCollection { 2, 4 },
            });
        }

        var samples = _samples.Count > 120 ? _samples.Skip(_samples.Count - 120).ToArray() : _samples;
        if (samples.Count < 2)
        {
            MaxLabel.Text = "等待流量";
            return;
        }

        var max = 1024d;
        foreach (var sample in samples)
        {
            max = Math.Max(max, Math.Max(sample.UploadBytesPerSecond, sample.DownloadBytesPerSecond));
        }

        MaxLabel.Text = FormatRate(max);
        AddSeries(samples, sample => sample.UploadBytesPerSecond, max, width, top, plotHeight, UpStroke, 2.2);
        AddSeries(samples, sample => sample.DownloadBytesPerSecond, max, width, top, plotHeight, DownStroke, 2.2);
    }

    private void AddSeries(
        IReadOnlyList<RateSample> samples,
        Func<RateSample, double> selector,
        double max,
        double width,
        double top,
        double plotHeight,
        Brush brush,
        double thickness)
    {
        var polyline = new Polyline
        {
            Stroke = brush,
            StrokeThickness = thickness,
            StrokeLineJoin = PenLineJoin.Round,
        };

        for (var i = 0; i < samples.Count; i++)
        {
            var x = width * i / (samples.Count - 1);
            var normalized = Math.Clamp(selector(samples[i]) / max, 0, 1);
            var y = top + plotHeight - (normalized * plotHeight);
            polyline.Points.Add(new Point(x, y));
        }

        Plot.Children.Add(polyline);
    }

    private static string FormatRate(double bytesPerSecond)
    {
        if (bytesPerSecond >= 1024 * 1024)
        {
            return $"{bytesPerSecond / (1024 * 1024):F1} MiB/s";
        }

        if (bytesPerSecond >= 1024)
        {
            return $"{bytesPerSecond / 1024:F1} KiB/s";
        }

        return $"{bytesPerSecond:F0} B/s";
    }
}
