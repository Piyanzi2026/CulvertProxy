using System.Collections.Concurrent;

namespace Nexsteaduser.CulvertProxy.Core.Engine;

/// <summary>每秒吞吐采样点。</summary>
public readonly record struct RateSample(DateTimeOffset Timestamp, double UploadBytesPerSecond, double DownloadBytesPerSecond);

/// <summary>全局流量与连接计数，附带最近若干秒的速率窗口。</summary>
public sealed class TrafficStats
{
    private const int MaxSamples = 300;
    private readonly ConcurrentQueue<RateSample> _samples = new();
    private readonly object _sampleLock = new();
    private long _totalUp;
    private long _totalDown;
    private long _totalConnections;
    private long _failedConnections;
    private long _blockedConnections;
    private long _dnsQueries;
    private long _lastUp;
    private long _lastDown;
    private DateTime _lastSampleAt = DateTime.UtcNow;
    private double _upRate;
    private double _downRate;

    public void AddUploaded(long bytes) => Interlocked.Add(ref _totalUp, bytes);

    public void AddDownloaded(long bytes) => Interlocked.Add(ref _totalDown, bytes);

    public void RecordConnection() => Interlocked.Increment(ref _totalConnections);

    public void RecordFailure() => Interlocked.Increment(ref _failedConnections);

    public void RecordBlocked() => Interlocked.Increment(ref _blockedConnections);

    public void RecordDnsQuery() => Interlocked.Increment(ref _dnsQueries);

    /// <summary>由引擎每秒调用一次，计算瞬时速率。</summary>
    public void Sample()
    {
        lock (_sampleLock)
        {
            var now = DateTime.UtcNow;
            var elapsed = Math.Max((now - _lastSampleAt).TotalSeconds, 0.001);
            var up = Interlocked.Read(ref _totalUp);
            var down = Interlocked.Read(ref _totalDown);
            _upRate = Math.Max(0, (up - _lastUp) / elapsed);
            _downRate = Math.Max(0, (down - _lastDown) / elapsed);
            _lastUp = up;
            _lastDown = down;
            _lastSampleAt = now;
            _samples.Enqueue(new RateSample(DateTimeOffset.Now, _upRate, _downRate));
            while (_samples.Count > MaxSamples && _samples.TryDequeue(out _))
            {
            }
        }
    }

    public TrafficSnapshot Snapshot()
    {
        lock (_sampleLock)
        {
            return new TrafficSnapshot(
                Interlocked.Read(ref _totalUp),
                Interlocked.Read(ref _totalDown),
                _upRate,
                _downRate,
                Interlocked.Read(ref _totalConnections),
                Interlocked.Read(ref _failedConnections),
                Interlocked.Read(ref _blockedConnections),
                Interlocked.Read(ref _dnsQueries),
                _samples.ToArray());
        }
    }
}

/// <summary>统计快照。</summary>
public sealed record TrafficSnapshot(
    long TotalUploadedBytes,
    long TotalDownloadedBytes,
    double UploadBytesPerSecond,
    double DownloadBytesPerSecond,
    long TotalConnections,
    long FailedConnections,
    long BlockedConnections,
    long DnsQueries,
    IReadOnlyList<RateSample> Samples);
