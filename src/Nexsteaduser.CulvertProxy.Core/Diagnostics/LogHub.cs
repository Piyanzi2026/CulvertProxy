using System.Collections.Concurrent;
using System.Text;
using System.Threading.Channels;

namespace Nexsteaduser.CulvertProxy.Core.Diagnostics;

/// <summary>日志级别。</summary>
public enum LogSeverity
{
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

/// <summary>一条日志记录。</summary>
public sealed record LogEntry(DateTimeOffset Timestamp, LogSeverity Severity, string Category, string Message, string? ExceptionText = null)
{
    public string ToLine() => ExceptionText is null
        ? $"{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Severity,-5}] {Category}: {Message}"
        : $"{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Severity,-5}] {Category}: {Message}{Environment.NewLine}{ExceptionText}";
}

/// <summary>非阻塞日志中枢：内存环形窗口供界面读取，同时异步落盘。</summary>
public sealed class LogHub : IAsyncDisposable
{
    private const int MaxRecentEntries = 2000;
    private readonly ConcurrentQueue<LogEntry> _recent = new();
    private readonly Channel<LogEntry> _channel;
    private readonly Task _pump;
    private readonly string _directory;
    private readonly bool _writeToDisk;
    private int _recentCount;
    private int _disposed;

    public LogHub(string? directory = null, bool writeToDisk = true)
    {
        _directory = directory ?? Path.Combine(AppContext.BaseDirectory, "logs");
        _writeToDisk = writeToDisk;
        _channel = Channel.CreateBounded<LogEntry>(new BoundedChannelOptions(16384)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });

        if (_writeToDisk)
        {
            Directory.CreateDirectory(_directory);
        }

        _pump = Task.Run(PumpAsync);
    }

    /// <summary>每条日志写入后触发；可能在任意线程执行。</summary>
    public event Action<LogEntry>? EntryAdded;

    public void Trace(string category, string message) => Write(LogSeverity.Trace, category, message);

    public void Debug(string category, string message) => Write(LogSeverity.Debug, category, message);

    public void Info(string category, string message) => Write(LogSeverity.Info, category, message);

    public void Warn(string category, string message, Exception? exception = null) => Write(LogSeverity.Warn, category, message, exception);

    public void Error(string category, string message, Exception? exception = null) => Write(LogSeverity.Error, category, message, exception);

    /// <summary>写入一条日志，绝不阻塞调用方。</summary>
    public void Write(LogSeverity severity, string category, string message, Exception? exception = null)
    {
        var entry = new LogEntry(DateTimeOffset.Now, severity, category, message, exception?.ToString());
        _recent.Enqueue(entry);
        if (Interlocked.Increment(ref _recentCount) > MaxRecentEntries && _recent.TryDequeue(out _))
        {
            Interlocked.Decrement(ref _recentCount);
        }

        _channel.Writer.TryWrite(entry);
        try
        {
            EntryAdded?.Invoke(entry);
        }
        catch
        {
            // 订阅方异常不得影响代理路径。
        }
    }

    /// <summary>取出最近日志，按时间升序。</summary>
    public IReadOnlyList<LogEntry> Snapshot(int max = 500)
    {
        var items = _recent.ToArray();
        return items.Length <= max ? items : items[^max..];
    }

    private async Task PumpAsync()
    {
        var reader = _channel.Reader;
        var buffer = new StringBuilder(4096);
        while (await reader.WaitToReadAsync().ConfigureAwait(false))
        {
            buffer.Clear();
            var count = 0;
            while (count < 256 && reader.TryRead(out var entry))
            {
                if (entry.Severity < LogSeverity.Debug)
                {
                    continue;
                }

                buffer.AppendLine(entry.ToLine());
                count++;
            }

            if (count == 0 || !_writeToDisk)
            {
                continue;
            }

            try
            {
                var path = GetCurrentLogFile();
                await File.AppendAllTextAsync(path, buffer.ToString(), Encoding.UTF8).ConfigureAwait(false);
            }
            catch
            {
                // 日志写入失败不能拖垮进程。
            }
        }
    }

    private string GetCurrentLogFile()
    {
        var baseName = $"culvert-{DateTime.Now:yyyyMMdd}.log";
        var path = Path.Combine(_directory, baseName);
        try
        {
            var info = new FileInfo(path);
            if (info.Exists && info.Length > 16 * 1024 * 1024)
            {
                path = Path.Combine(_directory, $"culvert-{DateTime.Now:yyyyMMdd}-{DateTime.Now:HHmmss}.log");
            }
        }
        catch
        {
            // 忽略探测失败。
        }

        return path;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _channel.Writer.TryComplete();
        try
        {
            await _pump.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        }
        catch
        {
            // 关闭阶段允许丢弃未落盘日志。
        }
    }
}
