using System.Collections.Concurrent;

namespace Nexsteaduser.CulvertProxy.Core.Engine;

/// <summary>连接建立时的静态信息。</summary>
public sealed record ConnectionInit(
    string Protocol,
    string Target,
    string? ProcessName,
    int? ProcessId,
    string RuleName,
    string? PolicyName);

/// <summary>传给界面的连接快照。</summary>
public sealed record ConnectionSnapshot(
    long Id,
    string Protocol,
    string Target,
    string? ProcessName,
    int? ProcessId,
    string RuleName,
    string? PolicyName,
    string? Route,
    string State,
    DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt,
    long BytesUp,
    long BytesDown,
    string? Error,
    bool IsActive)
{
    public long ElapsedMs => (long)((EndedAt ?? DateTimeOffset.UtcNow) - StartedAt).TotalMilliseconds;

    public long TotalBytes => BytesUp + BytesDown;
}

/// <summary>运行中的连接，可被界面主动取消。</summary>
public sealed class ActiveConnection
{
    private readonly object _sync = new();
    private readonly CancellationTokenSource _cts;
    private string _state = "connecting";
    private string? _route;
    private string? _error;
    private DateTimeOffset? _endedAt;
    private long _bytesUp;
    private long _bytesDown;

    internal ActiveConnection(long id, in ConnectionInit init, CancellationToken engineToken)
    {
        Id = id;
        Init = init;
        StartedAt = DateTimeOffset.Now;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(engineToken);
    }

    public long Id { get; }

    public ConnectionInit Init { get; }

    public DateTimeOffset StartedAt { get; }

    internal CancellationToken CancellationToken => _cts.Token;

    public void AddUploaded(long bytes) => Interlocked.Add(ref _bytesUp, bytes);

    public void AddDownloaded(long bytes) => Interlocked.Add(ref _bytesDown, bytes);

    public void SetState(string state)
    {
        lock (_sync)
        {
            _state = state;
        }
    }

    public void SetRoute(string route)
    {
        lock (_sync)
        {
            _route = route;
        }
    }

    public void SetError(string error)
    {
        lock (_sync)
        {
            _error = error;
        }
    }

    internal void MarkEnded()
    {
        lock (_sync)
        {
            _endedAt = DateTimeOffset.Now;
        }
    }

    internal ConnectionSnapshot Snapshot()
    {
        lock (_sync)
        {
            return new ConnectionSnapshot(
                Id,
                Init.Protocol,
                Init.Target,
                Init.ProcessName,
                Init.ProcessId,
                Init.RuleName,
                Init.PolicyName,
                _route,
                _state,
                StartedAt,
                _endedAt,
                Interlocked.Read(ref _bytesUp),
                Interlocked.Read(ref _bytesDown),
                _error,
                _endedAt is null);
        }
    }

    internal void Cancel() => _cts.Cancel();
}

/// <summary>活跃连接表与已完成连接历史。</summary>
public sealed class ConnectionRegistry
{
    private readonly ConcurrentDictionary<long, ActiveConnection> _active = new();
    private readonly ConcurrentQueue<ConnectionSnapshot> _history = new();
    private long _nextId;
    private int _historyCount;
    private volatile int _historyLimit = 500;

    public int ActiveCount => _active.Count;

    public IReadOnlyList<ConnectionSnapshot> ActiveSnapshots =>
        _active.Values.Select(c => c.Snapshot()).OrderByDescending(c => c.StartedAt).ToArray();

    public ActiveConnection Begin(in ConnectionInit init, CancellationToken engineToken)
    {
        var id = Interlocked.Increment(ref _nextId);
        var connection = new ActiveConnection(id, init, engineToken);
        _active[id] = connection;
        return connection;
    }

    /// <summary>结束连接并移入历史，超出上限时淘汰最旧记录。</summary>
    public void Complete(ActiveConnection connection, string? error = null)
    {
        if (error is not null)
        {
            connection.SetError(error);
        }

        connection.SetState(error is null ? "closed" : "failed");
        connection.MarkEnded();
        if (!_active.TryRemove(connection.Id, out _))
        {
            return;
        }

        _history.Enqueue(connection.Snapshot());
        Interlocked.Increment(ref _historyCount);
        var limit = _historyLimit;
        while (Interlocked.CompareExchange(ref _historyCount, 0, 0) > limit && _history.TryDequeue(out _))
        {
            Interlocked.Decrement(ref _historyCount);
        }
    }

    public void UpdateHistoryLimit(int limit)
    {
        _historyLimit = Math.Clamp(limit, 20, 5000);
        while (Interlocked.CompareExchange(ref _historyCount, 0, 0) > _historyLimit && _history.TryDequeue(out _))
        {
            Interlocked.Decrement(ref _historyCount);
        }
    }

    public IReadOnlyList<ConnectionSnapshot> Snapshot(bool includeHistory = true)
    {
        var active = _active.Values
            .Select(c => c.Snapshot())
            .OrderByDescending(c => c.StartedAt)
            .ToList();
        if (includeHistory)
        {
            active.AddRange(_history.ToArray().OrderByDescending(c => c.StartedAt));
        }

        return active;
    }

    public bool Kill(long connectionId)
    {
        if (!_active.TryGetValue(connectionId, out var connection))
        {
            return false;
        }

        connection.SetState("killing");
        connection.Cancel();
        return true;
    }

    public void KillAll()
    {
        foreach (var connection in _active.Values)
        {
            connection.Cancel();
        }
    }
}
