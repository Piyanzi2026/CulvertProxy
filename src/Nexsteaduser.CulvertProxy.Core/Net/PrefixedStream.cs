namespace Nexsteaduser.CulvertProxy.Core.Net;

/// <summary>把已读入的残余字节拼回流头，避免协议探测吞掉隧道数据。</summary>
public sealed class PrefixedStream : Stream
{
    private readonly Stream _inner;
    private byte[] _prefix;
    private int _prefixOffset;
    private readonly int _prefixLength;
    private readonly bool _leaveOpen;

    public PrefixedStream(byte[] prefix, int prefixOffset, int prefixLength, Stream inner, bool leaveOpen = false)
    {
        _prefix = prefix;
        _prefixOffset = prefixOffset;
        _prefixLength = prefixLength;
        _inner = inner;
        _leaveOpen = leaveOpen;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => _inner.CanWrite;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var available = _prefixLength - _prefixOffset;
        if (available > 0)
        {
            var take = Math.Min(available, count);
            Array.Copy(_prefix, _prefixOffset, buffer, offset, take);
            _prefixOffset += take;
            return take;
        }

        return _inner.Read(buffer, offset, count);
    }

    public override int Read(Span<byte> buffer)
    {
        var available = _prefixLength - _prefixOffset;
        if (available > 0)
        {
            var take = Math.Min(available, buffer.Length);
            _prefix.AsSpan(_prefixOffset, take).CopyTo(buffer);
            _prefixOffset += take;
            return take;
        }

        return _inner.Read(buffer);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var available = _prefixLength - _prefixOffset;
        if (available > 0)
        {
            var take = Math.Min(available, buffer.Length);
            _prefix.AsMemory(_prefixOffset, take).CopyTo(buffer);
            _prefixOffset += take;
            return take;
        }

        return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

    public override void Write(ReadOnlySpan<byte> buffer) => _inner.Write(buffer);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.WriteAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (!_leaveOpen)
            {
                _inner.Dispose();
            }

            _prefix = [];
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_leaveOpen)
        {
            await _inner.DisposeAsync().ConfigureAwait(false);
        }

        _prefix = [];
        await base.DisposeAsync().ConfigureAwait(false);
    }
}
