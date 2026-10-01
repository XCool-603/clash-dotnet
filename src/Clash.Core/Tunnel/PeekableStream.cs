using System.Buffers;

namespace Clash.Core.Tunnel;

/// <summary>
/// A read-through wrapper that lets the tunnel inspect the first bytes of a
/// client stream (TLS ClientHello, HTTP request line) without consuming them,
/// so sniffed bytes are replayed to the outbound exactly once.
/// </summary>
public sealed class PeekableStream : Stream
{
    private readonly Stream _inner;
    private readonly int _capacity;
    private byte[] _buffer;
    private int _start;
    private int _end;

    public PeekableStream(Stream inner, int capacity = 8192)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _capacity = Math.Max(512, capacity);
        _buffer = ArrayPool<byte>.Shared.Rent(_capacity);
    }

    /// <summary>Bytes read from the client but not yet consumed by a normal read.</summary>
    public ReadOnlyMemory<byte> Peeked => _buffer.AsMemory(_start, _end - _start);

    public int BufferedCount => _end - _start;

    /// <summary>
    /// Reads until at least <paramref name="count"/> bytes are buffered, the
    /// stream ends, or <paramref name="timeout"/> elapses. Returns the number of
    /// buffered bytes. A timeout is not an error: sniffing is best effort.
    /// </summary>
    public async ValueTask<int> PeekAsync(int count, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;
        var target = Math.Min(count, _capacity);

        while (BufferedCount < target)
        {
            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero) break;

            if (_end == _buffer.Length) Grow();
            if (_buffer.Length - _end < 512) Compact();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(remaining);

            int read;
            try
            {
                read = await _inner.ReadAsync(_buffer.AsMemory(_end, _buffer.Length - _end), timeoutCts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (IOException)
            {
                break;
            }

            if (read <= 0) break;
            _end += read;
        }

        return BufferedCount;
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

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (BufferedCount > 0)
        {
            var take = Math.Min(buffer.Length, BufferedCount);
            _buffer.AsSpan(_start, take).CopyTo(buffer);
            _start += take;
            if (_start == _end) _start = _end = 0;
            return take;
        }
        return _inner.Read(buffer);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (BufferedCount > 0)
        {
            var take = Math.Min(buffer.Length, BufferedCount);
            _buffer.AsMemory(_start, take).CopyTo(buffer);
            _start += take;
            if (_start == _end) _start = _end = 0;
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
            var buffer = _buffer;
            _buffer = [];
            if (buffer.Length > 0) ArrayPool<byte>.Shared.Return(buffer);
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        var buffer = _buffer;
        _buffer = [];
        if (buffer.Length > 0) ArrayPool<byte>.Shared.Return(buffer);
        await base.DisposeAsync().ConfigureAwait(false);
    }

    private void Grow()
    {
        var next = ArrayPool<byte>.Shared.Rent(_buffer.Length * 2);
        Array.Copy(_buffer, _start, next, 0, BufferedCount);
        _end -= _start;
        _start = 0;
        ArrayPool<byte>.Shared.Return(_buffer);
        _buffer = next;
    }

    private void Compact()
    {
        if (_start == 0) return;
        var count = BufferedCount;
        Array.Copy(_buffer, _start, _buffer, 0, count);
        _start = 0;
        _end = count;
    }
}
