using System.Net.Sockets;
using System.Text;
using Clash.Core.Common;

namespace Clash.Core.Listeners;

/// <summary>
/// A buffered, prependable view over the socket accepted by a listener.
/// <para>
/// Inbound protocol handlers must read the request line and headers before the
/// tunnel takes over, but every byte past the end of the header block still
/// belongs to the tunnel. This stream keeps those bytes in an internal buffer so
/// nothing is swallowed: whatever the parser did not consume is handed to the
/// tunnel on its next read. <see cref="Prepend"/> additionally lets a handler
/// synthesise bytes (for example a rewritten HTTP request line) that the tunnel
/// must see <em>before</em> the bytes already buffered.
/// </para>
/// </summary>
internal sealed class InboundStream : Stream
{
    private const int DefaultCapacity = 16 * 1024;

    private readonly Stream _inner;
    private readonly bool _ownsInner;
    private byte[] _buffer;
    private int _start;
    private int _end;

    /// <summary>Wraps <paramref name="inner"/>.</summary>
    public InboundStream(Stream inner, bool ownsInner = true, int capacity = DefaultCapacity)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _ownsInner = ownsInner;
        _buffer = new byte[Math.Max(capacity, 1024)];
    }

    /// <summary>Wraps the socket in an owning <see cref="NetworkStream"/>.</summary>
    public static InboundStream ForSocket(Socket socket)
        => new(new NetworkStream(socket, ownsSocket: true));

    /// <summary>Number of bytes currently buffered and not yet read.</summary>
    public int BufferedCount => _end - _start;

    /// <summary>Queues <paramref name="data"/> so it is returned by the next read, ahead of anything already buffered.</summary>
    public void Prepend(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return;
        }

        var available = _end - _start;
        if (_start >= data.Length)
        {
            _start -= data.Length;
            data.CopyTo(_buffer.AsSpan(_start));
            return;
        }

        var capacity = Math.Max(_buffer.Length, data.Length + available + 64);
        var grown = new byte[capacity];
        data.CopyTo(grown);
        if (available > 0)
        {
            _buffer.AsSpan(_start, available).CopyTo(grown.AsSpan(data.Length));
        }

        _buffer = grown;
        _start = 0;
        _end = data.Length + available;
    }

    /// <summary>Returns the next byte without consuming it, or -1 at end of stream.</summary>
    public async ValueTask<int> PeekByteAsync(CancellationToken cancellationToken)
    {
        if (_start == _end && !await FillAsync(cancellationToken).ConfigureAwait(false))
        {
            return -1;
        }

        return _buffer[_start];
    }

    /// <summary>Consumes and returns the next byte, or -1 at end of stream.</summary>
    public async ValueTask<int> ReadByteAsync(CancellationToken cancellationToken)
    {
        if (_start == _end && !await FillAsync(cancellationToken).ConfigureAwait(false))
        {
            return -1;
        }

        return _buffer[_start++];
    }

    /// <summary>Reads exactly <paramref name="count"/> bytes, throwing on premature end of stream.</summary>
    public async ValueTask<byte[]> ReadExactAsync(int count, CancellationToken cancellationToken)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        var result = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            if (_start == _end && !await FillAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new ClashException($"unexpected end of stream: wanted {count} bytes, got {offset}");
            }

            var take = Math.Min(count - offset, _end - _start);
            _buffer.AsSpan(_start, take).CopyTo(result.AsSpan(offset));
            _start += take;
            offset += take;
        }

        return result;
    }

    /// <summary>
    /// Reads one CRLF (or bare LF) terminated line, without its terminator.
    /// Returns null at a clean end of stream and throws when the line exceeds
    /// <paramref name="maxLength"/>.
    /// </summary>
    public async ValueTask<string?> ReadLineAsync(int maxLength, CancellationToken cancellationToken)
    {
        while (true)
        {
            var newline = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);
            if (newline >= 0)
            {
                var lineEnd = newline;
                if (lineEnd > _start && _buffer[lineEnd - 1] == (byte)'\r')
                {
                    lineEnd--;
                }

                var line = Encoding.UTF8.GetString(_buffer, _start, lineEnd - _start);
                _start = newline + 1;
                return line;
            }

            if (_end - _start > maxLength)
            {
                throw new ClashException($"protocol line exceeds the {maxLength} byte limit");
            }

            if (!await FillAsync(cancellationToken).ConfigureAwait(false))
            {
                if (_start == _end)
                {
                    return null;
                }

                var tail = Encoding.UTF8.GetString(_buffer, _start, _end - _start);
                _start = _end;
                return tail;
            }
        }
    }

    private async ValueTask<bool> FillAsync(CancellationToken cancellationToken)
    {
        if (_end == _buffer.Length)
        {
            if (_start > 0)
            {
                Buffer.BlockCopy(_buffer, _start, _buffer, 0, _end - _start);
                _end -= _start;
                _start = 0;
            }
            else
            {
                if (_buffer.Length >= 1024 * 1024)
                {
                    throw new ClashException("inbound buffer overflow");
                }

                Array.Resize(ref _buffer, _buffer.Length * 2);
            }
        }

        var read = await _inner.ReadAsync(_buffer.AsMemory(_end), cancellationToken).ConfigureAwait(false);
        if (read <= 0)
        {
            return false;
        }

        _end += read;
        return true;
    }

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => _inner.CanWrite;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public override void Flush() => _inner.Flush();

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
    {
        if (_start == _end)
        {
            var direct = _inner.Read(buffer);
            return direct;
        }

        var take = Math.Min(buffer.Length, _end - _start);
        _buffer.AsSpan(_start, take).CopyTo(buffer);
        _start += take;
        return take;
    }

    /// <inheritdoc />
    public override int ReadByte()
    {
        if (_start != _end)
        {
            return _buffer[_start++];
        }

        return _inner.ReadByte();
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_start != _end)
        {
            var take = Math.Min(buffer.Length, _end - _start);
            _buffer.AsSpan(_start, take).CopyTo(buffer.Span);
            _start += take;
            return take;
        }

        return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

    /// <inheritdoc />
    public override void Write(ReadOnlySpan<byte> buffer) => _inner.Write(buffer);

    /// <inheritdoc />
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.WriteAsync(buffer, cancellationToken);

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing && _ownsInner)
        {
            try
            {
                _inner.Dispose();
            }
            catch
            {
                // The peer is already gone; nothing left to release.
            }
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    public override async ValueTask DisposeAsync()
    {
        if (_ownsInner)
        {
            try
            {
                await _inner.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
                // The peer is already gone; nothing left to release.
            }
        }

        GC.SuppressFinalize(this);
    }
}
