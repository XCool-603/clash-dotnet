using System.Buffers;
using Clash.Core.Common;

namespace Clash.Core.Proxies.Outbound;

/// <summary>The block a header reader consumed plus whatever it read past the terminator.</summary>
internal readonly record struct HeaderRead(byte[] Block, byte[] Leftover);

/// <summary>
/// Small, allocation-light helpers for the request/response headers the outbound
/// protocols exchange (HTTP <c>CONNECT</c>, SOCKS5, Trojan). None of this runs on
/// the payload path.
/// </summary>
internal static class OutboundIo
{
    /// <summary>Largest header block any adapter here will buffer before giving up.</summary>
    internal const int MaxHeaderBytes = 32 * 1024;

    /// <summary>Reads until <paramref name="terminator"/> has been seen, keeping any extra bytes.</summary>
    internal static async ValueTask<HeaderRead> ReadUntilAsync(
        Stream stream,
        byte[] terminator,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(terminator);
        if (terminator.Length == 0) throw new ArgumentException("terminator must not be empty", nameof(terminator));

        var buffer = new byte[512];
        var length = 0;

        while (true)
        {
            if (length >= buffer.Length)
            {
                if (buffer.Length >= maxBytes)
                {
                    throw new ClashException($"outbound: response header exceeded {maxBytes} bytes");
                }

                Array.Resize(ref buffer, Math.Min(buffer.Length * 2, maxBytes));
            }

            var read = await stream.ReadAsync(buffer.AsMemory(length, buffer.Length - length), cancellationToken)
                .ConfigureAwait(false);
            if (read <= 0)
            {
                throw new ClashException("outbound: the peer closed the connection before the response header was complete");
            }

            length += read;
            var index = buffer.AsSpan(0, length).IndexOf(terminator);
            if (index >= 0)
            {
                var end = index + terminator.Length;
                return new HeaderRead(buffer[..end], buffer[end..length]);
            }
        }
    }

    /// <summary>Reads exactly <paramref name="destination"/>.Length bytes, or throws.</summary>
    internal static async ValueTask ReadExactlyAsync(Stream stream, Memory<byte> destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var read = 0;
        while (read < destination.Length)
        {
            var n = await stream.ReadAsync(destination[read..], cancellationToken).ConfigureAwait(false);
            if (n <= 0) throw new ClashException("outbound: the peer closed the connection mid-message");
            read += n;
        }
    }

    /// <inheritdoc cref="ReadExactlyAsync(Stream,Memory{byte},CancellationToken)"/>
    internal static void ReadExactly(Stream stream, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var read = 0;
        while (read < destination.Length)
        {
            var n = stream.Read(destination[read..]);
            if (n <= 0) throw new ClashException("outbound: the peer closed the connection mid-message");
            read += n;
        }
    }

    /// <summary>Copies <paramref name="payload"/> into <paramref name="destination"/> and returns the length.</summary>
    internal static int CopyInto(ReadOnlySpan<byte> payload, Memory<byte> destination)
    {
        if (payload.Length > destination.Length)
        {
            throw new ClashException($"outbound: received {payload.Length} bytes but only {destination.Length} fit in the caller's buffer");
        }

        payload.CopyTo(destination.Span);
        return payload.Length;
    }

    /// <summary>Parses the status line of an HTTP response, returning the numeric code.</summary>
    internal static bool TryParseStatusCode(ReadOnlySpan<byte> headerBlock, out int statusCode)
    {
        statusCode = 0;
        var text = System.Text.Encoding.ASCII.GetString(headerBlock);
        var endOfLine = text.IndexOf("\r\n", StringComparison.Ordinal);
        var startLine = endOfLine < 0 ? text : text[..endOfLine];
        var parts = startLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && int.TryParse(parts[1], out statusCode);
    }

    /// <summary>Finds the value of a header in an HTTP header block, or null.</summary>
    internal static string? FindHeader(ReadOnlySpan<byte> headerBlock, string name)
    {
        var text = System.Text.Encoding.ASCII.GetString(headerBlock);
        foreach (var line in text.Split("\r\n", StringSplitOptions.None))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            if (line.AsSpan(0, colon).Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return line[(colon + 1)..].Trim();
            }
        }

        return null;
    }
}

/// <summary>
/// Serves a small prefix of already-read bytes and then delegates to the stream
/// they came from. Header parsers read ahead, so the bytes after
/// <c>\r\n\r\n</c> must not be lost.
/// </summary>
internal sealed class PrefixStream : Stream
{
    private readonly byte[] _prefix;
    private readonly Stream _inner;
    private int _offset;

    internal PrefixStream(byte[] prefix, Stream inner)
    {
        _prefix = prefix ?? [];
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
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

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (_offset < _prefix.Length)
        {
            var take = Math.Min(buffer.Length, _prefix.Length - _offset);
            _prefix.AsSpan(_offset, take).CopyTo(buffer);
            _offset += take;
            return take;
        }

        return _inner.Read(buffer);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_offset < _prefix.Length)
        {
            var take = Math.Min(buffer.Length, _prefix.Length - _offset);
            _prefix.AsSpan(_offset, take).CopyTo(buffer.Span);
            _offset += take;
            return take;
        }

        return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

    public override void Write(ReadOnlySpan<byte> buffer) => _inner.Write(buffer);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.WriteAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try { _inner.Dispose(); } catch { /* already gone */ }
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        try { await _inner.DisposeAsync().ConfigureAwait(false); } catch { /* already gone */ }
        GC.SuppressFinalize(this);
    }
}

/// <summary>A pooled scratch buffer for the framing helpers.</summary>
internal sealed class PooledBuffer : IDisposable
{
    private byte[]? _buffer;

    internal PooledBuffer(int minimumSize)
    {
        _buffer = ArrayPool<byte>.Shared.Rent(Math.Max(1, minimumSize));
    }

    internal byte[] Array => _buffer ?? throw new ObjectDisposedException(nameof(PooledBuffer));

    internal Span<byte> Span => Array;

    internal Memory<byte> Memory(int length) => Array.AsMemory(0, length);

    public void Dispose()
    {
        var buffer = Interlocked.Exchange(ref _buffer, null);
        if (buffer is not null) ArrayPool<byte>.Shared.Return(buffer);
    }
}
