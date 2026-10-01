using System.Net;
using Clash.Core.Common;

namespace Clash.Core.Transport;

/// <summary>Shared stream plumbing for the transport layers.</summary>
internal static class TransportStream
{
    /// <summary>Largest header block any layer here will read before giving up.</summary>
    public const int MaxHeaderBytes = 64 * 1024;

    /// <summary>Fills <paramref name="buffer"/> completely, or reports end of stream.</summary>
    public static async ValueTask<bool> ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (n <= 0) return false;
            read += n;
        }

        return true;
    }

    /// <summary>A header block plus whatever payload arrived in the same read.</summary>
    public readonly record struct HeaderReadResult(byte[] Header, byte[] Leftover);

    /// <summary>
    /// Reads until <c>\r\n\r\n</c>. The returned block includes the terminator and
    /// <see cref="HeaderReadResult.Leftover"/> carries any payload bytes that
    /// arrived in the same read, so nothing is lost to buffering.
    /// </summary>
    public static async ValueTask<HeaderReadResult?> ReadHeaderBlockAsync(Stream stream, CancellationToken cancellationToken, int maxBytes = MaxHeaderBytes)
    {
        var buffer = new byte[1024];
        var length = 0;

        while (true)
        {
            if (length == buffer.Length)
            {
                if (buffer.Length >= maxBytes) throw new ClashException("transport: response header exceeded the maximum size");
                Array.Resize(ref buffer, Math.Min(buffer.Length * 2, maxBytes));
            }

            var n = await stream.ReadAsync(buffer.AsMemory(length, buffer.Length - length), cancellationToken).ConfigureAwait(false);
            if (n <= 0)
            {
                if (length == 0) return null;
                return new HeaderReadResult(buffer[..length], []);
            }

            length += n;
            var terminator = FindHeaderTerminator(buffer.AsSpan(0, length));
            if (terminator < 0) continue;

            var leftover = new byte[length - terminator];
            Array.Copy(buffer, terminator, leftover, 0, leftover.Length);
            return new HeaderReadResult(buffer[..terminator], leftover);
        }
    }

    /// <summary>Index just past the first <c>\r\n\r\n</c>, or -1.</summary>
    public static int FindHeaderTerminator(ReadOnlySpan<byte> buffer)
    {
        var index = buffer.IndexOf("\r\n\r\n"u8);
        return index < 0 ? -1 : index + 4;
    }

    /// <summary>Splits a header block into the start line and the header lines.</summary>
    public static (string StartLine, Dictionary<string, string> Headers, List<string> Order) ParseHeaderBlock(ReadOnlySpan<byte> block)
    {
        var text = System.Text.Encoding.ASCII.GetString(block);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();
        var startLine = lines.Length > 0 ? lines[0] : string.Empty;

        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0) break;
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (headers.TryGetValue(name, out var existing)) headers[name] = existing + ", " + value;
            else
            {
                headers[name] = value;
                order.Add(name);
            }
        }

        return (startLine, headers, order);
    }

    /// <summary>Wraps a stream, carrying the endpoints of the stream it was built on.</summary>
    public static ProxyStream Wrap(Stream inner, ProxyStream? basedOn)
    {
        if (basedOn is null) return ProxyStream.Wrap(inner);
        return new ProxyStream(inner, basedOn.LocalEndPoint, basedOn.RemoteEndPoint, owner: basedOn);
    }

    /// <summary>Best-effort remote endpoint of a stream that reports its own endpoints.</summary>
    public static EndPoint? EndPointOf(Stream stream)
        => stream is ProxyStream proxy ? proxy.RemoteEndPoint : null;
}

/// <summary>
/// Forwards everything to an inner stream but makes <see cref="Dispose"/> a no-op.
/// <see cref="System.Net.Http.SocketsHttpHandler"/> closes the stream its
/// <c>ConnectCallback</c> returned, and the transport contract says a layer must
/// not dispose the inner stream it was handed, so the handler is given this
/// wrapper instead.
/// </summary>
internal sealed class NonDisposingStream : Stream
{
    private readonly Stream _inner;

    public NonDisposingStream(Stream inner) => _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public override bool CanRead => _inner.CanRead;

    public override bool CanSeek => _inner.CanSeek;

    public override bool CanWrite => _inner.CanWrite;

    public override long Length => _inner.Length;

    public override long Position
    {
        get => _inner.Position;
        set => _inner.Position = value;
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

    public override int Read(Span<byte> buffer) => _inner.Read(buffer);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.ReadAsync(buffer, cancellationToken);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.ReadAsync(buffer, offset, count, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

    public override void SetLength(long value) => _inner.SetLength(value);

    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

    public override void Write(ReadOnlySpan<byte> buffer) => _inner.Write(buffer);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.WriteAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        // Deliberately does not dispose the inner stream.
    }

    public override ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
