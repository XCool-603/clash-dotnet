using System.Text;
using Clash.Core.Common;

namespace Clash.Core.Transport;

/// <summary>
/// HTTP/1.1 chunked transfer coding as a <see cref="Stream"/>. Writes become
/// chunks; reads decode them. When <c>chunked</c> is false the stream is a plain
/// pass-through, which is what the obfuscation layer uses when the server answers
/// without <c>Transfer-Encoding: chunked</c>.
/// </summary>
public sealed class ChunkedStream : Stream
{
    private readonly Stream _inner;
    private readonly bool _chunked;
    private byte[] _prefix;
    private int _prefixOffset;
    private byte[] _chunk = [];
    private int _chunkOffset;
    private int _chunkLength;
    private bool _readFinished;
    private bool _writeFinished;
    private readonly byte[] _lineScratch = new byte[1];

    /// <summary>Wraps <paramref name="inner"/>, replaying <paramref name="prefix"/> before reading from it.</summary>
    public ChunkedStream(Stream inner, byte[]? prefix = null, bool chunked = true)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _prefix = prefix ?? [];
        _chunked = chunked;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException("ChunkedStream is not seekable");

    public override long Position
    {
        get => throw new NotSupportedException("ChunkedStream is not seekable");
        set => throw new NotSupportedException("ChunkedStream is not seekable");
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException("ChunkedStream is not seekable");

    public override void SetLength(long value) => throw new NotSupportedException("ChunkedStream is not seekable");

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer) => ReadAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty || _readFinished) return 0;

        if (!_chunked)
        {
            var read = await ReadFromSourceAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read <= 0) _readFinished = true;
            return read;
        }

        while (_chunkOffset >= _chunkLength)
        {
            if (!await ReadNextChunkAsync(cancellationToken).ConfigureAwait(false))
            {
                _readFinished = true;
                return 0;
            }
        }

        var take = Math.Min(buffer.Length, _chunkLength - _chunkOffset);
        _chunk.AsSpan(_chunkOffset, take).CopyTo(buffer.Span);
        _chunkOffset += take;
        return take;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer) => WriteAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty || _writeFinished) return;

        if (!_chunked)
        {
            await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        var header = Encoding.ASCII.GetBytes($"{buffer.Length:x}\r\n");
        await _inner.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        await _inner.WriteAsync("\r\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>Writes the terminating zero-length chunk, once.</summary>
    public async ValueTask FinishAsync(CancellationToken cancellationToken = default)
    {
        if (!_chunked || _writeFinished) return;
        _writeFinished = true;
        await _inner.WriteAsync("0\r\n\r\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try
            {
                FinishAsync().AsTask().GetAwaiter().GetResult();
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
            {
            }

            _inner.Dispose();
        }

        base.Dispose(disposing);
    }

    private async ValueTask<bool> ReadNextChunkAsync(CancellationToken cancellationToken)
    {
        var line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (line is null) return false;

        var text = Encoding.ASCII.GetString(line);
        var semicolon = text.IndexOf(';');
        if (semicolon >= 0) text = text[..semicolon];
        text = text.Trim();

        if (!int.TryParse(text, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var size) || size < 0)
        {
            throw new ClashException($"http: malformed chunk size '{text}'");
        }

        if (size == 0)
        {
            // Consume the trailer section, which ends at the first empty line.
            while (true)
            {
                var trailer = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (trailer is null || trailer.Length == 0) break;
            }

            return false;
        }

        if (_chunk.Length < size) _chunk = new byte[size];
        if (!await ReadFromSourceAsync(_chunk.AsMemory(0, size), cancellationToken).ConfigureAwait(false))
        {
            throw new ClashException("http: the stream ended inside a chunk");
        }

        _chunkOffset = 0;
        _chunkLength = size;

        // Trailing CRLF after the chunk data.
        var cr = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (cr is null) throw new ClashException("http: the stream ended before the chunk terminator");
        return true;
    }

    private async ValueTask<byte[]?> ReadLineAsync(CancellationToken cancellationToken)
    {
        var buffer = new List<byte>(16);
        while (true)
        {
            var read = await ReadFromSourceAsync(_lineScratch, cancellationToken).ConfigureAwait(false);
            if (read <= 0) return buffer.Count == 0 ? null : buffer.ToArray();

            if (_lineScratch[0] == (byte)'\n')
            {
                if (buffer.Count > 0 && buffer[^1] == (byte)'\r') buffer.RemoveAt(buffer.Count - 1);
                return buffer.ToArray();
            }

            buffer.Add(_lineScratch[0]);
            if (buffer.Count > 8192) throw new ClashException("http: chunk header line too long");
        }
    }

    private async ValueTask<int> ReadFromSourceAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        if (_prefixOffset < _prefix.Length)
        {
            var take = Math.Min(destination.Length, _prefix.Length - _prefixOffset);
            _prefix.AsSpan(_prefixOffset, take).CopyTo(destination.Span);
            _prefixOffset += take;
            if (_prefixOffset >= _prefix.Length) _prefix = [];
            return take;
        }

        return await _inner.ReadAsync(destination, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// v2ray's HTTP obfuscation transport (<c>http-opts</c>). The client sends one
/// HTTP request header followed by a chunked body; the server answers with a
/// response header followed by the chunked payload.
/// <para>
/// <b>Documented limitation.</b> Only the client half is implemented: this layer
/// always dials out. The response header is parsed for its status code and for
/// <c>Transfer-Encoding</c>, and the body is decoded as chunked when the server
/// says so and passed through raw otherwise. v2ray's reference client streams the
/// body without the chunked coding; the chunked form is used here because it is
/// what the <c>http-opts</c> contract in this project describes.
/// </para>
/// </summary>
public sealed class HttpObfsTransport : ITransportLayer
{
    public string Name => "http";

    public async Task<ProxyStream> WrapAsync(
        ProxyStream? inner,
        DialContext context,
        YamlMap options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (inner is null) throw new ClashException("http: the layer needs an inner stream");

        var http = TransportOptions.ReadHttpObfsOptions(options);
        var path = http.Path.Count > 0 ? http.Path[Random.Shared.Next(http.Path.Count)] : "/";

        var request = BuildRequestHeader(http, context.Host, context.Port, path);
        await inner.Inner.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await inner.Inner.FlushAsync(cancellationToken).ConfigureAwait(false);

        var response = await TransportStream.ReadHeaderBlockAsync(inner.Inner, cancellationToken).ConfigureAwait(false);
        if (response is null) throw new ClashException("http: the server closed the connection before answering");

        var (startLine, headers, _) = TransportStream.ParseHeaderBlock(response.Value.Header);
        var parts = startLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var status))
        {
            throw new ClashException($"http: malformed response status line '{startLine}'");
        }

        if (status != 200)
        {
            throw new ClashException($"http: the server answered {status} {startLine}");
        }

        var chunked = headers.TryGetValue("Transfer-Encoding", out var encoding)
            && encoding.Contains("chunked", StringComparison.OrdinalIgnoreCase);

        return TransportStream.Wrap(new ChunkedStream(inner.Inner, response.Value.Leftover, chunked), inner);
    }

    /// <summary>Builds the request header the obfuscation layer sends.</summary>
    public static byte[] BuildRequestHeader(HttpObfsOptions options, string host, int port, string path)
    {
        ArgumentNullException.ThrowIfNull(options);

        var builder = new StringBuilder(256);
        builder.Append(options.Method).Append(' ').Append(string.IsNullOrEmpty(path) ? "/" : path).Append(" HTTP/1.1\r\n");
        builder.Append("Host: ").Append(WebSocketFraming.FormatHost(host, port)).Append("\r\n");
        builder.Append("User-Agent: ").Append(WebSocketFraming.DefaultUserAgent).Append("\r\n");
        builder.Append("Accept: */*\r\n");
        builder.Append("Accept-Language: en-US,en;q=0.8\r\n");
        builder.Append("Accept-Encoding: gzip, deflate\r\n");
        builder.Append("Connection: keep-alive\r\n");

        foreach (var (name, values) in options.Headers)
        {
            if (IsManagedHeader(name)) continue;
            foreach (var value in values)
            {
                builder.Append(name).Append(": ").Append(value).Append("\r\n");
            }
        }

        builder.Append("Transfer-Encoding: chunked\r\n\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static bool IsManagedHeader(string name)
        => name.Equals("Host", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Connection", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase);
}
