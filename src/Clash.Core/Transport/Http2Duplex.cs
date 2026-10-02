using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using Clash.Core.Common;

namespace Clash.Core.Transport;

/// <summary>
/// The 5-byte length prefix v2ray's gRPC and HTTP/2 transports put in front of
/// every message: <c>[compressed(1)][length(4, big-endian)][payload]</c>.
/// </summary>
public static class Http2MessageFraming
{
    /// <summary>Bytes of the message header.</summary>
    public const int HeaderSize = 5;

    /// <summary>
    /// Largest message this transport will frame or accept: 1 GiB, far above any
    /// real v2ray message yet well below the 32-bit length field's ceiling, so a
    /// malformed or hostile frame is rejected instead of allocated.
    /// </summary>
    public const int MaxMessageSize = 1024 * 1024 * 1024;

    /// <summary>Writes a message header. Returns the bytes written.</summary>
    public static int WriteHeader(Span<byte> destination, int payloadLength, bool compressed = false)
    {
        if (destination.Length < HeaderSize) throw new ArgumentException($"destination must be at least {HeaderSize} bytes", nameof(destination));
        if (payloadLength is < 0 or > MaxMessageSize) throw new ArgumentOutOfRangeException(nameof(payloadLength));

        destination[0] = compressed ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt32BigEndian(destination[1..], (uint)payloadLength);
        return HeaderSize;
    }

    /// <summary>Parses a message header.</summary>
    public static bool TryReadHeader(ReadOnlySpan<byte> source, out bool compressed, out int payloadLength)
    {
        compressed = false;
        payloadLength = 0;
        if (source.Length < HeaderSize) return false;

        compressed = source[0] != 0;
        var length = BinaryPrimitives.ReadUInt32BigEndian(source[1..]);
        if (length > MaxMessageSize) return false;

        payloadLength = (int)length;
        return true;
    }
}

/// <summary>
/// A duplex stream over one HTTP/2 request/response pair.
/// <para>
/// .NET 10 has no <c>DuplexContent</c> (the API does not exist in
/// <c>System.Net.Http</c>), so the request body is a hand-written
/// <see cref="HttpContent"/> that drains a <see cref="Pipe"/> and frames each
/// chunk as a gRPC message, while a background pump unframes the response body
/// into a second pipe. <c>SocketsHttpHandler.ConnectCallback</c> makes the client
/// use the already-established transport instead of opening its own connection,
/// and the request URI is plain <c>http://</c> so the handler does not add a
/// second TLS layer on top of the one the stack already applied.
/// </para>
/// </summary>
public sealed class Http2DuplexStream : Stream
{
    private readonly PipeWriter _outbound;
    private readonly PipeReader _inbound;
    private readonly HttpClient _client;
    private readonly HttpResponseMessage _response;
    private readonly ProxyStream? _owner;
    private int _disposed;

    internal Http2DuplexStream(PipeWriter outbound, PipeReader inbound, HttpClient client, HttpResponseMessage response, ProxyStream? owner)
    {
        _outbound = outbound;
        _inbound = inbound;
        _client = client;
        _response = response;
        _owner = owner;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException("Http2DuplexStream is not seekable");

    public override long Position
    {
        get => throw new NotSupportedException("Http2DuplexStream is not seekable");
        set => throw new NotSupportedException("Http2DuplexStream is not seekable");
    }

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException("Http2DuplexStream is not seekable");

    public override void SetLength(long value) => throw new NotSupportedException("Http2DuplexStream is not seekable");

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var scratch = new byte[buffer.Length];
        var n = ReadAsync(scratch).AsTask().GetAwaiter().GetResult();
        scratch.AsSpan(0, n).CopyTo(buffer);
        return n;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;

        while (true)
        {
            var result = await _inbound.ReadAsync(cancellationToken).ConfigureAwait(false);
            var sequence = result.Buffer;

            if (sequence.Length > 0)
            {
                var take = (int)Math.Min(sequence.Length, buffer.Length);
                sequence.Slice(0, take).CopyTo(buffer.Span);
                _inbound.AdvanceTo(sequence.GetPosition(take));
                return take;
            }

            _inbound.AdvanceTo(sequence.Start, sequence.End);
            if (result.IsCompleted) return 0;
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return;
        await _outbound.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        try
        {
            await _outbound.CompleteAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException)
        {
        }

        try
        {
            _response.Dispose();
        }
        catch (Exception ex) when (ex is ObjectDisposedException)
        {
        }

        _client.Dispose();
        if (_owner is not null) await _owner.DisposeAsync().ConfigureAwait(false);

        GC.SuppressFinalize(this);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                try
                {
                    _outbound.Complete();
                }
                catch (Exception ex) when (ex is InvalidOperationException or IOException)
                {
                }

                try
                {
                    _response.Dispose();
                }
                catch (Exception ex) when (ex is ObjectDisposedException)
                {
                }

                _client.Dispose();
                _owner?.Dispose();
            }
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// Builds the HTTP/2 duplex stream that the <c>grpc</c> and <c>h2</c> transports
/// run their message framing over.
/// </summary>
public static class Http2Duplex
{
    /// <summary>
    /// Opens the request and returns the duplex stream. Throws
    /// <see cref="TransportNotSupportedException"/> when the server refuses the
    /// HTTP/2 exchange, which is what a proxy in front of the server would do.
    /// </summary>
    public static async Task<Http2DuplexStream> ConnectAsync(
        Stream transport,
        string host,
        int port,
        string path,
        string? authority,
        string contentType,
        ProxyStream? owner,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        if (string.IsNullOrEmpty(path)) path = "/";
        if (!path.StartsWith('/')) path = "/" + path;

        var handedOut = 0;
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            EnableMultipleHttp2Connections = false,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
            ConnectTimeout = Timeout.InfiniteTimeSpan,
            ConnectCallback = (_, _) => Interlocked.Exchange(ref handedOut, 1) == 0
                ? new ValueTask<Stream>(new NonDisposingStream(transport))
                : ValueTask.FromException<Stream>(new IOException("h2: the handler requested a second connection, which this transport cannot provide")),
        };

        var client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };

        var outbound = new Pipe(new PipeOptions(
            useSynchronizationContext: false,
            pauseWriterThreshold: 1024 * 1024,
            resumeWriterThreshold: 512 * 1024));

        var inbound = new Pipe(new PipeOptions(useSynchronizationContext: false));

        var request = new HttpRequestMessage(HttpMethod.Post, $"http://{FormatAuthority(host, port)}{path}")
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = new FramedDuplexContent(outbound.Reader),
        };

        request.Headers.TryAddWithoutValidation("content-type", contentType);
        request.Headers.TryAddWithoutValidation("te", "trailers");
        if (!string.IsNullOrEmpty(authority)) request.Headers.Host = authority;

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException)
        {
            client.Dispose();
            throw new TransportNotSupportedException(
                $"h2/grpc (the server or an intermediary refused the HTTP/2 exchange for {path}: {ex.Message})");
        }

        if (response.StatusCode != HttpStatusCode.OK)
        {
            var status = response.StatusCode;
            response.Dispose();
            client.Dispose();
            throw new TransportNotSupportedException($"h2/grpc (the server answered {(int)status} {status} for {path} instead of 200)");
        }

        var stream = new Http2DuplexStream(outbound.Writer, inbound.Reader, client, response, owner);
        var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        _ = PumpResponseAsync(responseStream, inbound.Writer, cancellationToken);
        return stream;
    }

    private static string FormatAuthority(string host, int port)
        => host.Contains(':') && !host.StartsWith('[') ? $"[{host}]:{port}" : $"{host}:{port}";

    private static async Task PumpResponseAsync(Stream responseStream, PipeWriter writer, CancellationToken cancellationToken)
    {
        var header = new byte[Http2MessageFraming.HeaderSize];
        try
        {
            while (true)
            {
                if (!await TransportStream.ReadExactlyAsync(responseStream, header, cancellationToken).ConfigureAwait(false)) break;
                if (!Http2MessageFraming.TryReadHeader(header, out var compressed, out var length))
                {
                    throw new ClashException("h2: malformed message header");
                }

                if (compressed)
                {
                    throw new ClashException("h2: the peer sent a compressed message, but compression was never negotiated");
                }

                if (length == 0) continue;

                var payload = new byte[length];
                if (!await TransportStream.ReadExactlyAsync(responseStream, payload, cancellationToken).ConfigureAwait(false)) break;
                await writer.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            }

            await writer.CompleteAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await writer.CompleteAsync(ex).ConfigureAwait(false);
        }
    }

    /// <summary>Streams the outbound pipe to the request body as gRPC messages.</summary>
    private sealed class FramedDuplexContent : HttpContent
    {
        private readonly PipeReader _reader;

        public FramedDuplexContent(PipeReader reader) => _reader = reader;

        protected override bool TryComputeLength(out long length)
        {
            length = -1;
            return false;
        }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            var header = new byte[Http2MessageFraming.HeaderSize];

            while (true)
            {
                var result = await _reader.ReadAsync().ConfigureAwait(false);
                var buffer = result.Buffer;
                var consumed = buffer.Start;

                try
                {
                    while (buffer.Length > 0)
                    {
                        var take = (int)Math.Min(buffer.Length, Http2MessageFraming.MaxMessageSize);
                        var slice = buffer.Slice(0, take);
                        Http2MessageFraming.WriteHeader(header, take);
                        await stream.WriteAsync(header).ConfigureAwait(false);
                        foreach (var memory in slice)
                        {
                            await stream.WriteAsync(memory).ConfigureAwait(false);
                        }

                        buffer = buffer.Slice(take);
                        consumed = buffer.Start;
                    }

                    if (result.IsCompleted) break;
                }
                finally
                {
                    _reader.AdvanceTo(consumed, buffer.Start);
                }
            }

            await stream.FlushAsync().ConfigureAwait(false);
        }
    }
}
