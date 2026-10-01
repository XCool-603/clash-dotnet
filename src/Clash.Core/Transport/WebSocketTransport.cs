using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Common;

namespace Clash.Core.Transport;

/// <summary>The RFC 6455 opcode of a frame.</summary>
public enum WebSocketOpcode : byte
{
    /// <summary>Continuation of a fragmented message.</summary>
    Continuation = 0x0,

    /// <summary>UTF-8 text message.</summary>
    Text = 0x1,

    /// <summary>Binary message; the only opcode this transport sends.</summary>
    Binary = 0x2,

    /// <summary>Connection close.</summary>
    Close = 0x8,

    /// <summary>Ping; the peer must answer with a pong.</summary>
    Ping = 0x9,

    /// <summary>Pong.</summary>
    Pong = 0xA,
}

/// <summary>One decoded RFC 6455 frame.</summary>
public readonly record struct WebSocketFrame(WebSocketOpcode Opcode, bool Fin, bool Masked, byte[] Payload)
{
    /// <summary>True for close, ping and pong, which may not be fragmented.</summary>
    public bool IsControl => (byte)Opcode >= 0x8;
}

/// <summary>
/// The pure, byte-buffer half of RFC 6455: accept-key computation, frame
/// encode/decode and the client handshake. Everything here is static and
/// network-free so it can be exercised directly against buffers.
/// </summary>
public static class WebSocketFraming
{
    /// <summary>The GUID RFC 6455 mixes into <c>Sec-WebSocket-Accept</c>.</summary>
    public const string HandshakeGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    /// <summary>Control frames may not carry more than 125 bytes.</summary>
    public const int MaxControlPayload = 125;

    /// <summary>Largest frame this implementation will encode or accept.</summary>
    public const int MaxFramePayload = 16 * 1024 * 1024;

    /// <summary>The User-Agent sent when the configuration does not override it.</summary>
    public const string DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    /// <summary>Computes <c>Sec-WebSocket-Accept</c> for a client key.</summary>
    public static string ComputeAccept(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var material = Encoding.ASCII.GetBytes(key + HandshakeGuid);
        return Convert.ToBase64String(SHA1.HashData(material));
    }

    /// <summary>Generates a fresh <c>Sec-WebSocket-Key</c>.</summary>
    public static string CreateKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

    /// <summary>Bytes the frame header occupies for a payload of this length.</summary>
    public static int FrameHeaderSize(int payloadLength, bool mask)
    {
        if (payloadLength < 0) throw new ArgumentOutOfRangeException(nameof(payloadLength));
        var length = payloadLength < 126 ? 2 : payloadLength <= ushort.MaxValue ? 4 : 10;
        return mask ? length + 4 : length;
    }

    /// <summary>
    /// Encodes one frame. <paramref name="maskKey"/> is used as the little-endian
    /// mask when <paramref name="mask"/> is true. Returns the bytes written.
    /// </summary>
    public static int WriteFrame(
        Span<byte> destination,
        WebSocketOpcode opcode,
        ReadOnlySpan<byte> payload,
        bool mask,
        uint maskKey = 0,
        bool fin = true)
    {
        if ((byte)opcode >= 0x8 && (payload.Length > MaxControlPayload || !fin))
        {
            throw new ArgumentException("control frames must be final and at most 125 bytes", nameof(payload));
        }

        var headerSize = FrameHeaderSize(payload.Length, mask);
        var required = headerSize + payload.Length;
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        destination[0] = (byte)((fin ? 0x80 : 0x00) | (byte)opcode);
        var offset = 2;

        switch (payload.Length)
        {
            case < 126:
                destination[1] = (byte)payload.Length;
                break;
            case <= ushort.MaxValue:
                destination[1] = 126;
                BinaryPrimitives.WriteUInt16BigEndian(destination[2..], (ushort)payload.Length);
                offset = 4;
                break;
            default:
                destination[1] = 127;
                BinaryPrimitives.WriteUInt64BigEndian(destination[2..], (ulong)payload.Length);
                offset = 10;
                break;
        }

        if (mask)
        {
            destination[1] |= 0x80;
            destination[offset] = (byte)maskKey;
            destination[offset + 1] = (byte)(maskKey >> 8);
            destination[offset + 2] = (byte)(maskKey >> 16);
            destination[offset + 3] = (byte)(maskKey >> 24);
            offset += 4;
        }

        if (mask)
        {
            for (var i = 0; i < payload.Length; i++)
            {
                destination[offset + i] = (byte)(payload[i] ^ (byte)(maskKey >> ((i & 3) * 8)));
            }
        }
        else
        {
            payload.CopyTo(destination[offset..]);
        }

        return offset + payload.Length;
    }

    /// <summary>Decodes one frame from the head of <paramref name="source"/>.</summary>
    public static bool TryReadFrame(ReadOnlySpan<byte> source, out WebSocketFrame frame, out int consumed)
    {
        frame = default;
        consumed = 0;

        if (source.Length < 2) return false;

        var fin = (source[0] & 0x80) != 0;
        var opcode = (WebSocketOpcode)(source[0] & 0x0F);
        var masked = (source[1] & 0x80) != 0;
        var length = (long)(source[1] & 0x7F);
        var offset = 2;

        if (length == 126)
        {
            if (source.Length < 4) return false;
            length = BinaryPrimitives.ReadUInt16BigEndian(source[2..]);
            offset = 4;
        }
        else if (length == 127)
        {
            if (source.Length < 10) return false;
            var wide = BinaryPrimitives.ReadUInt64BigEndian(source[2..]);
            if (wide > MaxFramePayload) return false;
            length = (long)wide;
            offset = 10;
        }

        if (length > MaxFramePayload) return false;

        Span<byte> maskKey = stackalloc byte[4];
        if (masked)
        {
            if (source.Length < offset + 4) return false;
            source.Slice(offset, 4).CopyTo(maskKey);
            offset += 4;
        }

        if (source.Length < offset + length) return false;

        var payload = source.Slice(offset, (int)length).ToArray();
        if (masked)
        {
            for (var i = 0; i < payload.Length; i++) payload[i] ^= maskKey[i & 3];
        }

        consumed = offset + (int)length;
        frame = new WebSocketFrame(opcode, fin, masked, payload);
        return true;
    }

    /// <summary>
    /// Builds the client handshake request. <paramref name="earlyData"/>, when
    /// non-empty, is base64url-encoded into the header named by
    /// <see cref="WebSocketOptions.EarlyDataHeaderName"/> (default
    /// <c>Sec-WebSocket-Protocol</c>).
    /// </summary>
    public static byte[] BuildHandshakeRequest(
        string host,
        int port,
        WebSocketOptions options,
        string key,
        ReadOnlySpan<byte> earlyData)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(key);

        var builder = new StringBuilder(512);
        builder.Append("GET ").Append(string.IsNullOrEmpty(options.Path) ? "/" : options.Path).Append(" HTTP/1.1\r\n");
        builder.Append("Host: ").Append(FormatHost(host, port)).Append("\r\n");
        builder.Append("User-Agent: ").Append(DefaultUserAgent).Append("\r\n");
        builder.Append("Connection: Upgrade\r\n");
        builder.Append("Upgrade: websocket\r\n");

        if (!options.V2rayHttpUpgrade)
        {
            builder.Append("Sec-WebSocket-Version: 13\r\n");
            builder.Append("Sec-WebSocket-Key: ").Append(key).Append("\r\n");

            if (!earlyData.IsEmpty)
            {
                var headerName = string.IsNullOrEmpty(options.EarlyDataHeaderName) ? "Sec-WebSocket-Protocol" : options.EarlyDataHeaderName;
                builder.Append(headerName).Append(": ").Append(ClashBase64.EncodeUrlSafe(earlyData)).Append("\r\n");
            }
        }

        foreach (var (name, value) in options.Headers)
        {
            if (IsHandshakeManagedHeader(name)) continue;
            builder.Append(name).Append(": ").Append(value).Append("\r\n");
        }

        builder.Append("\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    /// <summary>Header names the handshake writes itself and therefore ignores in <c>ws-opts.headers</c>.</summary>
    public static bool IsHandshakeManagedHeader(string name)
        => name.Equals("Host", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Connection", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Sec-WebSocket-Key", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Sec-WebSocket-Version", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase);

    /// <summary>Formats a <c>Host</c> header, appending the port only when it is not the scheme default.</summary>
    public static string FormatHost(string host, int port)
        => port is 80 or 443 ? host : $"{host}:{port}";

    /// <summary>
    /// Parses the server's handshake response. <paramref name="headerLength"/> is
    /// the offset just past <c>\r\n\r\n</c>, where any already-received payload
    /// begins.
    /// </summary>
    public static bool TryParseHandshakeResponse(
        ReadOnlySpan<byte> source,
        out int headerLength,
        out string startLine,
        out string? accept,
        out string? upgrade,
        out bool success)
    {
        headerLength = 0;
        startLine = string.Empty;
        accept = null;
        upgrade = null;
        success = false;

        var terminator = TransportStream.FindHeaderTerminator(source);
        if (terminator < 0) return false;

        headerLength = terminator;
        var (line, headers, _) = TransportStream.ParseHeaderBlock(source[..terminator]);
        startLine = line;

        var parts = line.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !parts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)) return false;

        success = parts[1] == "101";
        headers.TryGetValue("Sec-WebSocket-Accept", out accept);
        headers.TryGetValue("Upgrade", out upgrade);
        return true;
    }

    /// <summary>Validates a handshake response against the key that was sent.</summary>
    public static bool ValidateHandshakeResponse(
        ReadOnlySpan<byte> source,
        string key,
        bool requireAccept,
        out int headerLength,
        out string failure)
    {
        failure = string.Empty;
        if (!TryParseHandshakeResponse(source, out headerLength, out var startLine, out var accept, out var upgrade, out var success))
        {
            failure = "malformed handshake response";
            return false;
        }

        if (!success)
        {
            failure = $"server answered '{startLine}' instead of 101 Switching Protocols";
            return false;
        }

        if (upgrade is null || !upgrade.Contains("websocket", StringComparison.OrdinalIgnoreCase))
        {
            failure = "response is missing 'Upgrade: websocket'";
            return false;
        }

        if (requireAccept)
        {
            var expected = ComputeAccept(key);
            if (accept is null || !string.Equals(accept, expected, StringComparison.OrdinalIgnoreCase))
            {
                failure = "Sec-WebSocket-Accept did not match the key that was sent";
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// A duplex <see cref="Stream"/> that speaks RFC 6455 over an already-connected
/// transport. Outgoing writes become masked binary frames (clients must mask);
/// incoming frames are unframed, with continuation, ping, pong and close handled
/// transparently.
/// <para>
/// The handshake is deferred to the first read or write so that early data can
/// ride along inside it: when <see cref="WebSocketOptions.MaxEarlyData"/> is set,
/// the first bytes of the first write are base64url-encoded into the
/// <c>Sec-WebSocket-Protocol</c> header instead of being sent as a frame.
/// </para>
/// </summary>
public sealed class WebSocketStream : Stream
{
    /// <summary>Largest payload this stream puts in a single outgoing frame.</summary>
    public const int OutgoingChunkSize = 16 * 1024;

    private readonly Stream _inner;
    private readonly WebSocketOptions _options;
    private readonly string _host;
    private readonly int _port;
    private readonly bool _maskOutgoing;
    private readonly string _key = WebSocketFraming.CreateKey();
    private readonly byte[] _readBuffer = new byte[8192];
    private readonly byte[] _frameHeader = new byte[14];
    private byte[] _sendBuffer = new byte[OutgoingChunkSize + 14];
    private readonly byte[] _maskKeyBytes = new byte[4];

    private int _readStart;
    private int _readEnd;
    private bool _handshakeCompleted;
    private bool _closed;
    private byte[] _message = [];
    private int _messageOffset;
    private int _messageLength;

    /// <summary>Creates the stream. The handshake runs on first use.</summary>
    public WebSocketStream(Stream inner, WebSocketOptions options, string host, int port, bool maskOutgoing = true)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _host = host;
        _port = port;
        _maskOutgoing = maskOutgoing;
    }

    /// <summary>True once the handshake has completed successfully.</summary>
    public bool HandshakeCompleted => _handshakeCompleted;

    /// <summary>The <c>Sec-WebSocket-Key</c> this stream sent, for diagnostics.</summary>
    public string Key => _key;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException("WebSocketStream is not seekable");

    public override long Position
    {
        get => throw new NotSupportedException("WebSocketStream is not seekable");
        set => throw new NotSupportedException("WebSocketStream is not seekable");
    }

    /// <summary>Performs the handshake with no early data.</summary>
    public ValueTask HandshakeAsync(CancellationToken cancellationToken = default)
        => _handshakeCompleted ? ValueTask.CompletedTask : SendHandshakeAsync(ReadOnlyMemory<byte>.Empty, cancellationToken);

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException("WebSocketStream is not seekable");

    public override void SetLength(long value) => throw new NotSupportedException("WebSocketStream is not seekable");

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer) => ReadAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;
        if (!_handshakeCompleted) await SendHandshakeAsync(ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);

        while (_messageOffset >= _messageLength)
        {
            if (!await ReadMessageAsync(cancellationToken).ConfigureAwait(false)) return 0;
        }

        var take = Math.Min(buffer.Length, _messageLength - _messageOffset);
        _message.AsSpan(_messageOffset, take).CopyTo(buffer.Span);
        _messageOffset += take;
        return take;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return;

        if (!_handshakeCompleted)
        {
            var consumed = await SendHandshakeAsync(buffer, cancellationToken).ConfigureAwait(false);
            buffer = buffer[consumed..];
            if (buffer.IsEmpty) return;
        }

        while (!buffer.IsEmpty)
        {
            var chunk = Math.Min(buffer.Length, OutgoingChunkSize);
            var frameSize = WebSocketFraming.FrameHeaderSize(chunk, _maskOutgoing) + chunk;
            if (_sendBuffer.Length < frameSize) _sendBuffer = new byte[Math.Max(frameSize, _sendBuffer.Length * 2)];

            var written = WebSocketFraming.WriteFrame(
                _sendBuffer,
                WebSocketOpcode.Binary,
                buffer.Span[..chunk],
                _maskOutgoing,
                NextMaskKey());

            await _inner.WriteAsync(_sendBuffer.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
            buffer = buffer[chunk..];
        }

        await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>Sends a close frame, best effort, and then releases the inner stream.</summary>
    public override async ValueTask DisposeAsync()
    {
        await SendCloseAsync(CancellationToken.None).ConfigureAwait(false);
        await _inner.DisposeAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try
            {
                SendCloseAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
            {
            }

            _inner.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <summary>Sends a close frame with the normal-closure status code (1000).</summary>
    public async ValueTask SendCloseAsync(CancellationToken cancellationToken)
    {
        if (_closed || !_handshakeCompleted) return;
        _closed = true;
        try
        {
            await SendControlAsync(WebSocketOpcode.Close, [0x03, 0xE8], cancellationToken).ConfigureAwait(false);
            await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
        }
    }

    private async ValueTask<int> SendHandshakeAsync(ReadOnlyMemory<byte> firstPayload, CancellationToken cancellationToken)
    {
        var consumed = 0;
        ReadOnlyMemory<byte> earlyData = default;

        if (_options.MaxEarlyData > 0 && !firstPayload.IsEmpty)
        {
            consumed = Math.Min(_options.MaxEarlyData, firstPayload.Length);
            earlyData = firstPayload[..consumed];
        }

        var request = WebSocketFraming.BuildHandshakeRequest(_host, _port, _options, _key, earlyData.Span);
        await _inner.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);

        var requireAccept = !_options.V2rayHttpUpgrade;
        if (!await ReadHandshakeResponseAsync(requireAccept, cancellationToken).ConfigureAwait(false))
        {
            throw new ClashException("ws: the server rejected the WebSocket handshake");
        }

        _handshakeCompleted = true;
        return consumed;
    }

    private async ValueTask<bool> ReadHandshakeResponseAsync(bool requireAccept, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        var length = 0;

        while (true)
        {
            if (length == buffer.Length)
            {
                if (buffer.Length >= TransportStream.MaxHeaderBytes) throw new ClashException("ws: handshake response header too large");
                Array.Resize(ref buffer, buffer.Length * 2);
            }

            var n = await _inner.ReadAsync(buffer.AsMemory(length), cancellationToken).ConfigureAwait(false);
            if (n <= 0) throw new ClashException("ws: the connection closed during the handshake");
            length += n;

            var terminator = TransportStream.FindHeaderTerminator(buffer.AsSpan(0, length));
            if (terminator < 0) continue;

            if (!WebSocketFraming.ValidateHandshakeResponse(buffer.AsSpan(0, terminator), _key, requireAccept, out _, out var failure))
            {
                throw new ClashException($"ws: {failure}");
            }

            var extra = length - terminator;
            if (extra > 0)
            {
                if (extra > _readBuffer.Length) Array.Resize(ref _readBuffer, extra);
                Array.Copy(buffer, terminator, _readBuffer, 0, extra);
                _readStart = 0;
                _readEnd = extra;
            }

            return true;
        }
    }

    private async ValueTask<bool> ReadMessageAsync(CancellationToken cancellationToken)
    {
        var assembled = new MemoryStream(16 * 1024);
        var inMessage = false;

        while (true)
        {
            var frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
            if (frame is null) return false;

            var value = frame.Value;
            switch (value.Opcode)
            {
                case WebSocketOpcode.Ping:
                    await SendControlAsync(WebSocketOpcode.Pong, value.Payload, cancellationToken).ConfigureAwait(false);
                    continue;

                case WebSocketOpcode.Pong:
                    continue;

                case WebSocketOpcode.Close:
                    await SendCloseAsync(cancellationToken).ConfigureAwait(false);
                    return false;

                case WebSocketOpcode.Binary:
                case WebSocketOpcode.Text:
                    assembled.Write(value.Payload);
                    inMessage = true;
                    break;

                case WebSocketOpcode.Continuation:
                    if (!inMessage) continue;
                    assembled.Write(value.Payload);
                    break;

                default:
                    continue;
            }

            if (!value.Fin) continue;

            _message = assembled.ToArray();
            _messageOffset = 0;
            _messageLength = _message.Length;
            return true;
        }
    }

    private async ValueTask<WebSocketFrame?> ReadFrameAsync(CancellationToken cancellationToken)
    {
        if (!await ReadExactAsync(_frameHeader.AsMemory(0, 2), cancellationToken).ConfigureAwait(false)) return null;

        var masked = (_frameHeader[1] & 0x80) != 0;
        var lengthCode = _frameHeader[1] & 0x7F;
        var offset = 2;
        long payloadLength;

        if (lengthCode < 126)
        {
            payloadLength = lengthCode;
        }
        else if (lengthCode == 126)
        {
            if (!await ReadExactAsync(_frameHeader.AsMemory(offset, 2), cancellationToken).ConfigureAwait(false)) return null;
            payloadLength = BinaryPrimitives.ReadUInt16BigEndian(_frameHeader.AsSpan(offset));
            offset += 2;
        }
        else
        {
            if (!await ReadExactAsync(_frameHeader.AsMemory(offset, 8), cancellationToken).ConfigureAwait(false)) return null;
            var wide = BinaryPrimitives.ReadUInt64BigEndian(_frameHeader.AsSpan(offset));
            if (wide > WebSocketFraming.MaxFramePayload) throw new ClashException("ws: frame larger than the 16 MiB limit");
            payloadLength = (long)wide;
            offset += 8;
        }

        var maskOffset = -1;
        if (masked)
        {
            if (!await ReadExactAsync(_frameHeader.AsMemory(offset, 4), cancellationToken).ConfigureAwait(false)) return null;
            maskOffset = offset;
            offset += 4;
        }

        if (payloadLength > WebSocketFraming.MaxFramePayload) throw new ClashException("ws: frame larger than the 16 MiB limit");

        var payload = new byte[payloadLength];
        if (payloadLength > 0 && !await ReadExactAsync(payload, cancellationToken).ConfigureAwait(false)) return null;

        if (masked)
        {
            var mask = _frameHeader.AsSpan(maskOffset, 4);
            for (var i = 0; i < payload.Length; i++) payload[i] ^= mask[i & 3];
        }

        return new WebSocketFrame((WebSocketOpcode)(_frameHeader[0] & 0x0F), (_frameHeader[0] & 0x80) != 0, masked, payload);
    }

    private async ValueTask SendControlAsync(WebSocketOpcode opcode, byte[] payload, CancellationToken cancellationToken)
    {
        if (payload.Length > WebSocketFraming.MaxControlPayload) payload = payload[..WebSocketFraming.MaxControlPayload];

        var frameSize = WebSocketFraming.FrameHeaderSize(payload.Length, _maskOutgoing) + payload.Length;
        var buffer = new byte[frameSize];
        var written = WebSocketFraming.WriteFrame(buffer, opcode, payload, _maskOutgoing, NextMaskKey());
        await _inner.WriteAsync(buffer.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
        await _inner.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private uint NextMaskKey()
    {
        RandomNumberGenerator.Fill(_maskKeyBytes);
        return BinaryPrimitives.ReadUInt32LittleEndian(_maskKeyBytes);
    }

    private async ValueTask<bool> FillAsync(CancellationToken cancellationToken)
    {
        if (_readStart < _readEnd) return true;
        _readStart = 0;
        _readEnd = 0;
        var n = await _inner.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false);
        if (n <= 0) return false;
        _readEnd = n;
        return true;
    }

    private async ValueTask<bool> ReadExactAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        var filled = 0;
        while (filled < destination.Length)
        {
            if (!await FillAsync(cancellationToken).ConfigureAwait(false)) return false;
            var take = Math.Min(destination.Length - filled, _readEnd - _readStart);
            _readBuffer.AsSpan(_readStart, take).CopyTo(destination.Span[filled..]);
            _readStart += take;
            filled += take;
        }

        return true;
    }
}

/// <summary>
/// The <c>ws</c> transport: a from-scratch RFC 6455 client, including v2ray's
/// <c>httpupgrade</c> variant, which skips the WebSocket key dance and sends a
/// plain <c>GET</c> with <c>Upgrade: websocket</c>.
/// </summary>
public sealed class WebSocketTransport : ITransportLayer
{
    public string Name => "ws";

    public async Task<ProxyStream> WrapAsync(
        ProxyStream? inner,
        DialContext context,
        YamlMap options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (inner is null) throw new ClashException("ws: the layer needs an inner stream");

        var ws = TransportOptions.ReadWebSocketOptions(options);
        var host = string.IsNullOrEmpty(ws.Host) ? context.Host : ws.Host;

        var stream = new WebSocketStream(inner.Inner, ws, host, context.Port, maskOutgoing: true);

        // With early data configured the handshake must wait for the first write,
        // because the payload it carries is not known yet.
        if (ws.MaxEarlyData <= 0)
        {
            await stream.HandshakeAsync(cancellationToken).ConfigureAwait(false);
        }

        return TransportStream.Wrap(stream, inner);
    }
}
