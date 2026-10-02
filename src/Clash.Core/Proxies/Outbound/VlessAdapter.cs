using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// Turns the configured <c>uuid</c> into the 16 bytes a VLESS request header
/// carries.
/// <para>
/// A well-formed UUID — dashed, bare, braced or <c>urn:uuid:</c>-prefixed — is used
/// verbatim. Anything else is hashed into a UUIDv5 over the nil namespace, because
/// that is what both reference clients do so a subscription carrying a non-UUID
/// "id" still derives a stable identity: sing-vmess <c>vless_client.go</c> falls
/// back to <c>uuid.NewV5(uuid.Nil, userId)</c> and mihomo to
/// <c>utils.UUIDMap</c>, which is <c>NewUUIDV5(uuid.Nil, str)</c>.
/// </para>
/// </summary>
internal static class VlessIds
{
    /// <summary>Parses a UUID, or derives a UUIDv5 from the string when it is not one.</summary>
    internal static byte[] Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        var candidate = value.Trim();
        var bare = candidate;
        if (bare.StartsWith("urn:uuid:", StringComparison.OrdinalIgnoreCase)) bare = bare[9..];
        if (bare.Length >= 2 && bare[0] == '{' && bare[^1] == '}') bare = bare[1..^1];

        return ClashHex.IsUuid(bare) ? ClashHex.ParseUuid(bare) : DeriveV5(candidate);
    }

    /// <summary>UUIDv5 (SHA-1 over the nil namespace) of <paramref name="name"/>.</summary>
    internal static byte[] DeriveV5(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        var nameBytes = Encoding.UTF8.GetBytes(name);
        var material = new byte[16 + nameBytes.Length];
        nameBytes.CopyTo(material, 16);

        Span<byte> hash = stackalloc byte[20];
        SHA1.HashData(material, hash);

        var uuid = hash[..16].ToArray();
        uuid[6] = (byte)((uuid[6] & 0x0F) | 0x50); // version 5
        uuid[8] = (byte)((uuid[8] & 0x3F) | 0x80); // RFC 4122 / RFC 9562 variant
        return uuid;
    }
}

/// <summary>
/// The VLESS TCP stream.
/// <para>
/// VLESS frames nothing: the request header is written once and the payload then
/// follows as a raw byte stream in both directions. The only framing left is the
/// server's response header — <c>version(1) | addons-length(1) | addons(N)</c> —
/// which the reference clients consume before the first payload byte
/// (mihomo <c>transport/vless/conn.go</c>, <c>recvResponse</c>; sing-vmess
/// <c>vless_protocol.go</c>, <c>ReadResponse</c>, which skips the addons).
/// </para>
/// <para>
/// It is read lazily on the first read rather than eagerly in the dial, so a server
/// that only answers after it has seen traffic cannot deadlock the dial. The addons
/// the server sends back are discarded, exactly as both references do.
/// </para>
/// </summary>
internal sealed class VlessTcpStream : Stream, IHalfCloseable
{
    private readonly Stream _inner;
    private bool _responseRead;

    internal VlessTcpStream(Stream inner) => _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
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
        if (buffer.IsEmpty) return 0;
        ReadResponseHeader();
        return _inner.Read(buffer);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;
        await ReadResponseHeaderAsync(cancellationToken).ConfigureAwait(false);
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

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>
    /// Passes the half-close down to the transport so the server sees EOF while the
    /// response path stays open. VLESS frames nothing on top of the payload, so
    /// nothing here needs to stay writable after the client has finished sending;
    /// without this the relay would fall back to its drain timeout instead.
    /// </summary>
    public void ShutdownSend()
    {
        switch (_inner)
        {
            case IHalfCloseable halfCloseable:
                try { halfCloseable.ShutdownSend(); } catch { /* peer already gone */ }
                break;
            case ProxyStream nested:
                nested.ShutdownSend();
                break;
        }
    }

    /// <summary>Reads <c>version | addons-length | addons</c> and leaves the stream on the first payload byte.</summary>
    private async ValueTask ReadResponseHeaderAsync(CancellationToken cancellationToken)
    {
        if (_responseRead) return;
        _responseRead = true;

        var prefix = new byte[2];
        await OutboundIo.ReadExactlyAsync(_inner, prefix, cancellationToken).ConfigureAwait(false);
        CheckVersion(prefix[0]);

        if (prefix[1] > 0)
        {
            var addons = new byte[prefix[1]];
            await OutboundIo.ReadExactlyAsync(_inner, addons, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <inheritdoc cref="ReadResponseHeaderAsync"/>
    private void ReadResponseHeader()
    {
        if (_responseRead) return;
        _responseRead = true;

        Span<byte> prefix = stackalloc byte[2];
        OutboundIo.ReadExactly(_inner, prefix);
        CheckVersion(prefix[0]);

        if (prefix[1] > 0)
        {
            Span<byte> addons = stackalloc byte[prefix[1]];
            OutboundIo.ReadExactly(_inner, addons);
        }
    }

    private static void CheckVersion(byte version)
    {
        if (version != VlessCrypto.Version)
        {
            throw new ClashException($"vless: the server answered with protocol version {version}, expected {VlessCrypto.Version}");
        }
    }

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

/// <summary>
/// A VLESS UDP association carried over the same TCP connection as its request
/// header — the classic "UDP over TCP" form.
/// <para>
/// <b>Framing.</b> The request header is the TCP one with command <c>0x02</c>
/// (<see cref="VlessCrypto.CommandUdp"/>) and an <em>empty</em> flow, and it names
/// the single destination the whole association talks to. Every datagram is then
/// framed as <c>length(2, big-endian) || payload</c>, in both directions, with no
/// per-datagram address and no other framing — the layout Xray-core's VLESS client
/// speaks for a <c>CommandUDP</c> connection, which is the interoperability target.
/// </para>
/// <para>
/// <b>One destination per connection.</b> Because the header carries the address
/// and no frame repeats it, an association cannot be re-pointed at a second remote;
/// the tunnel models a UDP flow the same way (see <c>UdpSession</c>, keyed by remote
/// endpoint) and dials one of these per destination, so
/// <see cref="SupportsMultipleDestinations"/> is false.
/// </para>
/// </summary>
internal sealed class VlessPacketConnection : IPacketConnection
{
    /// <summary>Largest datagram the two-byte length field can describe.</summary>
    private const int MaxDatagram = ushort.MaxValue;

    private readonly ProxyStream _stream;
    private readonly EndPoint? _remote;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private int _disposed;

    /// <summary>
    /// Takes ownership of the connection the request header was written on.
    /// <paramref name="remote"/> is the destination that header named, reported on
    /// every receive because the frames themselves carry no address.
    /// </summary>
    internal VlessPacketConnection(ProxyStream stream, EndPoint? remote)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _remote = remote;
    }

    /// <inheritdoc />
    public bool SupportsMultipleDestinations => false;

    /// <inheritdoc />
    public EndPoint? LocalEndPoint => _stream.LocalEndPoint;

    /// <inheritdoc />
    public async ValueTask<int> SendAsync(
        ReadOnlyMemory<byte> payload,
        EndPoint destination,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (payload.Length > MaxDatagram)
        {
            throw new ClashException($"vless: a {payload.Length}-byte datagram does not fit the two-byte UDP length field");
        }

        // `destination` is deliberately unused: VLESS names the destination once, in
        // the request header, and a frame carries nothing but a length and the
        // payload. The tunnel dials one association per remote, so the caller's
        // destination always matches the one this connection was opened for.
        var frame = new byte[2 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)payload.Length);
        payload.Span.CopyTo(frame.AsSpan(2));

        // The frame is one write so a datagram is never split across two length
        // fields; the lock keeps concurrent senders from interleaving.
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return payload.Length;
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var header = new byte[2];
        await OutboundIo.ReadExactlyAsync(_stream, header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt16BigEndian(header);

        // A zero-length datagram is legal on the wire and must still be reported as
        // one packet: reading zero payload bytes here would leave the length field
        // of the *next* frame to be mistaken for a payload, desynchronising the
        // stream.
        if (length == 0) return new PacketResult(0, _remote);

        var rented = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            await OutboundIo.ReadExactlyAsync(_stream, rented.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            return new PacketResult(OutboundIo.CopyInto(rented.AsSpan(0, length), buffer), _remote);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _sendLock.Dispose();
        await _stream.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// The XTLS <c>vision</c> (<c>xtls-rprx-vision</c>) framing layer.
/// <para>
/// <b>What it does.</b> Every write is wrapped in a padding block
/// <c>[uuid(16)] | command(1) | content-length(2, BE) | padding-length(2, BE) |
/// content | padding</c> until the reference's stop conditions fire, and every read
/// is unwrapped again. The UUID opens the first block only. See
/// <see cref="VlessVision"/> for the byte layout and the references it comes from.
/// </para>
/// <para>
/// <b>Layering.</b> This sits <em>above</em> <see cref="VlessTcpStream"/>, which is
/// the reference order: the server writes its VLESS response header unpadded and
/// only then starts padding, so the response header must be consumed before the
/// first padding block is parsed (mihomo builds <c>vision.Conn</c> on top of the
/// VLESS <c>Conn</c>, whose <c>recvResponse</c> runs first).
/// </para>
/// <para>
/// <b>Stop conditions</b> mirror <c>FilterTLS</c> plus the padding loop of
/// mihomo <c>transport/vless/vision/conn.go</c> and sing-vmess <c>vless_vision.go</c>:
/// padding ends on the first TLS application-data record, or — for traffic that
/// never looks like TLS — once the eight-packet filter window has almost run out.
/// </para>
/// <para>
/// <b>Documented limitation: the XTLS splice is not implemented.</b> The reference
/// can also answer <c>command = 2 (direct)</c>, after which it stops using the outer
/// TLS connection entirely and reads and writes raw bytes on the socket underneath
/// it (mihomo sets <c>netConn = tlsConn.NetConn()</c> and even reaches into the TLS
/// stack's own buffered <c>input</c>/<c>rawInput</c> by pointer; Xray does the same
/// through <c>UnwrapRawConn</c>). <see cref="SslStream"/> exposes neither the inner
/// stream nor its buffered input, so that half cannot be reproduced. This layer
/// therefore never emits <c>direct</c>, which is safe rather than divergent: the
/// server only switches to direct copy when the <em>client</em> asked for it, so it
/// keeps padding and un-padding normally and the traffic is simply carried inside
/// the outer TLS record layer instead of being spliced. A server that sends
/// <c>direct</c> anyway is refused with a clear error rather than mis-read.
/// </para>
/// </summary>
internal sealed class VlessVisionStream : Stream, IHalfCloseable
{
    /// <summary>Largest block content: the reference reshapes at <c>8192 - 21</c>.</summary>
    private const int ReshapeLimit = 8192 - VlessVision.FirstHeaderSize;

    private const byte TlsHandshakeTypeClientHello = 0x01;
    private const byte TlsHandshakeTypeServerHello = 0x02;

    private static readonly byte[] TlsClientHandshakeStart = [0x16, 0x03];
    private static readonly byte[] TlsServerHandshakeStart = [0x16, 0x03, 0x03];
    private static readonly byte[] TlsApplicationDataStart = [0x17, 0x03, 0x03];
    private static readonly byte[] Tls13SupportedVersions = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];

    private const string DirectModeMessage =
        "vless: the server asked to switch XTLS Vision to 'direct' copy mode. That mode writes and reads raw bytes on the socket "
        + "underneath the outer TLS, which System.Net.Security.SslStream cannot expose, so this build never requests it and cannot "
        + "honour it. Use a client that implements XTLS Vision, or drop 'flow' from the proxy.";

    private readonly Stream _inner;
    private readonly byte[] _uuid;
    private readonly Random _random;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly byte[] _header = new byte[VlessVision.FirstHeaderSize];
    private readonly byte[] _paddingSkip = new byte[4096];

    // Write side.
    private bool _writePadding = true;
    private bool _writeUuidPending = true;

    // Read side.
    private bool _readPadding = true;
    private bool _readUuidPending = true;
    private byte _readCommand = VlessVision.CommandContinue;
    private int _readContentRemaining;
    private int _readPaddingRemaining;
    private byte[] _passthrough = [];
    private int _passthroughOffset;

    // TLS-record filter state, shared by both directions exactly as in the reference.
    private int _packetsToFilter = 8;
    private bool _isTls;
    private bool _isTls12OrAbove;
    private int _remainingServerHello = -1;

    internal VlessVisionStream(Stream inner, ReadOnlySpan<byte> uuid, Random? random = null)
    {
        if (uuid.Length != VlessVision.UuidSize) throw new ArgumentException("uuid must be 16 bytes", nameof(uuid));
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _uuid = uuid.ToArray();
        _random = random ?? Random.Shared;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc cref="VlessTcpStream.ShutdownSend"/>
    public void ShutdownSend()
    {
        switch (_inner)
        {
            case IHalfCloseable halfCloseable:
                try { halfCloseable.ShutdownSend(); } catch { /* peer already gone */ }
                break;
            case ProxyStream nested:
                nested.ShutdownSend();
                break;
        }
    }

    // ── write ────────────────────────────────────────────────────────────────

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    /// <summary>
    /// Blocks on the asynchronous path so the block state machine has exactly one
    /// implementation; the tunnel's relay is asynchronous and never takes this one.
    /// </summary>
    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray()).AsTask().ConfigureAwait(false).GetAwaiter().GetResult();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_writePadding)
            {
                await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (buffer.IsEmpty)
            {
                await WriteBlockAsync(ReadOnlyMemory<byte>.Empty, VlessVision.CommandContinue, cancellationToken).ConfigureAwait(false);
                return;
            }

            FilterTls(buffer.Span);

            var offset = 0;
            while (offset < buffer.Length)
            {
                var length = Math.Min(buffer.Length - offset, ReshapeLimit);
                var piece = buffer.Slice(offset, length);

                byte command;
                if (_isTls && piece.Length > 6 && piece.Span[..3].SequenceEqual(TlsApplicationDataStart))
                {
                    command = VlessVision.CommandEnd;
                    _writePadding = false;
                }
                else if (!_isTls12OrAbove && _packetsToFilter <= 1)
                {
                    command = VlessVision.CommandEnd;
                    _writePadding = false;
                }
                else
                {
                    command = VlessVision.CommandContinue;
                }

                await WriteBlockAsync(piece, command, cancellationToken).ConfigureAwait(false);
                offset += length;

                if (!_writePadding) break;
            }

            if (offset < buffer.Length)
            {
                await _inner.WriteAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async ValueTask WriteBlockAsync(ReadOnlyMemory<byte> content, byte command, CancellationToken cancellationToken)
    {
        var paddingLength = VlessVision.NextPaddingLength(content.Length, _isTls, _random);
        var uuidLength = _writeUuidPending ? VlessVision.UuidSize : 0;
        var block = new byte[uuidLength + VlessVision.HeaderSize + content.Length + paddingLength];

        var offset = 0;
        if (_writeUuidPending)
        {
            _uuid.CopyTo(block, 0);
            offset += VlessVision.UuidSize;
            _writeUuidPending = false;
        }

        VlessVision.WriteHeader(block.AsSpan(offset), command, content.Length, paddingLength);
        offset += VlessVision.HeaderSize;
        content.Span.CopyTo(block.AsSpan(offset));
        offset += content.Length;

        // The padding carries no information — the receiver only skips it — and the
        // reference leaves the bytes uninitialised, so random is closer to its shape
        // than zeros would be.
        _random.NextBytes(block.AsSpan(offset, paddingLength));

        await _inner.WriteAsync(block, cancellationToken).ConfigureAwait(false);
    }

    // ── read ─────────────────────────────────────────────────────────────────

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    /// <inheritdoc cref="Write(ReadOnlySpan{byte})"/>
    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return 0;
        var rented = new byte[buffer.Length];
        var read = ReadAsync(rented).AsTask().ConfigureAwait(false).GetAwaiter().GetResult();
        rented.AsSpan(0, read).CopyTo(buffer);
        return read;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;

        while (true)
        {
            if (_passthroughOffset < _passthrough.Length)
            {
                var take = Math.Min(_passthrough.Length - _passthroughOffset, buffer.Length);
                _passthrough.AsSpan(_passthroughOffset, take).CopyTo(buffer.Span);
                _passthroughOffset += take;
                return take;
            }

            if (!_readPadding)
            {
                return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            }

            if (_readContentRemaining > 0)
            {
                var take = Math.Min(_readContentRemaining, buffer.Length);
                var read = await _inner.ReadAsync(buffer[..take], cancellationToken).ConfigureAwait(false);
                if (read <= 0) return read;
                _readContentRemaining -= read;
                FilterTls(buffer.Span[..read]);
                return read;
            }

            if (_readPaddingRemaining > 0)
            {
                var take = Math.Min(_readPaddingRemaining, _paddingSkip.Length);
                var read = await _inner.ReadAsync(_paddingSkip.AsMemory(0, take), cancellationToken).ConfigureAwait(false);
                if (read <= 0) return 0;
                _readPaddingRemaining -= read;
                continue;
            }

            if (_readCommand == VlessVision.CommandEnd)
            {
                _readPadding = false;
                continue;
            }

            if (!await ReadBlockHeaderAsync(cancellationToken).ConfigureAwait(false)) return 0;
        }
    }

    /// <summary>Reads one block header, or returns false when the stream ended cleanly at a block boundary.</summary>
    private async ValueTask<bool> ReadBlockHeaderAsync(CancellationToken cancellationToken)
    {
        if (_readUuidPending)
        {
            var filled = await FillAsync(_header, VlessVision.FirstHeaderSize, cancellationToken).ConfigureAwait(false);
            if (filled == 0) return false;
            if (filled < VlessVision.FirstHeaderSize)
            {
                throw new ClashException("vless: the server closed the connection inside the first XTLS Vision block header");
            }

            _readUuidPending = false;
            if (!_header.AsSpan(0, VlessVision.UuidSize).SequenceEqual(_uuid))
            {
                // Not our UUID: this server is not padding at all. sing-vmess's
                // unPadding hands such a buffer straight through, so stop un-padding
                // and replay the bytes that were only read to make the decision.
                _readPadding = false;
                _passthrough = _header[..VlessVision.FirstHeaderSize];
                _passthroughOffset = 0;
                return true;
            }

            return ParseBlockHeader(_header.AsSpan(VlessVision.UuidSize));
        }

        var read = await FillAsync(_header, VlessVision.HeaderSize, cancellationToken).ConfigureAwait(false);
        if (read == 0) return false;
        if (read < VlessVision.HeaderSize)
        {
            throw new ClashException("vless: the server closed the connection inside an XTLS Vision block header");
        }

        return ParseBlockHeader(_header.AsSpan(0, VlessVision.HeaderSize));
    }

    private bool ParseBlockHeader(ReadOnlySpan<byte> header)
    {
        if (!VlessVision.TryReadHeader(header, out var command, out var contentLength, out var paddingLength))
        {
            throw new ClashException($"vless: the server sent unknown XTLS Vision command {header[0]}");
        }

        if (command == VlessVision.CommandDirect)
        {
            throw new ClashException(DirectModeMessage);
        }

        _readCommand = command;
        _readContentRemaining = contentLength;
        _readPaddingRemaining = paddingLength;
        return true;
    }

    /// <summary>Fills <paramref name="destination"/> up to <paramref name="count"/> bytes; returns how many arrived.</summary>
    private async ValueTask<int> FillAsync(byte[] destination, int count, CancellationToken cancellationToken)
    {
        var filled = 0;
        while (filled < count)
        {
            var read = await _inner.ReadAsync(destination.AsMemory(filled, count - filled), cancellationToken).ConfigureAwait(false);
            if (read <= 0) break;
            filled += read;
        }

        return filled;
    }

    // ── TLS-record filter ────────────────────────────────────────────────────

    /// <summary>
    /// Ports the reference's <c>FilterTLS</c> (mihomo
    /// <c>transport/vless/vision/filter.go</c>, sing-vmess <c>filterTLS</c>): it
    /// watches the first eight buffers in both directions for a TLS ClientHello or
    /// ServerHello, which decides whether padding uses the long 900-byte target and
    /// when it may stop early.
    /// <para>
    /// The reference also records the negotiated cipher here so it can decide to
    /// splice; that half is deliberately absent because the splice is not
    /// implemented (see the type's remarks).
    /// </para>
    /// </summary>
    private void FilterTls(ReadOnlySpan<byte> buffer)
    {
        if (_packetsToFilter <= 0) return;
        _packetsToFilter--;

        var index = buffer.IndexOf(TlsServerHandshakeStart);
        if (index >= 0)
        {
            if (buffer.Length > index + 5 && buffer[0] == 22 && buffer[1] == 3 && buffer[2] == 3)
            {
                _isTls = true;
                if (buffer[5] == TlsHandshakeTypeServerHello)
                {
                    _isTls12OrAbove = true;
                    _remainingServerHello = BinaryPrimitives.ReadUInt16BigEndian(buffer[(index + 3)..]) + 5;
                }
            }
        }
        else
        {
            index = buffer.IndexOf(TlsClientHandshakeStart);
            if (index >= 0 && buffer.Length > index + 5 && buffer[index + 5] == TlsHandshakeTypeClientHello)
            {
                _isTls = true;
            }
        }

        if (_remainingServerHello <= 0) return;

        var start = index < 0 ? 0 : index;
        var end = _remainingServerHello;
        if (start + end > buffer.Length)
        {
            end = buffer.Length;
            _remainingServerHello -= end - start;
        }
        else
        {
            _remainingServerHello -= end;
            end += start;
        }

        if (buffer[start..end].IndexOf(Tls13SupportedVersions) >= 0)
        {
            _packetsToFilter = 0;
        }
        else if (_remainingServerHello <= 0)
        {
            _packetsToFilter = 0;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _writeLock.Dispose();
            try { _inner.Dispose(); } catch { /* already gone */ }
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        _writeLock.Dispose();
        try { await _inner.DisposeAsync().ConfigureAwait(false); } catch { /* already gone */ }
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// The <c>vless</c> adapter: a VLESS TCP stream over whatever transport the
/// composer builds for the entry.
/// <para>
/// <b>Options</b> are read under exactly the names a <c>vless://</c> share link and
/// a <c>proxies:</c> entry produce (<c>server</c>, <c>port</c>, <c>uuid</c>,
/// <c>tls</c>, <c>servername</c>, <c>flow</c>, <c>client-fingerprint</c>,
/// <c>skip-cert-verify</c>, <c>network</c>, <c>ws-opts</c>, <c>grpc-opts</c>,
/// <c>h2-opts</c>, <c>http-opts</c>). The transport layer already understands all
/// of them, so the whole entry map is handed to it unchanged, exactly as the
/// Shadowsocks adapter does — this adapter only adds the VLESS header.
/// </para>
/// <para>
/// <b>UDP</b> is carried over the same TCP connection in the classic "UDP over
/// TCP" form: the request header switches to command <c>0x02</c> with an empty
/// flow and every datagram is framed as <c>length(2, BE) || payload</c> (see
/// <see cref="VlessPacketConnection"/>). XTLS Vision is TCP-only, so a configured
/// <c>flow</c> is dropped for a UDP dial rather than applied to it.
/// </para>
/// </summary>
public sealed class VlessAdapter : OutboundAdapter
{
    private readonly byte[] _uuid;
    private readonly string? _flow;

    internal VlessAdapter(ProxyConfigEntry entry, AdapterBuildContext context, byte[] uuid, string? flow, bool udp)
        : base(entry, context, ProxyType.Vless, udp)
    {
        _uuid = uuid;
        _flow = flow;
    }

    /// <summary>Validates the entry and builds the adapter.</summary>
    internal static VlessAdapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var uuid = entry.Map.GetNonEmptyString("uuid");
        if (uuid is null)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (vless) requires a non-empty 'uuid'");
        }

        if (RequestsReality(entry.Map))
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (vless) requests REALITY (reality-opts), which this build cannot drive: REALITY needs a "
                + "ClientHello the client authors itself (a forged session id, a purpose-built X25519 key_share and an HMAC over "
                + "the ClientHello signed with the server's public key), while System.Net.Security.SslStream owns the record "
                + "layer and exposes no hook for any of that. Remove 'reality-opts', or terminate REALITY outside .NET.");
        }

        var flow = entry.Map.GetNonEmptyString("flow");
        if (flow is not null && !flow.Equals(VlessCrypto.FlowVision, StringComparison.Ordinal))
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (vless) has unsupported 'flow' [{flow}] (this build implements only "
                + $"'{VlessCrypto.FlowVision}', plus an empty flow for plain VLESS)");
        }

        return new VlessAdapter(entry, context, VlessIds.Parse(uuid), flow, entry.Map.GetBool("udp"));
    }

    /// <inheritdoc />
    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        var vision = _flow is not null;
        if (vision) RequireVisionConfiguration();

        var stream = await OpenRequestAsync(
            metadata,
            upstream,
            VlessCrypto.CommandTcp,
            vision ? _flow : null,
            cancellationToken).ConfigureAwait(false);

        return Complete(stream);
    }

    /// <inheritdoc />
    public override async Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (!UdpEnabled)
        {
            throw new NotSupportedException($"proxy [{Name}] of type [{TypeName}] has UDP disabled in its configuration");
        }

        // The flow is dropped rather than refused: XTLS Vision pads inside the outer
        // TLS records of a TCP stream and is defined for TCP only, and the reference
        // client sends an empty flow on a UDP connection even when the proxy entry
        // declares one. A node that sets `flow` for its TCP traffic therefore keeps
        // working for datagrams instead of failing the dial.
        var stream = await OpenRequestAsync(
            metadata,
            upstream: null,
            command: VlessCrypto.CommandUdp,
            flow: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        var connection = new VlessPacketConnection(stream, RemoteEndpoint(metadata));
        TrackConnection(new AsyncDisposeBridge(connection));
        return connection;
    }

    /// <summary>
    /// Opens the transport, writes the VLESS request header for
    /// <paramref name="command"/> and wraps the stream in the vision layer when
    /// <paramref name="flow"/> asks for it. TCP and UDP differ only in that command,
    /// in the flow and in the framing above this point, so both dials share this.
    /// </summary>
    private async Task<ProxyStream> OpenRequestAsync(
        Metadata metadata,
        Stream? upstream,
        byte command,
        string? flow,
        CancellationToken cancellationToken)
    {
        var raw = await OpenAsync(metadata, upstream, cancellationToken).ConfigureAwait(false);
        try
        {
            if (flow is not null) RequireVisionTransport(raw);

            var host = OutboundOptions.Destination(metadata);
            var addons = VlessCrypto.EncodeAddons(flow);
            var header = new byte[VlessWire.PrefixSize + addons.Length + 1 + 2 + VlessAddress.Size(host)];
            var written = VlessWire.WriteRequestHeader(
                header,
                _uuid,
                command,
                host,
                metadata.DestinationPort,
                addons);

            await raw.WriteAsync(header.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
            await raw.FlushAsync(cancellationToken).ConfigureAwait(false);

            // The response header is consumed before any padding block, so the vision
            // layer wraps it rather than the other way round — the reference order.
            // A UDP association has no padding at all, but the server still opens the
            // response with the same version/addons header, which VlessTcpStream eats
            // on the first read before the datagram frames begin.
            var framed = new VlessTcpStream(raw);
            Stream top = flow is null ? framed : new VlessVisionStream(framed, _uuid);
            return Wrap(top, raw);
        }
        catch (Exception ex)
        {
            await raw.DisposeAsync().ConfigureAwait(false);
            throw Fail(ex);
        }
    }

    /// <summary>
    /// The endpoint a datagram of this association came from: the destination the
    /// request header named, because no frame repeats it. A destination that is a
    /// name rather than an address has no endpoint to report, and the tunnel then
    /// falls back to the remote it keyed the session on.
    /// </summary>
    private static EndPoint? RemoteEndpoint(Metadata metadata)
        => IPAddress.TryParse(OutboundOptions.Destination(metadata), out var address)
            ? new IPEndPoint(address, metadata.DestinationPort)
            : null;

    /// <summary>
    /// XTLS Vision only exists for a plain TCP stream under TLS (Xray documents the
    /// flow as TCP-only, and the reference refuses a connection that is not TLS).
    /// </summary>
    private void RequireVisionConfiguration()
    {
        var network = (Options.GetNonEmptyString("network") ?? "tcp").Trim().ToLowerInvariant();
        if (!network.Equals("tcp", StringComparison.Ordinal))
        {
            throw Fail(new ClashException(
                $"proxy [{Name}] (vless) sets flow [{_flow}] with network [{network}]: XTLS Vision is defined only for "
                + "'network: tcp' over TLS, because its padding is keyed to the outer TLS records."));
        }

        if (!Options.GetBool("tls"))
        {
            throw Fail(new ClashException(
                $"proxy [{Name}] (vless) sets flow [{_flow}] without 'tls: true': XTLS Vision pads and un-pads inside a TLS 1.3 "
                + "outer connection, so plain VLESS cannot carry it."));
        }
    }

    /// <summary>Verifies the negotiated outer protocol when the transport exposes it.</summary>
    private void RequireVisionTransport(ProxyStream raw)
    {
        if (raw.Inner is SslStream ssl && ssl.SslProtocol != SslProtocols.Tls13)
        {
            throw Fail(new ClashException(
                $"proxy [{Name}] (vless) sets flow [{_flow}] but the outer TLS connection negotiated {ssl.SslProtocol}: XTLS "
                + "Vision requires TLS 1.3, which is the version the reference checks for before it will pad."));
        }
    }

    /// <summary>True when the entry carries a REALITY block with anything in it.</summary>
    private static bool RequestsReality(YamlMap map)
    {
        foreach (var (_, value) in map.GetMap("reality-opts").Raw)
        {
            if (value is null) continue;
            if (!string.IsNullOrWhiteSpace(Convert.ToString(value, CultureInfo.InvariantCulture))) return true;
        }

        return false;
    }
}

/// <summary>Builds <see cref="VlessAdapter"/> instances.</summary>
internal sealed class VlessAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "vless";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => [];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => VlessAdapter.Create(entry, context);
}
