using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The VMess destination address block: <c>ATYP || ADDR</c>.
/// <para>
/// VMess numbers its address types differently from SOCKS5 — <c>1</c> is IPv4,
/// <c>2</c> is a domain and <c>3</c> is IPv6, where SOCKS5 uses <c>3</c> for a
/// domain and <c>4</c> for IPv6 — so <see cref="Socks5Address"/> cannot be reused
/// here. The port does not belong to this block: the header carries it on its own,
/// ahead of the address type.
/// </para>
/// </summary>
internal static class VmessAddress
{
    /// <summary>ATYP for a 4-byte IPv4 literal.</summary>
    internal const byte TypeIpv4 = 0x01;

    /// <summary>ATYP for a length-prefixed domain name.</summary>
    internal const byte TypeDomain = 0x02;

    /// <summary>ATYP for a 16-byte IPv6 literal.</summary>
    internal const byte TypeIpv6 = 0x03;

    /// <summary>Bytes <see cref="Write"/> will need for <paramref name="host"/>.</summary>
    internal static int Size(string host)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (IPAddress.TryParse(host, out var address))
        {
            return 1 + (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 16 : 4);
        }

        var length = Encoding.UTF8.GetByteCount(host);
        if (length > Socks5Address.MaxDomainLength)
        {
            throw new ArgumentException($"domain name too long: {length} bytes", nameof(host));
        }

        return 1 + 1 + length;
    }

    /// <summary>Writes the address block and returns the number of bytes written.</summary>
    internal static int Write(Span<byte> destination, string host)
    {
        ArgumentNullException.ThrowIfNull(host);

        if (IPAddress.TryParse(host, out var address))
        {
            Span<byte> raw = stackalloc byte[16];
            if (!address.TryWriteBytes(raw, out var written)) throw new ArgumentException("unusable address", nameof(host));

            var required = 1 + written;
            if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

            destination[0] = written == 4 ? TypeIpv4 : TypeIpv6;
            raw[..written].CopyTo(destination[1..]);
            return required;
        }

        var length = Encoding.UTF8.GetByteCount(host);
        if (length > Socks5Address.MaxDomainLength)
        {
            throw new ArgumentException($"domain name too long: {length} bytes", nameof(host));
        }

        var size = 1 + 1 + length;
        if (destination.Length < size) throw new ArgumentException($"destination must be at least {size} bytes", nameof(destination));

        destination[0] = TypeDomain;
        destination[1] = (byte)length;
        Encoding.UTF8.GetBytes(host, destination[2..]);
        return size;
    }
}

/// <summary>
/// The VMess request header body, as it sits inside the sealed AEAD header.
/// <code>
/// version(1) | requestIV(16) | requestKey(16) | responseHeader(1) | option(1)
/// | (paddingLength &lt;&lt; 4 | security)(1) | 0x00(1) | command(1)
/// | port(2, big-endian) | addressType(1) | address | padding
/// | checksum(4, big-endian FNV-1a)
/// </code>
/// <para>
/// The port comes <em>before</em> the address type, and the padding length shares a
/// byte with the security because the low nibble is the cipher. This is
/// byte-for-byte what mihomo's <c>transport/vmess/conn.go</c> <c>sendRequest</c>
/// writes and what v2ray's <c>EncodeRequestHeader</c> writes with its
/// <c>PortThenAddress</c> address parser.
/// </para>
/// <para>
/// The command byte is <see cref="CommandTcp"/> for a TCP stream and
/// <see cref="CommandUdp"/> for a UDP association; nothing else in the header
/// changes between the two, so a UDP association is one TCP connection that
/// happens to say <c>0x02</c>.
/// </para>
/// </summary>
internal static class VmessRequestHeader
{
    /// <summary>The only protocol version this build speaks.</summary>
    internal const byte Version = 0x01;

    /// <summary>Chunked body with no chunk masking, no global padding and no authenticated length.</summary>
    internal const byte OptionChunkStream = 0x01;

    /// <summary>A single TCP stream.</summary>
    internal const byte CommandTcp = 0x01;

    /// <summary>
    /// A UDP association carried over the same TCP connection. The header is
    /// otherwise identical to the TCP one and every datagram is one body chunk,
    /// so the two commands share one handshake.
    /// </summary>
    internal const byte CommandUdp = 0x02;

    /// <summary>Width of the random request body IV and of the request body key.</summary>
    internal const int RequestBodyIvSize = 16;

    /// <summary>Width of the request body key. Always 16, even for ChaCha20-Poly1305.</summary>
    internal const int RequestBodyKeySize = 16;

    /// <summary>Exclusive upper bound the reference draws the padding length from.</summary>
    internal const int MaxPaddingLength = 16;

    /// <summary>FNV-1a offset basis.</summary>
    private const uint FnvOffsetBasis = 2166136261u;

    /// <summary>FNV-1a prime.</summary>
    private const uint FnvPrime = 16777619u;

    /// <summary>Bytes the body needs for a destination and <paramref name="paddingLength"/> padding bytes.</summary>
    internal static int BodySize(string host, int paddingLength)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (paddingLength is < 0 or >= MaxPaddingLength) throw new ArgumentOutOfRangeException(nameof(paddingLength));
        return 1 + RequestBodyIvSize + RequestBodyKeySize + 5 + 2 + VmessAddress.Size(host) + paddingLength + 4;
    }

    /// <summary>
    /// Writes the header body and returns the number of bytes written. The checksum
    /// covers every byte written before it, exactly as the protocol requires.
    /// <paramref name="command"/> is <see cref="CommandTcp"/> or
    /// <see cref="CommandUdp"/> and is the only byte that separates the two.
    /// </summary>
    internal static int WriteBody(
        Span<byte> destination,
        ReadOnlySpan<byte> requestBodyIv,
        ReadOnlySpan<byte> requestBodyKey,
        byte responseHeader,
        byte command,
        VmessSecurity security,
        string host,
        int port,
        ReadOnlySpan<byte> padding)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (requestBodyIv.Length != RequestBodyIvSize) throw new ArgumentException($"the request body IV must be {RequestBodyIvSize} bytes", nameof(requestBodyIv));
        if (requestBodyKey.Length != RequestBodyKeySize) throw new ArgumentException($"the request body key must be {RequestBodyKeySize} bytes", nameof(requestBodyKey));
        if (command is not (CommandTcp or CommandUdp)) throw new ArgumentOutOfRangeException(nameof(command), command, "the command must be 0x01 (TCP) or 0x02 (UDP)");
        if (padding.Length >= MaxPaddingLength) throw new ArgumentOutOfRangeException(nameof(padding), padding.Length, $"padding must be shorter than {MaxPaddingLength} bytes");
        if (port is < 0 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));

        var required = BodySize(host, padding.Length);
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        var offset = 0;
        destination[offset++] = Version;

        requestBodyIv.CopyTo(destination[offset..]);
        offset += requestBodyIv.Length;

        requestBodyKey.CopyTo(destination[offset..]);
        offset += requestBodyKey.Length;

        destination[offset++] = responseHeader;
        destination[offset++] = OptionChunkStream;
        destination[offset++] = (byte)((padding.Length << 4) | (byte)security);
        destination[offset++] = 0x00; // reserved
        destination[offset++] = command;

        BinaryPrimitives.WriteUInt16BigEndian(destination[offset..], (ushort)port);
        offset += 2;

        offset += VmessAddress.Write(destination[offset..], host);

        padding.CopyTo(destination[offset..]);
        offset += padding.Length;

        BinaryPrimitives.WriteUInt32BigEndian(destination[offset..], Fnv1a32(destination[..offset]));
        offset += 4;

        return offset;
    }

    /// <summary>The FNV-1a 32-bit hash the header checksum is defined as.</summary>
    internal static uint Fnv1a32(ReadOnlySpan<byte> bytes)
    {
        unchecked
        {
            var hash = FnvOffsetBasis;
            foreach (var b in bytes)
            {
                hash ^= b;
                hash *= FnvPrime;
            }

            return hash;
        }
    }
}

/// <summary>
/// The VMess chunked AEAD session: framing in both directions, with the server's
/// sealed response header consumed lazily on the first read.
/// <para>
/// The response header is validated on demand rather than during the dial because a
/// server is free to answer only after it has seen the client's first bytes;
/// reading it eagerly would deadlock that exchange. Once it has been checked, every
/// read decodes exactly one length-prefixed chunk.
/// </para>
/// <para>
/// A TCP flow drives this as a <see cref="Stream"/>, where a write is split across
/// as many chunks as it needs. A UDP association (<c>command 0x02</c>) drives it
/// through <see cref="WriteDatagramAsync"/> and <see cref="ReadDatagramAsync"/>
/// instead, where exactly one chunk is exactly one datagram; both share the same
/// chunk counters, because the counter is per connection and per direction, not
/// per chunk kind.
/// </para>
/// </summary>
internal sealed class VmessTcpStream : Stream
{
    private readonly Stream _inner;
    private readonly VmessSecurity _security;
    private readonly byte[] _requestKey;
    private readonly byte[] _requestIv;
    private readonly byte[] _responseKey;
    private readonly byte[] _responseIv;
    private readonly VmessAeadKeys _responseHeaderKeys;
    private readonly byte _responseHeader;
    private readonly byte[] _lengthBlock = new byte[VmessBody.LengthFieldSize];

    private byte[] _pending = [];
    private int _pendingOffset;
    private int _pendingLength;
    private ushort _writeCounter;
    private ushort _readCounter;
    private bool _responseHeaderRead;

    internal VmessTcpStream(
        Stream inner,
        VmessSecurity security,
        byte[] requestBodyKey,
        byte[] requestBodyIv,
        byte[] responseBodyKey,
        byte[] responseBodyIv,
        VmessAeadKeys responseHeaderKeys,
        byte responseHeader)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _security = security;
        _requestKey = VmessBody.DeriveKey(security, requestBodyKey ?? throw new ArgumentNullException(nameof(requestBodyKey)));
        _requestIv = requestBodyIv ?? throw new ArgumentNullException(nameof(requestBodyIv));
        _responseKey = VmessBody.DeriveKey(security, responseBodyKey ?? throw new ArgumentNullException(nameof(responseBodyKey)));
        _responseIv = responseBodyIv ?? throw new ArgumentNullException(nameof(responseBodyIv));
        _responseHeaderKeys = responseHeaderKeys ?? throw new ArgumentNullException(nameof(responseHeaderKeys));
        _responseHeader = responseHeader;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    /// <summary>
    /// The local endpoint of the transport underneath, when that transport reports
    /// one. A datagram association surfaces it as its
    /// <see cref="IPacketConnection.LocalEndPoint"/>.
    /// </summary>
    internal EndPoint? LocalEndPoint => (_inner as ProxyStream)?.LocalEndPoint;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (buffer.IsEmpty) return;

        var chunkPayload = VmessBody.MaxPayloadSize(_security);
        using var scratch = new PooledBuffer(VmessBody.FramedSize(_security, Math.Min(buffer.Length, chunkPayload)));
        while (!buffer.IsEmpty)
        {
            var chunk = Math.Min(buffer.Length, chunkPayload);
            var written = VmessBody.WriteChunk(_security, _requestKey, _requestIv, ref _writeCounter, buffer[..chunk], scratch.Span);
            _inner.Write(scratch.Array, 0, written);
            buffer = buffer[chunk..];
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return;

        var chunkPayload = VmessBody.MaxPayloadSize(_security);
        using var scratch = new PooledBuffer(VmessBody.FramedSize(_security, Math.Min(buffer.Length, chunkPayload)));
        var remaining = buffer;
        while (!remaining.IsEmpty)
        {
            var chunk = Math.Min(remaining.Length, chunkPayload);
            var written = VmessBody.WriteChunk(_security, _requestKey, _requestIv, ref _writeCounter, remaining.Span[..chunk], scratch.Span);
            await _inner.WriteAsync(scratch.Memory(written), cancellationToken).ConfigureAwait(false);
            remaining = remaining[chunk..];
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return 0;

        EnsureResponseHeader();

        while (_pendingOffset >= _pendingLength)
        {
            if (!ReadChunk()) return 0;
        }

        var take = Math.Min(buffer.Length, _pendingLength - _pendingOffset);
        _pending.AsSpan(_pendingOffset, take).CopyTo(buffer);
        _pendingOffset += take;
        return take;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;

        await EnsureResponseHeaderAsync(cancellationToken).ConfigureAwait(false);

        while (_pendingOffset >= _pendingLength)
        {
            if (!await ReadChunkAsync(cancellationToken).ConfigureAwait(false)) return 0;
        }

        var take = Math.Min(buffer.Length, _pendingLength - _pendingOffset);
        _pending.AsSpan(_pendingOffset, take).CopyTo(buffer.Span);
        _pendingOffset += take;
        return take;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>
    /// Writes one datagram as exactly one body chunk.
    /// <para>
    /// Unlike <see cref="WriteAsync(Memory{byte},CancellationToken)"/> this never
    /// splits the payload: a datagram that went out as two chunks would reach the
    /// peer as two datagrams, because the peer has no other way to find a boundary.
    /// A datagram that cannot fit one chunk is therefore refused rather than
    /// silently broken in two.
    /// </para>
    /// </summary>
    internal async ValueTask WriteDatagramAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        var maximum = VmessBody.MaxPayloadSize(_security);
        if (payload.Length > maximum)
        {
            throw new ClashException($"vmess: a {payload.Length}-byte datagram does not fit the {maximum} bytes one chunk can carry");
        }

        using var scratch = new PooledBuffer(VmessBody.FramedSize(_security, payload.Length));
        var written = VmessBody.WriteChunk(_security, _requestKey, _requestIv, ref _writeCounter, payload.Span, scratch.Span);
        await _inner.WriteAsync(scratch.Memory(written), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads exactly one body chunk as exactly one datagram, unlike
    /// <see cref="ReadAsync(Memory{byte},CancellationToken)"/>, which may hand back
    /// part of a chunk and leave the rest pending: a partial datagram would be
    /// indistinguishable from the next one.
    /// </summary>
    /// <returns>The datagram length, or 0 when the peer closed the association.</returns>
    internal async ValueTask<int> ReadDatagramAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        await EnsureResponseHeaderAsync(cancellationToken).ConfigureAwait(false);

        // Nothing is ever left pending here: the previous call consumed its whole
        // chunk. A zero-length frame is the reference's end-of-stream marker, so 0
        // means the association is gone rather than "an empty datagram arrived".
        if (_pendingOffset >= _pendingLength && !await ReadChunkAsync(cancellationToken).ConfigureAwait(false)) return 0;

        var length = _pendingLength - _pendingOffset;
        if (length > buffer.Length)
        {
            throw new ClashException($"vmess: a {length}-byte datagram does not fit the caller's {buffer.Length}-byte buffer");
        }

        _pending.AsSpan(_pendingOffset, length).CopyTo(buffer.Span);
        _pendingOffset += length;
        return length;
    }

    /// <summary>
    /// Consumes the sealed response header and checks that the server echoed the
    /// response header byte the request carried. That echo is the only proof the
    /// peer understood the request, so a mismatch is a hard failure; a non-zero
    /// command is rejected because this build cannot act on one.
    /// </summary>
    private async ValueTask EnsureResponseHeaderAsync(CancellationToken cancellationToken)
    {
        if (_responseHeaderRead) return;
        _responseHeaderRead = true;

        var lengthFrame = new byte[VmessBody.LengthFieldSize + VmessCrypto.TagSize];
        await OutboundIo.ReadExactlyAsync(_inner, lengthFrame, cancellationToken).ConfigureAwait(false);

        var bodyLength = ReadResponseBodyLength(lengthFrame);
        var frame = new byte[lengthFrame.Length + bodyLength + VmessCrypto.TagSize];
        lengthFrame.CopyTo(frame, 0);
        await OutboundIo.ReadExactlyAsync(_inner, frame.AsMemory(lengthFrame.Length), cancellationToken).ConfigureAwait(false);

        CheckResponseHeader(frame);
    }

    /// <inheritdoc cref="EnsureResponseHeaderAsync"/>
    private void EnsureResponseHeader()
    {
        if (_responseHeaderRead) return;
        _responseHeaderRead = true;

        var lengthFrame = new byte[VmessBody.LengthFieldSize + VmessCrypto.TagSize];
        OutboundIo.ReadExactly(_inner, lengthFrame);

        var bodyLength = ReadResponseBodyLength(lengthFrame);
        var frame = new byte[lengthFrame.Length + bodyLength + VmessCrypto.TagSize];
        lengthFrame.CopyTo(frame, 0);
        OutboundIo.ReadExactly(_inner, frame.AsSpan(lengthFrame.Length));

        CheckResponseHeader(frame);
    }

    private int ReadResponseBodyLength(ReadOnlySpan<byte> lengthFrame)
    {
        Span<byte> plaintext = stackalloc byte[VmessBody.LengthFieldSize];
        if (!VmessCrypto.Decrypt(_responseHeaderKeys.LengthKey, _responseHeaderKeys.LengthIv, lengthFrame, plaintext))
        {
            throw new ClashException("vmess: the response header length failed authentication");
        }

        return BinaryPrimitives.ReadUInt16BigEndian(plaintext);
    }

    private void CheckResponseHeader(ReadOnlySpan<byte> frame)
    {
        if (!VmessCrypto.TryOpenHeader(frame, _responseHeaderKeys, out _, out var body))
        {
            throw new ClashException("vmess: the response header failed authentication");
        }

        // [responseHeader(1)][option(1)][command(1)][commandLength(1)][command]
        if (body.Length < 4)
        {
            throw new ClashException("vmess: the response header is shorter than the fixed four bytes");
        }

        if (body[0] != _responseHeader)
        {
            throw new ClashException("vmess: the server did not echo the response header byte from the request");
        }

        if (body[2] != 0)
        {
            throw new ClashException($"vmess: the server sent response command {body[2]}, which this build cannot act on");
        }
    }

    /// <summary>
    /// Reads one chunk: the plaintext length field, then the sealed payload. A
    /// zero-length chunk is the reference client's end-of-stream marker.
    /// </summary>
    private bool ReadChunk()
    {
        if (!ReadExactlyOrEof(_lengthBlock)) return false;
        if (!VmessBody.TryReadChunkLength(_lengthBlock, out var framed)) return false;
        if (framed == 0) return false;
        if (framed > VmessBody.MaxChunkSize)
        {
            throw new ClashException($"vmess: chunk length {framed} exceeds the {VmessBody.MaxChunkSize}-byte limit");
        }

        if (_pending.Length < framed) _pending = new byte[framed];
        if (!ReadExactlyOrEof(_pending.AsSpan(0, framed))) return false;
        if (!VmessBody.TryReadChunkPayload(
                _security,
                _responseKey,
                _responseIv,
                ref _readCounter,
                _pending.AsSpan(0, framed),
                framed,
                _pending))
        {
            throw new ClashException("vmess: chunk payload failed authentication");
        }

        _pendingOffset = 0;
        _pendingLength = framed - VmessBody.TagSize(_security);
        return true;
    }

    /// <inheritdoc cref="ReadChunk"/>
    private async ValueTask<bool> ReadChunkAsync(CancellationToken cancellationToken)
    {
        if (!await ReadExactlyOrEofAsync(_lengthBlock, cancellationToken).ConfigureAwait(false)) return false;
        if (!VmessBody.TryReadChunkLength(_lengthBlock, out var framed)) return false;
        if (framed == 0) return false;
        if (framed > VmessBody.MaxChunkSize)
        {
            throw new ClashException($"vmess: chunk length {framed} exceeds the {VmessBody.MaxChunkSize}-byte limit");
        }

        if (_pending.Length < framed) _pending = new byte[framed];
        if (!await ReadExactlyOrEofAsync(_pending.AsMemory(0, framed), cancellationToken).ConfigureAwait(false)) return false;
        if (!VmessBody.TryReadChunkPayload(
                _security,
                _responseKey,
                _responseIv,
                ref _readCounter,
                _pending.AsSpan(0, framed),
                framed,
                _pending))
        {
            throw new ClashException("vmess: chunk payload failed authentication");
        }

        _pendingOffset = 0;
        _pendingLength = framed - VmessBody.TagSize(_security);
        return true;
    }

    /// <summary>Reads exactly <paramref name="destination"/>, reporting a clean end of stream.</summary>
    private bool ReadExactlyOrEof(Span<byte> destination)
    {
        var read = 0;
        while (read < destination.Length)
        {
            var n = _inner.Read(destination[read..]);
            if (n <= 0) return false;
            read += n;
        }

        return true;
    }

    /// <inheritdoc cref="ReadExactlyOrEof"/>
    private async ValueTask<bool> ReadExactlyOrEofAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < destination.Length)
        {
            var n = await _inner.ReadAsync(destination[read..], cancellationToken).ConfigureAwait(false);
            if (n <= 0) return false;
            read += n;
        }

        return true;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

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
/// A VMess UDP association: one datagram per body chunk in both directions, over
/// the TCP connection the <c>0x02</c> request header opened.
/// <para>
/// The destination is named once, in the request header, and the peer's chunks
/// carry no address — so this is a one-destination association, exactly like the
/// connected-socket one the direct outbound uses: <see cref="SendAsync"/> ignores
/// the endpoint the caller passes and <see cref="ReceiveAsync"/> reports the
/// endpoint the association was dialled for.
/// </para>
/// </summary>
internal sealed class VmessPacketConnection : IPacketConnection
{
    private readonly VmessTcpStream _stream;
    private readonly EndPoint? _destination;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private EndPoint? _lastDestination;
    private bool _disposed;

    /// <param name="stream">The framed session, which this instance owns.</param>
    /// <param name="destination">
    /// The destination the request header named, when it is an address literal. A
    /// domain destination is left null because the peer's replies cannot name it
    /// either, and the caller keeps its own record of the flow's remote.
    /// </param>
    internal VmessPacketConnection(VmessTcpStream stream, EndPoint? destination)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _destination = destination;
    }

    /// <inheritdoc />
    /// <remarks>
    /// False: the request header fixes the destination, so the caller must keep one
    /// association per remote.
    /// </remarks>
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

        // The chunk counter advances per write, so two datagrams racing each other
        // would interleave their frames and corrupt the stream.
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _stream.WriteDatagramAsync(payload, cancellationToken).ConfigureAwait(false);
            _lastDestination = destination;
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
        var length = await _stream.ReadDatagramAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (length == 0)
        {
            // A zero-length chunk is the reference's end-of-stream marker, so this
            // is a closed association rather than an empty datagram.
            throw new ClashException("vmess: the UDP association was closed by the server");
        }

        return new PacketResult(length, _destination ?? _lastDestination);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _sendLock.Dispose();
        await _stream.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// The <c>vmess</c> adapter: the VMess AEAD handshake (sealed AuthID, an 8-byte
/// connection nonce and a sealed request header) over whatever transport stack the
/// composer built from the entry's <c>network</c>/<c>tls</c> options.
/// <para>
/// <b>What is covered.</b> TCP with the AEAD header and the chunked AEAD body over
/// <c>tcp</c>, <c>ws</c>, <c>grpc</c>, <c>h2</c> and <c>http</c>, with or without
/// TLS, for <c>aes-128-gcm</c>, <c>chacha20-poly1305</c> and <c>none</c>. UDP rides
/// the same connection with the same framing: the header's command byte is
/// <c>0x02</c> instead of <c>0x01</c> and one datagram is one body chunk.
/// <c>alterId</c> is accepted and ignored, because it only selects the legacy
/// header.
/// </para>
/// <para>
/// <b>What is not covered.</b> The legacy (non-AEAD) header that <c>alterId &gt; 0</c>
/// with an old <c>aes-128-cfb</c> server needs, and mux. UDP follows the entry's
/// <c>udp</c> flag: <see cref="DialUdpAsync"/> refuses when the configuration did
/// not ask for it.
/// </para>
/// </summary>
public sealed class VmessAdapter : OutboundAdapter
{
    private readonly byte[] _uuid;
    private readonly byte[] _cmdKey;
    private readonly VmessSecurity _security;

    internal VmessAdapter(ProxyConfigEntry entry, AdapterBuildContext context, byte[] uuid, VmessSecurity security, bool udp)
        : base(entry, context, ProxyType.Vmess, udp)
    {
        _uuid = uuid;
        _cmdKey = VmessCrypto.CommandKey(uuid);
        _security = security;
    }

    /// <summary>Validates the entry and builds the adapter.</summary>
    internal static VmessAdapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var text = entry.Map.GetNonEmptyString("uuid");
        if (text is null)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (vmess) requires a non-empty 'uuid'");
        }

        byte[] uuid;
        try
        {
            uuid = ClashHex.ParseUuid(text);
        }
        catch (FormatException)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (vmess) has a malformed 'uuid' ({text}); expected 32 hex digits, optionally dash-separated");
        }

        var adapter = new VmessAdapter(entry, context, uuid, ParseSecurity(entry), entry.Map.GetBool("udp"));

        var alterId = entry.Map.GetInt("alterId", entry.Map.GetInt("alter-id"));
        if (alterId > 0)
        {
            // AEAD servers ignore alterId; only the legacy header uses it, and that
            // header is out of scope here.
            adapter.Logger.LogDebug(
                "proxy [{Name}] (vmess) sets alterId {AlterId}; it is ignored because this adapter always speaks the AEAD header",
                entry.Name,
                alterId);
        }

        return adapter;
    }

    /// <summary>Maps <c>cipher</c>/<c>security</c> onto the body cipher the header advertises.</summary>
    private static VmessSecurity ParseSecurity(ProxyConfigEntry entry)
    {
        var text = entry.Map.GetNonEmptyString("cipher") ?? entry.Map.GetNonEmptyString("security");
        return (text ?? "auto").Trim().ToLowerInvariant() switch
        {
            "auto" or "aes-128-gcm" => VmessSecurity.Aes128Gcm,
            "chacha20-poly1305" => VmessSecurity.ChaCha20Poly1305,
            "none" or "zero" => VmessSecurity.None,
            "aes-128-cfb" => throw new ProxyCreationException(
                $"proxy [{entry.Name}] (vmess) asks for cipher 'aes-128-cfb', which is the legacy header's cipher; "
                + "this adapter only speaks the AEAD header, so use 'auto', 'aes-128-gcm', 'chacha20-poly1305' or 'none'"),
            var other => throw new ProxyCreationException(
                $"proxy [{entry.Name}] (vmess) has an unsupported cipher '{other}'; "
                + "expected 'auto', 'aes-128-gcm', 'chacha20-poly1305' or 'none'"),
        };
    }

    /// <inheritdoc />
    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        var session = await HandshakeAsync(metadata, VmessRequestHeader.CommandTcp, upstream, cancellationToken)
            .ConfigureAwait(false);

        return Complete(Wrap(Frame(session), session.Raw));
    }

    /// <inheritdoc />
    /// <remarks>
    /// VMess carries UDP over the same TCP connection as TCP, with the same chunked
    /// AEAD body: the request header is identical except for the command byte, and
    /// each datagram is exactly one body chunk. The destination travels in the
    /// request header, so this is a one-destination association and the caller —
    /// <c>UdpSession</c> in the tunnel — caches one per remote endpoint.
    /// </remarks>
    public override async Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (!UdpEnabled)
        {
            throw new NotSupportedException($"proxy [{Name}] of type [{TypeName}] has UDP disabled in its configuration");
        }

        var session = await HandshakeAsync(metadata, VmessRequestHeader.CommandUdp, null, cancellationToken)
            .ConfigureAwait(false);

        var connection = new VmessPacketConnection(Frame(session), DestinationEndpoint(metadata));
        TrackConnection(new AsyncDisposeBridge(connection));
        return connection;
    }

    /// <summary>
    /// One VMess session as it stands once the request header has been written: the
    /// transport and the key material both directions need afterwards.
    /// </summary>
    private readonly record struct VmessSession(
        ProxyStream Raw,
        byte[] RequestBodyKey,
        byte[] RequestBodyIv,
        byte[] ResponseBodyKey,
        byte[] ResponseBodyIv,
        VmessAeadKeys ResponseHeaderKeys,
        byte ResponseHeader);

    /// <summary>
    /// Opens the transport and performs the AEAD handshake with
    /// <paramref name="command"/> in the request header. TCP and UDP differ in that
    /// byte and nowhere else, so both dials share this.
    /// <para>
    /// The caller owns the returned transport; on failure it is already disposed.
    /// </para>
    /// </summary>
    private async Task<VmessSession> HandshakeAsync(
        Metadata metadata,
        byte command,
        Stream? upstream,
        CancellationToken cancellationToken)
    {
        var raw = await OpenAsync(metadata, upstream, cancellationToken).ConfigureAwait(false);
        try
        {
            var host = OutboundOptions.Destination(metadata);

            // Both the IV and the key are 16 bytes even for ChaCha20-Poly1305: the
            // reference expands the 32-byte ChaCha key from the 16-byte one, and the
            // security byte sits behind the key so a peer could not parse a
            // variable-width field.
            var requestBodyKey = RandomNumberGenerator.GetBytes(VmessRequestHeader.RequestBodyKeySize);
            var requestBodyIv = RandomNumberGenerator.GetBytes(VmessRequestHeader.RequestBodyIvSize);
            var responseHeader = (byte)RandomNumberGenerator.GetInt32(1, 256);

            // The reference picks a random padding length in [0, 16) and pads the
            // header with that many random bytes; zero is the common case.
            var paddingLength = RandomNumberGenerator.GetInt32(0, VmessRequestHeader.MaxPaddingLength);
            var padding = paddingLength == 0 ? [] : RandomNumberGenerator.GetBytes(paddingLength);

            var body = new byte[VmessRequestHeader.BodySize(host, padding.Length)];
            var bodyLength = VmessRequestHeader.WriteBody(
                body,
                requestBodyIv,
                requestBodyKey,
                responseHeader,
                command,
                _security,
                host,
                metadata.DestinationPort,
                padding);

            var authIdPlaintext = new byte[VmessCrypto.AuthIdSize];
            VmessCrypto.BuildAuthIdPlaintext(
                authIdPlaintext,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                RandomNumberGenerator.GetBytes(4));

            var authId = new byte[VmessCrypto.AuthIdSize];
            VmessCrypto.SealAuthId(_uuid, authIdPlaintext, authId);

            var connectionNonce = RandomNumberGenerator.GetBytes(VmessCrypto.ConnectionNonceSize);
            var preamble = VmessCrypto.SealRequestHeader(_cmdKey, authId, connectionNonce, body.AsSpan(0, bodyLength));

            // AuthID, the sealed length, the connection nonce and the sealed body
            // travel as one write so a server never sees a half-open handshake.
            await raw.WriteAsync(preamble, cancellationToken).ConfigureAwait(false);
            await raw.FlushAsync(cancellationToken).ConfigureAwait(false);

            // The response direction never sees the request body key, so both peers
            // derive it from the request body key and IV the header carried.
            var (responseBodyKey, responseBodyIv) = VmessCrypto.DeriveResponseBodyKeys(requestBodyKey, requestBodyIv);
            return new VmessSession(
                raw,
                requestBodyKey,
                requestBodyIv,
                responseBodyKey,
                responseBodyIv,
                VmessCrypto.DeriveResponseHeaderKeys(responseBodyKey, responseBodyIv),
                responseHeader);
        }
        catch (Exception ex)
        {
            await raw.DisposeAsync().ConfigureAwait(false);
            throw Fail(ex);
        }
    }

    /// <summary>Wraps a session's transport in the chunked AEAD framing both commands share.</summary>
    private VmessTcpStream Frame(VmessSession session)
        => new(
            session.Raw,
            _security,
            session.RequestBodyKey,
            session.RequestBodyIv,
            session.ResponseBodyKey,
            session.ResponseBodyIv,
            session.ResponseHeaderKeys,
            session.ResponseHeader);

    /// <summary>
    /// The endpoint a UDP association's replies are attributed to. VMess names the
    /// destination only in the request header and the peer's chunks carry no
    /// address, so the association answers with the destination it was dialled for;
    /// a name rather than an address literal is left to the caller's own record of
    /// the flow, because the packet contract's remote is an <see cref="EndPoint"/>.
    /// </summary>
    private static EndPoint? DestinationEndpoint(Metadata metadata)
        => IPAddress.TryParse(OutboundOptions.Destination(metadata), out var address)
            ? new IPEndPoint(address, metadata.DestinationPort)
            : null;
}

/// <summary>Builds <see cref="VmessAdapter"/> instances.</summary>
internal sealed class VmessAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "vmess";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => [];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => VmessAdapter.Create(entry, context);
}
