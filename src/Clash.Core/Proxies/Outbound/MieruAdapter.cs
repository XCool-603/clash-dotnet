using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The mieru segment metadata: a fixed 32-byte block that appears in every
/// segment, encrypted and tagged like any other payload. It is what makes the
/// stream self-framing — <c>payload length</c>, <c>prefix length</c> and
/// <c>suffix length</c> tell the receiver exactly how many bytes follow, so no
/// outer length prefix is needed on the wire.
/// <para>
/// Offsets are from the protocol document's two metadata tables; the low-entropy
/// extension (protocol types 10/11) reuses the tail of the data table and is not
/// implemented here.
/// </para>
/// </summary>
internal static class MieruSegment
{
    /// <summary><c>openSessionRequest</c>: opens a session, carries at most 1024 payload bytes.</summary>
    internal const byte OpenSessionRequest = 2;

    /// <summary><c>openSessionResponse</c>: the peer's answer to an open request.</summary>
    internal const byte OpenSessionResponse = 3;

    /// <summary><c>closeSessionRequest</c>.</summary>
    internal const byte CloseSessionRequest = 4;

    /// <summary><c>closeSessionResponse</c>.</summary>
    internal const byte CloseSessionResponse = 5;

    /// <summary><c>dataClientToServer</c>.</summary>
    internal const byte DataClientToServer = 6;

    /// <summary><c>dataServerToClient</c>.</summary>
    internal const byte DataServerToClient = 7;

    /// <summary><c>ackClientToServer</c>: an explicit acknowledgement.</summary>
    internal const byte AckClientToServer = 8;

    /// <summary><c>ackServerToClient</c>: an explicit acknowledgement.</summary>
    internal const byte AckServerToClient = 9;

    /// <summary><c>dataClientToServerLowEntropy</c>; not implemented.</summary>
    internal const byte DataClientToServerLowEntropy = 10;

    /// <summary><c>dataServerToClientLowEntropy</c>; not implemented.</summary>
    internal const byte DataServerToClientLowEntropy = 11;

    /// <summary>
    /// Largest application fragment on the TCP underlay (<c>maxPDU = 32 * 1024</c>).
    /// The 16-bit <c>payload length</c> field could describe more, but a larger
    /// fragment would not match the reference's split.
    /// </summary>
    internal const int MaxFragment = 32 * 1024;

    /// <summary>A session segment (types 2-5) carries at most 1024 payload bytes.</summary>
    internal const int SessionPayloadLimit = 1024;

    /// <summary>
    /// The receive window this client advertises, in segments. Flow control on the
    /// TCP underlay is advisory here: reads are never throttled on purpose, so the
    /// window is simply large enough that a peer never stalls on us.
    /// </summary>
    internal const ushort WindowSegments = 256;

    // Session metadata (types 2-5): protocol type | unused | timestamp | session id
    // | sequence number | status code | payload length | suffix length | unused.
    internal const int TimestampOffset = 2;
    internal const int SessionIdOffset = 6;
    internal const int SequenceOffset = 10;
    internal const int StatusCodeOffset = 14;
    internal const int SessionPayloadLengthOffset = 15;
    internal const int SessionSuffixLengthOffset = 17;

    // Data metadata (types 6-9): the same head, then unacknowledged sequence
    // number | window size | fragment number | prefix length | payload length
    // | suffix length | unused.
    internal const int UnacknowledgedOffset = 14;
    internal const int WindowOffset = 18;
    internal const int FragmentNumberOffset = 20;
    internal const int PrefixLengthOffset = 21;
    internal const int PayloadLengthOffset = 22;
    internal const int SuffixLengthOffset = 24;

    /// <summary>True for the four session-level protocol types.</summary>
    internal static bool IsSession(byte type) => type is >= OpenSessionRequest and <= CloseSessionResponse;

    /// <summary>True for the four data/ack protocol types this client understands.</summary>
    internal static bool IsData(byte type)
        => type is DataClientToServer or DataServerToClient or AckClientToServer or AckServerToClient;

    /// <summary>True for the two protocol types that end a session.</summary>
    internal static bool IsClose(byte type) => type is CloseSessionRequest or CloseSessionResponse;

    /// <summary>
    /// Writes session metadata for <paramref name="payloadLength"/> payload bytes.
    /// Session metadata has no <c>prefix length</c> field at all, so a session
    /// segment can never carry <c>padding 1</c>.
    /// </summary>
    internal static void WriteSessionMetadata(
        Span<byte> metadata,
        byte type,
        uint sessionId,
        uint sequenceNumber,
        int payloadLength)
    {
        metadata.Clear();
        metadata[0] = type;
        BinaryPrimitives.WriteUInt32BigEndian(metadata[TimestampOffset..], CurrentMinutes());
        BinaryPrimitives.WriteUInt32BigEndian(metadata[SessionIdOffset..], sessionId);
        BinaryPrimitives.WriteUInt32BigEndian(metadata[SequenceOffset..], sequenceNumber);
        metadata[StatusCodeOffset] = 0; // statusOK; only quota exhaustion uses another value
        BinaryPrimitives.WriteUInt16BigEndian(metadata[SessionPayloadLengthOffset..], (ushort)payloadLength);
        metadata[SessionSuffixLengthOffset] = 0; // no padding 2
    }

    /// <summary>
    /// Writes data metadata for <paramref name="payloadLength"/> payload bytes. This
    /// client emits no padding of any kind — neither reference writer emits
    /// <c>padding 0</c>, and <c>padding 1</c>/<c>padding 2</c> are optional entropy
    /// shaping — so both length fields are zero and the payload follows the
    /// encrypted metadata immediately.
    /// </summary>
    internal static void WriteDataMetadata(
        Span<byte> metadata,
        byte type,
        uint sessionId,
        uint sequenceNumber,
        uint unacknowledgedSequenceNumber,
        int payloadLength)
    {
        metadata.Clear();
        metadata[0] = type;
        BinaryPrimitives.WriteUInt32BigEndian(metadata[TimestampOffset..], CurrentMinutes());
        BinaryPrimitives.WriteUInt32BigEndian(metadata[SessionIdOffset..], sessionId);
        BinaryPrimitives.WriteUInt32BigEndian(metadata[SequenceOffset..], sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(metadata[UnacknowledgedOffset..], unacknowledgedSequenceNumber);
        BinaryPrimitives.WriteUInt16BigEndian(metadata[WindowOffset..], WindowSegments);
        metadata[FragmentNumberOffset] = 0; // counts down; 0 marks the last fragment of a PDU
        metadata[PrefixLengthOffset] = 0;   // no padding 1
        BinaryPrimitives.WriteUInt16BigEndian(metadata[PayloadLengthOffset..], (ushort)payloadLength);
        metadata[SuffixLengthOffset] = 0;   // no padding 2
    }

    /// <summary>
    /// Parses the length fields of a decrypted metadata block. Returns false with a
    /// message for the types this client cannot honour (low-entropy mode, or a type
    /// outside the two tables).
    /// </summary>
    internal static bool TryParse(ReadOnlySpan<byte> metadata, out MieruMetadata parsed, out string? error)
    {
        parsed = default;
        error = null;

        if (metadata.Length < MieruCrypto.MetadataSize)
        {
            error = $"metadata shorter than {MieruCrypto.MetadataSize} bytes";
            return false;
        }

        var type = metadata[0];
        var sequence = BinaryPrimitives.ReadUInt32BigEndian(metadata[SequenceOffset..]);

        if (IsSession(type))
        {
            parsed = new MieruMetadata(
                type,
                sequence,
                PrefixLength: 0,
                PayloadLength: BinaryPrimitives.ReadUInt16BigEndian(metadata[SessionPayloadLengthOffset..]),
                SuffixLength: metadata[SessionSuffixLengthOffset]);
            return true;
        }

        if (IsData(type))
        {
            parsed = new MieruMetadata(
                type,
                sequence,
                PrefixLength: metadata[PrefixLengthOffset],
                PayloadLength: BinaryPrimitives.ReadUInt16BigEndian(metadata[PayloadLengthOffset..]),
                SuffixLength: metadata[SuffixLengthOffset]);
            return true;
        }

        error = type is DataClientToServerLowEntropy or DataServerToClientLowEntropy
            ? $"the peer selected low-entropy mode (protocol type {type}), which this client does not implement"
            : $"unknown protocol type {type}";
        return false;
    }

    /// <summary>Minutes since the Unix epoch, as the metadata timestamp field wants it.</summary>
    private static uint CurrentMinutes()
        => (uint)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60);
}

/// <summary>The three length fields that describe the rest of a segment.</summary>
internal readonly record struct MieruMetadata(
    byte Type,
    uint Sequence,
    int PrefixLength,
    int PayloadLength,
    int SuffixLength);

/// <summary>
/// The mieru TCP underlay: a duplex stream of AEAD segments over one plain TCP
/// connection.
/// <para>
/// <b>Framing.</b> A segment is <c>[nonce?] || encrypted metadata (32) || tag (16)
/// || padding 1 || encrypted payload || tag (16) || padding 2</c>. This client
/// emits no padding, and the nonce appears only in the first segment of each
/// direction, so in practice a segment is 48 bytes plus, when there is payload,
/// the payload and its tag.
/// </para>
/// <para>
/// <b>Nonce discipline.</b> The first segment of each direction carries the nonce
/// in the clear; every AEAD operation after that advances a big-endian counter, and
/// the metadata and the payload of one segment consume <em>separate</em> steps.
/// That is why the write side increments between the two encryptions rather than
/// once per segment, and why the read side does the same between the two
/// decryptions.
/// </para>
/// <para>
/// <b>Not implemented.</b> Low-entropy mode (protocol types 10/11) and explicit
/// <c>ack*</c> segments. Acknowledgements are implicit: every outgoing data
/// segment repeats the highest sequence number seen from the peer in its
/// <c>unacknowledged sequence number</c> field. The UDP underlay — which needs a
/// real reliability layer on top of the same framing — is not implemented at all;
/// see <see cref="MieruAdapter.DialUdpAsync"/>.
/// </para>
/// </summary>
internal sealed class MieruTcpStream : Stream
{
    private readonly Stream _inner;
    private readonly byte[] _key;
    private readonly uint _sessionId;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private readonly byte[] _writeMetadata = new byte[MieruCrypto.MetadataSize];
    private readonly byte[] _writeNonce = new byte[MieruCrypto.NonceSize];
    private readonly byte[] _readMetadata = new byte[MieruCrypto.MetadataSize];
    private readonly byte[] _readMetadataSealed = new byte[MieruCrypto.EncryptedMetadataSize];
    private readonly byte[] _readNonce = new byte[MieruCrypto.NonceSize];
    private readonly byte[] _scratch = new byte[512];

    private byte[] _pending = [];
    private int _pendingOffset;
    private uint _writeSequence;
    private uint _peerSequence;
    private bool _wroteFirstSegment;
    private bool _readFirstSegment;
    private bool _peerClosed;
    private bool _disposed;

    /// <summary>
    /// Wraps <paramref name="inner"/> in the mieru segment layer. The key is the
    /// connection key from <see cref="MieruCrypto.DeriveKey"/>; the write nonce is
    /// drawn once here, because it is sent in the clear with the first segment.
    /// </summary>
    internal MieruTcpStream(Stream inner, byte[] key, string username, uint sessionId)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(username);
        if (key.Length != MieruCrypto.KeySize)
        {
            throw new ArgumentException($"the mieru key must be {MieruCrypto.KeySize} bytes, got {key.Length}", nameof(key));
        }

        _key = key;
        _sessionId = sessionId;

        var nonce = MieruCrypto.CreateNonce(username);
        nonce.CopyTo(_writeNonce, 0);
        CryptographicOperations.ZeroMemory(nonce);
    }

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => true;

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
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return 0;

        while (true)
        {
            if (TryTakePending(buffer, out var taken)) return taken;
            if (_peerClosed) return 0;
            if (!ReadSegment()) return 0;
        }
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;

        while (true)
        {
            if (TryTakePending(buffer.Span, out var taken)) return taken;
            if (_peerClosed) return 0;
            if (!await ReadSegmentAsync(cancellationToken).ConfigureAwait(false)) return 0;
        }
    }

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    /// <inheritdoc />
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (buffer.IsEmpty) return;

        _writeLock.Wait();
        try
        {
            var first = !_wroteFirstSegment;
            var offset = 0;
            while (offset < buffer.Length)
            {
                var size = Math.Min(first ? MieruSegment.SessionPayloadLimit : MieruSegment.MaxFragment, buffer.Length - offset);
                _inner.Write(BuildSegment(first ? MieruSegment.OpenSessionRequest : MieruSegment.DataClientToServer, buffer.Slice(offset, size)));
                first = false;
                offset += size;
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <inheritdoc />
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return;

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var first = !_wroteFirstSegment;
            var offset = 0;
            while (offset < buffer.Length)
            {
                var size = Math.Min(first ? MieruSegment.SessionPayloadLimit : MieruSegment.MaxFragment, buffer.Length - offset);
                var type = first ? MieruSegment.OpenSessionRequest : MieruSegment.DataClientToServer;
                await _inner.WriteAsync(BuildSegment(type, buffer.Span.Slice(offset, size)), cancellationToken).ConfigureAwait(false);
                first = false;
                offset += size;
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            CryptographicOperations.ZeroMemory(_key);
            _writeLock.Dispose();
            try { _inner.Dispose(); } catch { /* transport already gone */ }
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            CryptographicOperations.ZeroMemory(_key);
            _writeLock.Dispose();
            try { await _inner.DisposeAsync().ConfigureAwait(false); } catch { /* transport already gone */ }
        }

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Serialises one segment and advances the write counter. The explicit nonce is
    /// emitted only with the very first segment; from then on the counter alone
    /// determines it, which is why the frame length changes after the first call.
    /// </summary>
    private byte[] BuildSegment(byte type, ReadOnlySpan<byte> payload)
    {
        var first = !_wroteFirstSegment;
        _wroteFirstSegment = true;
        _writeSequence++;

        if (MieruSegment.IsSession(type))
        {
            MieruSegment.WriteSessionMetadata(_writeMetadata, type, _sessionId, _writeSequence, payload.Length);
        }
        else
        {
            MieruSegment.WriteDataMetadata(_writeMetadata, type, _sessionId, _writeSequence, _peerSequence, payload.Length);
        }

        var frame = new byte[
            (first ? MieruCrypto.NonceSize : 0)
            + MieruCrypto.EncryptedMetadataSize
            + payload.Length
            + (payload.Length > 0 ? MieruCrypto.TagSize : 0)];

        var offset = 0;
        if (first)
        {
            _writeNonce.CopyTo(frame, 0);
            offset = MieruCrypto.NonceSize;
        }

        XChaCha20Poly1305.Encrypt(
            _key,
            _writeNonce,
            _writeMetadata,
            frame.AsSpan(offset, MieruCrypto.MetadataSize),
            frame.AsSpan(offset + MieruCrypto.MetadataSize, MieruCrypto.TagSize),
            default);
        offset += MieruCrypto.EncryptedMetadataSize;
        MieruCrypto.IncrementNonce(_writeNonce);

        if (payload.Length > 0)
        {
            XChaCha20Poly1305.Encrypt(
                _key,
                _writeNonce,
                payload,
                frame.AsSpan(offset, payload.Length),
                frame.AsSpan(offset + payload.Length, MieruCrypto.TagSize),
                default);
            MieruCrypto.IncrementNonce(_writeNonce);
        }

        return frame;
    }

    /// <summary>
    /// Reads one segment synchronously, returning false at a clean EOF — a peer that
    /// closes exactly at a segment boundary is a normal end of stream, while a close
    /// inside a header is a protocol error raised by <see cref="TryReadExactly"/>.
    /// </summary>
    private bool ReadSegment()
    {
        if (!_readFirstSegment)
        {
            if (!TryReadExactly(_readNonce)) return false;
            _readFirstSegment = true;
        }

        if (!TryReadExactly(_readMetadataSealed)) return false;

        var parsed = DecryptMetadata();
        if (parsed.PrefixLength > 0) Skip(parsed.PrefixLength);

        if (parsed.PayloadLength > 0)
        {
            var sealedPayload = new byte[parsed.PayloadLength + MieruCrypto.TagSize];
            OutboundIo.ReadExactly(_inner, sealedPayload);
            _pending = DecryptPayload(sealedPayload, parsed.PayloadLength);
            _pendingOffset = 0;
        }

        if (parsed.SuffixLength > 0) Skip(parsed.SuffixLength);
        if (MieruSegment.IsClose(parsed.Type)) _peerClosed = true;
        return true;
    }

    /// <summary>Reads one segment asynchronously, returning false at a clean EOF.</summary>
    private async ValueTask<bool> ReadSegmentAsync(CancellationToken cancellationToken)
    {
        if (!_readFirstSegment)
        {
            if (!await TryReadExactlyAsync(_readNonce, cancellationToken).ConfigureAwait(false)) return false;
            _readFirstSegment = true;
        }

        if (!await TryReadExactlyAsync(_readMetadataSealed, cancellationToken).ConfigureAwait(false)) return false;

        var parsed = DecryptMetadata();
        if (parsed.PrefixLength > 0) await SkipAsync(parsed.PrefixLength, cancellationToken).ConfigureAwait(false);

        if (parsed.PayloadLength > 0)
        {
            var sealedPayload = new byte[parsed.PayloadLength + MieruCrypto.TagSize];
            await OutboundIo.ReadExactlyAsync(_inner, sealedPayload, cancellationToken).ConfigureAwait(false);
            _pending = DecryptPayload(sealedPayload, parsed.PayloadLength);
            _pendingOffset = 0;
        }

        if (parsed.SuffixLength > 0) await SkipAsync(parsed.SuffixLength, cancellationToken).ConfigureAwait(false);
        if (MieruSegment.IsClose(parsed.Type)) _peerClosed = true;
        return true;
    }

    /// <summary>
    /// Decrypts the fixed 48-byte metadata block and advances the read counter. The
    /// failure message names the two causes that matter in practice: a wrong
    /// username/password, or a clock outside the server's ±2 minute salt window.
    /// </summary>
    private MieruMetadata DecryptMetadata()
    {
        if (!XChaCha20Poly1305.TryDecrypt(
                _key,
                _readNonce,
                _readMetadataSealed.AsSpan(0, MieruCrypto.MetadataSize),
                _readMetadataSealed.AsSpan(MieruCrypto.MetadataSize, MieruCrypto.TagSize),
                _readMetadata,
                default))
        {
            throw new ClashException(
                "mieru: the segment metadata failed authentication - the username or password is wrong, or the clock is more than two minutes away from the server's");
        }

        // The payload of this same segment uses the next counter value, so the step
        // happens here rather than after the payload is read.
        MieruCrypto.IncrementNonce(_readNonce);

        if (!MieruSegment.TryParse(_readMetadata, out var parsed, out var error))
        {
            throw new ClashException($"mieru: {error}");
        }

        _peerSequence = parsed.Sequence;
        return parsed;
    }

    /// <summary>Decrypts a payload block and advances the read counter.</summary>
    private byte[] DecryptPayload(byte[] sealedPayload, int payloadLength)
    {
        var plaintext = new byte[payloadLength];
        if (!XChaCha20Poly1305.TryDecrypt(
                _key,
                _readNonce,
                sealedPayload.AsSpan(0, payloadLength),
                sealedPayload.AsSpan(payloadLength, MieruCrypto.TagSize),
                plaintext,
                default))
        {
            throw new ClashException("mieru: the segment payload failed authentication");
        }

        MieruCrypto.IncrementNonce(_readNonce);
        return plaintext;
    }

    /// <summary>Copies buffered payload bytes out, returning false when none are left.</summary>
    private bool TryTakePending(Span<byte> buffer, out int taken)
    {
        taken = 0;
        var available = _pending.Length - _pendingOffset;
        if (available <= 0)
        {
            _pending = [];
            _pendingOffset = 0;
            return false;
        }

        taken = Math.Min(available, buffer.Length);
        _pending.AsSpan(_pendingOffset, taken).CopyTo(buffer);
        _pendingOffset += taken;
        if (_pendingOffset == _pending.Length)
        {
            _pending = [];
            _pendingOffset = 0;
        }

        return true;
    }

    /// <summary>Reads a full block, returning false when the peer closes at the boundary.</summary>
    private bool TryReadExactly(Span<byte> destination)
    {
        var read = _inner.Read(destination);
        if (read <= 0) return false;

        while (read < destination.Length)
        {
            var next = _inner.Read(destination[read..]);
            if (next <= 0) throw new ClashException("mieru: the peer closed the connection in the middle of a segment header");
            read += next;
        }

        return true;
    }

    /// <inheritdoc cref="TryReadExactly"/>
    private async ValueTask<bool> TryReadExactlyAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        var read = await _inner.ReadAsync(destination, cancellationToken).ConfigureAwait(false);
        if (read <= 0) return false;

        while (read < destination.Length)
        {
            var next = await _inner.ReadAsync(destination[read..], cancellationToken).ConfigureAwait(false);
            if (next <= 0) throw new ClashException("mieru: the peer closed the connection in the middle of a segment header");
            read += next;
        }

        return true;
    }

    /// <summary>Discards <paramref name="count"/> padding bytes in bounded blocks.</summary>
    private void Skip(int count)
    {
        var remaining = count;
        while (remaining > 0)
        {
            var block = Math.Min(remaining, _scratch.Length);
            OutboundIo.ReadExactly(_inner, _scratch.AsSpan(0, block));
            remaining -= block;
        }
    }

    private async ValueTask SkipAsync(int count, CancellationToken cancellationToken)
    {
        var remaining = count;
        while (remaining > 0)
        {
            var block = Math.Min(remaining, _scratch.Length);
            await OutboundIo.ReadExactlyAsync(_inner, _scratch.AsMemory(0, block), cancellationToken).ConfigureAwait(false);
            remaining -= block;
        }
    }
}

/// <summary>
/// The SOCKS5 request/response exchange that mieru carries as the first application
/// bytes of a session.
/// <para>
/// This is the real application handshake: mieru has no authentication message, so
/// the only way a server can reject a client is a non-zero <c>REP</c> in the SOCKS5
/// reply. The dial therefore waits for the reply and fails on it, rather than
/// deferring the check to the first read.
/// </para>
/// </summary>
internal static class MieruSocks5Handshake
{
    /// <summary>SOCKS5 version byte, the first byte of every request and reply.</summary>
    internal const byte Version = 0x05;

    /// <summary><c>CONNECT</c>: the command a TCP session uses.</summary>
    internal const byte CommandConnect = 0x01;

    /// <summary><c>UDP ASSOCIATE</c>: the command a datagram session uses.</summary>
    internal const byte CommandUdpAssociate = 0x03;

    /// <summary>Bytes <see cref="WriteRequest"/> needs for <paramref name="host"/>.</summary>
    internal static int RequestSize(string host) => 3 + Socks5Address.Size(host);

    /// <summary>
    /// Writes <c>[0x05][cmd][0x00][ATYP][ADDR][PORT]</c> and returns the length.
    /// The request is the session's first payload, so it is capped by the session
    /// segment's 1024-byte limit — a 255-byte domain plus the header fits easily.
    /// </summary>
    internal static int WriteRequest(Span<byte> destination, byte command, string host, int port)
    {
        var required = RequestSize(host);
        if (destination.Length < required)
        {
            throw new ArgumentException($"destination must be at least {required} bytes, got {destination.Length}", nameof(destination));
        }

        destination[0] = Version;
        destination[1] = command;
        destination[2] = 0x00; // RSV
        return 3 + Socks5Address.Write(destination[3..], host, port);
    }

    /// <summary>
    /// Reads the SOCKS5 reply and throws unless <c>REP == 0</c>. The bound address
    /// that follows is consumed and discarded so the stream is left positioned at the
    /// first payload byte; <c>RSV</c> is not validated because nothing depends on it.
    /// </summary>
    internal static async ValueTask ReadReplyAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var head = new byte[4];
        await OutboundIo.ReadExactlyAsync(stream, head, cancellationToken).ConfigureAwait(false);

        if (head[0] != Version)
        {
            throw new ClashException($"mieru: the SOCKS5 reply declared version 0x{head[0]:X2} instead of 0x05");
        }

        if (head[1] != 0)
        {
            throw new ClashException($"mieru: the server refused the SOCKS5 request with REP=0x{head[1]:X2}");
        }

        var tail = head[3] switch
        {
            Socks5Address.TypeIpv4 => 4 + 2,
            Socks5Address.TypeIpv6 => 16 + 2,
            Socks5Address.TypeDomain => await ReadDomainTailAsync(stream, cancellationToken).ConfigureAwait(false),
            _ => throw new ClashException($"mieru: the SOCKS5 reply used an unknown address type 0x{head[3]:X2}"),
        };

        await OutboundIo.ReadExactlyAsync(stream, new byte[tail], cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads the FQDN length byte and returns the bytes still to skip.</summary>
    private static async ValueTask<int> ReadDomainTailAsync(Stream stream, CancellationToken cancellationToken)
    {
        var length = new byte[1];
        await OutboundIo.ReadExactlyAsync(stream, length, cancellationToken).ConfigureAwait(false);
        return length[0] + 2;
    }
}

/// <summary>
/// The <c>mieru</c> outbound adapter: an AEAD segment stream over plain TCP.
/// <para>
/// mieru composes no TLS and no ALPN — it defines exactly two underlays over the
/// same crypto — so the transport stack is forced to bare TCP even if the option
/// map carries a stray <c>tls</c> or <c>network</c> key. The parser's
/// <c>skip-cert-verify</c> key is ignored for the same reason: there is no
/// certificate to verify.
/// </para>
/// <para>
/// <b>The UDP underlay is NOT implemented.</b> <c>transport: UDP</c> is accepted at
/// configuration time (so the proxy still appears in <c>/proxies</c>) and refused
/// with a <see cref="NotSupportedException"/> on both dial paths; see
/// <see cref="DialUdpAsync"/> for exactly what is missing. A half-working datagram
/// path would be worse than an honest refusal, so UDP is advertised as
/// unsupported and never silently downgraded.
/// </para>
/// </summary>
public sealed class MieruAdapter : OutboundAdapter
{
    private readonly string _username;
    private readonly string _password;
    private readonly bool _udpUnderlay;
    private readonly (int Begin, int End)? _portRange;

    internal MieruAdapter(
        ProxyConfigEntry entry,
        AdapterBuildContext context,
        string username,
        string password,
        bool udpUnderlay,
        (int Begin, int End)? portRange)
        : base(entry, context, ProxyType.Mieru, udp: false)
    {
        _username = username;
        _password = password;
        _udpUnderlay = udpUnderlay;
        _portRange = portRange;

        if (entry.Map.GetBool("udp"))
        {
            Logger.LogWarning(
                "proxy [{Name}] (mieru) declares udp: true, but this build cannot carry datagrams over mieru; UDP flows will not be routed to it",
                entry.Name);
        }
    }

    /// <summary>
    /// Validates the entry and builds the adapter. Unknown <c>transport</c> values and
    /// any <c>multiplexing</c> level other than off are refused here rather than
    /// ignored, because both would silently change the wire format.
    /// </summary>
    internal static MieruAdapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var username = entry.Map.GetNonEmptyString("username");
        if (username is null)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (mieru) requires a non-empty 'username'");
        }

        var password = entry.Map.GetNonEmptyString("password");
        if (password is null)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (mieru) requires a non-empty 'password'");
        }

        // The configuration values are case-sensitive: `tcp` is not a mieru transport.
        var transport = entry.Map.GetNonEmptyString("transport");
        var udpUnderlay = transport switch
        {
            null or "TCP" => false,
            "UDP" => true,
            _ => throw new ProxyCreationException(
                $"proxy [{entry.Name}] (mieru) has an unknown 'transport' [{transport}]; mieru accepts exactly 'TCP' or 'UDP'"),
        };

        var multiplexing = entry.Map.GetNonEmptyString("multiplexing");
        if (multiplexing is not null && !IsMultiplexingOff(multiplexing))
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (mieru) requested 'multiplexing: {multiplexing}', which is not implemented; "
                + "this client carries one flow per connection, so use MULTIPLEXING_OFF");
        }

        return new MieruAdapter(entry, context, username, password, udpUnderlay, ParsePortRange(entry));
    }

    /// <summary>
    /// mieru has no transport layer of its own to compose: no TLS, no ALPN, no
    /// websocket. The option map is therefore forced back to bare TCP so a stray
    /// <c>tls: true</c> or <c>network: ws</c> cannot wrap the segment stream in a
    /// layer the server does not expect.
    /// </summary>
    protected override YamlMap DialOptions => Options.With("tls", false).With("network", "tcp");

    /// <inheritdoc />
    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        EnsureTcpUnderlay();

        var raw = await OpenAsync(metadata, upstream, ServerHost!, SelectPort(), DialOptions, cancellationToken).ConfigureAwait(false);
        MieruTcpStream? stream = null;
        try
        {
            var key = MieruCrypto.DeriveKey(_password, _username, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            stream = new MieruTcpStream(raw, key, _username, NextSessionId());

            // The SOCKS5 request is the session's first application bytes; it travels
            // in the openSessionRequest segment, so it goes out before the reply is read.
            var host = OutboundOptions.Destination(metadata);
            var request = new byte[MieruSocks5Handshake.RequestSize(host)];
            var written = MieruSocks5Handshake.WriteRequest(request, MieruSocks5Handshake.CommandConnect, host, metadata.DestinationPort);

            await stream.WriteAsync(request.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            await MieruSocks5Handshake.ReadReplyAsync(stream, cancellationToken).ConfigureAwait(false);

            return Complete(Wrap(stream, raw));
        }
        catch (Exception ex)
        {
            if (stream is not null) await stream.DisposeAsync().ConfigureAwait(false);
            else await raw.DisposeAsync().ConfigureAwait(false);

            throw Fail(ex);
        }
    }

    /// <summary>
    /// Refuses every UDP flow. The mieru UDP underlay is not a thin datagram
    /// wrapper: it carries one segment per datagram with a fresh nonce each time
    /// <em>and</em> a full reliability layer of its own — <c>ack*</c> segments,
    /// <c>unacknowledged sequence number</c>, a segment window, a retransmit limit
    /// and MTU-sized fragmentation. None of that is implemented here, and neither is
    /// the <c>[0x00][length][data][0xff]</c> UDP-associate envelope that rides on top
    /// of it. Without those pieces a UDP association would look connected and then
    /// lose datagrams silently, so this path fails loudly instead.
    /// </summary>
    public override Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        return Task.FromException<IPacketConnection>(new NotSupportedException(
            $"proxy [{Name}] (mieru): the UDP underlay is not implemented in this build. mieru's UDP transport needs a reliable "
            + "datagram layer (ack segments, unacknowledged sequence numbers, a send window, retransmit limits and MTU-sized "
            + "fragmentation) that this client does not provide; use transport: TCP."));
    }

    /// <summary>Refuses the TCP path when the entry asked for the UDP underlay.</summary>
    private void EnsureTcpUnderlay()
    {
        if (_udpUnderlay)
        {
            throw new NotSupportedException(
                $"proxy [{Name}] (mieru) is configured with transport: UDP, and the UDP underlay is not implemented in this build; "
                + "change the entry to transport: TCP");
        }
    }

    /// <summary>
    /// The port to dial. With a <c>port-range</c> the reference picks a port from the
    /// range per connection, so a range that is a single port is also accepted.
    /// </summary>
    private int SelectPort()
    {
        if (_portRange is not { } range) return ServerPort;
        return range.Begin == range.End ? range.Begin : Random.Shared.Next(range.Begin, range.End + 1);
    }

    /// <summary>A non-zero random session id, unique per connection.</summary>
    private static uint NextSessionId()
    {
        Span<byte> raw = stackalloc byte[4];
        while (true)
        {
            RandomNumberGenerator.Fill(raw);
            var value = BinaryPrimitives.ReadUInt32BigEndian(raw);
            if (value != 0) return value;
        }
    }

    private static bool IsMultiplexingOff(string value)
        => value.Trim().ToUpperInvariant() is "MULTIPLEXING_OFF" or "OFF" or "FALSE" or "NONE";

    /// <summary>
    /// Parses <c>begin-end</c> (or a single port) and rejects anything that is not a
    /// usable range, so a typo cannot silently fall back to <c>port</c>.
    /// </summary>
    private static (int Begin, int End)? ParsePortRange(ProxyConfigEntry entry)
    {
        var text = entry.Map.GetNonEmptyString("port-range") ?? entry.Map.GetNonEmptyString("port_range");
        if (text is null) return null;

        var dash = text.IndexOf('-', StringComparison.Ordinal);
        var beginText = dash < 0 ? text : text[..dash];
        var endText = dash < 0 ? text : text[(dash + 1)..];

        if (!int.TryParse(beginText.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var begin)
            || !int.TryParse(endText.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var end))
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (mieru) has a malformed 'port-range' [{text}]; expected 'begin-end'");
        }

        if (begin is < 1 or > 65535 || end is < 1 or > 65535 || end < begin)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (mieru) has an invalid 'port-range' [{text}]; expected 1-65535 with begin <= end");
        }

        return (begin, end);
    }
}

/// <summary>Builds <see cref="MieruAdapter"/> instances.</summary>
internal sealed class MieruAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "mieru";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => [];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => MieruAdapter.Create(entry, context);
}
