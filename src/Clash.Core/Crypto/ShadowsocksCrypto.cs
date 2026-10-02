using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Common;

namespace Clash.Core.Crypto;

/// <summary>
/// Shadowsocks master-key derivation and the shared constants of the AEAD
/// framing.
/// </summary>
public static class ShadowsocksKey
{
    /// <summary>
    /// The HKDF info string mandated by the Shadowsocks AEAD specification
    /// (SIP004). The subkey is
    /// <c>HKDF-SHA1(ikm = masterKey, salt = salt, info = "ss-subkey")</c>.
    /// </summary>
    public static ReadOnlySpan<byte> HkdfInfo => "ss-subkey"u8;

    /// <summary>Longest key any Shadowsocks cipher uses.</summary>
    public const int MaxKeySize = 32;

    /// <summary>
    /// Derives the master key from the configured password using the
    /// <c>EVP_BytesToKey</c> construction with MD5, no salt and one iteration —
    /// the exact algorithm OpenSSL and every Shadowsocks implementation use:
    /// <code>
    /// D_1 = MD5(password)
    /// D_i = MD5(D_{i-1} || password)
    /// key = (D_1 || D_2 || ...)[0 .. keySize)
    /// </code>
    /// </summary>
    public static byte[] DeriveMasterKey(string password, int keySize)
    {
        ArgumentNullException.ThrowIfNull(password);
        return DeriveMasterKey(Encoding.UTF8.GetBytes(password), keySize);
    }

    /// <inheritdoc cref="DeriveMasterKey(string,int)"/>
    public static byte[] DeriveMasterKey(ReadOnlySpan<byte> password, int keySize)
    {
        if (keySize is <= 0 or > 64) throw new ArgumentOutOfRangeException(nameof(keySize), keySize, "key size must be between 1 and 64");

        var key = new byte[keySize];
        Span<byte> previous = stackalloc byte[16];
        Span<byte> digest = stackalloc byte[16];
        var havePrevious = false;
        var filled = 0;

        while (filled < keySize)
        {
            using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            if (havePrevious) md5.AppendData(previous);
            md5.AppendData(password);
            md5.GetHashAndReset(digest);

            var take = Math.Min(16, keySize - filled);
            digest[..take].CopyTo(key.AsSpan(filled));
            filled += take;

            digest.CopyTo(previous);
            havePrevious = true;
        }

        CryptographicOperations.ZeroMemory(digest);
        CryptographicOperations.ZeroMemory(previous);
        return key;
    }
}

/// <summary>
/// The Shadowsocks AEAD chunk framing, independent of any stream.
/// <para>
/// Every chunk is <c>[encrypted length][length tag][encrypted payload][payload tag]</c>
/// where the length is a 2-byte big-endian integer (maximum
/// <see cref="MaxChunkSize"/>) and the tags are <see cref="IAeadCipher.TagSize"/>
/// bytes. The nonce is a 12-byte little-endian counter that starts at zero and is
/// incremented once per AEAD operation — so the length and the payload of the
/// same chunk never share a nonce.
/// </para>
/// </summary>
public static class ShadowsocksAeadFraming
{
    /// <summary>Largest payload a single chunk may carry (0x3FFF).</summary>
    public const int MaxChunkSize = 0x3FFF;

    /// <summary>Width of the big-endian length field.</summary>
    public const int LengthFieldSize = 2;

    /// <summary>Width of every Shadowsocks AEAD nonce.</summary>
    public const int NonceSize = 12;

    /// <summary>Bytes on the wire for the encrypted length plus its tag.</summary>
    public static int EncryptedLengthSize(IAeadCipher cipher)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        return LengthFieldSize + cipher.TagSize;
    }

    /// <summary>Total bytes on the wire for a chunk carrying <paramref name="payloadLength"/> bytes.</summary>
    public static int FramedSize(IAeadCipher cipher, int payloadLength)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        if (payloadLength < 0 || payloadLength > MaxChunkSize)
        {
            throw new ArgumentOutOfRangeException(nameof(payloadLength), payloadLength, $"payload must be between 0 and {MaxChunkSize}");
        }

        return LengthFieldSize + cipher.TagSize + payloadLength + cipher.TagSize;
    }

    /// <summary>Writes the little-endian nonce for <paramref name="counter"/>.</summary>
    public static void WriteNonce(Span<byte> nonce, long counter)
    {
        if (nonce.Length < NonceSize) throw new ArgumentException($"nonce must be at least {NonceSize} bytes", nameof(nonce));
        nonce[..NonceSize].Clear();
        BinaryPrimitives.WriteInt64LittleEndian(nonce, counter);
    }

    /// <summary>
    /// Encodes one chunk into <paramref name="destination"/> and advances
    /// <paramref name="counter"/> past the two AEAD operations it performed.
    /// </summary>
    /// <returns>The number of bytes written.</returns>
    public static int WriteChunk(
        IAeadCipher cipher,
        ReadOnlySpan<byte> subkey,
        ref long counter,
        ReadOnlySpan<byte> payload,
        Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        if (payload.Length > MaxChunkSize) throw new ArgumentOutOfRangeException(nameof(payload), payload.Length, $"payload must be at most {MaxChunkSize} bytes");

        var framed = FramedSize(cipher, payload.Length);
        if (destination.Length < framed) throw new ArgumentException($"destination must be at least {framed} bytes", nameof(destination));

        Span<byte> nonce = stackalloc byte[NonceSize];
        Span<byte> lengthPlaintext = stackalloc byte[LengthFieldSize];
        BinaryPrimitives.WriteUInt16BigEndian(lengthPlaintext, (ushort)payload.Length);

        WriteNonce(nonce, counter++);
        cipher.Encrypt(subkey, nonce, lengthPlaintext, destination[..EncryptedLengthSize(cipher)]);

        // A zero-length payload still consumes a nonce (and emits its tag) so both
        // peers stay in step.
        WriteNonce(nonce, counter++);
        cipher.Encrypt(subkey, nonce, payload, destination.Slice(EncryptedLengthSize(cipher), payload.Length + cipher.TagSize));

        return framed;
    }

    /// <summary>
    /// Authenticates and decodes the encrypted length that starts a chunk.
    /// </summary>
    public static bool TryReadLength(
        IAeadCipher cipher,
        ReadOnlySpan<byte> subkey,
        ref long counter,
        ReadOnlySpan<byte> source,
        out int payloadLength)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        payloadLength = 0;

        var blockSize = EncryptedLengthSize(cipher);
        if (source.Length < blockSize) return false;

        Span<byte> nonce = stackalloc byte[NonceSize];
        Span<byte> lengthPlaintext = stackalloc byte[LengthFieldSize];

        WriteNonce(nonce, counter++);
        if (!cipher.Decrypt(subkey, nonce, source[..blockSize], lengthPlaintext)) return false;

        payloadLength = BinaryPrimitives.ReadUInt16BigEndian(lengthPlaintext);
        if (payloadLength > MaxChunkSize)
        {
            payloadLength = 0;
            return false;
        }

        return true;
    }

    /// <summary>
    /// Authenticates and decodes the payload of a chunk whose length was already
    /// read with <see cref="TryReadLength"/>.
    /// </summary>
    public static bool TryReadPayload(
        IAeadCipher cipher,
        ReadOnlySpan<byte> subkey,
        ref long counter,
        ReadOnlySpan<byte> source,
        int payloadLength,
        Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        if (payloadLength < 0 || payloadLength > MaxChunkSize) throw new ArgumentOutOfRangeException(nameof(payloadLength));

        var framed = payloadLength + cipher.TagSize;
        if (source.Length < framed) return false;
        if (destination.Length < payloadLength) throw new ArgumentException($"destination must be at least {payloadLength} bytes", nameof(destination));

        Span<byte> nonce = stackalloc byte[NonceSize];
        WriteNonce(nonce, counter++);
        return cipher.Decrypt(subkey, nonce, source[..framed], destination[..payloadLength]);
    }
}

/// <summary>
/// Writes the Shadowsocks AEAD chunk stream. The salt is emitted lazily, with
/// the first chunk that actually carries data, so a connection that never writes
/// never puts a salt on the wire.
/// </summary>
public sealed class ShadowsocksAeadWriter : IDisposable
{
    private readonly Stream _stream;
    private readonly IAeadCipher _cipher;
    private readonly byte[] _masterKey;
    private readonly byte[]? _explicitSalt;
    private byte[] _subkey = [];
    private byte[] _buffer = new byte[512];
    private long _counter;
    private bool _saltWritten;

    /// <summary>Creates a writer that generates a fresh random salt on first write.</summary>
    public ShadowsocksAeadWriter(Stream stream, IAeadCipher cipher, ReadOnlySpan<byte> masterKey)
        : this(stream, cipher, masterKey, null)
    {
    }

    /// <summary>Creates a writer that uses <paramref name="salt"/> instead of a random one.</summary>
    public ShadowsocksAeadWriter(Stream stream, IAeadCipher cipher, ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt)
        : this(stream, cipher, masterKey, salt.IsEmpty ? null : salt.ToArray())
    {
    }

    private ShadowsocksAeadWriter(Stream stream, IAeadCipher cipher, ReadOnlySpan<byte> masterKey, byte[]? salt)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        if (masterKey.Length != cipher.KeySize) throw new ArgumentException($"master key must be {cipher.KeySize} bytes", nameof(masterKey));
        if (salt is not null && salt.Length != cipher.SaltSize) throw new ArgumentException($"salt must be {cipher.SaltSize} bytes", nameof(salt));

        _masterKey = masterKey.ToArray();
        _explicitSalt = salt;
    }

    /// <summary>The cipher this writer frames with.</summary>
    public IAeadCipher Cipher => _cipher;

    /// <summary>Number of chunks written so far.</summary>
    public long ChunkCount { get; private set; }

    /// <summary>True once the salt has been put on the wire.</summary>
    public bool SaltWritten => _saltWritten;

    /// <summary>Writes the salt (and derives the subkey) if that has not happened yet.</summary>
    public void WriteSalt()
    {
        if (_saltWritten) return;

        var salt = _explicitSalt ?? RandomNumberGenerator.GetBytes(_cipher.SaltSize);
        _stream.Write(salt, 0, salt.Length);
        _subkey = _cipher.DeriveSubkey(_masterKey, salt);
        _saltWritten = true;
    }

    /// <summary>Frames and writes <paramref name="data"/>, splitting it into chunks.</summary>
    public void Write(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;
        WriteSalt();

        while (!data.IsEmpty)
        {
            var chunk = Math.Min(data.Length, ShadowsocksAeadFraming.MaxChunkSize);
            var framed = ShadowsocksAeadFraming.FramedSize(_cipher, chunk);
            if (_buffer.Length < framed) _buffer = new byte[Math.Max(framed, _buffer.Length * 2)];

            var written = ShadowsocksAeadFraming.WriteChunk(_cipher, _subkey, ref _counter, data[..chunk], _buffer);
            _stream.Write(_buffer, 0, written);
            ChunkCount++;
            data = data[chunk..];
        }
    }

    /// <inheritdoc cref="Write(ReadOnlySpan{byte})"/>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        if (data.IsEmpty) return;
        WriteSalt();

        var remaining = data;
        while (!remaining.IsEmpty)
        {
            var chunk = Math.Min(remaining.Length, ShadowsocksAeadFraming.MaxChunkSize);
            var framed = ShadowsocksAeadFraming.FramedSize(_cipher, chunk);
            if (_buffer.Length < framed) _buffer = new byte[Math.Max(framed, _buffer.Length * 2)];

            var written = ShadowsocksAeadFraming.WriteChunk(_cipher, _subkey, ref _counter, remaining.Span[..chunk], _buffer);
            await _stream.WriteAsync(_buffer.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
            ChunkCount++;
            remaining = remaining[chunk..];
        }
    }

    public void Flush() => _stream.Flush();

    public Task FlushAsync(CancellationToken cancellationToken = default) => _stream.FlushAsync(cancellationToken);

    /// <summary>
    /// Wipes the derived subkey. The underlying stream is owned by the caller and
    /// is deliberately left open.
    /// </summary>
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_subkey);
        CryptographicOperations.ZeroMemory(_masterKey);
        CryptographicOperations.ZeroMemory(_buffer);
    }
}

/// <summary>
/// Reads the Shadowsocks AEAD chunk stream. The salt is consumed from the head
/// of the stream on the first read.
/// </summary>
public sealed class ShadowsocksAeadReader
{
    private readonly Stream _stream;
    private readonly IAeadCipher _cipher;
    private readonly byte[] _masterKey;
    private byte[] _subkey = [];
    private byte[] _lengthBlock = [];
    private byte[] _chunk = [];
    private int _chunkOffset;
    private int _chunkLength;
    private long _counter;
    private bool _saltRead;

    /// <summary>Creates a reader over <paramref name="stream"/>.</summary>
    public ShadowsocksAeadReader(Stream stream, IAeadCipher cipher, ReadOnlySpan<byte> masterKey)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        if (masterKey.Length != cipher.KeySize) throw new ArgumentException($"master key must be {cipher.KeySize} bytes", nameof(masterKey));

        _masterKey = masterKey.ToArray();
        _lengthBlock = new byte[ShadowsocksAeadFraming.EncryptedLengthSize(cipher)];
        _chunk = new byte[ShadowsocksAeadFraming.MaxChunkSize + cipher.TagSize];
    }

    /// <summary>The cipher this reader unframes with.</summary>
    public IAeadCipher Cipher => _cipher;

    /// <summary>Number of chunks consumed so far.</summary>
    public long ChunkCount { get; private set; }

    /// <summary>Reads at least one byte unless the stream ended.</summary>
    public int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return 0;

        while (_chunkOffset >= _chunkLength)
        {
            if (!ReadChunk()) return 0;
        }

        var take = Math.Min(buffer.Length, _chunkLength - _chunkOffset);
        _chunk.AsSpan(_chunkOffset, take).CopyTo(buffer);
        _chunkOffset += take;
        return take;
    }

    /// <inheritdoc cref="Read(Span{byte})"/>
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;

        while (_chunkOffset >= _chunkLength)
        {
            if (!await ReadChunkAsync(cancellationToken).ConfigureAwait(false)) return 0;
        }

        var take = Math.Min(buffer.Length, _chunkLength - _chunkOffset);
        _chunk.AsSpan(_chunkOffset, take).CopyTo(buffer.Span);
        _chunkOffset += take;
        return take;
    }

    /// <summary>Reads and authenticates the salt, deriving the session subkey.</summary>
    public void ReadSalt()
    {
        if (_saltRead) return;

        var salt = new byte[_cipher.SaltSize];
        if (!ReadExactly(salt)) throw new ClashException("shadowsocks: connection closed before the salt arrived");
        _subkey = _cipher.DeriveSubkey(_masterKey, salt);
        _saltRead = true;
    }

    private bool ReadChunk()
    {
        ReadSalt();

        if (!ReadExactly(_lengthBlock)) return false;
        if (!ShadowsocksAeadFraming.TryReadLength(_cipher, _subkey, ref _counter, _lengthBlock, out var length))
        {
            throw new ClashException("shadowsocks: chunk length failed authentication");
        }

        if (length == 0)
        {
            // A legal empty chunk: consume its tag and keep reading. The tag is
            // still on the wire, so it must be read before the next length block
            // or the stream desynchronises.
            var tag = _emptyChunkBuffer.AsSpan(0, _cipher.TagSize);
            if (!ReadExactly(tag)) return false;
            if (!ShadowsocksAeadFraming.TryReadPayload(_cipher, _subkey, ref _counter, tag, 0, Span<byte>.Empty))
            {
                throw new ClashException("shadowsocks: chunk payload failed authentication");
            }

            ChunkCount++;
            _chunkOffset = 0;
            _chunkLength = 0;
            return true;
        }

        if (!ReadExactly(_chunk.AsSpan(0, length + _cipher.TagSize))) return false;
        if (!ShadowsocksAeadFraming.TryReadPayload(_cipher, _subkey, ref _counter, _chunk.AsSpan(0, length + _cipher.TagSize), length, _chunk))
        {
            throw new ClashException("shadowsocks: chunk payload failed authentication");
        }

        ChunkCount++;
        _chunkOffset = 0;
        _chunkLength = length;
        return true;
    }

    private async ValueTask<bool> ReadChunkAsync(CancellationToken cancellationToken)
    {
        ReadSalt();

        if (!await ReadExactlyAsync(_lengthBlock, cancellationToken).ConfigureAwait(false)) return false;
        if (!ShadowsocksAeadFraming.TryReadLength(_cipher, _subkey, ref _counter, _lengthBlock, out var length))
        {
            throw new ClashException("shadowsocks: chunk length failed authentication");
        }

        if (length == 0)
        {
            // See the synchronous path: the empty chunk still carries a tag.
            var tag = _emptyChunkBuffer.AsMemory(0, _cipher.TagSize);
            if (!await ReadExactlyAsync(tag, cancellationToken).ConfigureAwait(false)) return false;
            if (!ShadowsocksAeadFraming.TryReadPayload(_cipher, _subkey, ref _counter, tag.Span, 0, Span<byte>.Empty))
            {
                throw new ClashException("shadowsocks: chunk payload failed authentication");
            }

            ChunkCount++;
            _chunkOffset = 0;
            _chunkLength = 0;
            return true;
        }

        var framed = length + _cipher.TagSize;
        if (!await ReadExactlyAsync(_chunk.AsMemory(0, framed), cancellationToken).ConfigureAwait(false)) return false;
        if (!ShadowsocksAeadFraming.TryReadPayload(_cipher, _subkey, ref _counter, _chunk.AsSpan(0, framed), length, _chunk))
        {
            throw new ClashException("shadowsocks: chunk payload failed authentication");
        }

        ChunkCount++;
        _chunkOffset = 0;
        _chunkLength = length;
        return true;
    }

    /// <summary>Scratch space for the tag of an empty chunk; per instance, never shared.</summary>
    private readonly byte[] _emptyChunkBuffer = new byte[16];

    private bool ReadExactly(Span<byte> destination)
    {
        var read = 0;
        while (read < destination.Length)
        {
            var n = _stream.Read(destination[read..]);
            if (n <= 0) return false;
            read += n;
        }

        return true;
    }

    private async ValueTask<bool> ReadExactlyAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < destination.Length)
        {
            var n = await _stream.ReadAsync(destination[read..], cancellationToken).ConfigureAwait(false);
            if (n <= 0) return false;
            read += n;
        }

        return true;
    }
}

/// <summary>
/// Shadowsocks 2022 (SIP022) session framing.
/// <para>
/// <b>What is implemented.</b> The 2022 session subkey derivation
/// (<c>BLAKE3-DERIVE-KEY("shadowsocks 2022 session subkey", masterKey || salt)</c>)
/// and the UDP session datagram layout:
/// </para>
/// <code>
/// +------------------+------------------+--------------------------------+
/// | session id (8)   |  packet id (8)   |  AEAD body                     |
/// +------------------+------------------+--------------------------------+
///   body plaintext:  type (1) | timestamp (8) | padding length (2) | padding | address | payload
/// </code>
/// <para>
/// The AEAD nonce for a datagram is the little-endian packet id followed by four
/// zero bytes, and the subkey is derived from the session key and the 8-byte
/// session id acting as the salt.
/// </para>
/// <para>
/// <b>Documented choices.</b> The session id and packet id are written
/// little-endian, matching the little-endian convention Shadowsocks uses for its
/// AEAD nonces. The SIP022 document could not be consulted from this build
/// environment, so this byte order and the exact padding field width are the
/// only places where a peer that disagrees would fail to interoperate; both are
/// isolated in this type so they can be corrected in one place.
/// </para>
/// <para>
/// The 2022 TCP stream header (fixed/variable-length headers, padding and
/// request/response types) is <em>not</em> implemented here — it belongs to the
/// Shadowsocks adapter, which layers it on top of
/// <see cref="ShadowsocksAeadWriter"/> using the same subkey derivation.
/// </para>
/// </summary>
public static class Shadowsocks2022
{
    /// <summary>Width of the UDP session identifier.</summary>
    public const int SessionIdSize = 8;

    /// <summary>Width of the per-datagram packet identifier.</summary>
    public const int PacketIdSize = 8;

    /// <summary>Width of the 2022 timestamp field, in seconds since the Unix epoch.</summary>
    public const int TimestampSize = 8;

    /// <summary>Bytes of session header that precede the AEAD body of a datagram.</summary>
    public const int UdpHeaderSize = SessionIdSize + PacketIdSize;

    /// <summary>Width of the 2022 AEAD nonce.</summary>
    public const int NonceSize = 12;

    /// <summary>Bytes of fixed body header that precede the padding and address.</summary>
    public const int UdpBodyHeaderSize = 1 + TimestampSize + 2;

    /// <summary>
    /// The BLAKE3 derive-key context used for the 2022 session subkey.
    /// </summary>
    public const string SessionSubkeyContext = "shadowsocks 2022 session subkey";

    /// <summary>Derives the 2022 session subkey into <paramref name="subkey"/>.</summary>
    public static void DeriveSessionSubkey(ReadOnlySpan<byte> sessionKey, ReadOnlySpan<byte> salt, Span<byte> subkey)
    {
        if (subkey.IsEmpty) throw new ArgumentException("subkey destination must not be empty", nameof(subkey));
        Blake3Kdf.DeriveKey(SessionSubkeyContext, sessionKey, salt, subkey);
    }

    /// <summary>Derives a 2022 session subkey of <paramref name="keySize"/> bytes.</summary>
    public static byte[] DeriveSessionSubkey(ReadOnlySpan<byte> sessionKey, ReadOnlySpan<byte> salt, int keySize)
    {
        if (keySize <= 0) throw new ArgumentOutOfRangeException(nameof(keySize));
        var subkey = new byte[keySize];
        DeriveSessionSubkey(sessionKey, salt, subkey);
        return subkey;
    }

    /// <summary>Writes the 16-byte UDP session header.</summary>
    public static void WriteUdpHeader(Span<byte> destination, ulong sessionId, ulong packetId)
    {
        if (destination.Length < UdpHeaderSize) throw new ArgumentException($"destination must be at least {UdpHeaderSize} bytes", nameof(destination));
        BinaryPrimitives.WriteUInt64LittleEndian(destination, sessionId);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[SessionIdSize..], packetId);
    }

    /// <summary>Parses the 16-byte UDP session header.</summary>
    public static bool TryReadUdpHeader(ReadOnlySpan<byte> source, out ulong sessionId, out ulong packetId)
    {
        if (source.Length < UdpHeaderSize)
        {
            sessionId = 0;
            packetId = 0;
            return false;
        }

        sessionId = BinaryPrimitives.ReadUInt64LittleEndian(source);
        packetId = BinaryPrimitives.ReadUInt64LittleEndian(source[SessionIdSize..]);
        return true;
    }

    /// <summary>Builds the 12-byte AEAD nonce for a datagram with the given packet id.</summary>
    public static void BuildUdpNonce(Span<byte> nonce, ulong packetId)
    {
        if (nonce.Length < NonceSize) throw new ArgumentException($"nonce must be at least {NonceSize} bytes", nameof(nonce));
        nonce[..NonceSize].Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce, packetId);
    }

    /// <summary>Writes the fixed body header: type, timestamp and padding length.</summary>
    public static void WriteUdpBodyHeader(Span<byte> destination, Shadowsocks2022PacketType type, long timestamp, ushort paddingLength)
    {
        if (destination.Length < UdpBodyHeaderSize) throw new ArgumentException($"destination must be at least {UdpBodyHeaderSize} bytes", nameof(destination));
        destination[0] = (byte)type;
        BinaryPrimitives.WriteInt64BigEndian(destination[1..], timestamp);
        BinaryPrimitives.WriteUInt16BigEndian(destination[(1 + TimestampSize)..], paddingLength);
    }

    /// <summary>Parses the fixed body header.</summary>
    public static bool TryReadUdpBodyHeader(
        ReadOnlySpan<byte> source,
        out Shadowsocks2022PacketType type,
        out long timestamp,
        out ushort paddingLength)
    {
        type = default;
        timestamp = 0;
        paddingLength = 0;
        if (source.Length < UdpBodyHeaderSize) return false;

        type = (Shadowsocks2022PacketType)source[0];
        timestamp = BinaryPrimitives.ReadInt64BigEndian(source[1..]);
        paddingLength = BinaryPrimitives.ReadUInt16BigEndian(source[(1 + TimestampSize)..]);
        return true;
    }

    /// <summary>Seconds since the Unix epoch, the unit the 2022 timestamp uses.</summary>
    public static long NowUnixSeconds() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
}

/// <summary>The 2022 body <c>type</c> byte.</summary>
public enum Shadowsocks2022PacketType : byte
{
    /// <summary>Client to server, carrying a proxied stream.</summary>
    ClientStream = 0,

    /// <summary>Server to client, carrying a proxied stream.</summary>
    ServerStream = 1,

    /// <summary>Client to server, carrying a datagram.</summary>
    ClientPacket = 2,

    /// <summary>Server to client, carrying a datagram.</summary>
    ServerPacket = 3,
}

/// <summary>
/// A Shadowsocks 2022 UDP session: one session id, a monotonically increasing
/// packet id and the derived session subkey. Not thread-safe; the caller owns
/// the lock when the read and write pumps share a session.
/// </summary>
public sealed class Shadowsocks2022UdpSession
{
    private readonly IAeadCipher _cipher;
    private readonly byte[] _subkey;
    private readonly byte[] _nonce = new byte[Shadowsocks2022.NonceSize];
    private ulong _packetId;

    /// <summary>Creates a session with an explicit session key and session id.</summary>
    public Shadowsocks2022UdpSession(IAeadCipher cipher, ReadOnlySpan<byte> sessionKey, ulong sessionId)
    {
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        SessionId = sessionId;

        Span<byte> salt = stackalloc byte[Shadowsocks2022.SessionIdSize];
        BinaryPrimitives.WriteUInt64LittleEndian(salt, sessionId);
        _subkey = new byte[cipher.KeySize];
        Shadowsocks2022.DeriveSessionSubkey(sessionKey, salt, _subkey);
    }

    /// <summary>The identifier that prefixes every datagram of this session.</summary>
    public ulong SessionId { get; }

    /// <summary>The packet id that the next encoded datagram will use.</summary>
    public ulong NextPacketId => _packetId;

    /// <summary>
    /// Encodes one datagram: 16-byte session header followed by the AEAD-sealed
    /// body. <paramref name="address"/> is the SOCKS5-style address block
    /// (see <see cref="Socks5Address"/>), or empty for server-to-client packets.
    /// </summary>
    public byte[] Encode(
        Shadowsocks2022PacketType type,
        ReadOnlySpan<byte> address,
        ReadOnlySpan<byte> payload,
        int paddingLength = 0,
        long? timestamp = null)
    {
        if (paddingLength < 0) throw new ArgumentOutOfRangeException(nameof(paddingLength));

        var bodyLength = Shadowsocks2022.UdpBodyHeaderSize + paddingLength + address.Length + payload.Length;
        var packet = new byte[Shadowsocks2022.UdpHeaderSize + bodyLength + _cipher.TagSize];

        Shadowsocks2022.WriteUdpHeader(packet, SessionId, _packetId);

        var body = packet.AsSpan(Shadowsocks2022.UdpHeaderSize, bodyLength);
        Shadowsocks2022.WriteUdpBodyHeader(body, type, timestamp ?? Shadowsocks2022.NowUnixSeconds(), (ushort)paddingLength);
        if (paddingLength > 0) RandomNumberGenerator.Fill(body.Slice(Shadowsocks2022.UdpBodyHeaderSize, paddingLength));
        address.CopyTo(body[(Shadowsocks2022.UdpBodyHeaderSize + paddingLength)..]);
        payload.CopyTo(body[(Shadowsocks2022.UdpBodyHeaderSize + paddingLength + address.Length)..]);

        Shadowsocks2022.BuildUdpNonce(_nonce, _packetId);
        _cipher.Encrypt(_subkey, _nonce, body, packet.AsSpan(Shadowsocks2022.UdpHeaderSize));

        _packetId++;
        return packet;
    }

    /// <summary>
    /// Decodes a datagram produced by <see cref="Encode"/>. Returns false when
    /// the packet is too short, belongs to another session, or fails
    /// authentication.
    /// </summary>
    public bool TryDecode(
        ReadOnlySpan<byte> packet,
        out Shadowsocks2022PacketType type,
        out long timestamp,
        out byte[] address,
        out byte[] payload)
    {
        type = default;
        timestamp = 0;
        address = [];
        payload = [];

        if (!Shadowsocks2022.TryReadUdpHeader(packet, out var sessionId, out var packetId)) return false;
        if (sessionId != SessionId) return false;

        var sealedBody = packet[Shadowsocks2022.UdpHeaderSize..];
        if (sealedBody.Length < _cipher.TagSize) return false;

        var bodyLength = sealedBody.Length - _cipher.TagSize;
        if (bodyLength < Shadowsocks2022.UdpBodyHeaderSize) return false;

        var body = new byte[bodyLength];
        Shadowsocks2022.BuildUdpNonce(_nonce, packetId);
        if (!_cipher.Decrypt(_subkey, _nonce, sealedBody, body)) return false;

        if (!Shadowsocks2022.TryReadUdpBodyHeader(body, out type, out timestamp, out var paddingLength)) return false;
        if (Shadowsocks2022.UdpBodyHeaderSize + paddingLength > body.Length) return false;

        var rest = body.AsSpan(Shadowsocks2022.UdpBodyHeaderSize + paddingLength);
        if (type is Shadowsocks2022PacketType.ClientPacket or Shadowsocks2022PacketType.ClientStream)
        {
            if (!Socks5Address.TryRead(rest, out var consumed, out address)) return false;
            payload = rest[consumed..].ToArray();
        }
        else
        {
            address = [];
            payload = rest.ToArray();
        }

        return true;
    }
}

/// <summary>
/// The simple-obfs headers used by the Shadowsocks <c>obfs</c> plugin.
/// <para>
/// <b>Covered.</b> <c>http_simple</c> requests and responses, including the
/// first-chunk smuggling in the request path, and a structurally valid
/// <c>tls1.2_ticket_auth</c> ClientHello/ServerHello pair with the SNI and
/// session-ticket extensions simple-obfs uses.
/// </para>
/// <para>
/// <b>Not covered.</b> <c>http_post</c>, the obfs4-style handshakes of
/// <c>tls1.2_ticket_fastauth</c>, and the HMAC that real simple-obfs puts in the
/// TLS session id — a structurally correct ClientHello is emitted instead, which
/// defeats naive DPI but is not byte-compatible with the reference plugin's
/// authentication. Treat these as obfuscation, not as an authenticated handshake.
/// </para>
/// </summary>
public static class ShadowsocksObfs
{
    /// <summary>Name of the HTTP GET obfuscation.</summary>
    public const string HttpSimple = "http_simple";

    /// <summary>Name of the HTTP POST obfuscation (not implemented).</summary>
    public const string HttpPost = "http_post";

    /// <summary>Name of the fake TLS 1.2 session-ticket obfuscation.</summary>
    public const string Tls12TicketAuth = "tls1.2_ticket_auth";

    /// <summary>Largest first-payload prefix simple-obfs smuggles into the request path.</summary>
    public const int MaxPathPayload = 64;

    private static readonly string[] UserAgents =
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ];

    /// <summary>True when the named obfuscation can be produced by this class.</summary>
    public static bool IsSupported(string name)
        => name is not null && (name.Equals(HttpSimple, StringComparison.OrdinalIgnoreCase)
            || name.Equals(Tls12TicketAuth, StringComparison.OrdinalIgnoreCase));

    /// <summary>Builds an <c>http_simple</c> request. Returns the number of bytes written.</summary>
    public static int BuildHttpSimpleRequest(Span<byte> destination, string host, int port, ReadOnlySpan<byte> firstPayload, int? seed = null)
    {
        ArgumentNullException.ThrowIfNull(host);
        var random = seed.HasValue ? new Random(seed.Value) : Random.Shared;
        var embedded = Math.Min(firstPayload.Length, MaxPathPayload);

        var builder = new StringBuilder(256);
        builder.Append("GET /");
        for (var i = 0; i < embedded; i++) builder.Append('%').Append(firstPayload[i].ToString("x2"));
        builder.Append(" HTTP/1.1\r\n");
        builder.Append("Host: ").Append(host).Append(':').Append(port).Append("\r\n");
        builder.Append("User-Agent: ").Append(UserAgents[random.Next(UserAgents.Length)]).Append("\r\n");
        builder.Append("Accept: */*\r\n");
        builder.Append("Accept-Language: en-US,en;q=0.8\r\n");
        builder.Append("Accept-Encoding: gzip, deflate\r\n");
        builder.Append("DNT: 1\r\n");
        builder.Append("Connection: keep-alive\r\n\r\n");

        var header = Encoding.ASCII.GetBytes(builder.ToString());
        header.CopyTo(destination);
        var written = header.Length;

        if (firstPayload.Length > embedded)
        {
            firstPayload[embedded..].CopyTo(destination[written..]);
            written += firstPayload.Length - embedded;
        }

        return written;
    }

    /// <summary>Builds an <c>http_simple</c> response. Returns the number of bytes written.</summary>
    public static int BuildHttpSimpleResponse(Span<byte> destination, ReadOnlySpan<byte> firstPayload, int? seed = null)
    {
        var random = seed.HasValue ? new Random(seed.Value) : Random.Shared;
        var status = random.Next(2) == 0 ? "200 OK" : "302 Found";
        var builder = new StringBuilder(192);
        builder.Append("HTTP/1.1 ").Append(status).Append("\r\n");
        builder.Append("Server: nginx\r\n");
        builder.Append("Date: ").Append(DateTimeOffset.UtcNow.ToString("R")).Append("\r\n");
        builder.Append("Content-Type: text/html\r\n");
        builder.Append("Transfer-Encoding: chunked\r\n");
        builder.Append("Connection: keep-alive\r\n\r\n");

        var header = Encoding.ASCII.GetBytes(builder.ToString());
        header.CopyTo(destination);
        var written = header.Length;

        if (!firstPayload.IsEmpty)
        {
            var chunkHeader = Encoding.ASCII.GetBytes($"{firstPayload.Length:x}\r\n");
            chunkHeader.CopyTo(destination[written..]);
            written += chunkHeader.Length;
            firstPayload.CopyTo(destination[written..]);
            written += firstPayload.Length;
            "\r\n"u8.CopyTo(destination[written..]);
            written += 2;
        }

        return written;
    }

    /// <summary>
    /// Recognises an <c>http_simple</c> request and recovers the payload smuggled
    /// in its path.
    /// </summary>
    public static bool TryParseHttpSimpleRequest(ReadOnlySpan<byte> source, out int headerLength, out string host, out byte[] embedded)
    {
        headerLength = 0;
        host = string.Empty;
        embedded = [];

        var end = source.IndexOf("\r\n\r\n"u8);
        if (end < 0) return false;
        headerLength = end + 4;

        var text = Encoding.ASCII.GetString(source[..headerLength]);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0) return false;

        var requestLine = lines[0].Split(' ');
        if (requestLine.Length < 3) return false;
        if (!requestLine[0].Equals("GET", StringComparison.OrdinalIgnoreCase)) return false;

        var path = requestLine[1];
        if (path.StartsWith('/')) path = path[1..];
        embedded = DecodePercentEscapes(path);

        foreach (var line in lines)
        {
            if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
            {
                host = line[5..].Trim();
                break;
            }
        }

        return true;
    }

    /// <summary>
    /// Builds a <c>tls1.2_ticket_auth</c> ClientHello record followed by
    /// <paramref name="firstPayload"/>. Returns the number of bytes written.
    /// </summary>
    public static int BuildTls12TicketAuthClientHello(Span<byte> destination, string host, ReadOnlySpan<byte> firstPayload, int? seed = null)
    {
        ArgumentNullException.ThrowIfNull(host);
        var random = seed.HasValue ? new Random(seed.Value) : Random.Shared;

        var hostBytes = Encoding.ASCII.GetBytes(host);
        var sessionId = new byte[32];
        random.NextBytes(sessionId);

        // ClientHello body
        var body = new List<byte>(256);
        WriteUInt16(body, 0x0303);                       // client_version = TLS 1.2
        for (var i = 0; i < 32; i++) body.Add((byte)random.Next(256));
        body.Add(32);
        body.AddRange(sessionId);
        WriteUInt16(body, 12);                            // cipher_suites length
        foreach (var suite in new ushort[] { 0xC02B, 0xC02F, 0xC013, 0xC014, 0x009C, 0x009D })
        {
            WriteUInt16(body, suite);
        }

        body.Add(1);                                      // compression_methods
        body.Add(0);

        var extensions = new List<byte>(128);
        var sni = new List<byte>();
        WriteUInt16(sni, hostBytes.Length + 3);
        sni.Add(0);
        WriteUInt16(sni, hostBytes.Length);
        sni.AddRange(hostBytes);
        WriteExtension(extensions, 0x0000, sni);

        WriteExtension(extensions, 0x000B, [1, 0]);       // ec_point_formats
        WriteExtension(extensions, 0x0017, []);           // extended_master_secret
        WriteExtension(extensions, 0x0023, []);           // session_ticket (empty request)
        WriteExtension(extensions, 0x000D, [0, 2, 1, 1]); // signature_algorithms

        WriteUInt16(body, extensions.Count);
        body.AddRange(extensions);

        var handshake = new List<byte>(body.Count + 4) { 0x01 };
        WriteUInt24(handshake, body.Count);
        handshake.AddRange(body);

        var record = new List<byte>(handshake.Count + 5) { 0x16, 0x03, 0x01 };
        WriteUInt16(record, handshake.Count);
        record.AddRange(handshake);

        var recordBytes = record.ToArray();
        recordBytes.CopyTo(destination);
        var written = recordBytes.Length;

        if (!firstPayload.IsEmpty)
        {
            firstPayload.CopyTo(destination[written..]);
            written += firstPayload.Length;
        }

        return written;
    }

    /// <summary>
    /// Builds the matching <c>tls1.2_ticket_auth</c> ServerHello plus a
    /// ChangeCipherSpec and an empty Finished record. Returns the number of bytes
    /// written.
    /// </summary>
    public static int BuildTls12TicketAuthServerHello(Span<byte> destination, ReadOnlySpan<byte> firstPayload, int? seed = null)
    {
        var random = seed.HasValue ? new Random(seed.Value) : Random.Shared;

        var body = new List<byte>(128);
        WriteUInt16(body, 0x0303);
        for (var i = 0; i < 32; i++) body.Add((byte)random.Next(256));
        body.Add(0);                                      // empty session id
        WriteUInt16(body, 0xC02F);                        // chosen cipher suite
        body.Add(0);                                      // no compression

        var extensions = new List<byte>(32);
        WriteExtension(extensions, 0x0023, []);           // session_ticket accepted
        WriteExtension(extensions, 0x000B, [1, 0]);
        WriteUInt16(body, extensions.Count);
        body.AddRange(extensions);

        var handshake = new List<byte>(body.Count + 4) { 0x02 };
        WriteUInt24(handshake, body.Count);
        handshake.AddRange(body);

        var record = new List<byte>(handshake.Count + 5) { 0x16, 0x03, 0x03 };
        WriteUInt16(record, handshake.Count);
        record.AddRange(handshake);

        var recordBytes = record.ToArray();
        recordBytes.CopyTo(destination);
        var written = recordBytes.Length;

        // ChangeCipherSpec
        destination[written++] = 0x14;
        destination[written++] = 0x03;
        destination[written++] = 0x03;
        destination[written++] = 0x00;
        destination[written++] = 0x01;
        destination[written++] = 0x01;

        if (!firstPayload.IsEmpty)
        {
            firstPayload.CopyTo(destination[written..]);
            written += firstPayload.Length;
        }

        return written;
    }

    /// <summary>
    /// Returns the length of the fake TLS record at the head of
    /// <paramref name="source"/>, so a server can skip it and reach the payload.
    /// </summary>
    public static bool TryMeasureTlsRecord(ReadOnlySpan<byte> source, out int recordLength)
    {
        recordLength = 0;
        if (source.Length < 5) return false;
        if (source[0] != 0x16) return false;

        var length = BinaryPrimitives.ReadUInt16BigEndian(source[3..]);
        if (source.Length < 5 + length) return false;

        recordLength = 5 + length;
        return true;
    }

    private static void WriteUInt16(List<byte> target, int value)
    {
        target.Add((byte)(value >> 8));
        target.Add((byte)value);
    }

    private static void WriteUInt24(List<byte> target, int value)
    {
        target.Add((byte)(value >> 16));
        target.Add((byte)(value >> 8));
        target.Add((byte)value);
    }

    private static void WriteExtension(List<byte> target, ushort type, List<byte> data)
    {
        WriteUInt16(target, type);
        WriteUInt16(target, data.Count);
        target.AddRange(data);
    }

    private static byte[] DecodePercentEscapes(string path)
    {
        var result = new List<byte>(path.Length);
        for (var i = 0; i < path.Length; i++)
        {
            if (path[i] == '%' && i + 2 < path.Length
                && byte.TryParse(path.AsSpan(i + 1, 2), System.Globalization.NumberStyles.HexNumber, null, out var value))
            {
                result.Add(value);
                i += 2;
            }
            else
            {
                result.Add((byte)path[i]);
            }
        }

        return result.ToArray();
    }
}
