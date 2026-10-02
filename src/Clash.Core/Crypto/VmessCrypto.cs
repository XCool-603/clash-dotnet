using System.Buffers.Binary;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text;

namespace Clash.Core.Crypto;

/// <summary>
/// The key material VMess derives for one direction of one connection.
/// All four values are produced by <see cref="VmessCrypto.Kdf"/>.
/// </summary>
public sealed record VmessAeadKeys(byte[] LengthKey, byte[] LengthIv, byte[] PayloadKey, byte[] PayloadIv);

/// <summary>
/// The cryptographic primitives of the VMess AEAD header, plus the legacy
/// (pre-AEAD) MD5 variant.
/// <para>
/// <b>Wire layout implemented here.</b> The sealed request header is
/// <c>[ AuthID(16) ][ AEAD( length, 2 ) ][ connectionNonce(8) ][ AEAD( body ) ]</c>,
/// where both AEAD operations use the AuthID as associated data; the response
/// header is <c>[ AEAD( length, 2 ) ][ AEAD( body ) ]</c> with no associated data.
/// The AEAD is AES-128-GCM with a 16-byte tag in every case.
/// </para>
/// <para>
/// <b>Key schedule.</b> Everything hangs off the account's command key
/// <c>cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")</c> and the KDF,
/// which is a chain of nested HMAC-SHA256 instances rooted at
/// <c>"VMess AEAD KDF"</c>. The reference implementations build it by nesting
/// <c>hmac.New</c> calls, so level <c>i</c> is an HMAC keyed by its own path
/// element whose underlying hash is level <c>i-1</c>; the KDF input is the message
/// at the innermost level. <see cref="Kdf"/> reproduces that exactly.
/// </para>
/// <para>
/// This matches SagerNet/sing-vmess (the implementation mihomo uses),
/// v2ray-core's <c>proxy/vmess/aead</c> and mihomo's own
/// <c>transport/vmess</c>: <c>Key()</c>, <c>KDF()</c>, <c>AuthID()</c>,
/// <c>SealVMessAEADHeader()</c> and <c>CreateAuthID()</c>.
/// </para>
/// </summary>
public static class VmessCrypto
{
    /// <summary>KDF salt used to derive the AES key that seals the AuthID.</summary>
    public const string SaltAuthIdEncryptionKey = "AES Auth ID Encryption";

    /// <summary>KDF salt for the response header length key.</summary>
    public const string SaltResponseHeaderLengthKey = "AEAD Resp Header Len Key";

    /// <summary>KDF salt for the response header length nonce.</summary>
    public const string SaltResponseHeaderLengthIv = "AEAD Resp Header Len IV";

    /// <summary>KDF salt for the response header payload key.</summary>
    public const string SaltResponseHeaderPayloadKey = "AEAD Resp Header Key";

    /// <summary>KDF salt for the response header payload nonce.</summary>
    public const string SaltResponseHeaderPayloadIv = "AEAD Resp Header IV";

    /// <summary>The root of every KDF chain.</summary>
    public const string SaltVmessAeadKdf = "VMess AEAD KDF";

    /// <summary>KDF salt for the request header payload key.</summary>
    public const string SaltRequestHeaderPayloadKey = "VMess Header AEAD Key";

    /// <summary>KDF salt for the request header payload nonce.</summary>
    public const string SaltRequestHeaderPayloadIv = "VMess Header AEAD Nonce";

    /// <summary>KDF salt for the request header length key.</summary>
    public const string SaltRequestHeaderLengthKey = "VMess Header AEAD Key_Length";

    /// <summary>KDF salt for the request header length nonce.</summary>
    public const string SaltRequestHeaderLengthIv = "VMess Header AEAD Nonce_Length";

    /// <summary>Size of the AuthID field and of every AEAD key the header uses.</summary>
    public const int AuthIdSize = 16;

    /// <summary>Size of the AEAD nonce (the first 12 bytes of a derived nonce).</summary>
    public const int AeadNonceSize = 12;

    /// <summary>Size of a GCM tag.</summary>
    public const int TagSize = 16;

    /// <summary>Size of the random connection nonce between the AuthID and the body.</summary>
    public const int ConnectionNonceSize = 8;

    /// <summary>HMAC block size of SHA-256, the block size of every KDF level.</summary>
    private const int HmacBlockSize = 64;

    /// <summary>The salt that derives a user's alter ids for the legacy header.</summary>
    public const string SaltAlterId = "16167dc8-16b6-4e6d-b8bb-65dd68113a81";

    /// <summary>UTF-8 bytes of a KDF salt, so the call sites read like the protocol.</summary>
    public static byte[] Salt(string salt) => Encoding.UTF8.GetBytes(salt);

    /// <summary>
    /// The legacy (pre-AEAD) auth id: <c>HMAC-MD5(alterKey, timestamp)</c> with the
    /// timestamp written big-endian, where
    /// <c>alterKey = MD5(uuid || "16167dc8-16b6-4e6d-b8bb-65dd68113a81")</c>. The
    /// AEAD header seals its own AuthID instead and never uses this.
    /// </summary>
    public static byte[] CreateAuthId(ReadOnlySpan<byte> uuid, long timestamp)
    {
        if (uuid.Length != AuthIdSize) throw new ArgumentException($"uuid must be {AuthIdSize} bytes", nameof(uuid));

        var alterKey = MD5.HashData([.. uuid.ToArray(), .. Encoding.ASCII.GetBytes(SaltAlterId)]);
        Span<byte> material = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(material, timestamp);
        return HMACMD5.HashData(alterKey, material);
    }

    /// <summary>
    /// The account's command key, <c>MD5(uuid || the VMess magic string)</c>. Every
    /// VMess key schedule is rooted here, and the legacy header uses it as its
    /// AES-128-CFB key too.
    /// </summary>
    public static byte[] CommandKey(ReadOnlySpan<byte> uuid)
    {
        if (uuid.Length != AuthIdSize) throw new ArgumentException($"uuid must be {AuthIdSize} bytes", nameof(uuid));
        return VmessLegacy.DeriveCommandKey(uuid);
    }

    /// <summary>
    /// The VMess AEAD key-derivation function: a chain of nested HMAC-SHA256
    /// instances rooted at <see cref="SaltVmessAeadKdf"/>, keyed by
    /// <paramref name="key"/> and fed the path elements as the salt of each level.
    /// </summary>
    public static byte[] Kdf(ReadOnlySpan<byte> key, params byte[][] path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var elements = new byte[path.Length + 1][];
        elements[0] = Salt(SaltVmessAeadKdf);
        for (var i = 0; i < path.Length; i++)
        {
            elements[i + 1] = path[i] ?? throw new ArgumentNullException(nameof(path), "a KDF path element must not be null");
        }

        return Chain(key.ToArray(), elements, elements.Length - 1);
    }

    /// <summary><see cref="Kdf"/> truncated to the 16-byte key width the header uses.</summary>
    public static byte[] Kdf16(ReadOnlySpan<byte> key, params byte[][] path) => Kdf(key, path)[..AuthIdSize];

    /// <summary>
    /// One level of the KDF chain. Level zero is a plain HMAC-SHA256 under the root
    /// salt; every higher level is an HMAC keyed by its own path element whose
    /// underlying hash is the level below, which is what nesting
    /// <c>hmac.New(parent.Create, value)</c> produces.
    /// </summary>
    private static byte[] Chain(byte[] message, byte[][] elements, int level)
    {
        if (level == 0) return HMACSHA256.HashData(elements[0], message);

        var key = elements[level];
        if (key.Length > HmacBlockSize) key = SHA256.HashData(key);

        var inner = new byte[HmacBlockSize + message.Length];
        var outer = new byte[HmacBlockSize];
        for (var i = 0; i < HmacBlockSize; i++)
        {
            var b = i < key.Length ? key[i] : (byte)0;
            inner[i] = (byte)(b ^ 0x36);
            outer[i] = (byte)(b ^ 0x5c);
        }

        message.CopyTo(inner.AsSpan(HmacBlockSize));
        var innerHash = Chain(inner, elements, level - 1);

        var outerInput = new byte[HmacBlockSize + innerHash.Length];
        outer.CopyTo(outerInput, 0);
        innerHash.CopyTo(outerInput, HmacBlockSize);
        return Chain(outerInput, elements, level - 1);
    }

    /// <summary>
    /// Builds the 16-byte AuthID plaintext:
    /// <c>timestamp(8, big-endian) || random(4) || crc32(timestamp || random)</c>,
    /// with the CRC written big-endian.
    /// </summary>
    public static void BuildAuthIdPlaintext(Span<byte> destination, long timestamp, ReadOnlySpan<byte> random4)
    {
        if (destination.Length < AuthIdSize) throw new ArgumentException($"destination must be at least {AuthIdSize} bytes", nameof(destination));
        if (random4.Length != 4) throw new ArgumentException("random4 must be 4 bytes", nameof(random4));

        BinaryPrimitives.WriteInt64BigEndian(destination, timestamp);
        random4.CopyTo(destination[8..]);
        var crc = Crc32.HashToUInt32(destination[..12]);
        BinaryPrimitives.WriteUInt32BigEndian(destination[12..], crc);
    }

    /// <summary>
    /// Verifies the CRC inside a recovered AuthID plaintext, which is how a server
    /// knows it guessed the right user key.
    /// </summary>
    public static bool VerifyAuthIdPlaintext(ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length < AuthIdSize) return false;
        var expected = BinaryPrimitives.ReadUInt32BigEndian(plaintext[12..]);
        return Crc32.HashToUInt32(plaintext[..12]) == expected;
    }

    /// <summary>
    /// Seals a 16-byte AuthID plaintext with AES-128-ECB under
    /// <c>KDF16(cmdKey, "AES Auth ID Encryption")</c>.
    /// </summary>
    public static void SealAuthId(ReadOnlySpan<byte> uuid, ReadOnlySpan<byte> plaintext, Span<byte> destination)
    {
        if (plaintext.Length != AuthIdSize) throw new ArgumentException($"plaintext must be {AuthIdSize} bytes", nameof(plaintext));
        if (destination.Length < AuthIdSize) throw new ArgumentException($"destination must be at least {AuthIdSize} bytes", nameof(destination));

        var key = Kdf16(CommandKey(uuid), Salt(SaltAuthIdEncryptionKey));
        try
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.EncryptEcb(plaintext, destination[..AuthIdSize], PaddingMode.None);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Opens a sealed AuthID. Returns false when the key is not the right one.
    /// <para>
    /// AES-ECB is unauthenticated, so decryption succeeds under <em>any</em> key;
    /// the CRC32 inside the recovered plaintext is what proves the user was the
    /// right one, which is exactly how a VMess server picks the user.
    /// </para>
    /// </summary>
    public static bool TryOpenAuthId(ReadOnlySpan<byte> uuid, ReadOnlySpan<byte> sealedAuthId, Span<byte> plaintext)
    {
        if (sealedAuthId.Length != AuthIdSize) return false;
        if (plaintext.Length < AuthIdSize) throw new ArgumentException($"plaintext must be at least {AuthIdSize} bytes", nameof(plaintext));

        var key = Kdf16(CommandKey(uuid), Salt(SaltAuthIdEncryptionKey));
        try
        {
            using var aes = Aes.Create();
            aes.Key = key;
            if (!aes.TryDecryptEcb(sealedAuthId, plaintext[..AuthIdSize], PaddingMode.None, out _)) return false;

            if (VerifyAuthIdPlaintext(plaintext[..AuthIdSize])) return true;

            plaintext[..AuthIdSize].Clear();
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Derives the four AEAD parameters of the client's request header. The KDF is
    /// keyed by the command key and its path is the salt, the sealed AuthID and the
    /// connection nonce, all as raw bytes.
    /// </summary>
    public static VmessAeadKeys DeriveRequestHeaderKeys(
        ReadOnlySpan<byte> cmdKey,
        ReadOnlySpan<byte> authId,
        ReadOnlySpan<byte> connectionNonce)
    {
        var authIdBytes = authId.ToArray();
        var nonceBytes = connectionNonce.ToArray();

        return new VmessAeadKeys(
            Kdf16(cmdKey, Salt(SaltRequestHeaderLengthKey), authIdBytes, nonceBytes),
            Kdf(cmdKey, Salt(SaltRequestHeaderLengthIv), authIdBytes, nonceBytes)[..AeadNonceSize],
            Kdf16(cmdKey, Salt(SaltRequestHeaderPayloadKey), authIdBytes, nonceBytes),
            Kdf(cmdKey, Salt(SaltRequestHeaderPayloadIv), authIdBytes, nonceBytes)[..AeadNonceSize]);
    }

    /// <summary>
    /// Derives the four AEAD parameters of the server's response header. Unlike the
    /// request direction these hang off the response body key and IV with no other
    /// path elements, so both peers can compute them without exchanging anything.
    /// </summary>
    public static VmessAeadKeys DeriveResponseHeaderKeys(
        ReadOnlySpan<byte> responseBodyKey,
        ReadOnlySpan<byte> responseBodyIv)
    {
        return new VmessAeadKeys(
            Kdf16(responseBodyKey, Salt(SaltResponseHeaderLengthKey)),
            Kdf(responseBodyIv, Salt(SaltResponseHeaderLengthIv))[..AeadNonceSize],
            Kdf16(responseBodyKey, Salt(SaltResponseHeaderPayloadKey)),
            Kdf(responseBodyIv, Salt(SaltResponseHeaderPayloadIv))[..AeadNonceSize]);
    }

    /// <summary>
    /// Derives the response body key and IV: the first 16 bytes of the SHA-256 of
    /// the request body key and of the request body IV. Deriving fresh key material
    /// for the second direction is what keeps the two directions from sharing a
    /// keystream, and the server can compute both because the request header
    /// carries the request body key and IV.
    /// </summary>
    public static (byte[] Key, byte[] Iv) DeriveResponseBodyKeys(
        ReadOnlySpan<byte> requestBodyKey,
        ReadOnlySpan<byte> requestBodyIv)
    {
        if (requestBodyKey.Length != AuthIdSize)
        {
            throw new ArgumentException($"the request body key must be {AuthIdSize} bytes", nameof(requestBodyKey));
        }

        if (requestBodyIv.Length != AuthIdSize)
        {
            throw new ArgumentException($"the request body IV must be {AuthIdSize} bytes", nameof(requestBodyIv));
        }

        return (SHA256.HashData(requestBodyKey)[..AuthIdSize], SHA256.HashData(requestBodyIv)[..AuthIdSize]);
    }

    /// <summary>
    /// The 32-byte ChaCha20-Poly1305 key the reference derives from the 16-byte body
    /// key: <c>MD5(bodyKey) || MD5(MD5(bodyKey))</c>.
    /// </summary>
    public static byte[] Chacha20Poly1305Key(ReadOnlySpan<byte> bodyKey)
    {
        if (bodyKey.Length != AuthIdSize) throw new ArgumentException($"the body key must be {AuthIdSize} bytes", nameof(bodyKey));

        var key = new byte[32];
        var first = MD5.HashData(bodyKey);
        first.CopyTo(key, 0);
        MD5.HashData(first).CopyTo(key, AuthIdSize);
        return key;
    }

    /// <summary>
    /// Seals a whole VMess AEAD request header:
    /// <c>authID || AEAD(length) || connectionNonce || AEAD(body)</c>, with the
    /// AuthID as the associated data of both AEAD operations.
    /// </summary>
    public static byte[] SealRequestHeader(
        ReadOnlySpan<byte> cmdKey,
        ReadOnlySpan<byte> authId,
        ReadOnlySpan<byte> connectionNonce,
        ReadOnlySpan<byte> body)
    {
        if (authId.Length != AuthIdSize) throw new ArgumentException($"authId must be {AuthIdSize} bytes", nameof(authId));
        if (connectionNonce.Length != ConnectionNonceSize) throw new ArgumentException($"connectionNonce must be {ConnectionNonceSize} bytes", nameof(connectionNonce));
        if (body.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(body), body.Length, "header body too long");

        var keys = DeriveRequestHeaderKeys(cmdKey, authId, connectionNonce);
        var lengthFrame = 2 + TagSize;
        var result = new byte[AuthIdSize + lengthFrame + ConnectionNonceSize + body.Length + TagSize];

        authId.CopyTo(result);

        Span<byte> lengthPlaintext = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(lengthPlaintext, (ushort)body.Length);
        Encrypt(keys.LengthKey, keys.LengthIv, lengthPlaintext, result.AsSpan(AuthIdSize, lengthFrame), authId);

        connectionNonce.CopyTo(result.AsSpan(AuthIdSize + lengthFrame));
        Encrypt(keys.PayloadKey, keys.PayloadIv, body, result.AsSpan(AuthIdSize + lengthFrame + ConnectionNonceSize), authId);

        return result;
    }

    /// <summary>
    /// Opens a sealed request header. <paramref name="consumed"/> is the number of
    /// bytes the whole header occupied.
    /// </summary>
    public static bool TryOpenRequestHeader(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> cmdKey,
        out int consumed,
        out byte[] authId,
        out byte[] connectionNonce,
        out byte[] body)
    {
        consumed = 0;
        authId = [];
        connectionNonce = [];
        body = [];

        var lengthFrame = 2 + TagSize;
        if (source.Length < AuthIdSize + lengthFrame + ConnectionNonceSize) return false;

        authId = source[..AuthIdSize].ToArray();
        connectionNonce = source.Slice(AuthIdSize + lengthFrame, ConnectionNonceSize).ToArray();

        var keys = DeriveRequestHeaderKeys(cmdKey, authId, connectionNonce);

        Span<byte> lengthPlaintext = stackalloc byte[2];
        if (!Decrypt(keys.LengthKey, keys.LengthIv, source.Slice(AuthIdSize, lengthFrame), lengthPlaintext, authId)) return false;

        var bodyLength = BinaryPrimitives.ReadUInt16BigEndian(lengthPlaintext);
        var total = AuthIdSize + lengthFrame + ConnectionNonceSize + bodyLength + TagSize;
        if (source.Length < total) return false;

        var plaintext = new byte[bodyLength];
        if (!Decrypt(
                keys.PayloadKey,
                keys.PayloadIv,
                source.Slice(AuthIdSize + lengthFrame + ConnectionNonceSize, bodyLength + TagSize),
                plaintext,
                authId))
        {
            return false;
        }

        body = plaintext;
        consumed = total;
        return true;
    }

    /// <summary>
    /// Seals a response header: a 2-byte big-endian length followed by the header
    /// body, each encrypted with its own key and nonce and with no associated data.
    /// Returns the bytes written.
    /// </summary>
    public static int SealResponseHeader(ReadOnlySpan<byte> body, in VmessAeadKeys keys, Span<byte> destination)
        => SealFramed(body, keys, destination);

    /// <summary>
    /// Opens a sealed response header and returns its body.
    /// <paramref name="consumed"/> is the number of bytes the frame occupied.
    /// </summary>
    public static bool TryOpenHeader(ReadOnlySpan<byte> source, in VmessAeadKeys keys, out int consumed, out byte[] body)
    {
        consumed = 0;
        body = [];

        var lengthFrame = 2 + TagSize;
        if (source.Length < lengthFrame) return false;

        Span<byte> lengthPlaintext = stackalloc byte[2];
        if (!Decrypt(keys.LengthKey, keys.LengthIv, source[..lengthFrame], lengthPlaintext)) return false;

        var bodyLength = BinaryPrimitives.ReadUInt16BigEndian(lengthPlaintext);
        var total = lengthFrame + bodyLength + TagSize;
        if (source.Length < total) return false;

        var plaintext = new byte[bodyLength];
        if (!Decrypt(keys.PayloadKey, keys.PayloadIv, source.Slice(lengthFrame, bodyLength + TagSize), plaintext)) return false;

        consumed = total;
        body = plaintext;
        return true;
    }

    private static int SealFramed(ReadOnlySpan<byte> body, in VmessAeadKeys keys, Span<byte> destination)
    {
        if (body.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(body), body.Length, "header body too long");

        var lengthFrame = 2 + TagSize;
        var payloadFrame = body.Length + TagSize;
        if (destination.Length < lengthFrame + payloadFrame) throw new ArgumentException("destination too small", nameof(destination));

        Span<byte> lengthPlaintext = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(lengthPlaintext, (ushort)body.Length);
        Encrypt(keys.LengthKey, keys.LengthIv, lengthPlaintext, destination[..lengthFrame]);
        Encrypt(keys.PayloadKey, keys.PayloadIv, body, destination.Slice(lengthFrame, payloadFrame));

        return lengthFrame + payloadFrame;
    }

    /// <summary>
    /// AES-128-GCM seal with the nonce taken from the first 12 bytes of
    /// <paramref name="iv"/>.
    /// </summary>
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length < 16) throw new ArgumentException("key must be at least 16 bytes", nameof(key));
        if (iv.Length < AeadNonceSize) throw new ArgumentException($"iv must be at least {AeadNonceSize} bytes", nameof(iv));

        var ciphertext = destination[..plaintext.Length];
        var tag = destination.Slice(plaintext.Length, TagSize);
        AeadPrimitives.AesGcmEncrypt(key[..16], iv[..AeadNonceSize], plaintext, ciphertext, tag, associatedData);
    }

    /// <summary>AES-128-GCM open. Returns false when the tag does not verify.</summary>
    public static bool Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length < 16) throw new ArgumentException("key must be at least 16 bytes", nameof(key));
        if (iv.Length < AeadNonceSize) throw new ArgumentException($"iv must be at least {AeadNonceSize} bytes", nameof(iv));
        if (ciphertext.Length < TagSize) return false;

        return AeadPrimitives.AesGcmDecrypt(
            key[..16],
            iv[..AeadNonceSize],
            ciphertext[..^TagSize],
            ciphertext[^TagSize..],
            destination[..(ciphertext.Length - TagSize)],
            associatedData);
    }
}

/// <summary>
/// The body cipher a VMess connection negotiated. The numeric values are exactly
/// the ones the request header carries in the low nibble of its padding/security
/// byte.
/// </summary>
public enum VmessSecurity : byte
{
    /// <summary>AES-128-GCM, the modern default and what <c>auto</c> resolves to.</summary>
    Aes128Gcm = 0x03,

    /// <summary>ChaCha20-Poly1305, whose key the reference expands to 32 bytes.</summary>
    ChaCha20Poly1305 = 0x04,

    /// <summary>No body cipher at all: the payload is only length-prefixed.</summary>
    None = 0x05,
}

/// <summary>
/// The VMess chunked body framing, independent of any stream.
/// <para>
/// Every chunk is <c>[length(2, big-endian)][payload][tag]</c>. The length counts
/// the payload <em>plus</em> the tag, and the tag is absent under
/// <see cref="VmessSecurity.None"/>. The chunk nonce is the body IV with a
/// big-endian counter written over its first two bytes, and the counter advances
/// once per chunk — one AEAD operation per chunk, length first on the wire but not
/// authenticated separately.
/// </para>
/// <para>
/// This is mihomo's <c>transport/vmess/aead.go</c> and <c>chunk.go</c>, which in
/// turn match sing-vmess's <c>StreamChunkWriter</c> + <c>AEADWriter</c> and
/// v2ray's <c>NewAuthenticationWriter</c> with <c>PlainChunkSizeParser</c>: the
/// length prefix is in the clear, so the option byte this build sends is
/// <c>ChunkStream</c> alone (no chunk masking, no global padding, no authenticated
/// length).
/// </para>
/// </summary>
public static class VmessBody
{
    /// <summary>Chunk size the reference client frames with (<c>chunkSize</c>).</summary>
    public const int ChunkSize = 16 * 1024;

    /// <summary>Largest length field a reader accepts (<c>maxSize</c>).</summary>
    public const int MaxChunkSize = 17 * 1024;

    /// <summary>Width of the big-endian length field.</summary>
    public const int LengthFieldSize = 2;

    /// <summary>Width of the tag a security adds, or zero when nothing is encrypted.</summary>
    public static int TagSize(VmessSecurity security) => security == VmessSecurity.None ? 0 : VmessCrypto.TagSize;

    /// <summary>Largest payload one written chunk carries.</summary>
    public static int MaxPayloadSize(VmessSecurity security) => ChunkSize - TagSize(security);

    /// <summary>Bytes a chunk carrying <paramref name="payloadLength"/> bytes occupies on the wire.</summary>
    public static int FramedSize(VmessSecurity security, int payloadLength)
    {
        if (payloadLength < 0 || payloadLength > MaxPayloadSize(security))
        {
            throw new ArgumentOutOfRangeException(nameof(payloadLength), payloadLength, $"payload must be between 0 and {MaxPayloadSize(security)}");
        }

        return LengthFieldSize + payloadLength + TagSize(security);
    }

    /// <summary>
    /// Writes the chunk nonce: the big-endian counter in the first two bytes and the
    /// body IV from byte two on, which is how every reference builds it.
    /// </summary>
    public static void WriteNonce(Span<byte> nonce, ReadOnlySpan<byte> bodyIv, ushort counter)
    {
        if (nonce.Length < VmessCrypto.AeadNonceSize) throw new ArgumentException($"nonce must be at least {VmessCrypto.AeadNonceSize} bytes", nameof(nonce));
        if (bodyIv.Length < VmessCrypto.AeadNonceSize) throw new ArgumentException($"the body IV must be at least {VmessCrypto.AeadNonceSize} bytes", nameof(bodyIv));

        BinaryPrimitives.WriteUInt16BigEndian(nonce, counter);
        bodyIv.Slice(2, VmessCrypto.AeadNonceSize - 2).CopyTo(nonce[2..]);
    }

    /// <summary>
    /// Encodes one chunk into <paramref name="destination"/> and advances
    /// <paramref name="counter"/>. <paramref name="aeadKey"/> is the key the cipher
    /// itself takes, i.e. already expanded for ChaCha20-Poly1305.
    /// </summary>
    /// <returns>The number of bytes written.</returns>
    public static int WriteChunk(
        VmessSecurity security,
        ReadOnlySpan<byte> aeadKey,
        ReadOnlySpan<byte> bodyIv,
        ref ushort counter,
        ReadOnlySpan<byte> payload,
        Span<byte> destination)
    {
        var framed = FramedSize(security, payload.Length);
        if (destination.Length < framed) throw new ArgumentException($"destination must be at least {framed} bytes", nameof(destination));

        BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)(payload.Length + TagSize(security)));

        if (security == VmessSecurity.None)
        {
            payload.CopyTo(destination[LengthFieldSize..]);
            return framed;
        }

        Span<byte> nonce = stackalloc byte[VmessCrypto.AeadNonceSize];
        WriteNonce(nonce, bodyIv, counter++);
        Encrypt(security, aeadKey, nonce, payload, destination.Slice(LengthFieldSize, payload.Length + TagSize(security)));
        return framed;
    }

    /// <summary>Reads the plaintext length field that starts a chunk.</summary>
    public static bool TryReadChunkLength(ReadOnlySpan<byte> source, out int framedLength)
    {
        framedLength = 0;
        if (source.Length < LengthFieldSize) return false;

        framedLength = BinaryPrimitives.ReadUInt16BigEndian(source);
        return true;
    }

    /// <summary>
    /// Authenticates and decodes the payload of a chunk whose length was already
    /// read with <see cref="TryReadChunkLength"/>.
    /// </summary>
    public static bool TryReadChunkPayload(
        VmessSecurity security,
        ReadOnlySpan<byte> aeadKey,
        ReadOnlySpan<byte> bodyIv,
        ref ushort counter,
        ReadOnlySpan<byte> source,
        int framedLength,
        Span<byte> destination)
    {
        var payloadLength = framedLength - TagSize(security);
        if (payloadLength < 0) return false;
        if (source.Length < framedLength) return false;
        if (destination.Length < payloadLength) throw new ArgumentException($"destination must be at least {payloadLength} bytes", nameof(destination));

        if (security == VmessSecurity.None)
        {
            source[..payloadLength].CopyTo(destination);
            return true;
        }

        Span<byte> nonce = stackalloc byte[VmessCrypto.AeadNonceSize];
        WriteNonce(nonce, bodyIv, counter++);
        return Decrypt(security, aeadKey, nonce, source[..framedLength], destination[..payloadLength]);
    }

    /// <summary>The AEAD key a direction encrypts with, given its 16-byte body key.</summary>
    public static byte[] DeriveKey(VmessSecurity security, ReadOnlySpan<byte> bodyKey)
        => security == VmessSecurity.ChaCha20Poly1305 ? VmessCrypto.Chacha20Poly1305Key(bodyKey) : bodyKey.ToArray();

    private static void Encrypt(
        VmessSecurity security,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        switch (security)
        {
            case VmessSecurity.Aes128Gcm:
                VmessCrypto.Encrypt(key, nonce, plaintext, destination);
                break;

            case VmessSecurity.ChaCha20Poly1305:
                if (key.Length != 32) throw new ArgumentException("ChaCha20-Poly1305 needs a 32-byte key", nameof(key));
                AeadPrimitives.ChaChaEncrypt(
                    key,
                    nonce,
                    plaintext,
                    destination[..plaintext.Length],
                    destination.Slice(plaintext.Length, VmessCrypto.TagSize),
                    default);
                break;

            default:
                throw new NotSupportedException($"vmess: security 0x{(byte)security:X2} has no body cipher");
        }
    }

    private static bool Decrypt(
        VmessSecurity security,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination)
    {
        switch (security)
        {
            case VmessSecurity.Aes128Gcm:
                return VmessCrypto.Decrypt(key, nonce, ciphertext, destination);

            case VmessSecurity.ChaCha20Poly1305:
                if (key.Length != 32) throw new ArgumentException("ChaCha20-Poly1305 needs a 32-byte key", nameof(key));
                if (ciphertext.Length < VmessCrypto.TagSize) return false;
                return AeadPrimitives.ChaChaDecrypt(
                    key,
                    nonce,
                    ciphertext[..^VmessCrypto.TagSize],
                    ciphertext[^VmessCrypto.TagSize..],
                    destination[..(ciphertext.Length - VmessCrypto.TagSize)],
                    default);

            default:
                throw new NotSupportedException($"vmess: security 0x{(byte)security:X2} has no body cipher");
        }
    }
}

/// <summary>
/// The legacy, pre-AEAD VMess header. The request header is encrypted with
/// AES-128-CFB under keys derived from the user id and a fixed magic string, and
/// the auth id is the MD5 construction in <see cref="VmessCrypto.CreateAuthId"/>.
/// <para>
/// <b>What is used today.</b> <see cref="DeriveCommandKey"/> is not legacy-only:
/// it is the account's command key, the root of every AEAD key schedule as well.
/// The CFB header transform itself is unused by this build, which only speaks the
/// AEAD header.
/// </para>
/// </summary>
public static class VmessLegacy
{
    /// <summary>The magic suffix VMess mixes into the account command key.</summary>
    public const string KeyMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

    /// <summary>Derives the account command key: <c>MD5(uuid || magic)</c>.</summary>
    public static byte[] DeriveCommandKey(ReadOnlySpan<byte> uuid)
    {
        if (uuid.Length != 16) throw new ArgumentException("uuid must be 16 bytes", nameof(uuid));
        return MD5.HashData([.. uuid.ToArray(), .. Encoding.ASCII.GetBytes(KeyMagic)]);
    }

    /// <summary>Derives the legacy AES-128-CFB command IV: <c>MD5(baseIv || magic)</c>.</summary>
    public static byte[] DeriveCommandIv(ReadOnlySpan<byte> baseIv)
        => MD5.HashData([.. baseIv.ToArray(), .. Encoding.ASCII.GetBytes(KeyMagic)]);

    /// <summary>
    /// Applies the legacy AES-128-CFB header transform. VMess uses the encryptor
    /// in both directions for the header, so this is symmetric.
    /// </summary>
    public static void TransformHeader(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
    {
        var cipher = new CfbStreamCipher("vmess-legacy-header", 16, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine())
        {
            Encrypting = true,
        };
        cipher.Init(key, iv);
        cipher.Process(input, output);
    }
}
