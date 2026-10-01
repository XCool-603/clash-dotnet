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
/// <b>Wire layout implemented here.</b>
/// </para>
/// <code>
/// Request  : [ AuthID (16) ][ AEAD( length, 2 ) ][ AEAD( header payload ) ]
/// Response : [ AEAD( length, 2 ) ][ AEAD( header payload ) ]
/// </code>
/// <para>
/// The AEAD is AES-128-GCM with a 16-byte tag. <c>AuthID</c> is the AES-128-ECB
/// seal of a 16-byte plaintext <c>timestamp(8, big-endian) || random(4) || crc32(4)</c>
/// under <c>KDF(uuid, "AES Auth ID Encryption")[0..16]</c>; the server tries each
/// known user key until one opens, then uses the recovered plaintext as the
/// <em>connection nonce</em>.
/// </para>
/// <para>
/// <b>Documented limitation.</b> The AEAD KDF salt strings and the
/// <c>AuthID</c> construction above are the ones v2ray/Xray use; the
/// <see cref="CreateAuthId"/> MD5 construction is the legacy header's auth id as
/// specified for this project. The environment this was written in had no
/// network access, so neither could be checked against a live peer. Both are
/// isolated here, and <see cref="Kdf"/> — the one piece that is shared by every
/// variant — is exactly <c>HMAC-SHA256</c> chained over the salt strings.
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

    /// <summary>The root KDF salt.</summary>
    public const string SaltVmessAeadKdf = "VMess AEAD KDF";

    /// <summary>KDF salt for the request header payload key.</summary>
    public const string SaltRequestHeaderPayloadKey = "VMess Header AEAD Key";

    /// <summary>KDF salt for the request header payload nonce.</summary>
    public const string SaltRequestHeaderPayloadIv = "VMess Header AEAD Nonce";

    /// <summary>KDF salt for the request header length key.</summary>
    public const string SaltRequestHeaderLengthKey = "VMess Header AEAD Key_Length";

    /// <summary>KDF salt for the request header length nonce.</summary>
    public const string SaltRequestHeaderLengthIv = "VMess Header AEAD Nonce_Length";

    /// <summary>Size of the AuthID field and of every AEAD key VMess derives.</summary>
    public const int AuthIdSize = 16;

    /// <summary>Size of the AEAD nonce (the first 12 bytes of a derived IV).</summary>
    public const int AeadNonceSize = 12;

    /// <summary>Size of a GCM tag.</summary>
    public const int TagSize = 16;

    /// <summary>
    /// The VMess AEAD key-derivation function:
    /// <c>KDF(key, p1, p2) = HMAC-SHA256(HMAC-SHA256(key, p1), p2)</c>.
    /// Every salt string is hashed as UTF-8.
    /// </summary>
    public static byte[] Kdf(ReadOnlySpan<byte> key, params string[] path)
    {
        ArgumentNullException.ThrowIfNull(path);

        var current = key.ToArray();
        foreach (var salt in path)
        {
            var saltBytes = Encoding.UTF8.GetBytes(salt);
            current = HMACSHA256.HashData(current, saltBytes);
        }

        return current;
    }

    /// <inheritdoc cref="Kdf(ReadOnlySpan{byte},string[])"/>
    public static void Kdf(ReadOnlySpan<byte> key, Span<byte> destination, params string[] path)
    {
        var derived = Kdf(key, path);
        derived.AsSpan(0, Math.Min(derived.Length, destination.Length)).CopyTo(destination);
    }

    /// <summary>
    /// The VMess auth id used by the legacy request header:
    /// <c>MD5(uuid || timestamp)</c> with the timestamp written as 4 little-endian
    /// bytes.
    /// </summary>
    public static byte[] CreateAuthId(ReadOnlySpan<byte> uuid, uint timestamp)
    {
        if (uuid.Length != 16) throw new ArgumentException("uuid must be 16 bytes", nameof(uuid));

        Span<byte> material = stackalloc byte[20];
        uuid.CopyTo(material);
        BinaryPrimitives.WriteUInt32LittleEndian(material[16..], timestamp);
        return MD5.HashData(material);
    }

    /// <summary>
    /// Builds the 16-byte AuthID plaintext that the AEAD request header seals:
    /// <c>timestamp(8, big-endian) || random(4) || crc32(timestamp || random)</c>.
    /// </summary>
    public static void BuildAuthIdPlaintext(Span<byte> destination, long timestamp, ReadOnlySpan<byte> random4)
    {
        if (destination.Length < AuthIdSize) throw new ArgumentException($"destination must be at least {AuthIdSize} bytes", nameof(destination));
        if (random4.Length != 4) throw new ArgumentException("random4 must be 4 bytes", nameof(random4));

        BinaryPrimitives.WriteInt64BigEndian(destination, timestamp);
        random4.CopyTo(destination[8..]);
        var crc = Crc32.HashToUInt32(destination[..12]);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[12..], crc);
    }

    /// <summary>
    /// Verifies the CRC inside a recovered AuthID plaintext, which is how a server
    /// knows it guessed the right user key.
    /// </summary>
    public static bool VerifyAuthIdPlaintext(ReadOnlySpan<byte> plaintext)
    {
        if (plaintext.Length < AuthIdSize) return false;
        var expected = BinaryPrimitives.ReadUInt32LittleEndian(plaintext[12..]);
        return Crc32.HashToUInt32(plaintext[..12]) == expected;
    }

    /// <summary>
    /// Seals a 16-byte AuthID plaintext with AES-128-ECB under
    /// <c>KDF(uuid, "AES Auth ID Encryption")[0..16]</c>.
    /// </summary>
    public static void SealAuthId(ReadOnlySpan<byte> uuid, ReadOnlySpan<byte> plaintext, Span<byte> destination)
    {
        if (plaintext.Length != AuthIdSize) throw new ArgumentException($"plaintext must be {AuthIdSize} bytes", nameof(plaintext));
        if (destination.Length < AuthIdSize) throw new ArgumentException($"destination must be at least {AuthIdSize} bytes", nameof(destination));

        var key = Kdf(uuid, SaltAuthIdEncryptionKey);
        try
        {
            using var aes = Aes.Create();
            aes.Key = key.AsSpan(0, 16).ToArray();
            aes.EncryptEcb(plaintext, destination[..AuthIdSize], PaddingMode.None);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Opens a sealed AuthID. Returns false when the key is not the right one.</summary>
    public static bool TryOpenAuthId(ReadOnlySpan<byte> uuid, ReadOnlySpan<byte> sealedAuthId, Span<byte> plaintext)
    {
        if (sealedAuthId.Length != AuthIdSize) return false;
        if (plaintext.Length < AuthIdSize) throw new ArgumentException($"plaintext must be at least {AuthIdSize} bytes", nameof(plaintext));

        var key = Kdf(uuid, SaltAuthIdEncryptionKey);
        try
        {
            using var aes = Aes.Create();
            aes.Key = key.AsSpan(0, 16).ToArray();
            return aes.TryDecryptEcb(sealedAuthId, plaintext[..AuthIdSize], PaddingMode.None, out _);
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
    /// Derives the four AEAD parameters of the client's request header from the
    /// connection nonce (the AuthID plaintext), the sealed AuthID and the user id.
    /// </summary>
    public static VmessAeadKeys DeriveRequestHeaderKeys(ReadOnlySpan<byte> connectionNonce, ReadOnlySpan<byte> authId, ReadOnlySpan<byte> uuid)
    {
        var uuidHex = ClashHex.Encode(uuid);
        var authIdHex = ClashHex.Encode(authId);

        var lengthKey = Kdf(connectionNonce, SaltRequestHeaderLengthKey, authIdHex, uuidHex);
        var lengthIv = Kdf(connectionNonce, SaltRequestHeaderLengthIv, authIdHex, uuidHex);
        var payloadKey = Kdf(connectionNonce, SaltRequestHeaderPayloadKey, authIdHex, uuidHex);
        var payloadIv = Kdf(connectionNonce, SaltRequestHeaderPayloadIv, authIdHex, uuidHex);

        return new VmessAeadKeys(lengthKey, lengthIv, payloadKey, payloadIv);
    }

    /// <summary>Derives the four AEAD parameters of the server's response header.</summary>
    public static VmessAeadKeys DeriveResponseHeaderKeys(ReadOnlySpan<byte> connectionNonce)
    {
        var lengthKey = Kdf(connectionNonce, SaltResponseHeaderLengthKey);
        var lengthIv = Kdf(connectionNonce, SaltResponseHeaderLengthIv);
        var payloadKey = Kdf(connectionNonce, SaltResponseHeaderPayloadKey);
        var payloadIv = Kdf(connectionNonce, SaltResponseHeaderPayloadIv);

        return new VmessAeadKeys(lengthKey, lengthIv, payloadKey, payloadIv);
    }

    /// <summary>
    /// Seals the request header: a 2-byte big-endian length followed by the header
    /// body, each encrypted with its own key and nonce. Returns the bytes written.
    /// </summary>
    public static int SealRequestHeader(ReadOnlySpan<byte> body, in VmessAeadKeys keys, Span<byte> destination)
    {
        return SealFramed(body, keys, destination);
    }

    /// <summary>
    /// Seals the response header. Same shape as
    /// <see cref="SealRequestHeader"/>; kept separate so the two call sites read
    /// the way the protocol does.
    /// </summary>
    public static int SealResponseHeader(ReadOnlySpan<byte> body, in VmessAeadKeys keys, Span<byte> destination)
    {
        return SealFramed(body, keys, destination);
    }

    /// <summary>
    /// Opens a sealed header (request or response) and returns its body.
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

    /// <summary>AES-128-GCM seal with the nonce taken from the first 12 bytes of <paramref name="iv"/>.</summary>
    public static void Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext, Span<byte> destination)
    {
        if (key.Length < 16) throw new ArgumentException("key must be at least 16 bytes", nameof(key));
        if (iv.Length < AeadNonceSize) throw new ArgumentException($"iv must be at least {AeadNonceSize} bytes", nameof(iv));

        var ciphertext = destination[..plaintext.Length];
        var tag = destination.Slice(plaintext.Length, TagSize);
        AeadPrimitives.AesGcmEncrypt(key[..16], iv[..AeadNonceSize], plaintext, ciphertext, tag, default);
    }

    /// <summary>AES-128-GCM open. Returns false when the tag does not verify.</summary>
    public static bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, Span<byte> destination)
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
            default);
    }
}

/// <summary>
/// The legacy, pre-AEAD VMess header. The request header is encrypted with
/// AES-128-CFB under keys derived from the user id and a fixed magic string, and
/// the auth id is the MD5 construction in <see cref="VmessCrypto.CreateAuthId"/>.
/// <para>
/// <b>Documented limitation.</b> Only the key/IV derivation and the CFB sealing
/// are implemented. The field layout of the legacy header body belongs to the
/// protocol adapter. The magic string and the <c>MD5(material || magic)</c>
/// construction are the ones v2ray uses, but could not be checked against a live
/// peer from this build environment.
/// </para>
/// </summary>
public static class VmessLegacy
{
    /// <summary>The magic suffix VMess mixes into the legacy header keys.</summary>
    public const string KeyMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

    /// <summary>Derives the AES-128-CFB command key: <c>MD5(uuid || magic)</c>.</summary>
    public static byte[] DeriveCommandKey(ReadOnlySpan<byte> uuid)
    {
        if (uuid.Length != 16) throw new ArgumentException("uuid must be 16 bytes", nameof(uuid));
        return MD5.HashData([.. uuid.ToArray(), .. Encoding.ASCII.GetBytes(KeyMagic)]);
    }

    /// <summary>Derives the AES-128-CFB command IV: <c>MD5(baseIv || magic)</c>.</summary>
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
