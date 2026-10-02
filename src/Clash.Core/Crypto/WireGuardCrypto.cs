using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Common;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace Clash.Core.Crypto;

/// <summary>
/// The cryptographic primitives WireGuard needs that the .NET 10 BCL does not
/// ship: BLAKE2s (unkeyed, keyed and inside HMAC), X25519, and the small
/// fixed-nonce AEAD helper the Noise handshake is written against.
/// <para>
/// Everything here is a thin, literal transcription of the named specifications
/// rather than a redesign of them:
/// </para>
/// <list type="bullet">
/// <item><description>BLAKE2s — RFC 7693. Provided by BouncyCastle's
/// <see cref="Blake2sDigest"/>; this type only fixes the two shapes WireGuard
/// uses (32-byte unkeyed <c>HASH</c>, 16-byte keyed <c>MAC</c>).</description></item>
/// <item><description>HMAC — RFC 2104 over BLAKE2s with the 64-byte BLAKE2s block
/// size. WireGuard names HMAC-BLAKE2s as a primitive; the BCL has no HMAC for a
/// non-BCL hash, so the ipad/opad construction is spelled out here.</description></item>
/// <item><description>ChaCha20-Poly1305 — RFC 7539, taken from the BCL. It is
/// deliberately <em>not</em> reimplemented.</description></item>
/// <item><description>X25519 — RFC 7748, from BouncyCastle. BouncyCastle clamps
/// the scalar inside the scalar multiplication, so an unclamped
/// <c>private-key</c> (as the RFC 7748 test vectors use) behaves exactly like
/// <c>wg genkey</c> output.</description></item>
/// <item><description>XChaCha20-Poly1305 — only for the cookie reply, reused from
/// <see cref="XChaCha20Poly1305"/>.</description></item>
/// </list>
/// <para>
/// The only literals in the whole protocol are the four ASCII strings below; they
/// are exposed as spans so the handshake can concatenate them without allocating.
/// </para>
/// </summary>
public static class WireGuardCrypto
{
    /// <summary>Length of a BLAKE2s-256 digest, and of every chaining key.</summary>
    public const int HashSize = 32;

    /// <summary>Length of a keyed-BLAKE2s <c>MAC</c>, and of a Poly1305 tag.</summary>
    public const int MacSize = 16;

    /// <summary>Length of an X25519 key or a ChaCha20-Poly1305 key.</summary>
    public const int KeySize = 32;

    /// <summary>Length of the ChaCha20-Poly1305 nonce, <c>0x00000000 || LE64(counter)</c>.</summary>
    public const int NonceSize = 12;

    /// <summary>Block size BLAKE2s and therefore HMAC-BLAKE2s use.</summary>
    public const int BlockSize = 64;

    /// <summary>Length of the TAI64N timestamp carried in a handshake initiation.</summary>
    public const int TimestampSize = 12;

    /// <summary>The 64-bit TAI epoch offset TAI64N adds to a Unix timestamp.</summary>
    private const ulong Tai64NBase = 0x400000000000000AUL;

    /// <summary><c>Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s</c> — the handshake construction name.</summary>
    public static ReadOnlySpan<byte> Construction => "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"u8;

    /// <summary><c>WireGuard v1 zx2c4 Jason@zx2c4.com</c> — the protocol identifier.</summary>
    public static ReadOnlySpan<byte> Identifier => "WireGuard v1 zx2c4 Jason@zx2c4.com"u8;

    /// <summary><c>mac1----</c> — prefixes the key that authenticates a handshake message.</summary>
    public static ReadOnlySpan<byte> LabelMac1 => "mac1----"u8;

    /// <summary><c>cookie--</c> — prefixes the key that seals a cookie reply.</summary>
    public static ReadOnlySpan<byte> LabelCookie => "cookie--"u8;

    /// <summary>
    /// <c>HASH(in)</c>: BLAKE2s-256, 32 bytes.
    /// </summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="output">A buffer of at least 32 bytes.</param>
    public static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var digest = new Blake2sDigest();
        digest.BlockUpdate(input);
        digest.DoFinal(output);
    }

    /// <summary>
    /// <c>HASH(a ‖ b)</c>: the shape every Noise hash chain uses. The two pieces
    /// are fed to the digest separately so neither has to be copied into a scratch
    /// buffer.
    /// </summary>
    /// <param name="a">The first piece.</param>
    /// <param name="b">The second piece.</param>
    /// <param name="output">A buffer of at least 32 bytes.</param>
    /// <remarks>
    /// <paramref name="output"/> may alias <paramref name="a"/>: BLAKE2s buffers
    /// every input byte internally before it emits anything, so the digest never
    /// reads an input it has already overwritten.
    /// </remarks>
    public static void Hash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> output)
    {
        var digest = new Blake2sDigest();
        digest.BlockUpdate(a);
        digest.BlockUpdate(b);
        digest.DoFinal(output);
    }

    /// <summary><c>HASH(a ‖ b ‖ c)</c>, for the two-deep hash chain of the construction.</summary>
    /// <param name="a">The first piece.</param>
    /// <param name="b">The second piece.</param>
    /// <param name="c">The third piece.</param>
    /// <param name="output">A buffer of at least 32 bytes.</param>
    public static void Hash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, Span<byte> output)
    {
        var digest = new Blake2sDigest();
        digest.BlockUpdate(a);
        digest.BlockUpdate(b);
        digest.BlockUpdate(c);
        digest.DoFinal(output);
    }

    /// <summary>
    /// Keyed BLAKE2s with a caller-chosen digest length. The digest length is part
    /// of the BLAKE2 parameter block, so a 16-byte result is <em>not</em> the first
    /// half of the 32-byte one — which is exactly why WireGuard's <c>MAC</c> is a
    /// distinct primitive and not a truncation.
    /// </summary>
    /// <param name="key">The key, 1..32 bytes.</param>
    /// <param name="input">The bytes to authenticate.</param>
    /// <param name="output">A buffer of 1..32 bytes; its length is the digest length.</param>
    public static void KeyedHash(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (key.IsEmpty || key.Length > KeySize)
        {
            throw new ArgumentException($"a BLAKE2s key is 1..{KeySize} bytes, got {key.Length}", nameof(key));
        }

        if (output.IsEmpty || output.Length > KeySize)
        {
            throw new ArgumentException($"a BLAKE2s digest is 1..{KeySize} bytes, got {output.Length}", nameof(output));
        }

        var digest = new Blake2sDigest(key.ToArray(), output.Length, null, null);
        digest.BlockUpdate(input);
        digest.DoFinal(output);
    }

    /// <summary>
    /// <c>MAC(key, in)</c>: keyed BLAKE2s truncated to 16 bytes. Used for
    /// <c>mac1</c>/<c>mac2</c> and for the cookie value itself.
    /// </summary>
    /// <param name="key">A 32-byte key.</param>
    /// <param name="input">The bytes to authenticate.</param>
    /// <param name="output">A buffer of at least 16 bytes.</param>
    public static void Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
        => KeyedHash(key, input, output[..MacSize]);

    /// <summary>
    /// <c>HMAC(key, in)</c> as RFC 2104 defines it, over BLAKE2s-256 with the
    /// 64-byte BLAKE2s block size. A key longer than one block is hashed first, as
    /// the RFC requires.
    /// </summary>
    /// <param name="key">The HMAC key.</param>
    /// <param name="input">The message.</param>
    /// <param name="output">A buffer of at least 32 bytes.</param>
    public static void Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> normalized = stackalloc byte[BlockSize];
        normalized.Clear();

        if (key.Length > BlockSize)
        {
            Hash(key, normalized);
        }
        else
        {
            key.CopyTo(normalized);
        }

        Span<byte> inner = stackalloc byte[HashSize];
        var digest = new Blake2sDigest();
        for (var i = 0; i < BlockSize; i++) digest.Update((byte)(normalized[i] ^ 0x36));
        digest.BlockUpdate(input);
        digest.DoFinal(inner);

        var outer = new Blake2sDigest();
        for (var i = 0; i < BlockSize; i++) outer.Update((byte)(normalized[i] ^ 0x5C));
        outer.BlockUpdate(inner);
        outer.DoFinal(output);

        CryptographicOperations.ZeroMemory(normalized);
        CryptographicOperations.ZeroMemory(inner);
    }

    /// <summary>
    /// <c>HMAC(key, a ‖ b)</c> — the only concatenated form the key schedule needs
    /// (a chaining key followed by a one-byte label).
    /// </summary>
    /// <param name="key">The HMAC key.</param>
    /// <param name="a">The first message piece.</param>
    /// <param name="b">The second message piece.</param>
    /// <param name="output">A buffer of at least 32 bytes.</param>
    public static void Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> output)
    {
        Span<byte> normalized = stackalloc byte[BlockSize];
        normalized.Clear();

        if (key.Length > BlockSize)
        {
            Hash(key, normalized);
        }
        else
        {
            key.CopyTo(normalized);
        }

        Span<byte> inner = stackalloc byte[HashSize];
        var digest = new Blake2sDigest();
        for (var i = 0; i < BlockSize; i++) digest.Update((byte)(normalized[i] ^ 0x36));
        digest.BlockUpdate(a);
        digest.BlockUpdate(b);
        digest.DoFinal(inner);

        var outer = new Blake2sDigest();
        for (var i = 0; i < BlockSize; i++) outer.Update((byte)(normalized[i] ^ 0x5C));
        outer.BlockUpdate(inner);
        outer.DoFinal(output);

        CryptographicOperations.ZeroMemory(normalized);
        CryptographicOperations.ZeroMemory(inner);
    }

    /// <summary>
    /// The ChaCha20-Poly1305 nonce <c>0x00000000 ‖ LE64(counter)</c> that
    /// <c>AEAD()</c> is defined with.
    /// </summary>
    /// <param name="counter">The 64-bit counter (or the literal zero of a handshake AEAD).</param>
    /// <param name="nonce">A buffer of at least 12 bytes.</param>
    public static void AeadNonce(ulong counter, Span<byte> nonce)
    {
        nonce[..4].Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
    }

    /// <summary>
    /// <c>AEAD(key, counter, plain, auth)</c>: ChaCha20-Poly1305 with the
    /// WireGuard nonce, the ciphertext followed by its 16-byte tag.
    /// </summary>
    /// <param name="key">A 32-byte key.</param>
    /// <param name="counter">The AEAD counter.</param>
    /// <param name="plaintext">The bytes to seal.</param>
    /// <param name="output">Exactly <c>plaintext.Length + 16</c> bytes.</param>
    /// <param name="associatedData">The additional authenticated data (the Noise hash, or empty).</param>
    public static void AeadSeal(
        ReadOnlySpan<byte> key,
        ulong counter,
        ReadOnlySpan<byte> plaintext,
        Span<byte> output,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (output.Length != plaintext.Length + MacSize)
        {
            throw new ArgumentException($"the sealed form is {plaintext.Length + MacSize} bytes", nameof(output));
        }

        Span<byte> nonce = stackalloc byte[NonceSize];
        AeadNonce(counter, nonce);

        using var aead = new System.Security.Cryptography.ChaCha20Poly1305(key);
        aead.Encrypt(
            nonce,
            plaintext,
            output[..plaintext.Length],
            output.Slice(plaintext.Length, MacSize),
            associatedData);
    }

    /// <summary>
    /// The inverse of <see cref="AeadSeal"/>. Returns false — and clears the
    /// output — when the tag does not verify, so a caller can treat a bad tag as a
    /// dropped datagram rather than an exception on the receive path.
    /// </summary>
    /// <param name="key">A 32-byte key.</param>
    /// <param name="counter">The AEAD counter.</param>
    /// <param name="sealedData">Ciphertext followed by the 16-byte tag.</param>
    /// <param name="plaintext">Exactly <c>sealedData.Length - 16</c> bytes.</param>
    /// <param name="associatedData">The additional authenticated data.</param>
    public static bool AeadOpen(
        ReadOnlySpan<byte> key,
        ulong counter,
        ReadOnlySpan<byte> sealedData,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (sealedData.Length < MacSize || plaintext.Length != sealedData.Length - MacSize)
        {
            throw new ArgumentException("the sealed form must be the plaintext plus a 16-byte tag", nameof(sealedData));
        }

        Span<byte> nonce = stackalloc byte[NonceSize];
        AeadNonce(counter, nonce);

        try
        {
            using var aead = new System.Security.Cryptography.ChaCha20Poly1305(key);
            aead.Decrypt(
                nonce,
                sealedData[..plaintext.Length],
                sealedData[^MacSize..],
                plaintext,
                associatedData);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            plaintext.Clear();
            return false;
        }
        catch (CryptographicException)
        {
            plaintext.Clear();
            return false;
        }
    }

    /// <summary>
    /// <c>DH(private, public)</c> on Curve25519. Throws when the result is the
    /// all-zero point, which is what WireGuard does: a low-order peer key would
    /// otherwise silently produce a shared secret both sides "agree" on.
    /// </summary>
    /// <param name="privateKey">A 32-byte private key, clamped or not.</param>
    /// <param name="publicKey">A 32-byte public key.</param>
    /// <param name="shared">A buffer of at least 32 bytes.</param>
    public static void Dh(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey, Span<byte> shared)
    {
        if (privateKey.Length != KeySize) throw new ArgumentException("an X25519 private key is 32 bytes", nameof(privateKey));
        if (publicKey.Length != KeySize) throw new ArgumentException("an X25519 public key is 32 bytes", nameof(publicKey));

        var secret = new X25519PrivateKeyParameters(privateKey);
        var peer = new X25519PublicKeyParameters(publicKey);
        try
        {
            secret.GenerateSecret(peer, shared[..KeySize]);
        }
        catch (InvalidOperationException ex)
        {
            // BouncyCastle refuses the all-zero output itself and reports it as an
            // invalid operation; translate it into this library's own error type so
            // a caller sees a protocol failure rather than a library artefact.
            shared[..KeySize].Clear();
            throw new ClashException("wireguard: the peer's static public key is a low-order point", ex);
        }

        if (IsAllZero(shared[..KeySize]))
        {
            shared[..KeySize].Clear();
            throw new ClashException("wireguard: the peer's static public key is a low-order point");
        }
    }

    /// <summary>Derives the public half of an X25519 key pair.</summary>
    /// <param name="privateKey">A 32-byte private key.</param>
    /// <returns>The 32-byte public key.</returns>
    public static byte[] PublicKeyFrom(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != KeySize) throw new ArgumentException("an X25519 private key is 32 bytes", nameof(privateKey));
        var secret = new X25519PrivateKeyParameters(privateKey);
        return secret.GeneratePublicKey().GetEncoded();
    }

    /// <summary>Generates an X25519 key pair the way <c>wg genkey</c> does.</summary>
    /// <param name="privateKey">Receives the 32-byte private key.</param>
    /// <param name="publicKey">Receives the 32-byte public key.</param>
    public static void GenerateKeyPair(out byte[] privateKey, out byte[] publicKey)
    {
        privateKey = RandomNumberGenerator.GetBytes(KeySize);
        publicKey = PublicKeyFrom(privateKey);
    }

    /// <summary>
    /// <c>TAI64N()</c>: 8 big-endian bytes of TAI seconds (Unix seconds plus the
    /// 10-second TAI offset baked into the TAI64 epoch) followed by 4 big-endian
    /// bytes of nanoseconds. The responder discards any initiation whose timestamp
    /// is not strictly greater than the last one it saw, so the caller must keep
    /// this monotonic — see <c>WireGuardSession</c>.
    /// </summary>
    /// <param name="now">The wall clock reading to stamp.</param>
    /// <param name="output">A buffer of at least 12 bytes.</param>
    public static void Tai64N(DateTimeOffset now, Span<byte> output)
    {
        // UtcTicks counts from 0001-01-01, so the Unix epoch has to be subtracted
        // before the TAI64 base is added; using the raw tick count would be off by
        // the 62 135 596 800 seconds between the two epochs.
        var sinceEpoch = now.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks;
        var seconds = (ulong)(sinceEpoch / TimeSpan.TicksPerSecond);
        var nanoseconds = (uint)((sinceEpoch % TimeSpan.TicksPerSecond) * 100);

        BinaryPrimitives.WriteUInt64BigEndian(output, Tai64NBase + seconds);
        BinaryPrimitives.WriteUInt32BigEndian(output[8..], nanoseconds);
    }

    /// <summary>True when every byte is zero.</summary>
    /// <param name="data">The bytes to test.</param>
    public static bool IsAllZero(ReadOnlySpan<byte> data)
    {
        var accumulator = 0;
        foreach (var b in data) accumulator |= b;
        return accumulator == 0;
    }

    /// <summary>
    /// Constant-time equality, used for the <c>mac1</c> and tag comparisons. The
    /// BCL's version is used directly; this overload exists so the handshake reads
    /// as prose rather than as a static call.
    /// </summary>
    /// <param name="left">One value.</param>
    /// <param name="right">The other value.</param>
    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        => CryptographicOperations.FixedTimeEquals(left, right);

    /// <summary>Decodes the base64 form every WireGuard configuration uses for keys.</summary>
    /// <param name="text">The base64 text.</param>
    /// <param name="expectedLength">The required decoded length.</param>
    /// <param name="value">The decoded bytes.</param>
    public static bool TryDecodeKey(string? text, int expectedLength, out byte[] value)
    {
        value = [];

        if (string.IsNullOrWhiteSpace(text)) return false;

        Span<byte> buffer = stackalloc byte[64];
        if (!Convert.TryFromBase64String(text.Trim(), buffer, out var written) || written != expectedLength)
        {
            return false;
        }

        value = buffer[..written].ToArray();
        return true;
    }

    /// <summary>Renders bytes as lowercase hex, for log messages and test failures.</summary>
    /// <param name="data">The bytes.</param>
    public static string ToHex(ReadOnlySpan<byte> data) => Convert.ToHexString(data).ToLowerInvariant();

    /// <summary>Encodes a key the way <c>wg pubkey</c> prints it.</summary>
    /// <param name="key">The key bytes.</param>
    public static string ToBase64(ReadOnlySpan<byte> key) => Convert.ToBase64String(key);

    /// <summary>ASCII bytes of a literal, kept out of the hot path.</summary>
    /// <param name="text">The literal.</param>
    internal static byte[] Ascii(string text) => Encoding.ASCII.GetBytes(text);
}
