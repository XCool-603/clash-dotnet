using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Clash.Core.Crypto;

/// <summary>
/// The mieru v3 key schedule, the nonce construction and the implicit-nonce
/// counter, written from the protocol document's field tables.
/// <para>
/// mieru has no authentication message: a connection is authenticated by the mere
/// fact that the first segment's metadata decrypts under a key derived from the
/// username, the password and the current two-minute time bucket. Every value here
/// therefore has to be byte-exact, so the whole chain takes an explicit Unix time
/// instead of reading the clock itself — that is what makes the time-salt window
/// testable rather than a silent-failure mode.
/// </para>
/// <para>
/// The wire facts come from the mieru protocol document (<c>docs/protocol.md</c>)
/// and this project's mieru factsheet. The upstream implementation is GPL-3.0 and
/// no code from it was used: this is an independent implementation of the
/// documented format.
/// </para>
/// </summary>
public static class MieruCrypto
{
    /// <summary>AEAD key length, and the PBKDF2 output length: 32 bytes.</summary>
    public const int KeySize = 32;

    /// <summary>XChaCha20-Poly1305 nonce length: 24 bytes.</summary>
    public const int NonceSize = 24;

    /// <summary>Every segment's metadata is exactly 32 bytes.</summary>
    public const int MetadataSize = 32;

    /// <summary>Poly1305 authentication tag length.</summary>
    public const int TagSize = 16;

    /// <summary>Encrypted metadata plus its tag: the fixed 48-byte head of every segment.</summary>
    public const int EncryptedMetadataSize = MetadataSize + TagSize;

    /// <summary>PBKDF2 iteration count for mieru v3. (v2 used 4096 and is not compatible.)</summary>
    public const int Pbkdf2Iterations = 64;

    /// <summary>The time salt rounds the clock to this many seconds.</summary>
    public const int TimeBucketSeconds = 120;

    /// <summary>How many nonce bytes the username hash replaces.</summary>
    public const int NonceHintLength = 4;

    /// <summary>Offset of the four nonce bytes that carry the username hash.</summary>
    public const int NonceHintOffset = NonceSize - NonceHintLength;

    /// <summary>How many leading nonce bytes the username hash is computed over.</summary>
    public const int NonceHintSeedLength = 16;

    /// <summary>
    /// <c>hashedPassword = SHA-256(password || 0x00 || username)</c>. The separator
    /// is a literal zero byte, not a terminator: it keeps
    /// <c>("ab", "c")</c> and <c>("a", "bc")</c> apart.
    /// </summary>
    public static byte[] HashPassword(string password, string username)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(username);

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var usernameBytes = Encoding.UTF8.GetBytes(username);
        var material = new byte[passwordBytes.Length + 1 + usernameBytes.Length];
        passwordBytes.CopyTo(material, 0);
        material[passwordBytes.Length] = 0x00;
        usernameBytes.CopyTo(material, passwordBytes.Length + 1);

        try
        {
            return SHA256.HashData(material);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
        }
    }

    /// <summary>
    /// Rounds a Unix time to the nearest <see cref="TimeBucketSeconds"/> boundary,
    /// halves away from zero. The reference rounds rather than truncates, but the
    /// server tries three salts — <c>bucket - 2min</c>, <c>bucket</c> and
    /// <c>bucket + 2min</c> — so a client that truncated instead would still be
    /// accepted; what the client must not do is drift by more than two minutes.
    /// </summary>
    public static long RoundUnixTime(long unixTime)
    {
        var remainder = unixTime % TimeBucketSeconds;
        var bucket = unixTime - remainder;

        if (remainder * 2 >= TimeBucketSeconds) bucket += TimeBucketSeconds;
        else if (remainder * 2 <= -TimeBucketSeconds) bucket -= TimeBucketSeconds;

        return bucket;
    }

    /// <summary>
    /// <c>timeSalt = SHA-256(uint64_BE(round(unixTime, 2 minutes)))</c>. The rounded
    /// epoch-seconds value goes on the wire as eight big-endian bytes, per the
    /// protocol document's global big-endian rule.
    /// </summary>
    public static byte[] TimeSalt(long unixTime)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, (ulong)RoundUnixTime(unixTime));
        return SHA256.HashData(encoded);
    }

    /// <summary>
    /// The connection key:
    /// <c>PBKDF2-HMAC-SHA256(hashedPassword, timeSalt, 64 iterations, 32 bytes)</c>.
    /// There is no HKDF step, no info string and no constant salt beyond the time.
    /// </summary>
    public static byte[] DeriveKey(string password, string username, long unixTime)
    {
        var hashedPassword = HashPassword(password, username);
        var timeSalt = TimeSalt(unixTime);

        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                hashedPassword,
                timeSalt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256,
                KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hashedPassword);
            CryptographicOperations.ZeroMemory(timeSalt);
        }
    }

    /// <summary>
    /// Builds a 24-byte nonce: <paramref name="random"/> verbatim, with its last
    /// four bytes replaced by <c>SHA-256(username || random[0..16])[0..4]</c>.
    /// <para>
    /// The override is a server-side user-lookup hint: it lets the server index
    /// candidate keys without attempting a decryption per configured user. It is
    /// not a secret and it is not verified by the peer.
    /// </para>
    /// </summary>
    public static void BuildNonce(string username, ReadOnlySpan<byte> random, Span<byte> nonce)
    {
        ArgumentNullException.ThrowIfNull(username);
        if (random.Length != NonceSize)
        {
            throw new ArgumentException($"the random part must be {NonceSize} bytes, got {random.Length}", nameof(random));
        }

        if (nonce.Length < NonceSize)
        {
            throw new ArgumentException($"the nonce must be at least {NonceSize} bytes, got {nonce.Length}", nameof(nonce));
        }

        random[..NonceSize].CopyTo(nonce);

        var usernameBytes = Encoding.UTF8.GetBytes(username);
        var material = new byte[usernameBytes.Length + NonceHintSeedLength];
        usernameBytes.CopyTo(material, 0);
        nonce[..NonceHintSeedLength].CopyTo(material.AsSpan(usernameBytes.Length));

        var hash = SHA256.HashData(material);
        hash.AsSpan(0, NonceHintLength).CopyTo(nonce[NonceHintOffset..]);

        CryptographicOperations.ZeroMemory(material);
    }

    /// <summary>Creates a fresh nonce with <see cref="BuildNonce"/> from the system RNG.</summary>
    public static byte[] CreateNonce(string username)
    {
        var random = RandomNumberGenerator.GetBytes(NonceSize);
        var nonce = new byte[NonceSize];
        BuildNonce(username, random, nonce);
        CryptographicOperations.ZeroMemory(random);
        return nonce;
    }

    /// <summary>
    /// Advances the nonce counter by one, big-endian: increment the last byte and
    /// carry towards index 0.
    /// <para>
    /// This is the mieru TCP rule. Only the first segment of each direction carries
    /// the nonce in the clear; afterwards the sender and receiver both advance this
    /// counter, and <em>every</em> AEAD operation consumes one step — the metadata
    /// and the payload of the same segment use consecutive nonces.
    /// </para>
    /// </summary>
    public static void IncrementNonce(Span<byte> nonce)
    {
        for (var i = nonce.Length - 1; i >= 0; i--)
        {
            if (++nonce[i] != 0) break;
        }
    }
}
