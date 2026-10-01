namespace Clash.Core.Crypto;

/// <summary>
/// An AEAD construction as used by Shadowsocks (AEAD and 2022), VMess and VLESS.
/// Implementations must be thread-safe after <see cref="DeriveSubkey"/>: the
/// caller caches subkeys per session and calls the encrypt/decrypt methods
/// concurrently from the read and write pumps.
/// </summary>
public interface IAeadCipher
{
    /// <summary>Canonical lower-case name, e.g. <c>aes-256-gcm</c>.</summary>
    string Name { get; }

    /// <summary>Master key length in bytes.</summary>
    int KeySize { get; }

    /// <summary>Salt length in bytes; 16 for AES-GCM, 32 for ChaCha20-Poly1305.</summary>
    int SaltSize { get; }

    /// <summary>Nonce length in bytes; 12 for every cipher Shadowsocks defines.</summary>
    int NonceSize { get; }

    /// <summary>Authentication tag length in bytes; always 16 here.</summary>
    int TagSize { get; }

    /// <summary>
    /// Shadowsocks key derivation (HKDF-SHA1 with the salt as info), used to turn
    /// the master key plus a per-session salt into the session subkey.
    /// </summary>
    byte[] DeriveSubkey(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and appends the tag. Writes
    /// <c>plaintext.Length + TagSize</c> bytes into <paramref name="destination"/>.
    /// </summary>
    void Encrypt(
        ReadOnlySpan<byte> subkey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default);

    /// <summary>
    /// Verifies and decrypts. Returns false when the tag does not verify, which
    /// callers must treat as a fatal protocol error rather than a retry.
    /// </summary>
    bool Decrypt(
        ReadOnlySpan<byte> subkey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default);
}

/// <summary>A legacy byte-stream cipher (Shadowsocks stream methods, ShadowsocksR).</summary>
public interface IStreamCipher
{
    string Name { get; }
    int KeySize { get; }
    int IvSize { get; }

    /// <summary>Seeds the keystream. Must be called before the first <see cref="Process"/>.</summary>
    void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv);

    /// <summary>Transforms bytes in place. Encryption and decryption are the same operation.</summary>
    void Process(Span<byte> buffer);

    void Process(ReadOnlySpan<byte> input, Span<byte> output);
}

/// <summary>Lookup of AEAD ciphers by the names used in configuration files.</summary>
public static class AeadCiphers
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Func<IAeadCipher>> Factories =
        new(StringComparer.OrdinalIgnoreCase);

    private static int _initialised;

    /// <summary>Registers a cipher factory. Called by <see cref="AeadCipherRegistry"/>.</summary>
    public static void Register(string name, Func<IAeadCipher> factory) => Factories[name] = factory;

    /// <summary>Returns the cipher, or throws <see cref="NotSupportedException"/> listing the known names.</summary>
    public static IAeadCipher Get(string name)
    {
        EnsureInitialised();
        return TryGet(name, out var cipher)
            ? cipher
            : throw new NotSupportedException($"unsupported AEAD cipher: {name} (known: {string.Join(", ", Names)})");
    }

    /// <summary>Registry lookup. Names are matched case-insensitively.</summary>
    public static bool TryGet(string name, out IAeadCipher cipher)
    {
        EnsureInitialised();
        if (Factories.TryGetValue(name, out var factory))
        {
            cipher = factory();
            return true;
        }
        cipher = null!;
        return false;
    }

    /// <summary>Every supported name, for validation messages.</summary>
    public static IReadOnlyCollection<string> Names
    {
        get
        {
            EnsureInitialised();
            return Factories.Keys.ToList();
        }
    }

    private static void EnsureInitialised()
    {
        if (Interlocked.Exchange(ref _initialised, 1) == 0) AeadCipherRegistry.Register();
    }
}

/// <summary>Lookup of stream ciphers by configuration name.</summary>
public static class StreamCiphers
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Func<IStreamCipher>> Factories =
        new(StringComparer.OrdinalIgnoreCase);

    private static int _initialised;

    public static void Register(string name, Func<IStreamCipher> factory) => Factories[name] = factory;

    public static IStreamCipher Get(string name)
    {
        EnsureInitialised();
        return TryGet(name, out var cipher)
            ? cipher
            : throw new NotSupportedException($"unsupported stream cipher: {name} (known: {string.Join(", ", Names)})");
    }

    public static bool TryGet(string name, out IStreamCipher cipher)
    {
        EnsureInitialised();
        if (Factories.TryGetValue(name, out var factory))
        {
            cipher = factory();
            return true;
        }
        cipher = null!;
        return false;
    }

    public static IReadOnlyCollection<string> Names
    {
        get
        {
            EnsureInitialised();
            return Factories.Keys.ToList();
        }
    }

    private static void EnsureInitialised()
    {
        if (Interlocked.Exchange(ref _initialised, 1) == 0) StreamCipherRegistry.Register();
    }
}

/// <summary>Base64 helpers that accept both standard and URL-safe alphabets.</summary>
public static class ClashBase64
{
    public static byte[] Decode(string value)
    {
        var normalized = value.Trim().Replace('-', '+').Replace('_', '/');
        switch (normalized.Length % 4)
        {
            case 2: normalized += "=="; break;
            case 3: normalized += "="; break;
        }
        return Convert.FromBase64String(normalized);
    }

    public static bool TryDecode(string value, out byte[] bytes)
    {
        try
        {
            bytes = Decode(value);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    public static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes);

    public static string EncodeUrlSafe(ReadOnlySpan<byte> bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>Hex helpers used by VMess/VLESS user ids and Trojan passwords.</summary>
public static class ClashHex
{
    public static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    public static byte[] Decode(string hex) => Convert.FromHexString(hex.Trim());

    public static bool TryDecode(string hex, out byte[] bytes)
    {
        try
        {
            bytes = Decode(hex);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }

    /// <summary>True when the string is a well-formed UUID (with or without dashes).</summary>
    public static bool IsUuid(string value)
    {
        var stripped = value.Replace("-", string.Empty);
        return stripped.Length == 32 && TryDecode(stripped, out _);
    }

    /// <summary>Parses a UUID into its 16 raw bytes, tolerating a missing-dash form.</summary>
    public static byte[] ParseUuid(string value)
    {
        var stripped = value.Replace("-", string.Empty);
        if (stripped.Length != 32) throw new FormatException($"invalid UUID: {value}");
        return Decode(stripped);
    }

    /// <summary>Renders 16 raw bytes as a canonical dashed UUID.</summary>
    public static string FormatUuid(ReadOnlySpan<byte> bytes)
    {
        var hex = Encode(bytes);
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
    }
}
