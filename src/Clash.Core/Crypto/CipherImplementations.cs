using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Clash.Core.Crypto;

/// <summary>
/// A stream cipher whose keystream feedback depends on the direction of travel.
/// <para>
/// Cipher-feedback mode (every <c>*-cfb</c> method) feeds the <em>ciphertext</em>
/// back into the shift register, so the encryptor and the decryptor are not the
/// same transform: the encryptor feeds back the byte it just produced, the
/// decryptor feeds back the byte it just consumed. CTR, ChaCha20, Salsa20 and
/// RC4 are self-inverse and never implement this interface.
/// </para>
/// <para>
/// Callers must therefore create one <see cref="IStreamCipher"/> per direction
/// (see <see cref="StreamCipherFactory"/>) or set <see cref="Encrypting"/>
/// before the first <see cref="IStreamCipher.Process(Span{byte})"/> call.
/// </para>
/// </summary>
public interface IDirectionalStreamCipher
{
    /// <summary>True to behave as the encryptor (feedback is the produced byte).</summary>
    bool Encrypting { get; set; }
}

/// <summary>
/// Convenience factories that hand back a correctly-directed
/// <see cref="IStreamCipher"/> for the Shadowsocks stream methods.
/// </summary>
public static class StreamCipherFactory
{
    /// <summary>Creates a cipher ready to <em>encrypt</em> (write side).</summary>
    public static IStreamCipher CreateEncryptor(string name, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        => Create(name, key, iv, encrypting: true);

    /// <summary>Creates a cipher ready to <em>decrypt</em> (read side).</summary>
    public static IStreamCipher CreateDecryptor(string name, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        => Create(name, key, iv, encrypting: false);

    /// <summary>Creates and seeds a cipher in the requested direction.</summary>
    public static IStreamCipher Create(string name, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool encrypting)
    {
        var cipher = StreamCiphers.Get(name);
        if (cipher is IDirectionalStreamCipher directional) directional.Encrypting = encrypting;
        cipher.Init(key, iv);
        return cipher;
    }
}

/// <summary>BLAKE3 key-derivation helpers shared by the 2022 ciphers.</summary>
internal static class Blake3Kdf
{
    /// <summary>
    /// The BLAKE3 derive-key context used by the Shadowsocks 2022 session subkey
    /// derivation (SIP022).
    /// </summary>
    internal const string SessionSubkeyContext = "shadowsocks 2022 session subkey";

    /// <summary>
    /// BLAKE3 in derive-key mode: <c>output = BLAKE3-DERIVE-KEY(context, keyMaterial)</c>.
    /// The output may be any length; BLAKE3's XOF is used when it is not 32 bytes.
    /// </summary>
    internal static void DeriveKey(string context, ReadOnlySpan<byte> keyMaterial, Span<byte> output)
    {
        using var hasher = Blake3.Hasher.NewDeriveKey(context);
        hasher.Update(keyMaterial);
        hasher.Finalize(output);
    }

    /// <summary>
    /// BLAKE3 derive-key over two concatenated inputs, without materialising the
    /// concatenation (<c>keyMaterial || salt</c>).
    /// </summary>
    internal static void DeriveKey(string context, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, Span<byte> output)
    {
        using var hasher = Blake3.Hasher.NewDeriveKey(context);
        hasher.Update(first);
        hasher.Update(second);
        hasher.Finalize(output);
    }
}

/// <summary>
/// Thread-local <see cref="AesGcm"/> and <see cref="ChaCha20Poly1305"/> instances.
/// <para>
/// .NET 10 exposes no span-based static one-shot for either type (the statics take
/// <c>byte[]</c> and accept no associated data), and the instance API is not
/// documented as thread-safe, so each thread keeps one instance that is re-keyed
/// whenever the subkey changes. That keeps the hot path allocation-free while
/// still satisfying the <see cref="IAeadCipher"/> requirement that a cipher be
/// usable concurrently from the read and write pumps.
/// </para>
/// </summary>
internal static class AeadPrimitives
{
    [ThreadStatic] private static AesGcm? _aes;
    [ThreadStatic] private static byte[]? _aesKey;
    [ThreadStatic] private static System.Security.Cryptography.ChaCha20Poly1305? _chacha;
    [ThreadStatic] private static byte[]? _chachaKey;

    public static void AesGcmEncrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
        => RentAesGcm(key).Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

    public static bool AesGcmDecrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        try
        {
            RentAesGcm(key).Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return true;
        }
        catch (CryptographicException)
        {
            plaintext.Clear();
            return false;
        }
    }

    public static void ChaChaEncrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
        => RentChaCha(key).Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

    public static bool ChaChaDecrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        try
        {
            RentChaCha(key).Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return true;
        }
        catch (CryptographicException)
        {
            plaintext.Clear();
            return false;
        }
    }

    private static AesGcm RentAesGcm(ReadOnlySpan<byte> key)
    {
        if (!AesGcm.IsSupported) throw new PlatformNotSupportedException("AES-GCM is not supported on this platform");
        if (_aes is not null && _aesKey is not null && _aesKey.AsSpan().SequenceEqual(key)) return _aes;

        _aes?.Dispose();
        _aesKey = key.ToArray();
        _aes = new AesGcm(_aesKey, tagSizeInBytes: 16);
        return _aes;
    }

    private static System.Security.Cryptography.ChaCha20Poly1305 RentChaCha(ReadOnlySpan<byte> key)
    {
        if (!System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
        {
            throw new PlatformNotSupportedException("ChaCha20-Poly1305 is not supported on this platform");
        }

        if (_chacha is not null && _chachaKey is not null && _chachaKey.AsSpan().SequenceEqual(key)) return _chacha;

        _chacha?.Dispose();
        _chachaKey = key.ToArray();
        _chacha = new System.Security.Cryptography.ChaCha20Poly1305(_chachaKey);
        return _chacha;
    }
}

/// <summary>Shared shape of every <see cref="IAeadCipher"/> in this assembly.</summary>
internal abstract class AeadCipherBase : IAeadCipher
{
    public abstract string Name { get; }

    public abstract int KeySize { get; }

    public abstract int SaltSize { get; }

    public virtual int NonceSize => 12;

    public virtual int TagSize => 16;

    public abstract byte[] DeriveSubkey(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt);

    public abstract void Encrypt(
        ReadOnlySpan<byte> subkey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default);

    public abstract bool Decrypt(
        ReadOnlySpan<byte> subkey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default);

    /// <summary>Validates the fixed-size inputs shared by every implementation.</summary>
    protected void CheckEncryptArguments(ReadOnlySpan<byte> subkey, ReadOnlySpan<byte> nonce, int plaintextLength, Span<byte> destination)
    {
        if (subkey.Length != KeySize) throw new ArgumentException($"subkey must be {KeySize} bytes, got {subkey.Length}", nameof(subkey));
        if (nonce.Length != NonceSize) throw new ArgumentException($"nonce must be {NonceSize} bytes, got {nonce.Length}", nameof(nonce));
        if (destination.Length < plaintextLength + TagSize)
        {
            throw new ArgumentException($"destination must be at least {plaintextLength + TagSize} bytes, got {destination.Length}", nameof(destination));
        }
    }

    /// <summary>Validates the fixed-size inputs shared by every implementation.</summary>
    protected void CheckDecryptArguments(ReadOnlySpan<byte> subkey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, Span<byte> destination)
    {
        if (subkey.Length != KeySize) throw new ArgumentException($"subkey must be {KeySize} bytes, got {subkey.Length}", nameof(subkey));
        if (nonce.Length != NonceSize) throw new ArgumentException($"nonce must be {NonceSize} bytes, got {nonce.Length}", nameof(nonce));
        if (ciphertext.Length < TagSize) throw new ArgumentException("ciphertext shorter than the tag", nameof(ciphertext));
        if (destination.Length < ciphertext.Length - TagSize)
        {
            throw new ArgumentException($"destination must be at least {ciphertext.Length - TagSize} bytes, got {destination.Length}", nameof(destination));
        }
    }
}

/// <summary>
/// The original Shadowsocks AEAD ciphers: AES-GCM at 128/192/256 bits,
/// ChaCha20-Poly1305 and XChaCha20-Poly1305.
/// <para>
/// Subkeys come from <c>HKDF-SHA1(ikm = masterKey, salt = salt, info = "ss-subkey")</c>
/// with an output length of <see cref="KeySize"/>, exactly as SIP004 specifies.
/// The AEAD itself is the in-box hardware-accelerated primitive
/// (<see cref="AesGcm"/> / <see cref="ChaCha20Poly1305"/>); XChaCha20-Poly1305 is
/// built from HChaCha20 plus the in-box ChaCha20-Poly1305 via BouncyCastle.
/// </para>
/// </summary>
internal sealed class HkdfAeadCipher : AeadCipherBase
{
    /// <summary>The AEAD primitive behind one <see cref="HkdfAeadCipher"/>.</summary>
    internal enum Primitive
    {
        Aes128Gcm,
        Aes192Gcm,
        Aes256Gcm,
        ChaCha20Poly1305,
        XChaCha20Poly1305,
    }

    /// <summary>HKDF info string mandated by the Shadowsocks AEAD specification.</summary>
    internal static readonly byte[] HkdfInfo = "ss-subkey"u8.ToArray();

    private readonly Primitive _primitive;

    public HkdfAeadCipher(string name, Primitive primitive)
    {
        Name = name;
        _primitive = primitive;
        KeySize = primitive switch
        {
            Primitive.Aes128Gcm => 16,
            Primitive.Aes192Gcm => 24,
            Primitive.Aes256Gcm => 32,
            _ => 32,
        };
        SaltSize = KeySize;
    }

    public override string Name { get; }

    public override int KeySize { get; }

    public override int SaltSize { get; }

    public override byte[] DeriveSubkey(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt)
    {
        if (masterKey.Length != KeySize) throw new ArgumentException($"master key must be {KeySize} bytes", nameof(masterKey));
        if (salt.Length != SaltSize) throw new ArgumentException($"salt must be {SaltSize} bytes", nameof(salt));

        var subkey = new byte[KeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA1, masterKey, subkey, salt, HkdfInfo);
        return subkey;
    }

    public override void Encrypt(
        ReadOnlySpan<byte> subkey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default)
    {
        CheckEncryptArguments(subkey, nonce, plaintext.Length, destination);

        var ciphertext = destination[..plaintext.Length];
        var tag = destination.Slice(plaintext.Length, TagSize);

        switch (_primitive)
        {
            case Primitive.Aes128Gcm:
            case Primitive.Aes192Gcm:
            case Primitive.Aes256Gcm:
                AeadPrimitives.AesGcmEncrypt(subkey, nonce, plaintext, ciphertext, tag, associatedData);
                break;

            case Primitive.ChaCha20Poly1305:
                AeadPrimitives.ChaChaEncrypt(subkey, nonce, plaintext, ciphertext, tag, associatedData);
                break;

            default:
                XChaCha20Poly1305.Encrypt(subkey, nonce, plaintext, ciphertext, tag, associatedData);
                break;
        }
    }

    public override bool Decrypt(
        ReadOnlySpan<byte> subkey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default)
    {
        CheckDecryptArguments(subkey, nonce, ciphertext, destination);

        var body = ciphertext[..^TagSize];
        var tag = ciphertext[^TagSize..];
        var plaintext = destination[..body.Length];

        return _primitive switch
        {
            Primitive.Aes128Gcm or Primitive.Aes192Gcm or Primitive.Aes256Gcm
                => AeadPrimitives.AesGcmDecrypt(subkey, nonce, body, tag, plaintext, associatedData),
            Primitive.ChaCha20Poly1305
                => AeadPrimitives.ChaChaDecrypt(subkey, nonce, body, tag, plaintext, associatedData),
            _ => XChaCha20Poly1305.TryDecrypt(subkey, nonce, body, tag, plaintext, associatedData),
        };
    }
}

/// <summary>
/// The Shadowsocks 2022 AEAD ciphers. They differ from the SIP004 ciphers in two
/// places only:
/// <list type="number">
///   <item><description>the session subkey comes from BLAKE3 in derive-key mode
///   instead of HKDF-SHA1, and</description></item>
///   <item><description>the salt is 32 bytes (16 for AES-128-GCM, per SIP022).</description></item>
/// </list>
/// The AEAD primitive itself is unchanged, so the in-box
/// <see cref="AesGcm"/>/<see cref="ChaCha20Poly1305"/> classes are reused.
/// </summary>
internal sealed class Blake3AeadCipher : AeadCipherBase
{
    private readonly HkdfAeadCipher.Primitive _primitive;

    public Blake3AeadCipher(string name, HkdfAeadCipher.Primitive primitive, int keySize, int saltSize)
    {
        Name = name;
        _primitive = primitive;
        KeySize = keySize;
        SaltSize = saltSize;
    }

    public override string Name { get; }

    public override int KeySize { get; }

    public override int SaltSize { get; }

    public override byte[] DeriveSubkey(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> salt)
    {
        if (masterKey.Length != KeySize) throw new ArgumentException($"master key must be {KeySize} bytes", nameof(masterKey));
        if (salt.Length != SaltSize) throw new ArgumentException($"salt must be {SaltSize} bytes", nameof(salt));

        var subkey = new byte[KeySize];
        Blake3Kdf.DeriveKey(Blake3Kdf.SessionSubkeyContext, masterKey, salt, subkey);
        return subkey;
    }

    public override void Encrypt(
        ReadOnlySpan<byte> subkey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default)
    {
        CheckEncryptArguments(subkey, nonce, plaintext.Length, destination);

        var ciphertext = destination[..plaintext.Length];
        var tag = destination.Slice(plaintext.Length, TagSize);

        switch (_primitive)
        {
            case HkdfAeadCipher.Primitive.Aes128Gcm:
            case HkdfAeadCipher.Primitive.Aes192Gcm:
            case HkdfAeadCipher.Primitive.Aes256Gcm:
                AeadPrimitives.AesGcmEncrypt(subkey, nonce, plaintext, ciphertext, tag, associatedData);
                break;

            case HkdfAeadCipher.Primitive.ChaCha20Poly1305:
                AeadPrimitives.ChaChaEncrypt(subkey, nonce, plaintext, ciphertext, tag, associatedData);
                break;

            default:
                XChaCha20Poly1305.Encrypt(subkey, nonce, plaintext, ciphertext, tag, associatedData);
                break;
        }
    }

    public override bool Decrypt(
        ReadOnlySpan<byte> subkey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination,
        ReadOnlySpan<byte> associatedData = default)
    {
        CheckDecryptArguments(subkey, nonce, ciphertext, destination);

        var body = ciphertext[..^TagSize];
        var tag = ciphertext[^TagSize..];
        var plaintext = destination[..body.Length];

        return _primitive switch
        {
            HkdfAeadCipher.Primitive.Aes128Gcm or HkdfAeadCipher.Primitive.Aes192Gcm or HkdfAeadCipher.Primitive.Aes256Gcm
                => AeadPrimitives.AesGcmDecrypt(subkey, nonce, body, tag, plaintext, associatedData),
            HkdfAeadCipher.Primitive.ChaCha20Poly1305
                => AeadPrimitives.ChaChaDecrypt(subkey, nonce, body, tag, plaintext, associatedData),
            _ => XChaCha20Poly1305.TryDecrypt(subkey, nonce, body, tag, plaintext, associatedData),
        };
    }
}

/// <summary>
/// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha). .NET has no in-box
/// implementation, so HChaCha20 is implemented here and the resulting subkey is
/// fed to BouncyCastle's RFC 7539 ChaCha20-Poly1305 with the IETF nonce
/// <c>00000000 || nonce[16..24]</c>.
/// </summary>
internal static class XChaCha20Poly1305
{
    private const int KeySize = 32;
    private const int NonceSize = 24;

    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        if (key.Length != KeySize) throw new ArgumentException($"key must be {KeySize} bytes", nameof(key));
        if (nonce.Length != NonceSize) throw new ArgumentException($"nonce must be {NonceSize} bytes", nameof(nonce));

        Span<byte> subkey = stackalloc byte[KeySize];
        Span<byte> ietfNonce = stackalloc byte[12];
        DeriveIetfParameters(key, nonce, subkey, ietfNonce);

        var input = plaintext.ToArray();
        var output = new byte[input.Length + 16];
        RunBc(true, subkey, ietfNonce, input, output, associatedData);
        output.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
        output.AsSpan(plaintext.Length, 16).CopyTo(tag);

        CryptographicOperations.ZeroMemory(subkey);
        CryptographicOperations.ZeroMemory(output);
    }

    public static bool TryDecrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        if (key.Length != KeySize) throw new ArgumentException($"key must be {KeySize} bytes", nameof(key));
        if (nonce.Length != NonceSize) throw new ArgumentException($"nonce must be {NonceSize} bytes", nameof(nonce));

        Span<byte> subkey = stackalloc byte[KeySize];
        Span<byte> ietfNonce = stackalloc byte[12];
        DeriveIetfParameters(key, nonce, subkey, ietfNonce);

        var input = new byte[ciphertext.Length + 16];
        ciphertext.CopyTo(input);
        tag.CopyTo(input.AsSpan(ciphertext.Length));

        var output = new byte[input.Length];
        try
        {
            var written = RunBc(false, subkey, ietfNonce, input, output, associatedData);
            output.AsSpan(0, written).CopyTo(plaintext);
            return true;
        }
        catch (InvalidCipherTextException)
        {
            plaintext.Clear();
            return false;
        }
        catch (CryptoException)
        {
            plaintext.Clear();
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(output);
        }
    }

    private static void DeriveIetfParameters(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> subkey, Span<byte> ietfNonce)
    {
        HChaCha20(key, nonce[..16], subkey);
        ietfNonce[..4].Clear();
        nonce[16..24].CopyTo(ietfNonce[4..]);
    }

    private static int RunBc(
        bool encrypting,
        ReadOnlySpan<byte> subkey,
        ReadOnlySpan<byte> nonce,
        byte[] input,
        byte[] output,
        ReadOnlySpan<byte> associatedData)
    {
        var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        var parameters = new AeadParameters(new KeyParameter(subkey.ToArray()), 128, nonce.ToArray(), associatedData.ToArray());
        cipher.Init(encrypting, parameters);
        var written = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        written += cipher.DoFinal(output, written);
        return written;
    }

    /// <summary>HChaCha20 (draft-irtf-cfrg-xchacha §2.2): the 20-round core without the final addition.</summary>
    internal static void HChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce16, Span<byte> output)
    {
        if (key.Length != 32) throw new ArgumentException("HChaCha20 needs a 32-byte key", nameof(key));
        if (nonce16.Length != 16) throw new ArgumentException("HChaCha20 needs a 16-byte nonce", nameof(nonce16));
        if (output.Length < 32) throw new ArgumentException("HChaCha20 needs a 32-byte output", nameof(output));

        Span<uint> state = stackalloc uint[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (var i = 0; i < 8; i++) state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
        for (var i = 0; i < 4; i++) state[12 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce16.Slice(i * 4, 4));

        for (var i = 0; i < 10; i++)
        {
            QuarterRound(state, 0, 4, 8, 12);
            QuarterRound(state, 1, 5, 9, 13);
            QuarterRound(state, 2, 6, 10, 14);
            QuarterRound(state, 3, 7, 11, 15);
            QuarterRound(state, 0, 5, 10, 15);
            QuarterRound(state, 1, 6, 11, 12);
            QuarterRound(state, 2, 7, 8, 13);
            QuarterRound(state, 3, 4, 9, 14);
        }

        for (var i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(i * 4, 4), state[i]);
        for (var i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(16 + i * 4, 4), state[12 + i]);
    }

    private static void QuarterRound(Span<uint> s, int a, int b, int c, int d)
    {
        s[a] += s[b];
        s[d] = BitOperations.RotateLeft(s[d] ^ s[a], 16);
        s[c] += s[d];
        s[b] = BitOperations.RotateLeft(s[b] ^ s[c], 12);
        s[a] += s[b];
        s[d] = BitOperations.RotateLeft(s[d] ^ s[a], 8);
        s[c] += s[d];
        s[b] = BitOperations.RotateLeft(s[b] ^ s[c], 7);
    }
}

/// <summary>
/// The <c>none</c> cipher: a pass-through used by ShadowsocksR's <c>plain</c>
/// obfuscation and by debug configurations.
/// </summary>
internal sealed class NoneStreamCipher : IStreamCipher
{
    public string Name => "none";

    public int KeySize => 0;

    public int IvSize => 0;

    public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
    }

    public void Process(Span<byte> buffer)
    {
    }

    public void Process(ReadOnlySpan<byte> input, Span<byte> output) => input.CopyTo(output);
}

/// <summary>
/// <c>rc4-md5</c>: RC4 keyed with <c>MD5(key || iv)</c>. The IV is 16 bytes and
/// is sent in the clear at the head of the stream.
/// </summary>
internal sealed class Rc4Md5StreamCipher : IStreamCipher
{
    private readonly RC4Engine _engine = new();

    public string Name => "rc4-md5";

    public int KeySize => 16;

    public int IvSize => 16;

    public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        var material = new byte[key.Length + iv.Length];
        key.CopyTo(material);
        iv.CopyTo(material.AsSpan(key.Length));
        var sessionKey = MD5.HashData(material);
        try
        {
            _engine.Init(true, new KeyParameter(sessionKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
            CryptographicOperations.ZeroMemory(sessionKey);
        }
    }

    public void Process(Span<byte> buffer) => BouncyCastleStreamHelper.Transform(_engine, buffer, buffer);

    public void Process(ReadOnlySpan<byte> input, Span<byte> output) => BouncyCastleStreamHelper.Transform(_engine, input, output);
}

/// <summary>
/// Any BouncyCastle stream engine (ChaCha20, Salsa20, RC4) behind
/// <see cref="IStreamCipher"/>. These are all self-inverse.
/// </summary>
internal sealed class BouncyCastleStreamCipher : IStreamCipher
{
    private readonly Func<Org.BouncyCastle.Crypto.IStreamCipher> _factory;
    private readonly bool _withIv;
    private Org.BouncyCastle.Crypto.IStreamCipher? _engine;

    public BouncyCastleStreamCipher(string name, int keySize, int ivSize, Func<Org.BouncyCastle.Crypto.IStreamCipher> factory, bool withIv = true)
    {
        Name = name;
        KeySize = keySize;
        IvSize = ivSize;
        _factory = factory;
        _withIv = withIv;
    }

    public string Name { get; }

    public int KeySize { get; }

    public int IvSize { get; }

    public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != KeySize) throw new ArgumentException($"key must be {KeySize} bytes", nameof(key));
        if (iv.Length != IvSize) throw new ArgumentException($"iv must be {IvSize} bytes", nameof(iv));

        var engine = _factory();
        ICipherParameters parameters = new KeyParameter(key.ToArray());
        if (_withIv) parameters = new ParametersWithIV(parameters, iv.ToArray());
        engine.Init(true, parameters);
        _engine = engine;
    }

    public void Process(Span<byte> buffer) => BouncyCastleStreamHelper.Transform(Engine, buffer, buffer);

    public void Process(ReadOnlySpan<byte> input, Span<byte> output) => BouncyCastleStreamHelper.Transform(Engine, input, output);

    private Org.BouncyCastle.Crypto.IStreamCipher Engine
        => _engine ?? throw new InvalidOperationException($"{Name}: Init must be called before Process");
}

/// <summary>
/// AES/Camellia in cipher-feedback mode (CFB-128) as used by the legacy
/// Shadowsocks stream methods. Directional: see <see cref="IDirectionalStreamCipher"/>.
/// </summary>
internal sealed class CfbStreamCipher : IStreamCipher, IDirectionalStreamCipher
{
    private const int BlockSize = 16;

    private readonly Func<IBlockCipher> _factory;
    private readonly byte[] _shift = new byte[BlockSize];
    private readonly byte[] _keystream = new byte[BlockSize];
    private IBlockCipher? _engine;
    private int _position = BlockSize;
    private int _writeIndex;

    public CfbStreamCipher(string name, int keySize, Func<IBlockCipher> factory)
    {
        Name = name;
        KeySize = keySize;
        _factory = factory;
    }

    public string Name { get; }

    public int KeySize { get; }

    public int IvSize => BlockSize;

    /// <inheritdoc />
    public bool Encrypting { get; set; } = true;

    public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != KeySize) throw new ArgumentException($"key must be {KeySize} bytes", nameof(key));
        if (iv.Length != IvSize) throw new ArgumentException($"iv must be {IvSize} bytes", nameof(iv));

        var engine = _factory();
        engine.Init(true, new KeyParameter(key.ToArray()));
        _engine = engine;

        // The shift register starts as the IV and is consumed in order, so at every
        // segment boundary (_position == BlockSize) _shift already holds the last
        // BlockSize ciphertext bytes in the correct order.
        iv.CopyTo(_shift);
        _position = BlockSize;
        _writeIndex = 0;
    }

    public void Process(Span<byte> buffer) => Process(buffer, buffer);

    public void Process(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length < input.Length) throw new ArgumentException("output buffer too small", nameof(output));
        var engine = _engine ?? throw new InvalidOperationException($"{Name}: Init must be called before Process");

        for (var i = 0; i < input.Length; i++)
        {
            if (_position == BlockSize)
            {
                engine.ProcessBlock(_shift, 0, _keystream, 0);
                _position = 0;
                _writeIndex = 0;
            }

            var source = input[i];
            var transformed = (byte)(source ^ _keystream[_position]);
            output[i] = transformed;
            _shift[_writeIndex++] = Encrypting ? transformed : source;
            _position++;
        }
    }
}

/// <summary>
/// AES in counter mode (CTR-128) as used by the legacy Shadowsocks stream
/// methods. The whole 16-byte block is incremented as a big-endian integer,
/// matching Go's <c>crypto/cipher.NewCTR</c> that every Shadowsocks
/// implementation follows. Self-inverse.
/// </summary>
internal sealed class CtrStreamCipher : IStreamCipher
{
    private const int BlockSize = 16;

    private readonly byte[] _counter = new byte[BlockSize];
    private readonly byte[] _keystream = new byte[BlockSize];
    private readonly Func<IBlockCipher> _factory;
    private IBlockCipher? _engine;
    private int _position = BlockSize;

    public CtrStreamCipher(string name, int keySize, Func<IBlockCipher> factory)
    {
        Name = name;
        KeySize = keySize;
        _factory = factory;
    }

    public string Name { get; }

    public int KeySize { get; }

    public int IvSize => BlockSize;

    public void Init(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != KeySize) throw new ArgumentException($"key must be {KeySize} bytes", nameof(key));
        if (iv.Length != IvSize) throw new ArgumentException($"iv must be {IvSize} bytes", nameof(iv));

        var engine = _factory();
        engine.Init(true, new KeyParameter(key.ToArray()));
        _engine = engine;
        iv.CopyTo(_counter);
        _position = BlockSize;
    }

    public void Process(Span<byte> buffer) => Process(buffer, buffer);

    public void Process(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length < input.Length) throw new ArgumentException("output buffer too small", nameof(output));
        var engine = _engine ?? throw new InvalidOperationException($"{Name}: Init must be called before Process");

        for (var i = 0; i < input.Length; i++)
        {
            if (_position == BlockSize)
            {
                engine.ProcessBlock(_counter, 0, _keystream, 0);
                IncrementCounter();
                _position = 0;
            }

            output[i] = (byte)(input[i] ^ _keystream[_position++]);
        }
    }

    private void IncrementCounter()
    {
        for (var i = BlockSize - 1; i >= 0; i--)
        {
            if (++_counter[i] != 0) break;
        }
    }
}

/// <summary>
/// Bridges BouncyCastle's array-only stream API to spans, processing in bounded
/// chunks through a pooled buffer so a large write never allocates.
/// </summary>
internal static class BouncyCastleStreamHelper
{
    private const int ChunkSize = 8192;

    public static void Transform(Org.BouncyCastle.Crypto.IStreamCipher engine, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length < input.Length) throw new ArgumentException("output buffer too small", nameof(output));
        if (input.Length == 0) return;

        var buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(Math.Min(input.Length, ChunkSize));
        try
        {
            var offset = 0;
            while (offset < input.Length)
            {
                var count = Math.Min(buffer.Length, input.Length - offset);
                input.Slice(offset, count).CopyTo(buffer);
                engine.ProcessBytes(buffer, 0, count, buffer, 0);
                buffer.AsSpan(0, count).CopyTo(output.Slice(offset, count));
                offset += count;
            }
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
