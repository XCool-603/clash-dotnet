using System.Buffers.Binary;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace Clash.Tests.WireGuard;

/// <summary>
/// A second, deliberately independent implementation of the four primitives
/// WireGuard needs, written straight against BouncyCastle for the test suite only.
/// <para>
/// Why it exists: the fake peer must implement the responder half of the handshake
/// without sharing any code with the initiator under test, otherwise a mistake in
/// <c>WireGuardCrypto</c> would be reproduced on both sides and cancel itself out.
/// This type therefore reaches for BouncyCastle directly — <c>Blake2sDigest</c>,
/// <c>X25519Agreement</c> and the RFC 7539 <c>ChaCha20Poly1305</c> engine — instead
/// of calling into the production wrapper. The production wrapper is pinned
/// separately, against RFC 7693, RFC 7748 and the BLAKE2 reference vector.
/// </para>
/// </summary>
internal static class TestCrypto
{
    internal const int HashSize = 32;
    internal const int MacSize = 16;
    internal const int KeySize = 32;
    internal const int BlockSize = 64;

    /// <summary><c>HASH(in)</c> — unkeyed BLAKE2s-256.</summary>
    internal static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        var digest = new Blake2sDigest();
        digest.BlockUpdate(input);
        digest.DoFinal(output);
    }

    /// <summary><c>HASH(a ‖ b)</c>.</summary>
    internal static void Hash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> output)
    {
        var digest = new Blake2sDigest();
        digest.BlockUpdate(a);
        digest.BlockUpdate(b);
        digest.DoFinal(output);
    }

    /// <summary><c>HASH(a ‖ b)</c> into a fresh array.</summary>
    internal static byte[] Hash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var output = new byte[HashSize];
        Hash(a, b, output);
        return output;
    }

    /// <summary><c>MAC(key, in)</c> — keyed BLAKE2s truncated to 16 bytes.</summary>
    internal static void Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        var digest = new Blake2sDigest(key.ToArray(), MacSize, null, null);
        digest.BlockUpdate(input);
        digest.DoFinal(output);
    }

    /// <summary><c>MAC(key, in)</c> into a fresh 16-byte array.</summary>
    internal static byte[] Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
    {
        var output = new byte[MacSize];
        Mac(key, input, output);
        return output;
    }

    /// <summary><c>HMAC-BLAKE2s(key, a ‖ b)</c>, written out as RFC 2104 defines it.</summary>
    internal static void Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> output)
    {
        var normalized = new byte[BlockSize];
        if (key.Length > BlockSize) Hash(key, normalized);
        else key.CopyTo(normalized);

        var ipad = new byte[BlockSize];
        var opad = new byte[BlockSize];
        for (var i = 0; i < BlockSize; i++)
        {
            ipad[i] = (byte)(normalized[i] ^ 0x36);
            opad[i] = (byte)(normalized[i] ^ 0x5C);
        }

        var inner = new byte[HashSize];
        var digest = new Blake2sDigest();
        digest.BlockUpdate(ipad);
        digest.BlockUpdate(a);
        digest.BlockUpdate(b);
        digest.DoFinal(inner);

        var outer = new Blake2sDigest();
        outer.BlockUpdate(opad);
        outer.BlockUpdate(inner);
        outer.DoFinal(output);
    }

    /// <summary><c>DH(private, public)</c> through BouncyCastle's agreement object.</summary>
    internal static void Dh(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey, Span<byte> shared)
    {
        var agreement = new Org.BouncyCastle.Crypto.Agreement.X25519Agreement();
        agreement.Init(new X25519PrivateKeyParameters(privateKey));
        agreement.CalculateAgreement(new X25519PublicKeyParameters(publicKey), shared);
    }

    /// <summary>Derives an X25519 public key from a private key.</summary>
    internal static byte[] PublicFrom(ReadOnlySpan<byte> privateKey)
        => new X25519PrivateKeyParameters(privateKey).GeneratePublicKey().GetEncoded();

    /// <summary>The <c>0x00000000 ‖ LE64(counter)</c> nonce <c>AEAD()</c> is defined with.</summary>
    internal static void AeadNonce(ulong counter, Span<byte> nonce)
    {
        nonce[..4].Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
    }

    /// <summary><c>AEAD(key, counter, plain, auth)</c> through BouncyCastle's RFC 7539 engine.</summary>
    internal static void AeadSeal(
        ReadOnlySpan<byte> key,
        ulong counter,
        ReadOnlySpan<byte> plaintext,
        Span<byte> output,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> nonce = stackalloc byte[12];
        AeadNonce(counter, nonce);

        var input = plaintext.ToArray();
        var buffer = new byte[input.Length + MacSize];
        var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        cipher.Init(true, new AeadParameters(new KeyParameter(key.ToArray()), 128, nonce.ToArray(), associatedData.ToArray()));
        var written = cipher.ProcessBytes(input, 0, input.Length, buffer, 0);
        written += cipher.DoFinal(buffer, written);

        buffer.AsSpan(0, plaintext.Length).CopyTo(output);
        buffer.AsSpan(plaintext.Length, MacSize).CopyTo(output[plaintext.Length..]);
        _ = written;
    }

    /// <summary>The inverse of <see cref="AeadSeal"/>; false when the tag does not verify.</summary>
    internal static bool AeadOpen(
        ReadOnlySpan<byte> key,
        ulong counter,
        ReadOnlySpan<byte> sealedData,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> nonce = stackalloc byte[12];
        AeadNonce(counter, nonce);

        var ciphertextLength = sealedData.Length - MacSize;
        var input = new byte[sealedData.Length];
        sealedData.CopyTo(input);

        var buffer = new byte[input.Length];
        try
        {
            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            cipher.Init(
                false,
                new AeadParameters(new KeyParameter(key.ToArray()), 128, nonce.ToArray(), associatedData.ToArray()));
            var written = cipher.ProcessBytes(input, 0, input.Length, buffer, 0);
            written += cipher.DoFinal(buffer, written);
            buffer.AsSpan(0, ciphertextLength).CopyTo(plaintext);
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
    }

    /// <summary>TAI64N, big-endian, exactly as the protocol page defines it.</summary>
    internal static void Tai64N(DateTimeOffset now, Span<byte> output)
    {
        const ulong tai64NBase = 0x400000000000000AUL;
        var ticks = now.UtcTicks;
        BinaryPrimitives.WriteUInt64BigEndian(output, tai64NBase + (ulong)(ticks / TimeSpan.TicksPerSecond));
        BinaryPrimitives.WriteUInt32BigEndian(output[8..], (uint)((ticks % TimeSpan.TicksPerSecond) * 100));
    }
}
