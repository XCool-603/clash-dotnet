using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Crypto;
using Xunit;

namespace Clash.Tests.WireGuard;

/// <summary>
/// Pins the primitives against their normative vectors before anything is built on
/// top of them. Each of these values comes from a specification or from the
/// reference implementation's own known-answer file, not from this repository:
/// RFC 7693 appendix B for BLAKE2s, the BLAKE2 reference <c>blake2s-kat.txt</c>
/// for keyed BLAKE2s, RFC 7748 section 6.1 for X25519, and RFC 2104 for HMAC.
/// </summary>
public class WireGuardCryptoTests
{
    [Fact]
    public void Blake2sMatchesTheRfc7693Vector()
    {
        var output = new byte[WireGuardCrypto.HashSize];
        WireGuardCrypto.Hash("abc"u8, output);

        Assert.Equal(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            WireGuardCrypto.ToHex(output));
    }

    [Fact]
    public void Blake2sHashConcatenationEqualsTheConcatenatedHash()
    {
        var together = new byte[WireGuardCrypto.HashSize];
        WireGuardCrypto.Hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"u8, "WireGuard v1 zx2c4 Jason@zx2c4.com"u8, together);

        var concatenated = new byte[WireGuardCrypto.HashSize];
        WireGuardCrypto.Hash(
            [.. "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"u8, .. "WireGuard v1 zx2c4 Jason@zx2c4.com"u8],
            concatenated);

        Assert.Equal(concatenated, together);
    }

    [Fact]
    public void KeyedBlake2sMatchesTheReferenceKnownAnswer()
    {
        // blake2s-kat.txt, first keyed entry: key = 00..1f, empty input.
        var key = new byte[32];
        for (var i = 0; i < key.Length; i++) key[i] = (byte)i;

        var output = new byte[32];
        WireGuardCrypto.KeyedHash(key, ReadOnlySpan<byte>.Empty, output);

        Assert.Equal(
            "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
            WireGuardCrypto.ToHex(output));
    }

    [Fact]
    public void TheDigestLengthIsPartOfTheKeyedHashAndNotATruncation()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var message = "wireguard"u8;

        var full = new byte[32];
        WireGuardCrypto.KeyedHash(key, message, full);

        var mac = new byte[16];
        WireGuardCrypto.Mac(key, message, mac);

        // BLAKE2 mixes the digest length into its parameter block, so MAC is not
        // the first half of the 32-byte keyed digest. If this ever starts passing,
        // the implementation has silently become a truncation.
        Assert.NotEqual(full[..16], mac);
        Assert.Equal(16, mac.Length);
    }

    [Fact]
    public void X25519MatchesTheRfc7748Section61Vectors()
    {
        var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        var alicePublic = WireGuardCrypto.PublicKeyFrom(alicePrivate);
        var bobPublic = WireGuardCrypto.PublicKeyFrom(bobPrivate);

        Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", WireGuardCrypto.ToHex(alicePublic));
        Assert.Equal("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", WireGuardCrypto.ToHex(bobPublic));

        var fromAlice = new byte[32];
        var fromBob = new byte[32];
        WireGuardCrypto.Dh(alicePrivate, bobPublic, fromAlice);
        WireGuardCrypto.Dh(bobPrivate, alicePublic, fromBob);

        Assert.Equal("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", WireGuardCrypto.ToHex(fromAlice));
        Assert.Equal(fromAlice, fromBob);
    }

    [Fact]
    public void HmacIsTheRfc2104ConstructionOverBlake2s()
    {
        var key = new byte[32];
        for (var i = 0; i < key.Length; i++) key[i] = (byte)(i * 7);
        var message = "wireguard"u8.ToArray();

        var actual = new byte[32];
        WireGuardCrypto.Hmac(key, message, actual);

        // H((K ^ opad) ‖ H((K ^ ipad) ‖ m)), written out again with the BLAKE2s
        // block size of 64 bytes.
        var ipad = new byte[64];
        var opad = new byte[64];
        key.CopyTo(ipad, 0);
        key.CopyTo(opad, 0);
        for (var i = 0; i < 64; i++)
        {
            ipad[i] ^= 0x36;
            opad[i] ^= 0x5C;
        }

        var inner = new byte[32];
        WireGuardCrypto.Hash(ipad, message, inner);
        var expected = new byte[32];
        WireGuardCrypto.Hash(opad, inner, expected);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void HmacHashesAKeyLongerThanOneBlockFirst()
    {
        var longKey = RandomNumberGenerator.GetBytes(200);
        var message = "wireguard"u8.ToArray();

        var actual = new byte[32];
        WireGuardCrypto.Hmac(longKey, message, actual);

        var hashedKey = new byte[32];
        WireGuardCrypto.Hash(longKey, hashedKey);
        var expected = new byte[32];
        WireGuardCrypto.Hmac(hashedKey, message, expected);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void AeadUsesTheLittleEndianCounterNonceAndRejectsTheWrongKeyOrTag()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = Encoding.ASCII.GetBytes("the inner packet");
        var aad = RandomNumberGenerator.GetBytes(32);

        var sealedData = new byte[plaintext.Length + WireGuardCrypto.MacSize];
        WireGuardCrypto.AeadSeal(key, 7, plaintext, sealedData, aad);

        var opened = new byte[plaintext.Length];
        Assert.True(WireGuardCrypto.AeadOpen(key, 7, sealedData, opened, aad));
        Assert.Equal(plaintext, opened);

        // The counter is the nonce, so the same ciphertext under a different
        // counter must not open.
        var wrongCounter = new byte[plaintext.Length];
        Assert.False(WireGuardCrypto.AeadOpen(key, 8, sealedData, wrongCounter, aad));
        Assert.All(wrongCounter, b => Assert.Equal(0, b));

        // Neither must the same ciphertext under a different associated data.
        var wrongAad = RandomNumberGenerator.GetBytes(32);
        Assert.False(WireGuardCrypto.AeadOpen(key, 7, sealedData, opened, wrongAad));

        // And a single flipped tag bit must fail.
        sealedData[^1] ^= 0x01;
        Assert.False(WireGuardCrypto.AeadOpen(key, 7, sealedData, opened, aad));
    }

    [Fact]
    public void AeadNonceIsFourZeroBytesThenTheLittleEndianCounter()
    {
        Span<byte> nonce = stackalloc byte[WireGuardCrypto.NonceSize];
        WireGuardCrypto.AeadNonce(0x0102030405060708UL, nonce);

        Assert.Equal(new byte[] { 0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1 }, nonce.ToArray());
    }

    [Fact]
    public void Tai64NIsBigEndianTaiSecondsFollowedByNanoseconds()
    {
        var when = DateTimeOffset.FromUnixTimeSeconds(0x100000000).AddTicks(1234567);

        Span<byte> stamp = stackalloc byte[WireGuardCrypto.TimestampSize];
        WireGuardCrypto.Tai64N(when, stamp);

        Assert.Equal(0x400000000000000AUL + 0x100000000UL, BinaryPrimitives.ReadUInt64BigEndian(stamp));
        Assert.Equal((uint)(1234567 * 100), BinaryPrimitives.ReadUInt32BigEndian(stamp[8..]));
    }

    [Fact]
    public void TryDecodeKeyAcceptsOnlyBase64OfTheRightLength()
    {
        var key = RandomNumberGenerator.GetBytes(32);

        Assert.True(WireGuardCrypto.TryDecodeKey(WireGuardCrypto.ToBase64(key), 32, out var decoded));
        Assert.Equal(key, decoded);

        Assert.False(WireGuardCrypto.TryDecodeKey("not base64 at all", 32, out _));
        Assert.False(WireGuardCrypto.TryDecodeKey(Convert.ToBase64String(new byte[16]), 32, out _));
        Assert.False(WireGuardCrypto.TryDecodeKey(null, 32, out _));
    }

    [Fact]
    public void DhRefusesALowOrderPublicKey()
    {
        var privateKey = RandomNumberGenerator.GetBytes(32);
        var allZero = new byte[32];

        Assert.Throws<Clash.Core.Common.ClashException>(() =>
        {
            Span<byte> shared = stackalloc byte[32];
            WireGuardCrypto.Dh(privateKey, allZero, shared);
        });
    }
}
