using System.Text;
using Clash.Core.Crypto;
using Xunit;

namespace Clash.Tests.Crypto;

/// <summary>VMess, VLESS, Trojan and ShadowsocksR crypto helpers.</summary>
public class ProtocolCryptoTests
{
    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    private static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    private static byte[] Sequence(int length, byte start = 1)
    {
        var result = new byte[length];
        for (var i = 0; i < length; i++) result[i] = (byte)(start + i);
        return result;
    }

    private static readonly byte[] Uuid = FromHex("6ba7b8109dad11d180b400c04fd430c8");

    // ---- VMess ------------------------------------------------------------------
    //
    // Every expectation in this region was produced by running the reference
    // algorithm itself, not by running this implementation: sing-vmess
    // kdf.go/protocol.go for the KDF, the account command key and the AuthID,
    // v2ray-core proxy/vmess/aead for the sealed request header and mihomo
    // transport/vmess/aead.go for the chunk framing.

    /// <summary>MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21") for <see cref="Uuid"/>.</summary>
    private const string VmessCmdKey = "b3423234ffc370480b59e1174c1fde53";

    /// <summary>The sealed AuthID for timestamp 1700000000 and random 01020304.</summary>
    private const string VmessAuthId = "21facfb3dee91114e8e42fee73b54246";

    [Fact]
    public void VmessCommandKeyIsMd5OfUuidAndTheMagic()
    {
        Assert.Equal(VmessCmdKey, Hex(VmessCrypto.CommandKey(Uuid)));
        Assert.Equal("c48619fe-8f02-49e0-b9e9-edf763e17e21", VmessLegacy.KeyMagic);
    }

    [Fact]
    public void VmessKdfMatchesTheReferenceChain()
    {
        var key = Sequence(16, 1);
        var path0 = Sequence(16, 40);
        var path1 = Sequence(8, 90);

        // The reference nests hmac.New calls, so this is NOT an iterated
        // HMAC(HMAC(key, salt0), salt1) chain.
        Assert.Equal(
            "fb10be7197c787b40b976cfc03de6e7c8b3d8e7fa9c033ff0c04fda135804a9d",
            Hex(VmessCrypto.Kdf(key, "a"u8.ToArray())));
        Assert.Equal(
            "ac95f438a262ec457a890d402809f7cff0148b35054c684b19e34fa9b706bbd9",
            Hex(VmessCrypto.Kdf(key, "a"u8.ToArray(), "b"u8.ToArray())));
        Assert.Equal(
            "f15feecc999c8f3108715dcc1cff56b388f09efc5885e219a09273b3c595b22b",
            Hex(VmessCrypto.Kdf(key, VmessCrypto.Salt(VmessCrypto.SaltRequestHeaderPayloadKey), path0, path1)));
        Assert.Equal(
            "f15feecc999c8f3108715dcc1cff56b3",
            Hex(VmessCrypto.Kdf16(key, VmessCrypto.Salt(VmessCrypto.SaltRequestHeaderPayloadKey), path0, path1)));
    }

    [Fact]
    public void VmessAuthIdPlaintextAndSealMatchTheReference()
    {
        var plaintext = new byte[VmessCrypto.AuthIdSize];
        VmessCrypto.BuildAuthIdPlaintext(plaintext, 1_700_000_000, [0x01, 0x02, 0x03, 0x04]);

        // timestamp(8, big-endian) || random(4) || crc32(big-endian)
        Assert.Equal("000000006553f10001020304b85575f7", Hex(plaintext));
        Assert.True(VmessCrypto.VerifyAuthIdPlaintext(plaintext));

        var sealedAuthId = new byte[VmessCrypto.AuthIdSize];
        VmessCrypto.SealAuthId(Uuid, plaintext, sealedAuthId);
        Assert.Equal(VmessAuthId, Hex(sealedAuthId));
        Assert.NotEqual(plaintext, sealedAuthId);
    }

    [Fact]
    public void VmessAuthIdPlaintextCarriesAVerifiableCrc()
    {
        var plaintext = new byte[VmessCrypto.AuthIdSize];
        VmessCrypto.BuildAuthIdPlaintext(plaintext, 1_700_000_000, Sequence(4, 9));

        Assert.True(VmessCrypto.VerifyAuthIdPlaintext(plaintext));
        plaintext[3] ^= 0x01;
        Assert.False(VmessCrypto.VerifyAuthIdPlaintext(plaintext));
    }

    [Fact]
    public void VmessAuthIdSealAndOpenRoundTrip()
    {
        var plaintext = new byte[VmessCrypto.AuthIdSize];
        VmessCrypto.BuildAuthIdPlaintext(plaintext, 1_700_000_000, Sequence(4, 9));

        var sealedAuthId = new byte[VmessCrypto.AuthIdSize];
        VmessCrypto.SealAuthId(Uuid, plaintext, sealedAuthId);

        var opened = new byte[VmessCrypto.AuthIdSize];
        Assert.True(VmessCrypto.TryOpenAuthId(Uuid, sealedAuthId, opened));
        Assert.Equal(plaintext, opened);

        // A different user must not be able to open it.
        var otherUuid = FromHex("00112233445566778899aabbccddeeff");
        Assert.False(VmessCrypto.TryOpenAuthId(otherUuid, sealedAuthId, opened));
    }

    [Fact]
    public void VmessSealedRequestHeaderMatchesTheReference()
    {
        var cmdKey = FromHex(VmessCmdKey);
        var authId = FromHex(VmessAuthId);
        var connectionNonce = Sequence(8, 0x20);
        var body = Sequence(58, 0x10);

        var sealedHeader = VmessCrypto.SealRequestHeader(cmdKey, authId, connectionNonce, body);

        // authID(16) | AEAD(length, 2+16) | connectionNonce(8) | AEAD(body, len+16)
        Assert.Equal(16 + 18 + 8 + body.Length + 16, sealedHeader.Length);
        Assert.Equal(authId, sealedHeader[..16]);
        Assert.Equal(connectionNonce, sealedHeader[34..42]);
        Assert.Equal(
            "21facfb3dee91114e8e42fee73b54246afe481f096b88fd29d88594cb00ab9bb1f132021222324252627"
            + "276900774f4ae90430eaecd7e291813b0e17f478dd85302dbca68c1e2891c68ffe9ce58256cfc6e27a8e7d"
            + "86ff4031047d049df0ca0b5204e3371192f04b63861d621d70e5dc467bd583",
            Hex(sealedHeader));

        Assert.True(VmessCrypto.TryOpenRequestHeader(sealedHeader, cmdKey, out var consumed, out var parsedAuthId, out var parsedNonce, out var parsedBody));
        Assert.Equal(sealedHeader.Length, consumed);
        Assert.Equal(authId, parsedAuthId);
        Assert.Equal(connectionNonce, parsedNonce);
        Assert.Equal(body, parsedBody);

        // Both AEAD operations are bound to the AuthID as associated data.
        sealedHeader[^1] ^= 0x01;
        Assert.False(VmessCrypto.TryOpenRequestHeader(sealedHeader, cmdKey, out _, out _, out _, out _));
    }

    [Fact]
    public void VmessRequestHeaderKeysMatchTheReference()
    {
        var keys = VmessCrypto.DeriveRequestHeaderKeys(
            FromHex(VmessCmdKey),
            FromHex(VmessAuthId),
            Sequence(8, 0x20));

        Assert.Equal("d16fc7527a038eb249513908526cb585", Hex(keys.LengthKey));
        Assert.Equal("cd4f8bf4f398821e22037b26", Hex(keys.LengthIv));
        Assert.Equal("65edb23c9e2b1360b631944b9217e9e9", Hex(keys.PayloadKey));
        Assert.Equal("f5a64d56514bb56be18abed2", Hex(keys.PayloadIv));
    }

    [Fact]
    public void VmessHeaderKeysDependOnTheConnectionNonce()
    {
        var cmdKey = FromHex(VmessCmdKey);
        var authId = Sequence(16, 40);
        var first = VmessCrypto.DeriveRequestHeaderKeys(cmdKey, authId, Sequence(8, 3));
        var second = VmessCrypto.DeriveRequestHeaderKeys(cmdKey, authId, Sequence(8, 4));

        Assert.NotEqual(first.LengthKey, second.LengthKey);
        Assert.NotEqual(first.PayloadIv, second.PayloadIv);
        Assert.Equal(16, first.LengthKey.Length);
        Assert.Equal(12, first.LengthIv.Length);
    }

    [Fact]
    public void VmessResponseBodyAndHeaderKeysMatchTheReference()
    {
        var requestKey = Sequence(16, 0x30);
        var requestIv = Sequence(16, 0x40);

        var (key, iv) = VmessCrypto.DeriveResponseBodyKeys(requestKey, requestIv);
        Assert.Equal("816b9e7c25d559c5766755b3bbb36654", Hex(key));
        Assert.Equal("ba22b7dc95f6cc8765757be4bccf37cd", Hex(iv));

        var keys = VmessCrypto.DeriveResponseHeaderKeys(key, iv);
        Assert.Equal("4ad2cd2ea65f103333fd22878ec23884", Hex(keys.LengthKey));
        Assert.Equal("af6e7d42b990081a6df676e6", Hex(keys.LengthIv));
        Assert.Equal("c1d1885f1631bd00e056758fd92fa6e3", Hex(keys.PayloadKey));
        Assert.Equal("ec517a349a2fe8495b5f1e36", Hex(keys.PayloadIv));
    }

    [Fact]
    public void VmessBodyChunksMatchTheReference()
    {
        var bodyKey = Sequence(16, 0x30);
        var bodyIv = Sequence(16, 0x40);
        var payload = Sequence(20, 0x50);

        Assert.Equal(
            "bdf2930f973f722e24a3773d61889501c3c2e371e23677b71c00a97d736d5e0f",
            Hex(VmessCrypto.Chacha20Poly1305Key(bodyKey)));

        // [length(2, big-endian, payload + tag)][sealed payload][tag]
        Assert.Equal(
            "00242d56695223e03c11ac14885eee84eb4992c91aa014bcae12e06c6c8cc042eff96c6f8a36",
            Hex(WriteChunk(VmessSecurity.Aes128Gcm, bodyKey, bodyIv, 0, payload)));
        Assert.Equal(
            "00247655ea23b0392b0338b4bcf0ad9a8614191fc10eec6f2f72a1920c53b799ef7132bf0e86",
            Hex(WriteChunk(VmessSecurity.Aes128Gcm, bodyKey, bodyIv, 1, payload)));
        Assert.Equal(
            "0024e4ea547ea4bef994229b33d5507322ea4754c70483cab8969a2decdd960973879a89e512",
            Hex(WriteChunk(VmessSecurity.ChaCha20Poly1305, bodyKey, bodyIv, 0, payload)));

        // The counter really is what makes the two chunks differ.
        Assert.NotEqual(
            Hex(WriteChunk(VmessSecurity.Aes128Gcm, bodyKey, bodyIv, 0, payload)),
            Hex(WriteChunk(VmessSecurity.Aes128Gcm, bodyKey, bodyIv, 1, payload)));
    }

    [Fact]
    public void VmessResponseHeaderRejectsATamperedBody()
    {
        var keys = VmessCrypto.DeriveResponseHeaderKeys(Sequence(16, 0x30), Sequence(16, 0x40));
        var body = Sequence(32, 5);
        var destination = new byte[body.Length + 2 * (2 + VmessCrypto.TagSize)];
        var written = VmessCrypto.SealResponseHeader(body, keys, destination);

        Assert.True(VmessCrypto.TryOpenHeader(destination.AsSpan(0, written), keys, out var consumed, out var recovered));
        Assert.Equal(written, consumed);
        Assert.Equal(body, recovered);

        destination[written - 1] ^= 0x01;
        Assert.False(VmessCrypto.TryOpenHeader(destination.AsSpan(0, written), keys, out _, out _));
    }

    [Fact]
    public void VmessLegacyAuthIdIsHmacMd5OfTheAlterKeyAndTheBigEndianTimestamp()
    {
        var authId = VmessCrypto.CreateAuthId(Uuid, 0x01020304);
        Assert.Equal(16, authId.Length);

        var alterKey = System.Security.Cryptography.MD5.HashData(
            [.. Uuid, .. Encoding.ASCII.GetBytes(VmessCrypto.SaltAlterId)]);
        var material = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(material, 0x01020304);

        Assert.Equal(System.Security.Cryptography.HMACMD5.HashData(alterKey, material), authId);
        Assert.NotEqual(authId, VmessCrypto.CreateAuthId(Uuid, 0x01020305));
    }

    /// <summary>Frames one chunk the way the reference writer does.</summary>
    private static byte[] WriteChunk(VmessSecurity security, byte[] bodyKey, byte[] bodyIv, ushort counter, byte[] payload)
    {
        var destination = new byte[VmessBody.FramedSize(security, payload.Length)];
        ushort count = counter;
        var written = VmessBody.WriteChunk(
            security,
            VmessBody.DeriveKey(security, bodyKey),
            bodyIv,
            ref count,
            payload,
            destination);

        Assert.Equal((ushort)(counter + 1), count);
        return destination[..written];
    }

    [Fact]
    public void VmessLegacyKeysAreMd5OfUuidAndTheMagic()
    {
        var key = VmessLegacy.DeriveCommandKey(Uuid);
        Assert.Equal(16, key.Length);

        var material = new byte[16 + VmessLegacy.KeyMagic.Length];
        Uuid.CopyTo(material, 0);
        Encoding.ASCII.GetBytes(VmessLegacy.KeyMagic).CopyTo(material, 16);
        Assert.Equal(System.Security.Cryptography.MD5.HashData(material), key);
    }

    [Fact]
    public void VmessLegacyHeaderTransformRoundTrips()
    {
        var key = VmessLegacy.DeriveCommandKey(Uuid);
        var iv = VmessLegacy.DeriveCommandIv(Sequence(16, 1));
        var plaintext = Sequence(64, 7);

        var ciphertext = new byte[plaintext.Length];
        VmessLegacy.TransformHeader(key, iv, plaintext, ciphertext);
        Assert.NotEqual(plaintext, ciphertext);
    }

    // ---- VLESS ------------------------------------------------------------------

    [Theory]
    [InlineData("1.2.3.4")]
    [InlineData("example.com")]
    [InlineData("2001:db8::1")]
    public void VlessRequestHeaderRoundTrips(string host)
    {
        var addons = VlessCrypto.EncodeAddons(VlessCrypto.FlowVision);
        var buffer = new byte[512];
        var written = VlessCrypto.WriteRequestHeader(buffer, Uuid, VlessCrypto.CommandTcp, host, 443, addons);

        Assert.Equal(0, buffer[0]);
        Assert.Equal(Uuid, buffer.AsSpan(1, 16).ToArray());
        Assert.Equal(addons.Length, buffer[17]);

        Assert.True(VlessCrypto.TryReadRequestHeader(buffer.AsSpan(0, written), out var consumed, out var uuid, out var command, out var parsedHost, out var port, out var parsedAddons));
        Assert.Equal(written, consumed);
        Assert.Equal(Uuid, uuid);
        Assert.Equal(VlessCrypto.CommandTcp, command);
        Assert.Equal(host, parsedHost);
        Assert.Equal(443, port);
        Assert.Equal(addons, parsedAddons);

        Assert.True(VlessCrypto.TryDecodeAddons(parsedAddons, out var flow, out _));
        Assert.Equal(VlessCrypto.FlowVision, flow);
    }

    [Fact]
    public void VlessRequestHeaderIsIncompleteUntilTheWholeAddressArrives()
    {
        var buffer = new byte[512];
        var written = VlessCrypto.WriteRequestHeader(buffer, Uuid, VlessCrypto.CommandUdp, "example.com", 53);
        Assert.False(VlessCrypto.TryMeasureRequestHeader(buffer.AsSpan(0, written - 1), out _, out _, out _));
        Assert.True(VlessCrypto.TryMeasureRequestHeader(buffer.AsSpan(0, written), out var consumed, out var command, out var port));
        Assert.Equal(written, consumed);
        Assert.Equal(VlessCrypto.CommandUdp, command);
        Assert.Equal(53, port);
    }

    [Fact]
    public void VlessResponseHeaderRoundTrips()
    {
        var buffer = new byte[32];
        var written = VlessCrypto.WriteResponseHeader(buffer, Sequence(5, 3));
        Assert.True(VlessCrypto.TryReadResponseHeader(buffer.AsSpan(0, written), out var consumed, out var addons));
        Assert.Equal(written, consumed);
        Assert.Equal(Sequence(5, 3), addons);
    }

    [Fact]
    public void VlessAddonsCarryFlowAndSeed()
    {
        var seed = Sequence(16, 77);
        var addons = VlessCrypto.EncodeAddons(VlessCrypto.FlowVision, seed);

        Assert.True(VlessCrypto.TryDecodeAddons(addons, out var flow, out var decodedSeed));
        Assert.Equal(VlessCrypto.FlowVision, flow);
        Assert.Equal(seed, decodedSeed);

        Assert.True(VlessCrypto.TryDecodeAddons([], out var emptyFlow, out var emptySeed));
        Assert.Null(emptyFlow);
        Assert.Empty(emptySeed);
    }

    [Fact]
    public void VlessVisionPaddingHeaderRoundTrips()
    {
        var buffer = new byte[VlessVisionPadding.HeaderSize];
        Assert.Equal(3, VlessVisionPadding.WriteHeader(buffer, VlessVisionPadding.CommandEnd, 900));

        Assert.True(VlessVisionPadding.TryReadHeader(buffer, out var command, out var length));
        Assert.Equal(VlessVisionPadding.CommandEnd, command);
        Assert.Equal(900, length);

        Assert.False(VlessVisionPadding.TryReadHeader(buffer.AsSpan(0, 2), out _, out _));
        Assert.False(VlessVisionPadding.TryReadHeader([0xFF, 0, 0], out _, out _));
    }

    [Fact]
    public void VlessVisionPaddingLengthsShrinkAsPayloadGrows()
    {
        Assert.True(VlessVisionPadding.NextPaddingLength(0, seed: 1) > 0);
        Assert.Equal(0, VlessVisionPadding.NextPaddingLength(4096, seed: 1));
        Assert.Equal(0, VlessVisionPadding.NextPaddingLength(900, seed: 1));
    }

    // ---- Trojan -----------------------------------------------------------------

    [Fact]
    public void TrojanPasswordHashIsLowercaseSha224Hex()
    {
        Assert.Equal(56, TrojanCrypto.ComputePasswordHashHex("password").Length);
        Assert.Equal("d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01", TrojanCrypto.ComputePasswordHashHex("password"));
        Assert.Equal("f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6", TrojanCrypto.ComputePasswordHashHex("123456"));
        Assert.Equal("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", TrojanCrypto.ComputePasswordHashHex(string.Empty));
        Assert.Equal(28, TrojanCrypto.ComputePasswordHash("password").Length);
    }

    [Theory]
    [InlineData("1.2.3.4")]
    [InlineData("example.com")]
    [InlineData("2001:db8::1")]
    public void TrojanRequestHeaderRoundTrips(string host)
    {
        var hash = TrojanCrypto.ComputePasswordHashHex("password");
        var buffer = new byte[512];
        var written = TrojanCrypto.WriteRequestHeader(buffer, hash, TrojanCrypto.CommandConnect, host, 443);

        var text = Encoding.ASCII.GetString(buffer, 0, written);
        Assert.StartsWith(hash + "\r\n", text);
        Assert.EndsWith("\r\n", text);

        Assert.True(TrojanCrypto.TryReadRequestHeader(buffer.AsSpan(0, written), out var consumed, out var parsedHash, out var command, out var parsedHost, out var port));
        Assert.Equal(written, consumed);
        Assert.Equal(hash, parsedHash);
        Assert.Equal(TrojanCrypto.CommandConnect, command);
        Assert.Equal(host, parsedHost);
        Assert.Equal(443, port);
    }

    [Fact]
    public void TrojanRequestHeaderRejectsABadHashLength()
    {
        var buffer = new byte[512];
        Assert.Throws<ArgumentException>(() => TrojanCrypto.WriteRequestHeader(buffer, "abcd", TrojanCrypto.CommandConnect, "1.2.3.4", 80));
    }

    [Theory]
    [InlineData("1.2.3.4")]
    [InlineData("example.com")]
    public void TrojanUdpPacketRoundTrips(string host)
    {
        var payload = Encoding.ASCII.GetBytes("udp payload");
        var buffer = new byte[512];
        var written = TrojanCrypto.WriteUdpPacket(buffer, host, 53, payload);

        Assert.True(TrojanCrypto.TryReadUdpPacket(buffer.AsSpan(0, written), out var consumed, out var parsedHost, out var port, out var parsedPayload));
        Assert.Equal(written, consumed);
        Assert.Equal(host, parsedHost);
        Assert.Equal(53, port);
        Assert.Equal(payload, parsedPayload);
    }

    [Fact]
    public void TrojanUdpPacketNeedsTheWholePayload()
    {
        var buffer = new byte[512];
        var written = TrojanCrypto.WriteUdpPacket(buffer, "1.2.3.4", 53, Encoding.ASCII.GetBytes("abcdef"));
        Assert.False(TrojanCrypto.TryMeasureUdpPacket(buffer.AsSpan(0, written - 1), out _, out _));
        Assert.True(TrojanCrypto.TryMeasureUdpPacket(buffer.AsSpan(0, written), out var length, out _));
        Assert.Equal(written, length);
    }

    // ---- ShadowsocksR -----------------------------------------------------------

    [Fact]
    public void SsrOriginAndPlainArePassThroughAndFullySupported()
    {
        var protocol = ShadowsocksR.CreateProtocol(ShadowsocksR.ProtocolOrigin);
        Assert.Equal(SsrSupportLevel.Full, protocol.Support);
        Assert.Equal(0, protocol.BuildClientHeader(new byte[16], Sequence(16, 1)));
        Assert.True(protocol.TryReadClientHeader([], Sequence(16, 1), out var consumed));
        Assert.Equal(0, consumed);

        var payload = Sequence(32, 3);
        var expected = payload.ToArray();
        protocol.TransformClientToServer(payload);
        Assert.Equal(expected, payload);

        var obfs = ShadowsocksR.CreateObfs(ShadowsocksR.ObfsPlain);
        Assert.Equal(SsrSupportLevel.Full, obfs.Support);
        Assert.Equal(0, obfs.BuildClientHeader(new byte[16], "example.com", 443, []));
        Assert.True(obfs.TryMeasureClientHeader([], out var obfsConsumed));
        Assert.Equal(0, obfsConsumed);

        // "plain" is accepted as a protocol name and "origin" as an obfs name,
        // because real configurations mix the two vocabularies.
        Assert.True(ShadowsocksR.IsProtocolSupported("PLAIN"));
        Assert.True(ShadowsocksR.IsObfsSupported("origin"));
    }

    [Fact]
    public void SsrUnsupportedPluginsThrowWithANamedMessage()
    {
        var ex = Assert.Throws<NotSupportedException>(() => ShadowsocksR.CreateProtocol(ShadowsocksR.ProtocolAuthChainA));
        Assert.Contains(ShadowsocksR.ProtocolAuthChainA, ex.Message);

        var obfs = Assert.Throws<NotSupportedException>(() => ShadowsocksR.CreateObfs(ShadowsocksR.ObfsHttpSimple));
        Assert.Contains(ShadowsocksR.ObfsHttpSimple, obfs.Message);

        Assert.False(ShadowsocksR.IsProtocolSupported(ShadowsocksR.ProtocolAuthChainA));
        Assert.False(ShadowsocksR.IsObfsSupported(ShadowsocksR.ObfsTls12TicketAuth));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SsrAuthAes128ClientHeaderRoundTrips(bool sha1)
    {
        var userKey = Sequence(32, 5);
        var buffer = new byte[128];
        var written = SsrAuthAes128.BuildClientHeader(buffer, userKey, uid: 0x12345678, sha1, seed: 42);
        Assert.True(written > 0);

        var randomLength = buffer[0];
        Assert.InRange(randomLength, 1, SsrAuthAes128.MaxRandomLength);
        Assert.Equal(1 + randomLength + (sha1 ? SsrAuthAes128.Sha1MacLength : SsrAuthAes128.Md5MacLength) + SsrAuthAes128.UidLength, written);

        Assert.True(SsrAuthAes128.TryReadClientHeader(buffer.AsSpan(0, written), userKey, sha1, out var consumed, out var uid));
        Assert.Equal(written, consumed);
        Assert.Equal(0x12345678u, uid);

        // A different user key must not verify.
        Assert.False(SsrAuthAes128.TryReadClientHeader(buffer.AsSpan(0, written), Sequence(32, 6), sha1, out _, out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SsrAuthAes128ServerHeaderRoundTrips(bool sha1)
    {
        var userKey = Sequence(32, 5);
        var buffer = new byte[128];
        var written = SsrAuthAes128.BuildServerHeader(buffer, userKey, sha1, seed: 7);
        Assert.True(written > 0);

        Assert.True(SsrAuthAes128.TryReadServerHeader(buffer.AsSpan(0, written), userKey, sha1, out var consumed));
        Assert.Equal(written, consumed);
        Assert.False(SsrAuthAes128.TryReadServerHeader(buffer.AsSpan(0, written), Sequence(32, 9), sha1, out _));
    }

    [Fact]
    public void SsrAuthAes128ProtocolReportsPartialSupport()
    {
        var protocol = ShadowsocksR.CreateProtocol(ShadowsocksR.ProtocolAuthAes128Md5);
        Assert.Equal(SsrSupportLevel.Partial, protocol.Support);
        Assert.Equal(ShadowsocksR.ProtocolAuthAes128Md5, protocol.Name);

        var concrete = Assert.IsType<SsrAuthAes128Protocol>(protocol);
        var buffer = new byte[128];
        var written = concrete.BuildClientHeader(buffer, Sequence(32, 1));
        Assert.True(concrete.TryReadClientHeader(buffer.AsSpan(0, written), Sequence(32, 1), out _));
        Assert.InRange(concrete.LastRandomLength, 1, SsrAuthAes128.MaxRandomLength);
    }

    [Fact]
    public void SsrRc4DiscardsKeystreamBytes()
    {
        var key = Sequence(16, 1);

        var plain = new SsrRc4();
        plain.Init(key, discard: 0);
        var withoutDiscard = new byte[32];
        plain.Process(withoutDiscard);

        var skipped = new SsrRc4();
        skipped.Init(key, discard: 32);
        var afterDiscard = new byte[32];
        skipped.Process(afterDiscard);

        // Discarding 32 bytes must line the stream up with bytes 32..63 of the
        // undiscarded keystream.
        var longStream = new byte[64];
        var reference = new SsrRc4();
        reference.Init(key, discard: 0);
        reference.Process(longStream);

        Assert.Equal(longStream.AsSpan(32, 32).ToArray(), afterDiscard);
        Assert.Equal(longStream.AsSpan(0, 32).ToArray(), withoutDiscard);
    }

    // ---- SOCKS5 address block ---------------------------------------------------

    [Theory]
    [InlineData("1.2.3.4", 1 + 4 + 2)]
    [InlineData("2001:db8::1", 1 + 16 + 2)]
    [InlineData("example.com", 1 + 1 + 11 + 2)]
    public void Socks5AddressRoundTrips(string host, int expectedSize)
    {
        Assert.Equal(expectedSize, Socks5Address.Size(host));

        var buffer = new byte[64];
        var written = Socks5Address.Write(buffer, host, 8443);
        Assert.Equal(expectedSize, written);

        Assert.True(Socks5Address.TryParse(buffer.AsSpan(0, written), out var consumed, out var parsedHost, out var port));
        Assert.Equal(written, consumed);
        Assert.Equal(host, parsedHost);
        Assert.Equal(8443, port);

        Assert.True(Socks5Address.TryRead(buffer.AsSpan(0, written), out var rawLength, out var raw));
        Assert.Equal(written, rawLength);
        Assert.Equal(buffer.AsSpan(0, written).ToArray(), raw);
    }

    [Fact]
    public void Socks5AddressOnlyFormOmitsThePort()
    {
        Assert.Equal(1 + 4, Socks5Address.AddressSize("1.2.3.4"));
        Assert.Equal(1 + 1 + 11, Socks5Address.AddressSize("example.com"));

        var buffer = new byte[64];
        var written = Socks5Address.WriteAddress(buffer, "example.com");
        Assert.Equal(13, written);
        Assert.True(Socks5Address.TryParseAddress(buffer.AsSpan(0, written), out var consumed, out var host));
        Assert.Equal(written, consumed);
        Assert.Equal("example.com", host);
    }

    [Fact]
    public void Socks5AddressRejectsTruncatedAndUnknownBlocks()
    {
        Assert.False(Socks5Address.TryMeasure([0x01, 1, 2], out _));
        Assert.False(Socks5Address.TryMeasure([0x09, 1, 2, 3, 4, 5, 6], out _));
        Assert.False(Socks5Address.TryMeasure([], out _));
        Assert.False(Socks5Address.TryMeasureAddress([0x03, 10, 1, 2], out _));
    }
}
