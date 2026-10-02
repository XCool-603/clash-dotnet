using System.Text;
using Clash.Core.Common;
using Clash.Core.Crypto;
using Xunit;

namespace Clash.Tests.Crypto;

/// <summary>Master-key derivation, AEAD framing and the Shadowsocks 2022 helpers.</summary>
public class ShadowsocksCryptoTests
{
    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    private static byte[] Sequence(int length, byte start = 1)
    {
        var result = new byte[length];
        for (var i = 0; i < length; i++) result[i] = (byte)(start + i);
        return result;
    }

    // ---- EVP_BytesToKey ---------------------------------------------------------

    [Fact]
    public void DeriveMasterKeyMatchesEvpBytesToKey()
    {
        // Values produced independently with MD5 over the OpenSSL construction
        // (verified against Node's crypto and .NET's MD5).
        Assert.Equal("098f6bcd4621d373cade4e832627b4f6", Hex(ShadowsocksKey.DeriveMasterKey("test", 16)));
        Assert.Equal(
            "098f6bcd4621d373cade4e832627b4f60a9172716ae6428409885b8b829ccb05",
            Hex(ShadowsocksKey.DeriveMasterKey("test", 32)));
        Assert.Equal("e10adc3949ba59abbe56e057f20f883e", Hex(ShadowsocksKey.DeriveMasterKey("123456", 16)));
    }

    [Fact]
    public void DeriveMasterKeyHandlesSizesLargerThanOneDigest()
    {
        var key = ShadowsocksKey.DeriveMasterKey("test", 48);
        Assert.Equal(48, key.Length);
        Assert.Equal(ShadowsocksKey.DeriveMasterKey("test", 16), key.AsSpan(0, 16).ToArray());
        Assert.Equal(ShadowsocksKey.DeriveMasterKey("test", 32), key.AsSpan(0, 32).ToArray());
    }

    [Fact]
    public void DeriveMasterKeyRejectsImpossibleSizes()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ShadowsocksKey.DeriveMasterKey("test", 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => ShadowsocksKey.DeriveMasterKey("test", -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => ShadowsocksKey.DeriveMasterKey("test", 65));
    }

    [Fact]
    public void HkdfInfoIsTheSpecificationString()
    {
        Assert.Equal("ss-subkey", Encoding.ASCII.GetString(ShadowsocksKey.HkdfInfo));
    }

    // ---- chunk framing ----------------------------------------------------------

    [Fact]
    public void FramedSizeMatchesTheSpecificationLayout()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");

        // [encrypted length (2)][length tag (16)][payload][payload tag (16)]
        Assert.Equal(18, ShadowsocksAeadFraming.EncryptedLengthSize(cipher));
        Assert.Equal(18 + 5 + 16, ShadowsocksAeadFraming.FramedSize(cipher, 5));
        Assert.Equal(18 + 0 + 16, ShadowsocksAeadFraming.FramedSize(cipher, 0));
        Assert.Equal(0x3FFF, ShadowsocksAeadFraming.MaxChunkSize);
        Assert.Throws<ArgumentOutOfRangeException>(() => ShadowsocksAeadFraming.FramedSize(cipher, 0x4000));
    }

    [Fact]
    public void NonceIsALittleEndianCounter()
    {
        Span<byte> nonce = stackalloc byte[ShadowsocksAeadFraming.NonceSize];
        ShadowsocksAeadFraming.WriteNonce(nonce, 1);
        Assert.Equal("010000000000000000000000", Hex(nonce));

        ShadowsocksAeadFraming.WriteNonce(nonce, 0x0102);
        Assert.Equal("020100000000000000000000", Hex(nonce));
    }

    [Fact]
    public void ChunkCodecRoundTripsThroughTheFramingApi()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var master = ShadowsocksKey.DeriveMasterKey("test", cipher.KeySize);
        var salt = Sequence(cipher.SaltSize, 0);
        var subkey = cipher.DeriveSubkey(master, salt);

        long writerCounter = 0;
        var payload = Sequence(300, 5);
        var framed = new byte[ShadowsocksAeadFraming.FramedSize(cipher, payload.Length)];
        var written = ShadowsocksAeadFraming.WriteChunk(cipher, subkey, ref writerCounter, payload, framed);
        Assert.Equal(framed.Length, written);
        Assert.Equal(2, writerCounter);

        long readerCounter = 0;
        Assert.True(ShadowsocksAeadFraming.TryReadLength(cipher, subkey, ref readerCounter, framed, out var length));
        Assert.Equal(payload.Length, length);

        var recovered = new byte[length];
        Assert.True(ShadowsocksAeadFraming.TryReadPayload(cipher, subkey, ref readerCounter, framed.AsSpan(18), length, recovered));
        Assert.Equal(payload, recovered);
        Assert.Equal(2, readerCounter);
    }

    [Fact]
    public void TamperedLengthIsRejected()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var subkey = Sequence(cipher.KeySize, 3);
        long counter = 0;
        var framed = new byte[ShadowsocksAeadFraming.FramedSize(cipher, 4)];
        ShadowsocksAeadFraming.WriteChunk(cipher, subkey, ref counter, Sequence(4, 9), framed);

        framed[0] ^= 0x01;
        long readerCounter = 0;
        Assert.False(ShadowsocksAeadFraming.TryReadLength(cipher, subkey, ref readerCounter, framed, out _));
    }

    // ---- writer / reader --------------------------------------------------------

    public static TheoryData<int> PayloadSizes()
    {
        var data = new TheoryData<int>();
        foreach (var size in new[] { 0, 1, 15, 16, 1000, 0x3FFE, 0x3FFF, 0x4000, 0x4001, 100_000, 300_000 }) data.Add(size);
        return data;
    }

    [Theory]
    [MemberData(nameof(PayloadSizes))]
    public void AeadWriterReaderRoundTrip(int size)
    {
        var cipher = AeadCiphers.Get("chacha20-ietf-poly1305");
        var master = ShadowsocksKey.DeriveMasterKey("hunter2", cipher.KeySize);
        var payload = Sequence(size, 17);

        using var wire = new MemoryStream();
        var writer = new ShadowsocksAeadWriter(wire, cipher, master);
        writer.Write(payload);

        // An empty write is a deliberate no-op (see EmptyWriteIsANoOpAndDoesNotEmitTheSalt),
        // so the salt only goes out once there is a byte to carry.
        Assert.Equal(size > 0, writer.SaltWritten);

        wire.Position = 0;
        var reader = new ShadowsocksAeadReader(wire, cipher, master);
        var recovered = new byte[size];
        var read = 0;
        while (read < size)
        {
            var n = reader.Read(recovered.AsSpan(read));
            Assert.True(n > 0, "reader stopped before the payload was complete");
            read += n;
        }

        Assert.Equal(payload, recovered);
    }

    [Fact]
    public void WriterEmitsTheSaltOnlyOnceAndBeforeAnyChunk()
    {
        var cipher = AeadCiphers.Get("aes-128-gcm");
        var master = ShadowsocksKey.DeriveMasterKey("pw", cipher.KeySize);

        using var wire = new MemoryStream();
        var writer = new ShadowsocksAeadWriter(wire, cipher, master);
        writer.Write(Encoding.ASCII.GetBytes("abc"));
        var afterFirst = wire.Length;
        writer.Write(Encoding.ASCII.GetBytes("def"));
        var afterSecond = wire.Length;

        Assert.Equal(cipher.SaltSize + ShadowsocksAeadFraming.FramedSize(cipher, 3), afterFirst);
        Assert.Equal(afterFirst + ShadowsocksAeadFraming.FramedSize(cipher, 3), afterSecond);
    }

    [Fact]
    public void WriterSplitsPayloadsLargerThanTheChunkLimit()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var master = ShadowsocksKey.DeriveMasterKey("pw", cipher.KeySize);

        using var wire = new MemoryStream();
        var writer = new ShadowsocksAeadWriter(wire, cipher, master);
        writer.Write(new byte[ShadowsocksAeadFraming.MaxChunkSize * 2 + 10]);

        Assert.Equal(3, writer.ChunkCount);
        Assert.Equal(
            cipher.SaltSize
            + ShadowsocksAeadFraming.FramedSize(cipher, ShadowsocksAeadFraming.MaxChunkSize) * 2
            + ShadowsocksAeadFraming.FramedSize(cipher, 10),
            wire.Length);
    }

    [Fact]
    public void WriterAcceptsAnExplicitSalt()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var master = ShadowsocksKey.DeriveMasterKey("pw", cipher.KeySize);
        var salt = Sequence(cipher.SaltSize, 200);

        using var wire = new MemoryStream();
        var writer = new ShadowsocksAeadWriter(wire, cipher, master, salt);
        writer.Write(Encoding.ASCII.GetBytes("payload"));

        wire.Position = 0;
        var actualSalt = new byte[cipher.SaltSize];
        Assert.Equal(cipher.SaltSize, wire.Read(actualSalt));
        Assert.Equal(salt, actualSalt);
    }

    [Fact]
    public void EmptyWriteIsANoOpAndDoesNotEmitTheSalt()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var master = ShadowsocksKey.DeriveMasterKey("pw", cipher.KeySize);

        using var wire = new MemoryStream();
        var writer = new ShadowsocksAeadWriter(wire, cipher, master);
        writer.Write(ReadOnlySpan<byte>.Empty);

        Assert.Equal(0, wire.Length);
        Assert.False(writer.SaltWritten);
    }

    [Fact]
    public void ReaderSkipsZeroLengthChunks()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var master = ShadowsocksKey.DeriveMasterKey("test", cipher.KeySize);
        var salt = Sequence(cipher.SaltSize, 0);
        var subkey = cipher.DeriveSubkey(master, salt);

        using var wire = new MemoryStream();
        wire.Write(salt);

        long counter = 0;
        var scratch = new byte[ShadowsocksAeadFraming.FramedSize(cipher, 5)];
        var emptyFrame = new byte[ShadowsocksAeadFraming.FramedSize(cipher, 0)];
        var n = ShadowsocksAeadFraming.WriteChunk(cipher, subkey, ref counter, ReadOnlySpan<byte>.Empty, emptyFrame);
        wire.Write(emptyFrame, 0, n);

        n = ShadowsocksAeadFraming.WriteChunk(cipher, subkey, ref counter, "hello"u8, scratch);
        wire.Write(scratch, 0, n);

        wire.Position = 0;
        var reader = new ShadowsocksAeadReader(wire, cipher, master);
        var output = new byte[16];
        var read = reader.Read(output);

        Assert.Equal(5, read);
        Assert.Equal("hello", Encoding.ASCII.GetString(output, 0, 5));
        Assert.Equal(2, reader.ChunkCount);
    }

    [Fact]
    public void ReaderRejectsATamperedChunk()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var master = ShadowsocksKey.DeriveMasterKey("test", cipher.KeySize);

        using var wire = new MemoryStream();
        var writer = new ShadowsocksAeadWriter(wire, cipher, master);
        writer.Write(Encoding.ASCII.GetBytes("attack at dawn"));

        var bytes = wire.ToArray();
        bytes[^1] ^= 0x01;

        using var tampered = new MemoryStream(bytes);
        var reader = new ShadowsocksAeadReader(tampered, cipher, master);
        Assert.Throws<ClashException>(() => reader.Read(new byte[64]));
    }

    [Fact]
    public async Task AsyncRoundTripMatchesTheSyncPath()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var master = ShadowsocksKey.DeriveMasterKey("async", cipher.KeySize);
        var payload = Sequence(70_000, 4);

        using var wire = new MemoryStream();
        var writer = new ShadowsocksAeadWriter(wire, cipher, master);
        await writer.WriteAsync(payload);
        await writer.FlushAsync();

        wire.Position = 0;
        var reader = new ShadowsocksAeadReader(wire, cipher, master);
        var recovered = new byte[payload.Length];
        var read = 0;
        while (read < payload.Length)
        {
            var n = await reader.ReadAsync(recovered.AsMemory(read));
            Assert.True(n > 0);
            read += n;
        }

        Assert.Equal(payload, recovered);
    }

    // ---- Shadowsocks 2022 -------------------------------------------------------

    [Fact]
    public void SessionSubkeyIsDeterministicAndKeySized()
    {
        var sessionKey = Sequence(32, 1);
        var salt = Sequence(8, 90);

        var first = Shadowsocks2022.DeriveSessionSubkey(sessionKey, salt, 32);
        var second = Shadowsocks2022.DeriveSessionSubkey(sessionKey, salt, 32);
        Assert.Equal(first, second);
        Assert.Equal(32, first.Length);

        var shorter = Shadowsocks2022.DeriveSessionSubkey(sessionKey, salt, 16);
        Assert.Equal(first.AsSpan(0, 16).ToArray(), shorter);

        Assert.NotEqual(first, Shadowsocks2022.DeriveSessionSubkey(sessionKey, Sequence(8, 91), 32));
    }

    [Fact]
    public void UdpSessionHeaderIsSixteenBytes()
    {
        var buffer = new byte[Shadowsocks2022.UdpHeaderSize];
        Shadowsocks2022.WriteUdpHeader(buffer, 0x0102030405060708UL, 0x1112131415161718UL);
        Assert.Equal("08070605040302011817161514131211", Hex(buffer));

        Assert.True(Shadowsocks2022.TryReadUdpHeader(buffer, out var sessionId, out var packetId));
        Assert.Equal(0x0102030405060708UL, sessionId);
        Assert.Equal(0x1112131415161718UL, packetId);

        Assert.False(Shadowsocks2022.TryReadUdpHeader(buffer.AsSpan(0, 15), out _, out _));
    }

    [Fact]
    public void UdpNonceIsTheLittleEndianPacketIdFollowedByZeroes()
    {
        var nonce = new byte[Shadowsocks2022.NonceSize];
        Shadowsocks2022.BuildUdpNonce(nonce, 0x0102030405060708UL);
        Assert.Equal("080706050403020100000000", Hex(nonce));
    }

    [Fact]
    public void UdpBodyHeaderRoundTrips()
    {
        var buffer = new byte[Shadowsocks2022.UdpBodyHeaderSize];
        Shadowsocks2022.WriteUdpBodyHeader(buffer, Shadowsocks2022PacketType.ClientPacket, 1_700_000_000, 7);

        Assert.True(Shadowsocks2022.TryReadUdpBodyHeader(buffer, out var type, out var timestamp, out var padding));
        Assert.Equal(Shadowsocks2022PacketType.ClientPacket, type);
        Assert.Equal(1_700_000_000, timestamp);
        Assert.Equal(7, padding);
    }

    [Fact]
    public void UdpSessionRoundTripsAddressAndPayload()
    {
        var cipher = AeadCiphers.Get("2022-blake3-aes-256-gcm");
        var sessionKey = Sequence(32, 1);
        var session = new Shadowsocks2022UdpSession(cipher, sessionKey, sessionId: 0xDEADBEEF);

        var address = new byte[Socks5Address.Size("example.com")];
        var addressLength = Socks5Address.Write(address, "example.com", 443);

        var payload = Encoding.ASCII.GetBytes("dns query bytes");
        var packet = session.Encode(Shadowsocks2022PacketType.ClientPacket, address.AsSpan(0, addressLength), payload);

        Assert.Equal(Shadowsocks2022.UdpHeaderSize, packet.Length - Shadowsocks2022.UdpBodyHeaderSize - addressLength - payload.Length - cipher.TagSize);

        Assert.True(session.TryDecode(packet, out var type, out var timestamp, out var decodedAddress, out var decodedPayload));
        Assert.Equal(Shadowsocks2022PacketType.ClientPacket, type);
        Assert.Equal(address.AsSpan(0, addressLength).ToArray(), decodedAddress);
        Assert.Equal(payload, decodedPayload);
        Assert.True(Math.Abs(timestamp - Shadowsocks2022.NowUnixSeconds()) < 60);
        Assert.Equal(1UL, session.NextPacketId);
    }

    [Fact]
    public void UdpSessionRejectsAnotherSessionAndTamperedPackets()
    {
        var cipher = AeadCiphers.Get("2022-blake3-chacha20-poly1305");
        var sessionKey = Sequence(32, 1);
        var session = new Shadowsocks2022UdpSession(cipher, sessionKey, sessionId: 7);
        var other = new Shadowsocks2022UdpSession(cipher, sessionKey, sessionId: 8);

        var packet = session.Encode(Shadowsocks2022PacketType.ServerPacket, [], "x"u8);

        Assert.False(other.TryDecode(packet, out _, out _, out _, out _));

        packet[^1] ^= 0x01;
        Assert.False(session.TryDecode(packet, out _, out _, out _, out _));
    }

    // ---- simple-obfs ------------------------------------------------------------

    [Fact]
    public void HttpSimpleRequestRoundTripsTheEmbeddedPayload()
    {
        var firstPayload = Sequence(200, 0x41);
        var buffer = new byte[1024];
        var written = ShadowsocksObfs.BuildHttpSimpleRequest(buffer, "example.com", 443, firstPayload, seed: 1234);
        var request = buffer.AsSpan(0, written).ToArray();

        Assert.StartsWith("GET /", Encoding.ASCII.GetString(request));
        Assert.Contains("Host: example.com:443", Encoding.ASCII.GetString(request));

        Assert.True(ShadowsocksObfs.TryParseHttpSimpleRequest(request, out var headerLength, out var host, out var embedded));
        Assert.Equal("example.com:443", host);
        Assert.True(headerLength > 0);
        Assert.Equal(firstPayload.AsSpan(0, ShadowsocksObfs.MaxPathPayload).ToArray(), embedded);
    }

    [Fact]
    public void HttpSimpleRequestWithoutPayloadProducesABareGet()
    {
        var buffer = new byte[512];
        var written = ShadowsocksObfs.BuildHttpSimpleRequest(buffer, "1.2.3.4", 80, ReadOnlySpan<byte>.Empty, seed: 7);
        var text = Encoding.ASCII.GetString(buffer, 0, written);
        Assert.StartsWith("GET / HTTP/1.1\r\n", text);
        Assert.Contains("Host: 1.2.3.4:80", text);
    }

    [Fact]
    public void Tls12TicketAuthClientHelloIsAMeasurableRecord()
    {
        var buffer = new byte[2048];
        var payload = Encoding.ASCII.GetBytes("early data");
        var written = ShadowsocksObfs.BuildTls12TicketAuthClientHello(buffer, "example.org", payload, seed: 99);

        Assert.Equal(0x16, buffer[0]);
        Assert.Equal(0x03, buffer[1]);
        Assert.Equal(0x01, buffer[2]);
        Assert.Equal(0x01, buffer[5]);

        Assert.True(ShadowsocksObfs.TryMeasureTlsRecord(buffer, out var recordLength));
        Assert.Equal(written - payload.Length, recordLength);
        Assert.Equal(payload, buffer.AsSpan(recordLength, payload.Length).ToArray());

        Assert.Contains("example.org", Encoding.ASCII.GetString(buffer, 0, recordLength));
    }

    [Fact]
    public void Tls12TicketAuthServerHelloIsAlsoAMeasurableRecord()
    {
        var buffer = new byte[1024];
        var written = ShadowsocksObfs.BuildTls12TicketAuthServerHello(buffer, [], seed: 5);
        Assert.True(written > 0);
        Assert.True(ShadowsocksObfs.TryMeasureTlsRecord(buffer, out var recordLength));
        Assert.True(recordLength < written, "the ChangeCipherSpec record should follow the ServerHello");
    }

    [Fact]
    public void ObfsSupportIsReportedHonestly()
    {
        Assert.True(ShadowsocksObfs.IsSupported("http_simple"));
        Assert.True(ShadowsocksObfs.IsSupported("TLS1.2_TICKET_AUTH"));
        Assert.False(ShadowsocksObfs.IsSupported("http_post"));
        Assert.False(ShadowsocksObfs.IsSupported("nonexistent"));
    }
}
