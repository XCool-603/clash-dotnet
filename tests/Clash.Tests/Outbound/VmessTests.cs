using System.Buffers.Binary;
using System.IO.Hashing;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Clash.Core.Proxies.Outbound;
using Xunit;

namespace Clash.Tests.Outbound;

/// <summary>
/// VMess AEAD coverage. The fake server below is written from the protocol
/// reference rather than from the adapter: it derives every key itself with its own
/// transcription of the sing-vmess KDF, opens the AuthID with AES-ECB, unseals the
/// request header with the AuthID as associated data, parses the header body the
/// way mihomo's <c>sendRequest</c> lays it out and unframes the chunks the way
/// mihomo's <c>aeadReader</c> does. Nothing in it calls the adapter's own reader,
/// so a mismatch shows up as a failing assertion rather than as two bugs agreeing.
/// </summary>
public class VmessTests
{
    private static readonly byte[] Uuid = Convert.FromHexString("6ba7b8109dad11d180b400c04fd430c8");
    private const string UuidText = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

    // mihomo transport/vmess/vmess.go
    private const byte Version = 1;
    private const byte OptionChunkStream = 1;
    private const byte CommandTcp = 1;
    private const byte CommandUdp = 2;
    private const byte AtypIpv4 = 1;
    private const byte AtypDomain = 2;
    private const byte AtypIpv6 = 3;
    private const int ReferenceChunkSize = 1 << 14;
    private const int ReferenceMaxSize = 17 * 1024;

    private const string KeyMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

    /// <summary>A configuration entry pointing at the fake server on loopback.</summary>
    private static ProxyConfigEntry Entry(int port, params (string Key, object? Value)[] extra)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = "vmess-node",
            ["type"] = "vmess",
            ["server"] = "127.0.0.1",
            ["port"] = port,
            ["uuid"] = UuidText,
            ["alterId"] = 0,
        };

        foreach (var (key, value) in extra) map[key] = value;
        return new ProxyConfigEntry(new YamlMap(map));
    }

    // ── round trip ───────────────────────────────────────────────────────────

    [Fact]
    public async Task AeadTcpCarriesThePayloadInBothDirections()
    {
        var payload = new byte[40000]; // more than two reference chunks
        Random.Shared.NextBytes(payload);
        var reply = Encoding.ASCII.GetBytes("vmess says hello");

        FakeVmessServer? seen = null;
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var session = new FakeVmessServer(stream);
            seen = session;
            await session.ReadRequestAsync(payload.Length, ct);
            await session.WriteResponseAsync(reply, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(Entry(server.Port));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        await outbound.WriteAsync(payload);
        var echoed = new byte[reply.Length];
        await outbound.ReadExactlyAsync(echoed);

        Assert.Equal(reply, echoed);
        await outbound.DisposeAsync();
        await server.WaitAsync();

        Assert.Equal(payload, seen!.Payload);
    }

    // ── wire framing ─────────────────────────────────────────────────────────

    [Fact]
    public async Task AeadTcpWritesTheReferenceHeaderAndChunkFraming()
    {
        var payload = new byte[5000];
        Random.Shared.NextBytes(payload);

        FakeVmessServer? seen = null;
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var session = new FakeVmessServer(stream);
            seen = session;
            await session.ReadRequestAsync(payload.Length, ct);
            await session.WriteResponseAsync(new byte[] { 0x2A }, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(Entry(server.Port));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443));
        await outbound.WriteAsync(payload);
        var single = new byte[1];
        await outbound.ReadExactlyAsync(single);
        Assert.Equal(0x2A, single[0]);
        await outbound.DisposeAsync();
        await server.WaitAsync();

        var wire = seen!;

        // 1. The AuthID is a 16-byte AES-ECB seal of timestamp || random || crc32,
        //    and the server had to derive the command key to open it at all.
        Assert.Equal(16, wire.SealedAuthId.Length);
        Assert.NotEqual(wire.AuthIdPlaintext, wire.SealedAuthId);
        Assert.True(wire.AuthIdCrcValid);

        // 2. The header body was sealed with the AuthID as associated data: the
        //    server's own derivation opened it, and the frame is longer than the body.
        Assert.True(wire.HeaderBody.Length > 0);
        Assert.Equal(wire.HeaderBody.Length + 16, wire.SealedHeaderBody.Length);

        // 3. The header body is laid out the way the reference writes it.
        Assert.Equal(Version, wire.HeaderVersion);
        Assert.Equal(16, wire.RequestBodyIv.Length);
        Assert.Equal(16, wire.RequestBodyKey.Length);
        Assert.InRange(wire.ResponseHeaderByte, 1, 255);
        Assert.Equal(OptionChunkStream, wire.Option);
        Assert.Equal(0x00, wire.Reserved);
        Assert.Equal(CommandTcp, wire.Command);
        Assert.InRange(wire.PaddingLength, 0, 15);
        Assert.Equal(VmessSecurity.Aes128Gcm, wire.Security);

        // 4. The port precedes the address type, and the checksum covers every byte
        //    before it — padding included.
        Assert.Equal(wire.PortOffset + 2, wire.AddressTypeOffset);
        Assert.Equal(wire.HeaderBody.Length, wire.ChecksumOffset + 4);
        Assert.Equal(Fnv1a32(wire.HeaderBody.AsSpan(0, wire.ChecksumOffset)), wire.Checksum);

        // 5. The body is the reference chunk stream: a plaintext big-endian length
        //    that counts the payload plus the 16-byte tag, then the sealed payload.
        Assert.Equal(payload.Length + 16, wire.ChunkLengths[0]);
        Assert.Equal(new ushort[] { 0 }, wire.ChunkCounters);
        Assert.Equal(payload, wire.Payload);

        // 6. Those chunks really are authenticated: a wrong body key does not open them.
        Assert.False(wire.TryOpenFirstChunkWithWrongKey());
    }

    [Fact]
    public async Task AeadTcpAdvancesTheChunkNonceOncePerChunk()
    {
        var payload = new byte[40000];
        Random.Shared.NextBytes(payload);

        FakeVmessServer? seen = null;
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var session = new FakeVmessServer(stream);
            seen = session;
            await session.ReadRequestAsync(payload.Length, ct);
            await session.WriteResponseAsync(new byte[] { 0x2A }, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(Entry(server.Port));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("1.2.3.4", 8080));
        await outbound.WriteAsync(payload);
        var single = new byte[1];
        await outbound.ReadExactlyAsync(single);
        Assert.Equal(0x2A, single[0]);
        await outbound.DisposeAsync();
        await server.WaitAsync();

        var wire = seen!;

        // 40000 bytes at the reference chunk size of 16384 (minus the 16-byte tag)
        // is three chunks of 16368, 16368 and 7264 bytes.
        Assert.Equal(3, wire.ChunkLengths.Count);
        Assert.Equal(new ushort[] { 0, 1, 2 }, wire.ChunkCounters);
        Assert.Equal(new int[] { 16368 + 16, 16368 + 16, 7264 + 16 }, wire.ChunkLengths);
        Assert.Equal(payload, wire.Payload);
    }

    // ── destination ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData("example.com", 443, AtypDomain)]
    [InlineData("1.2.3.4", 8080, AtypIpv4)]
    [InlineData("2001:db8::1", 8443, AtypIpv6)]
    public async Task AeadTcpCarriesTheDestinationInTheSealedHeader(string host, int port, byte expectedType)
    {
        FakeVmessServer? seen = null;
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var session = new FakeVmessServer(stream);
            seen = session;
            await session.ReadRequestAsync(3, ct);
            await session.WriteResponseAsync(new byte[] { 0x01 }, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(Entry(server.Port));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow(host, port));
        await outbound.WriteAsync(new byte[] { 1, 2, 3 });
        var single = new byte[1];
        await outbound.ReadExactlyAsync(single);
        await outbound.DisposeAsync();
        await server.WaitAsync();

        var wire = seen!;
        Assert.Equal(expectedType, wire.AddressType);
        Assert.Equal(host, wire.Host);
        Assert.Equal(port, wire.Port);
    }

    // ── other body ciphers ───────────────────────────────────────────────────

    [Fact]
    public async Task ChaChaBodyCipherRoundTrips()
    {
        var payload = Encoding.ASCII.GetBytes("chacha framed payload");
        var reply = Encoding.ASCII.GetBytes("chacha reply");

        FakeVmessServer? seen = null;
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var session = new FakeVmessServer(stream);
            seen = session;
            await session.ReadRequestAsync(payload.Length, ct);
            await session.WriteResponseAsync(reply, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(Entry(server.Port, ("cipher", "chacha20-poly1305")));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443));

        await outbound.WriteAsync(payload);
        var echoed = new byte[reply.Length];
        await outbound.ReadExactlyAsync(echoed);

        Assert.Equal(reply, echoed);
        await outbound.DisposeAsync();
        await server.WaitAsync();

        Assert.Equal(VmessSecurity.ChaCha20Poly1305, seen!.Security);
        Assert.Equal(16, seen.RequestBodyKey.Length);
        Assert.Equal(payload, seen.Payload);
    }

    [Fact]
    public async Task NoneBodyCipherUsesThePlainChunkStream()
    {
        var payload = Encoding.ASCII.GetBytes("unframed payload");
        var reply = Encoding.ASCII.GetBytes("unframed reply");

        FakeVmessServer? seen = null;
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var session = new FakeVmessServer(stream);
            seen = session;
            await session.ReadRequestAsync(payload.Length, ct);
            await session.WriteResponseAsync(reply, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(Entry(server.Port, ("cipher", "none")));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        await outbound.WriteAsync(payload);
        var echoed = new byte[reply.Length];
        await outbound.ReadExactlyAsync(echoed);

        Assert.Equal(reply, echoed);
        await outbound.DisposeAsync();
        await server.WaitAsync();

        Assert.Equal(VmessSecurity.None, seen!.Security);

        // Without a cipher the length counts the payload alone and the bytes follow
        // in the clear, which is mihomo's chunkWriter.
        Assert.Equal(payload.Length, seen.ChunkLengths[0]);
        Assert.Equal(payload, seen.Payload);
    }

    // ── UDP over the same TCP connection ─────────────────────────────────────

    /// <summary>
    /// Offset of the command byte in the header body, from the layout documented on
    /// <c>VmessRequestHeader</c>: version(1) || IV(16) || key(16) || responseHeader(1)
    /// || option(1) || padding/security(1) || reserved(1) || command(1).
    /// </summary>
    private const int CommandOffset = 1 + 16 + 16 + 1 + 1 + 1 + 1;

    /// <summary>Writes a header body with the reference layout and returns it.</summary>
    private static byte[] WriteHeaderBody(byte command)
    {
        var body = new byte[VmessRequestHeader.BodySize("example.com", 0)];
        var written = VmessRequestHeader.WriteBody(
            body,
            new byte[VmessRequestHeader.RequestBodyIvSize],
            new byte[VmessRequestHeader.RequestBodyKeySize],
            responseHeader: 0x5A,
            command,
            VmessSecurity.Aes128Gcm,
            "example.com",
            443,
            []);

        Assert.Equal(body.Length, written);
        return body;
    }

    [Fact]
    public void TheUdpRequestHeaderCarriesCommand0x02AtTheDocumentedOffset()
    {
        var body = WriteHeaderBody(VmessRequestHeader.CommandUdp);

        // The byte itself, the adapter's own constant and the reference's.
        Assert.Equal(0x02, body[CommandOffset]);
        Assert.Equal(VmessRequestHeader.CommandUdp, body[CommandOffset]);
        Assert.Equal(CommandUdp, body[CommandOffset]);

        // The bytes around it, so a shift in the layout could not pass unnoticed.
        Assert.Equal(Version, body[0]);
        Assert.Equal(0x5A, body[CommandOffset - 4]);
        Assert.Equal(OptionChunkStream, body[CommandOffset - 3]);
        Assert.Equal((byte)VmessSecurity.Aes128Gcm, body[CommandOffset - 2]);
        Assert.Equal(0x00, body[CommandOffset - 1]);
    }

    [Fact]
    public void TheTcpRequestHeaderStillCarriesCommand0x01AtTheDocumentedOffset()
    {
        var body = WriteHeaderBody(VmessRequestHeader.CommandTcp);

        Assert.Equal(0x01, body[CommandOffset]);
        Assert.Equal(VmessRequestHeader.CommandTcp, body[CommandOffset]);
        Assert.Equal(CommandTcp, body[CommandOffset]);
    }

    [Fact]
    public void SupportUdpFollowsTheConfiguredUdpFlag()
    {
        Assert.False(OutboundHarness.Build(Entry(443)).SupportUdp);
        Assert.True(OutboundHarness.Build(Entry(443, ("udp", true))).SupportUdp);
    }

    [Theory]
    [InlineData(false)] // udp omitted entirely, which is the default
    [InlineData(true)]  // udp written out as false
    public async Task DialUdpRefusesWhenUdpIsNotEnabled(bool writeTheFlag)
    {
        var entry = writeTheFlag ? Entry(443, ("udp", false)) : Entry(443);
        var adapter = OutboundHarness.Build(entry);

        Assert.False(adapter.SupportUdp);

        var ex = await Assert.ThrowsAsync<NotSupportedException>(
            () => adapter.DialUdpAsync(OutboundHarness.UdpFlow("1.1.1.1", 53)));

        Assert.Equal("proxy [vmess-node] of type [Vmess] has UDP disabled in its configuration", ex.Message);
    }

    [Fact]
    public async Task AeadUdpCarriesOneDatagramPerChunk()
    {
        var datagram = Encoding.ASCII.GetBytes("vmess udp datagram");
        var reply = Encoding.ASCII.GetBytes("vmess udp reply");

        FakeVmessServer? seen = null;
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var session = new FakeVmessServer(stream);
            seen = session;
            await session.ReadRequestAsync(datagram.Length, ct);
            await session.WriteResponseAsync(reply, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(Entry(server.Port, ("udp", true)));
        await using var connection = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("1.1.1.1", 53));

        var destination = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);
        Assert.Equal(datagram.Length, await connection.SendAsync(datagram, destination));

        var buffer = new byte[65535];
        var received = await connection.ReceiveAsync(buffer);

        Assert.Equal(reply.Length, received.BytesRead);
        Assert.Equal(reply, buffer[..received.BytesRead].ToArray());
        Assert.Equal(destination, received.Remote);

        await connection.DisposeAsync();
        await server.WaitAsync();

        var wire = seen!;

        // The request header says UDP, and it names the destination the association
        // was dialled for.
        Assert.Equal(CommandUdp, wire.Command);
        Assert.Equal(AtypIpv4, wire.AddressType);
        Assert.Equal("1.1.1.1", wire.Host);
        Assert.Equal(53, wire.Port);

        // One SendAsync produced exactly one chunk whose plaintext length field
        // counts the payload plus the 16-byte AEAD tag, and that length field is the
        // two big-endian bytes the framing requires.
        Assert.Equal(datagram, wire.Payload);
        Assert.Single(wire.ChunkLengths);
        Assert.Equal(datagram.Length + 16, wire.ChunkLengths[0]);
        Assert.Equal(Uint16Bytes((ushort)(datagram.Length + 16)), wire.ChunkLengthPrefixes[0]);
        Assert.Equal(new ushort[] { 0 }, wire.ChunkCounters);
    }

    [Fact]
    public async Task AeadUdpKeepsDatagramBoundaries()
    {
        var first = Encoding.ASCII.GetBytes("first datagram");
        var second = Encoding.ASCII.GetBytes("second datagram, which is longer");
        var replies = new[]
        {
            Encoding.ASCII.GetBytes("reply one"),
            Encoding.ASCII.GetBytes("reply two, which is longer"),
        };

        FakeVmessServer? seen = null;
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var session = new FakeVmessServer(stream);
            seen = session;
            await session.ReadRequestAsync(first.Length + second.Length, ct);
            await session.WriteResponseDatagramsAsync(replies, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(Entry(server.Port, ("udp", true)));
        await using var connection = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("9.9.9.9", 5353));

        var destination = new IPEndPoint(IPAddress.Parse("9.9.9.9"), 5353);
        await connection.SendAsync(first, destination);
        await connection.SendAsync(second, destination);

        var buffer = new byte[65535];
        var one = await connection.ReceiveAsync(buffer);
        var onePayload = buffer[..one.BytesRead].ToArray();
        var two = await connection.ReceiveAsync(buffer);
        var twoPayload = buffer[..two.BytesRead].ToArray();

        Assert.Equal(replies[0], onePayload);
        Assert.Equal(replies[1], twoPayload);

        await connection.DisposeAsync();
        await server.WaitAsync();

        var wire = seen!;

        // Two datagrams in, two chunks out: the client must never merge them, and the
        // chunk nonce must advance once per datagram.
        Assert.Equal(2, wire.ChunkLengths.Count);
        Assert.Equal(new[] { first.Length + 16, second.Length + 16 }, wire.ChunkLengths);
        Assert.Equal(new ushort[] { 0, 1 }, wire.ChunkCounters);
        Assert.Equal([.. first, .. second], wire.Payload);
    }

    [Fact]
    public async Task AnOversizeDatagramIsRefusedRatherThanSplitInTwo()
    {
        await using var server = new FakeTcpServer((stream, ct) => OutboundHarness.DrainAsync(stream, ct));

        var adapter = OutboundHarness.Build(Entry(server.Port, ("udp", true)));
        await using var connection = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("1.1.1.1", 53));

        // One chunk is one datagram, so a datagram that does not fit one chunk
        // cannot be sent without inventing a boundary the peer cannot see.
        var oversized = new byte[VmessBody.MaxPayloadSize(VmessSecurity.Aes128Gcm) + 1];
        var destination = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);

        var ex = await Assert.ThrowsAsync<ClashException>(() => connection.SendAsync(oversized, destination).AsTask());
        Assert.Contains("does not fit", ex.Message);

        await connection.DisposeAsync();
        await server.WaitAsync();
    }

    // ── construction ─────────────────────────────────────────────────────────

    [Fact]
    public void VmessIsRegisteredAndReportsTheApiTypeName()
    {
        Assert.True(AdapterRegistry.IsKnown("vmess"));

        var adapter = OutboundHarness.Build(Entry(443));
        Assert.Equal("Vmess", adapter.TypeName);
        Assert.Equal(ProxyType.Vmess, adapter.Type);
        Assert.False(adapter.SupportUdp);
    }

    [Fact]
    public void AMissingUuidIsRejected()
    {
        var withoutUuid = new ProxyConfigEntry(new YamlMap(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = "no-uuid",
            ["type"] = "vmess",
            ["server"] = "127.0.0.1",
            ["port"] = 443,
        }));

        var ex = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(withoutUuid));
        Assert.Contains("uuid", ex.Message);
    }

    [Fact]
    public void AMalformedUuidIsRejected()
    {
        var entry = new ProxyConfigEntry(new YamlMap(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = "bad-uuid",
            ["type"] = "vmess",
            ["server"] = "127.0.0.1",
            ["port"] = 443,
            ["uuid"] = "not-a-uuid",
        }));

        var ex = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(entry));
        Assert.Contains("uuid", ex.Message);
    }

    [Theory]
    [InlineData("aes-256-gcm")]
    [InlineData("rc4-md5")]
    [InlineData("aes-128-cfb")]
    public void AnUnsupportedCipherIsRejected(string cipher)
    {
        var ex = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(Entry(443, ("cipher", cipher))));
        Assert.Contains(cipher, ex.Message);
    }

    [Fact]
    public void TheSecurityKeyIsAcceptedAsAnAliasForCipher()
    {
        var adapter = OutboundHarness.Build(Entry(443, ("security", "chacha20-poly1305")));
        Assert.Equal(ProxyType.Vmess, adapter.Type);
    }

    // ── reference helpers (transcribed from the Go sources, not from the adapter) ──

    /// <summary>sing-vmess <c>kdf.go</c>: a chain of nested HMAC-SHA256 instances.</summary>
    private static byte[] Kdf(byte[] key, params byte[][] path)
    {
        var elements = new List<byte[]> { Encoding.UTF8.GetBytes("VMess AEAD KDF") };
        elements.AddRange(path);
        return Level(elements, elements.Count - 1, key);
    }

    private static byte[] Level(List<byte[]> elements, int level, byte[] message)
    {
        if (level == 0) return HMACSHA256.HashData(elements[0], message);

        var padded = new byte[64];
        elements[level].CopyTo(padded, 0);

        var inner = new byte[64 + message.Length];
        for (var i = 0; i < 64; i++) inner[i] = (byte)(padded[i] ^ 0x36);
        message.CopyTo(inner, 64);

        var innerHash = Level(elements, level - 1, inner);

        var outer = new byte[64 + innerHash.Length];
        for (var i = 0; i < 64; i++) outer[i] = (byte)(padded[i] ^ 0x5c);
        innerHash.CopyTo(outer, 64);

        return Level(elements, level - 1, outer);
    }

    private static byte[] Kdf16(byte[] key, params byte[][] path) => Kdf(key, path)[..16];

    private static byte[] AesGcmSeal(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
    {
        var ciphertext = new byte[plaintext.Length + 16];
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, plaintext, ciphertext.AsSpan(0, plaintext.Length), ciphertext.AsSpan(plaintext.Length), associatedData);
        return ciphertext;
    }

    private static byte[] AesGcmOpen(byte[] key, byte[] nonce, byte[] ciphertext, byte[] associatedData)
    {
        var plaintext = new byte[ciphertext.Length - 16];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, ciphertext.AsSpan(0, ciphertext.Length - 16), ciphertext.AsSpan(ciphertext.Length - 16), plaintext, associatedData);
        return plaintext;
    }

    private static byte[] AesEcbDecrypt(byte[] key, byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        return aes.DecryptEcb(data, PaddingMode.None);
    }

    /// <summary>mihomo/v2ray's 16 -> 32 byte ChaCha20-Poly1305 key expansion.</summary>
    private static byte[] ChachaKey(byte[] bodyKey)
    {
        var key = new byte[32];
        var first = MD5.HashData(bodyKey);
        first.CopyTo(key, 0);
        MD5.HashData(first).CopyTo(key, 16);
        return key;
    }

    /// <summary>mihomo <c>aeadWriter</c>: nonce = BE16(counter) || iv[2..12], length = payload + tag.</summary>
    private static byte[] SealChunk(byte security, byte[] aeadKey, byte[] bodyIv, byte[] payload, ushort counter)
    {
        var nonce = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(nonce, counter);
        bodyIv.AsSpan(2, 10).CopyTo(nonce.AsSpan(2));

        byte[] sealedPayload;
        if (security == (byte)VmessSecurity.Aes128Gcm)
        {
            sealedPayload = AesGcmSeal(aeadKey, nonce, payload, []);
        }
        else
        {
            var chachaSealed = new byte[payload.Length + 16];
            using var chacha = new ChaCha20Poly1305(aeadKey);
            chacha.Encrypt(nonce, payload, chachaSealed.AsSpan(0, payload.Length), chachaSealed.AsSpan(payload.Length));
            sealedPayload = chachaSealed;
        }

        var framed = new byte[2 + sealedPayload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)sealedPayload.Length);
        sealedPayload.CopyTo(framed, 2);
        return framed;
    }

    /// <summary>The FNV-1a 32-bit hash the header checksum is defined as.</summary>
    private static uint Fnv1a32(ReadOnlySpan<byte> bytes)
    {
        unchecked
        {
            var hash = 2166136261u;
            foreach (var b in bytes)
            {
                hash ^= b;
                hash *= 16777619u;
            }

            return hash;
        }
    }

    private static byte[] Uint16Bytes(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    /// <summary>
    /// The server half of one VMess AEAD session, written from the reference: it
    /// derives its own keys, opens the AuthID, unseals the header and unframes the
    /// body, recording every field so a test can assert on the exact bytes.
    /// </summary>
    private sealed class FakeVmessServer
    {
        private readonly Stream _stream;
        private readonly byte[] _cmdKey;

        internal FakeVmessServer(Stream stream)
        {
            _stream = stream;
            _cmdKey = MD5.HashData([.. Uuid, .. Encoding.ASCII.GetBytes(KeyMagic)]);
        }

        internal byte[] SealedAuthId { get; private set; } = [];

        internal byte[] AuthIdPlaintext { get; private set; } = [];

        internal bool AuthIdCrcValid { get; private set; }

        internal byte[] ConnectionNonce { get; private set; } = [];

        internal byte[] SealedHeaderBody { get; private set; } = [];

        internal byte[] HeaderBody { get; private set; } = [];

        internal byte HeaderVersion { get; private set; }

        internal byte[] RequestBodyIv { get; private set; } = [];

        internal byte[] RequestBodyKey { get; private set; } = [];

        internal byte ResponseHeaderByte { get; private set; }

        internal byte Option { get; private set; }

        internal byte Reserved { get; private set; }

        internal byte Command { get; private set; }

        internal int PaddingLength { get; private set; }

        internal VmessSecurity Security { get; private set; }

        internal byte AddressType { get; private set; }

        internal string Host { get; private set; } = string.Empty;

        internal int Port { get; private set; }

        internal int PortOffset { get; private set; }

        internal int AddressTypeOffset { get; private set; }

        internal int ChecksumOffset { get; private set; }

        internal uint Checksum { get; private set; }

        internal ushort FirstChunkCounter { get; private set; }

        internal List<ushort> ChunkCounters { get; } = [];

        internal List<int> ChunkLengths { get; } = [];

        /// <summary>The raw two-byte length prefix of every chunk, as it arrived.</summary>
        internal List<byte[]> ChunkLengthPrefixes { get; } = [];

        internal byte[] FirstChunkFrame { get; private set; } = [];

        internal byte[] Payload { get; private set; } = [];

        /// <summary>Reads the handshake and <paramref name="expectedPayloadLength"/> bytes of body.</summary>
        internal async Task ReadRequestAsync(int expectedPayloadLength, CancellationToken cancellationToken)
        {
            // AuthID: AES-128-ECB under KDF16(cmdKey, "AES Auth ID Encryption").
            SealedAuthId = new byte[16];
            await _stream.ReadExactlyAsync(SealedAuthId, cancellationToken).ConfigureAwait(false);
            AuthIdPlaintext = AesEcbDecrypt(Kdf16(_cmdKey, Encoding.UTF8.GetBytes("AES Auth ID Encryption")), SealedAuthId);
            AuthIdCrcValid = Crc32.HashToUInt32(AuthIdPlaintext.AsSpan(0, 12))
                == BinaryPrimitives.ReadUInt32BigEndian(AuthIdPlaintext.AsSpan(12));

            // The sealed length comes next, then the connection nonce it was derived
            // with: authID | AEAD(length) | connectionNonce | AEAD(body).
            var lengthFrame = new byte[18];
            await _stream.ReadExactlyAsync(lengthFrame, cancellationToken).ConfigureAwait(false);

            ConnectionNonce = new byte[8];
            await _stream.ReadExactlyAsync(ConnectionNonce, cancellationToken).ConfigureAwait(false);

            var lengthKey = Kdf16(_cmdKey, Encoding.UTF8.GetBytes("VMess Header AEAD Key_Length"), SealedAuthId, ConnectionNonce);
            var lengthNonce = Kdf(_cmdKey, Encoding.UTF8.GetBytes("VMess Header AEAD Nonce_Length"), SealedAuthId, ConnectionNonce)[..12];
            var bodyLength = BinaryPrimitives.ReadUInt16BigEndian(AesGcmOpen(lengthKey, lengthNonce, lengthFrame, SealedAuthId));

            SealedHeaderBody = new byte[bodyLength + 16];
            await _stream.ReadExactlyAsync(SealedHeaderBody, cancellationToken).ConfigureAwait(false);

            var headerKey = Kdf16(_cmdKey, Encoding.UTF8.GetBytes("VMess Header AEAD Key"), SealedAuthId, ConnectionNonce);
            var headerNonce = Kdf(_cmdKey, Encoding.UTF8.GetBytes("VMess Header AEAD Nonce"), SealedAuthId, ConnectionNonce)[..12];
            HeaderBody = AesGcmOpen(headerKey, headerNonce, SealedHeaderBody, SealedAuthId);

            ParseHeaderBody();

            if (Security == VmessSecurity.None)
            {
                // mihomo's chunkReader: a plain big-endian length, then the bytes.
                var plain = new List<byte>(expectedPayloadLength);
                while (plain.Count < expectedPayloadLength)
                {
                    var plainLengthBytes = new byte[2];
                    await _stream.ReadExactlyAsync(plainLengthBytes, cancellationToken).ConfigureAwait(false);
                    var plainFramed = BinaryPrimitives.ReadUInt16BigEndian(plainLengthBytes);
                    Assert.InRange(plainFramed, 1, ReferenceMaxSize);

                    var plainFrame = new byte[plainFramed];
                    await _stream.ReadExactlyAsync(plainFrame, cancellationToken).ConfigureAwait(false);
                    ChunkLengths.Add(plainFramed);
                    ChunkLengthPrefixes.Add(plainLengthBytes);
                    plain.AddRange(plainFrame);
                }

                Payload = [.. plain];
                return;
            }

            var aeadKey = Security == VmessSecurity.ChaCha20Poly1305 ? ChachaKey(RequestBodyKey) : RequestBodyKey;
            var collected = new List<byte>(expectedPayloadLength);
            ushort counter = 0;

            while (collected.Count < expectedPayloadLength)
            {
                var lengthBytes = new byte[2];
                await _stream.ReadExactlyAsync(lengthBytes, cancellationToken).ConfigureAwait(false);
                var framed = BinaryPrimitives.ReadUInt16BigEndian(lengthBytes);
                Assert.InRange(framed, 1, ReferenceMaxSize);

                var frame = new byte[framed];
                await _stream.ReadExactlyAsync(frame, cancellationToken).ConfigureAwait(false);
                if (FirstChunkFrame.Length == 0)
                {
                    FirstChunkFrame = frame;
                    FirstChunkCounter = counter;
                }

                var nonce = new byte[12];
                BinaryPrimitives.WriteUInt16BigEndian(nonce, counter);
                RequestBodyIv.AsSpan(2, 10).CopyTo(nonce.AsSpan(2));

                var plaintext = new byte[framed - 16];
                if (Security == VmessSecurity.Aes128Gcm)
                {
                    using var gcm = new AesGcm(aeadKey, 16);
                    gcm.Decrypt(
                        nonce,
                        frame.AsSpan(0, framed - 16),
                        frame.AsSpan(framed - 16),
                        plaintext,
                        []);
                }
                else
                {
                    using var chacha = new ChaCha20Poly1305(aeadKey);
                    chacha.Decrypt(
                        nonce,
                        frame.AsSpan(0, framed - 16),
                        frame.AsSpan(framed - 16),
                        plaintext,
                        []);
                }

                ChunkCounters.Add(counter);
                ChunkLengths.Add(framed);
                ChunkLengthPrefixes.Add(lengthBytes);
                counter++;
                collected.AddRange(plaintext);
            }

            Payload = [.. collected];
        }

        /// <summary>Seals a response header echoing the client's byte, then frames <paramref name="payload"/>.</summary>
        internal async Task WriteResponseAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            await WriteResponseHeaderAsync(cancellationToken).ConfigureAwait(false);

            if (Security == VmessSecurity.None)
            {
                await WritePlainChunksAsync(payload, cancellationToken).ConfigureAwait(false);
                return;
            }

            var aeadKey = Security == VmessSecurity.ChaCha20Poly1305 ? ChachaKey(ResponseKey) : ResponseKey;
            var remaining = payload;
            ushort counter = 0;
            while (!remaining.IsEmpty)
            {
                var take = Math.Min(remaining.Length, ReferenceChunkSize - 16);
                var chunk = SealChunk((byte)Security, aeadKey, ResponseIv, remaining.Span[..take].ToArray(), counter);
                counter++;
                await _stream.WriteAsync(chunk, cancellationToken).ConfigureAwait(false);
                remaining = remaining[take..];
            }
        }

        /// <summary>
        /// Writes the response header once and then exactly one chunk per datagram,
        /// which is the shape a VMess UDP association answers with.
        /// </summary>
        internal async Task WriteResponseDatagramsAsync(IReadOnlyList<byte[]> datagrams, CancellationToken cancellationToken)
        {
            await WriteResponseHeaderAsync(cancellationToken).ConfigureAwait(false);

            ushort counter = 0;
            foreach (var datagram in datagrams)
            {
                if (Security == VmessSecurity.None)
                {
                    await _stream.WriteAsync(Uint16Bytes((ushort)datagram.Length), cancellationToken).ConfigureAwait(false);
                    await _stream.WriteAsync(datagram, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    var aeadKey = Security == VmessSecurity.ChaCha20Poly1305 ? ChachaKey(ResponseKey) : ResponseKey;
                    await _stream.WriteAsync(SealChunk((byte)Security, aeadKey, ResponseIv, datagram, counter), cancellationToken).ConfigureAwait(false);
                }

                counter++;
            }
        }

        /// <summary>Seals the response header, which precedes every body chunk of the response.</summary>
        internal async Task WriteResponseHeaderAsync(CancellationToken cancellationToken)
        {
            var lengthKey = Kdf16(ResponseKey, Encoding.UTF8.GetBytes("AEAD Resp Header Len Key"));
            var lengthNonce = Kdf(ResponseIv, Encoding.UTF8.GetBytes("AEAD Resp Header Len IV"))[..12];
            var headerKey = Kdf16(ResponseKey, Encoding.UTF8.GetBytes("AEAD Resp Header Key"));
            var headerNonce = Kdf(ResponseIv, Encoding.UTF8.GetBytes("AEAD Resp Header IV"))[..12];

            // [responseHeader][option][command][commandLength]
            var body = new byte[] { ResponseHeaderByte, 0, 0, 0 };

            await _stream.WriteAsync(AesGcmSeal(lengthKey, lengthNonce, Uint16Bytes((ushort)body.Length), []), cancellationToken).ConfigureAwait(false);
            await _stream.WriteAsync(AesGcmSeal(headerKey, headerNonce, body, []), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>The server's body key: the first 16 bytes of the SHA-256 of the request's.</summary>
        private byte[] ResponseKey => SHA256.HashData(RequestBodyKey)[..16];

        /// <inheritdoc cref="ResponseKey"/>
        private byte[] ResponseIv => SHA256.HashData(RequestBodyIv)[..16];

        private async Task WritePlainChunksAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            var remaining = payload;
            while (!remaining.IsEmpty)
            {
                var take = Math.Min(remaining.Length, ReferenceChunkSize);
                await _stream.WriteAsync(Uint16Bytes((ushort)take), cancellationToken).ConfigureAwait(false);
                await _stream.WriteAsync(remaining[..take], cancellationToken).ConfigureAwait(false);
                remaining = remaining[take..];
            }
        }

        /// <summary>Opens the first chunk with a deliberately wrong body key.</summary>
        internal bool TryOpenFirstChunkWithWrongKey()
        {
            if (FirstChunkFrame.Length < 16 || Security != VmessSecurity.Aes128Gcm) return false;

            var nonce = new byte[12];
            BinaryPrimitives.WriteUInt16BigEndian(nonce, FirstChunkCounter);
            RequestBodyIv.AsSpan(2, 10).CopyTo(nonce.AsSpan(2));

            var plaintext = new byte[FirstChunkFrame.Length - 16];
            try
            {
                using var gcm = new AesGcm(new byte[16], 16);
                gcm.Decrypt(
                    nonce,
                    FirstChunkFrame.AsSpan(0, FirstChunkFrame.Length - 16),
                    FirstChunkFrame.AsSpan(FirstChunkFrame.Length - 16),
                    plaintext,
                    []);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        /// <summary>Walks the header body exactly as the reference writes it.</summary>
        private void ParseHeaderBody()
        {
            var body = HeaderBody.AsSpan();
            var offset = 0;

            HeaderVersion = body[offset++];
            RequestBodyIv = body.Slice(offset, 16).ToArray();
            offset += 16;
            RequestBodyKey = body.Slice(offset, 16).ToArray();
            offset += 16;
            ResponseHeaderByte = body[offset++];
            Option = body[offset++];
            var paddingAndSecurity = body[offset++];
            PaddingLength = paddingAndSecurity >> 4;
            Security = (VmessSecurity)(paddingAndSecurity & 0x0F);
            Reserved = body[offset++];
            Command = body[offset++];

            // Port first, then the address block: mihomo's `// Port AddrType Addr`.
            PortOffset = offset;
            Port = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
            offset += 2;

            AddressTypeOffset = offset;
            AddressType = body[offset];
            offset += 1;
            switch (AddressType)
            {
                case AtypIpv4:
                    Host = new System.Net.IPAddress(body.Slice(offset, 4)).ToString();
                    offset += 4;
                    break;

                case AtypIpv6:
                    Host = new System.Net.IPAddress(body.Slice(offset, 16)).ToString();
                    offset += 16;
                    break;

                case AtypDomain:
                    var nameLength = body[offset];
                    offset += 1;
                    Host = Encoding.UTF8.GetString(body.Slice(offset, nameLength));
                    offset += nameLength;
                    break;

                default:
                    Assert.Fail($"unknown address type {AddressType}");
                    break;
            }

            offset += PaddingLength;

            ChecksumOffset = offset;
            Checksum = BinaryPrimitives.ReadUInt32BigEndian(body[offset..]);
            offset += 4;

            Assert.Equal(body.Length, offset);
        }
    }
}
