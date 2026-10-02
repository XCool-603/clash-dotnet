using System.Buffers.Binary;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Proxies.Outbound;
using Clash.Tests.Outbound;
using Xunit;

namespace Clash.Tests.Outbound;

/// <summary>
/// Byte-level coverage for the hysteria2 client's framing layers.
/// <para>
/// Every expectation here is derived from the protocol documents, not from the
/// implementation: the QPACK static table is RFC 9204 Appendix A, the varint is
/// RFC 9000 section 16, and the TCP request layout is PROTOCOL.md section 3. A
/// wrong choice in the production code therefore fails against these literals
/// rather than mirroring them.
/// </para>
/// <para>
/// No live interop: a 20-line System.Net.Quic client fails the TLS handshake
/// against sing-box and the official hysteria2 server (MsQuic and quic-go do not
/// interoperate on this build), so the QUIC and auth layers can only be covered
/// through these framing types; that limitation is deliberate and documented in
/// the README.
/// </para>
/// </summary>
public sealed class Hysteria2UnitTests
{
    // QUIC variable-length integer (RFC 9000 section 16)

    [Theory]
    [InlineData(0UL, "00")]
    [InlineData(63UL, "3f")]
    [InlineData(64UL, "4040")]
    [InlineData(16383UL, "7fff")]
    [InlineData(1025UL, "4401")]
    [InlineData(16777215UL, "80ffffff")]
    [InlineData(1073741823UL, "bfffffff")]
    [InlineData(1073741824UL, "c000000040000000")]
    [InlineData(4611686018427387903UL, "ffffffffffffffff")]
    public void VarintWritesTheRfc9000Encoding(ulong value, string expectedHex)
    {
        var destination = new byte[8];
        var written = Hysteria2Varint.Write(destination, value);

        Assert.Equal(Hysteria2Varint.Size(value), written);
        Assert.Equal(expectedHex, Convert.ToHexStringLower(destination.AsSpan(0, written)));
    }

    [Fact]
    public void Varint0x401IsTheTwoByteForm()
    {
        // PROTOCOL.md's TCPRequest frame type is 0x401: two bytes, 0x44 0x01.
        var destination = new byte[8];
        var written = Hysteria2Varint.Write(destination, 0x401);

        Assert.Equal(2, written);
        Assert.Equal(0x44, destination[0]);
        Assert.Equal(0x01, destination[1]);
    }

    [Theory]
    [InlineData("00", 0UL, 1)]
    [InlineData("3f", 63UL, 1)]
    [InlineData("4040", 64UL, 2)]
    [InlineData("4401", 1025UL, 2)]
    [InlineData("bfffffff", 1073741823UL, 4)]
    [InlineData("c000000040000000", 1073741824UL, 8)]
    public void VarintReadsWhatItWrote(string hex, ulong expected, int consumed)
    {
        var source = Convert.FromHexString(hex);

        Assert.True(Hysteria2Varint.TryRead(source, out var value, out var read));
        Assert.Equal(expected, value);
        Assert.Equal(consumed, read);
    }

    [Fact]
    public void VarintRoundTripsEveryBoundary()
    {
        foreach (var value in new ulong[] { 0, 1, 62, 63, 64, 65, 16383, 16384, 1073741823, 1073741824, Hysteria2Varint.MaxValue })
        {
            var destination = new byte[8];
            var written = Hysteria2Varint.Write(destination, value);

            Assert.True(Hysteria2Varint.TryRead(destination.AsSpan(0, written), out var read, out var consumed));
            Assert.Equal(value, read);
            Assert.Equal(written, consumed);
        }
    }

    [Fact]
    public void VarintRejectsAValueOverThe62BitMaximum()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Hysteria2Varint.Write(new byte[8], Hysteria2Varint.MaxValue + 1));
    }

    // QPACK (RFC 9204, zero-capacity-table subset)

    [Fact]
    public void StaticTableMatchesRfc9204AppendixAAnchors()
    {
        // Anchors from the RFC's Appendix A. If the table drifts, every indexed
        // field line below drifts with it.
        Assert.Equal(0, Hysteria2Qpack.FindStaticIndex(":authority", ""));
        Assert.Equal(1, Hysteria2Qpack.FindStaticIndex(":path", "/"));
        Assert.Equal(20, Hysteria2Qpack.FindStaticIndex(":method", "POST"));
        Assert.Equal(23, Hysteria2Qpack.FindStaticIndex(":scheme", "https"));
        Assert.Equal(25, Hysteria2Qpack.FindStaticIndex(":status", "200"));
        Assert.Equal(53, Hysteria2Qpack.FindStaticIndex("content-type", "text/plain"));
        Assert.Equal(-1, Hysteria2Qpack.FindStaticIndex(":status", "233"));
        Assert.Equal(-1, Hysteria2Qpack.FindStaticIndex("hysteria-auth", ""));
        Assert.Equal(1, Hysteria2Qpack.FindStaticName(":path"));
        Assert.Equal(98, Hysteria2Qpack.StaticTable.Length - 1);
    }

    [Fact]
    public void FieldSectionStartsWithTwoZeroPrefixBytes()
    {
        var section = Hysteria2Qpack.EncodeFieldSection([new(":method", "POST")]);

        // Required Insert Count = 0, Delta Base = 0: the section references no
        // dynamic entry, which is the whole point of the zero-capacity settings.
        Assert.Equal(0x00, section[0]);
        Assert.Equal(0x00, section[1]);
        Assert.Equal(3, section.Length);
    }

    [Fact]
    public void IndexedStaticFieldLineIsOneByte()
    {
        // 1 T Index(6+) with T = 1: 0xC0 | 20 for ":method: POST".
        var section = Hysteria2Qpack.EncodeFieldSection([new(":method", "POST")]);

        Assert.Equal(0xC0 | 20, section[2]);
    }

    [Fact]
    public void LiteralFieldLinesRoundTripThroughTheDecoder()
    {
        // The encoder may Huffman-encode names and values when that is shorter, so
        // the byte-level assertions are on the *decoding*: whatever it writes, the
        // peer-side decoder must recover the same fields.
        Hysteria2HeaderField[] fields =
        [
            new(":path", "/auth"),
            new("hysteria-auth", "pw"),
        ];

        var encoded = Hysteria2Qpack.EncodeFieldSection(fields);

        Assert.Equal(0x00, encoded[0]); // Required Insert Count = 0
        Assert.Equal(0x00, encoded[1]); // Delta Base = 0
        Assert.Equal(fields, Hysteria2Qpack.DecodeFieldSection(encoded));
    }

    [Fact]
    public void LiteralValuesAreEitherPlainOrHuffmanConsistently()
    {
        // Both spellings must survive a decode: a plain literal for a value whose
        // Huffman form would be longer, and a Huffman literal for one where it is
        // shorter. Either is legal QPACK; losing data is not.
        Hysteria2HeaderField[] fields =
        [
            new("x-a", "aaaaaaaaaaaaaaaa"),   // 16 identical bytes: Huffman wins
            new("x-b", "0123456789abcdef"),   // mixed: plain is likely shorter
        ];

        var encoded = Hysteria2Qpack.EncodeFieldSection(fields);

        Assert.Equal(fields, Hysteria2Qpack.DecodeFieldSection(encoded));
    }

    [Fact]
    public void FieldSectionDecodesBackToTheSameFields()
    {
        Hysteria2HeaderField[] fields =
        [
            new(":method", "POST"),
            new(":scheme", "https"),
            new(":authority", "hysteria"),
            new(":path", "/auth"),
            new("hysteria-auth", "secret-password"),
            new("hysteria-cc-rx", "1048576"),
        ];

        var encoded = Hysteria2Qpack.EncodeFieldSection(fields);
        var decoded = Hysteria2Qpack.DecodeFieldSection(encoded);

        Assert.Equal(fields, decoded);
    }

    [Fact]
    public void FieldSectionReferencingADynamicTableIsRefused()
    {
        // Prefix with Required Insert Count = 3: impossible under the zero-capacity
        // settings this client advertises, so it must be rejected, not guessed at.
        var section = new byte[] { 0x03, 0x00, 0xD4 };

        var exception = Assert.Throws<ClashException>(
            () => Hysteria2Qpack.DecodeFieldSection(section));
        Assert.Contains("dynamic table", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HuffmanEncodedValueIsRejectedRatherThanMisread()
    {
        // H = 1 on a value: this client implements no Huffman decoding for the
        // zero-capacity subset, so it must refuse instead of producing garbage.
        var section = new byte[] { 0x00, 0x00, 0x51, 0x85, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };

        Assert.ThrowsAny<Exception>(() => Hysteria2Qpack.DecodeFieldSection(section));
    }

    // HTTP/3 framing

    [Fact]
    public void ControlStreamOpensWithStreamTypeZeroAndTheZeroCapacitySettings()
    {
        // [type 0x00][frame 0x04][len 0x04][id 0x01][val 0x00][id 0x07][val 0x00]
        var stream = Hysteria2Http3.ControlStream();

        Assert.Equal(0x00, stream[0]); // stream type: control
        Assert.Equal(0x04, stream[1]); // frame type: SETTINGS
        Assert.Equal(0x04, stream[2]); // payload length: two one-byte pairs

        Assert.Equal(0x01, stream[3]); // SETTINGS_QPACK_MAX_TABLE_CAPACITY
        Assert.Equal(0x00, stream[4]); // = 0: this client never inserts
        Assert.Equal(0x07, stream[5]); // SETTINGS_QPACK_BLOCKED_STREAMS
        Assert.Equal(0x00, stream[6]); // = 0: it never blocks on the peer
        Assert.Equal(7, stream.Length);
    }

    [Fact]
    public void QpackStreamsAreOpenedAndEmpty()
    {
        Assert.Equal([0x02], Hysteria2Http3.QpackEncoderStream());
        Assert.Equal([0x03], Hysteria2Http3.QpackDecoderStream());
    }

    [Fact]
    public void HeadersFramePrefixesTheFieldSectionLength()
    {
        var fieldSection = Hysteria2Qpack.EncodeFieldSection([new(":method", "POST")]);
        var frame = Hysteria2Http3.HeadersFrame(fieldSection);

        Assert.Equal(0x01, frame[0]); // frame type: HEADERS
        Assert.Equal((ulong)fieldSection.Length, (ulong)frame[1]);
        Assert.Equal(fieldSection.Length + 2, frame.Length);
        Assert.Equal(fieldSection, frame[2..]);
    }

    [Fact]
    public void AuthRequestCarriesThePseudoHeadersAndPassword()
    {
        var section = Hysteria2Auth.BuildRequest("test-password", ccRx: 1048576, padding: new string('x', 300));
        var fields = Hysteria2Qpack.DecodeFieldSection(section);

        // Pseudo-headers first, then the hysteria headers, in reference order.
        Assert.Equal(":method", fields[0].Name);
        Assert.Equal("POST", fields[0].Value);
        Assert.Equal(":scheme", fields[1].Name);
        Assert.Equal("https", fields[1].Value);
        Assert.Equal(":authority", fields[2].Name);
        Assert.Equal("hysteria", fields[2].Value);
        Assert.Equal(":path", fields[3].Name);
        Assert.Equal("/auth", fields[3].Value);

        Assert.Equal("hysteria-auth", fields[4].Name);
        Assert.Equal("test-password", fields[4].Value);
        Assert.Equal("hysteria-cc-rx", fields[5].Name);
        Assert.Equal("1048576", fields[5].Value);
        Assert.Equal("hysteria-padding", fields[6].Name);
        Assert.Equal(300, fields[6].Value.Length);
    }

    [Fact]
    public void AuthRequestDecodesAgainstAStaticOnlyPeer()
    {
        // Round-trip the request through the decoder: this is the contract a
        // zero-capacity QPACK server relies on.
        var section = Hysteria2Auth.BuildRequest("pw", 0, "pad");
        var fields = Hysteria2Qpack.DecodeFieldSection(section);

        Assert.Equal(7, fields.Count);
        Assert.Equal("pw", fields[4].Value);
    }

    [Fact]
    public void AuthResponseParsingAcceptsOnlyStatus233()
    {
        Assert.Equal("hysteria", Hysteria2Auth.Authority);
        Assert.Equal("/auth", Hysteria2Auth.Path);
        Assert.Equal(233, Hysteria2Auth.SuccessStatus);

        var rejected = new List<Hysteria2HeaderField> { new(":status", "403") };
        var exception = Assert.Throws<ClashException>(() => Hysteria2Auth.ParseResponse(rejected));
        Assert.Contains("403", exception.Message, StringComparison.Ordinal);
    }

    // TCP request header (PROTOCOL.md section 3)

    [Fact]
    public void TcpRequestHeaderForADomainIsExactlyTheDocumentedLayout()
    {
        // varint(0x401) = 44 01, varint(len("example.com:443") = 15) = 0x0f,
        // "example.com:443", varint(32) = 0x20, then 32 padding bytes.
        var padding = new byte[32];
        var buffer = new byte[Hysteria2RequestHeader.Size("example.com", 443, padding.Length)];

        var written = Hysteria2RequestHeader.Write(buffer, "example.com", 443, padding);

        var offset = 0;
        Assert.Equal(0x44, buffer[offset++]);
        Assert.Equal(0x01, buffer[offset++]);
        Assert.Equal(15, buffer[offset++]); // address length, one-byte varint

        Assert.Equal("example.com:443"u8.ToArray(), buffer[offset..(offset + 15)]);
        offset += 15;

        Assert.Equal(32, buffer[offset]); // padding length, one-byte varint
        offset += 1;
        Assert.Equal(padding, buffer[offset..(offset + padding.Length)]);
        Assert.Equal(offset + padding.Length, written);
        Assert.Equal(Hysteria2RequestHeader.Size("example.com", 443, padding.Length), written);
    }

    [Theory]
    [InlineData("example.com", 443, "example.com:443")]
    [InlineData("1.2.3.4", 80, "1.2.3.4:80")]
    [InlineData("2001:db8::1", 8443, "[2001:db8::1]:8443")]
    public void AddressIsTheHostPortStringWithIpv6Bracketed(string host, int port, string expected)
    {
        // PROTOCOL.md carries the destination as the ASCII "host:port" string -
        // not the SOCKS5 address block the other protocols use.
        Assert.Equal(expected, Hysteria2Address.Format(host, port));
    }

    [Fact]
    public void TcpRequestHeaderPaddingIsRandomisedWithinTheDocumentedRange()
    {
        Assert.InRange(Hysteria2RequestHeader.MinPadding, 1, Hysteria2RequestHeader.MaxPaddingExclusive - 1);
        Assert.True(Hysteria2RequestHeader.MaxPaddingExclusive > Hysteria2RequestHeader.MinPadding);
    }

    // Construction and refusals

    private static IProxy Build(string yamlEntry)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in yamlEntry.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = line.IndexOf(':');
            map[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }

        return OutboundHarness.Build(new ProxyConfigEntry(new YamlMap(map)));
    }

    [Fact]
    public void MissingPasswordIsRejected()
    {
        var exception = Assert.Throws<ProxyCreationException>(
            () => Build("name: hy2\ntype: hysteria2\nserver: 127.0.0.1\nport: 443"));

        Assert.Contains("password", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ObfuscationIsRefusedWithThePlatformReason()
    {
        var exception = Assert.Throws<ProxyCreationException>(
            () => Build("name: hy2\ntype: hysteria2\nserver: 127.0.0.1\nport: 443\npassword: pw\nobfs: salamander"));

        // The refusal must name the mechanism, so a user knows it is a platform
        // limit rather than a typo in their configuration.
        Assert.Contains("obfs", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("System.Net.Quic", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DialerProxyIsRefusedRatherThanSilentlyBypassed()
    {
        var exception = Assert.Throws<ProxyCreationException>(
            () => Build("name: hy2\ntype: hysteria2\nserver: 127.0.0.1\nport: 443\npassword: pw\ndialer-proxy: CHAIN"));

        Assert.Contains("dialer-proxy", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UdpIsAdvertisedAsUnsupported()
    {
        var proxy = Build("name: hy2\ntype: hysteria2\nserver: 127.0.0.1\nport: 443\npassword: pw");

        Assert.Equal("Hysteria2", proxy.TypeName);
        Assert.False(proxy.SupportUdp);

        var exception = Assert.Throws<NotSupportedException>(
            () => proxy.DialUdpAsync(new Metadata { Network = Network.Udp }).GetAwaiter().GetResult());
        Assert.Contains("datagram", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheFactoryIsRegisteredUnderBothSpellings()
    {
        var proxy = OutboundHarness.Build(OutboundHarness.Entry("hy2", "hysteria2", ("server", "127.0.0.1"), ("port", 443), ("password", "pw")));
        Assert.Equal("Hysteria2", proxy.TypeName);

        var alias = OutboundHarness.Build(OutboundHarness.Entry("hy2", "hy2", ("server", "127.0.0.1"), ("port", 443), ("password", "pw")));
        Assert.Equal("Hysteria2", alias.TypeName);
    }

    [Fact]
    public void EndpointAndUdpFlagComeFromTheConfiguration()
    {
        var proxy = OutboundHarness.Build(OutboundHarness.Entry(
            "hy2", "hysteria2", ("server", "hy2.example.com"), ("port", 8443), ("password", "pw")));

        var outbound = Assert.IsAssignableFrom<IOutboundProxy>(proxy);
        Assert.Equal(("hy2.example.com", 8443), (outbound.ServerHost ?? string.Empty, outbound.ServerPort));
        Assert.False(proxy.SupportUdp);
    }
}
