using System.Buffers.Binary;
using System.Net;
using Clash.Core.Netstack;
using Xunit;

namespace Clash.Tests.Netstack;

/// <summary>
/// Unit tests for the packet layer: IPv4 header parsing and building, the
/// checksum, and the TCP pseudo-header checksum. They check against a published
/// vector and against the tests' own independent checksum implementation.
/// </summary>
public class Ipv4TcpPacketTests
{
    /// <summary>The IPv4 header checksum example from RFC 1071-style literature.</summary>
    private static readonly byte[] KnownHeader =
    [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
        0xB8, 0x61, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
    ];

    [Fact]
    public void Ipv4ChecksumMatchesTheKnownVector()
    {
        var header = KnownHeader.ToArray();
        header[10] = 0;
        header[11] = 0;

        var sum = InternetChecksum.Accumulate(0, header);
        var checksum = InternetChecksum.Complete(sum);

        Assert.Equal(0xB861, checksum);
        Assert.True(InternetChecksum.IsValid(InternetChecksum.Accumulate(0, KnownHeader)));
    }

    [Fact]
    public void Ipv4HeaderParsesTheKnownDatagram()
    {
        var packet = new byte[0x73];
        KnownHeader.CopyTo(packet, 0);

        Assert.True(Ipv4Header.TryParse(packet, out var header));
        Assert.Equal(4, packet[0] >> 4);
        Assert.Equal(20, header.HeaderLength);
        Assert.Equal(0x73, header.TotalLength);
        Assert.Equal(0x73 - 20, header.PayloadLength);
        Assert.Equal(17, header.Protocol);
        Assert.Equal(64, header.TimeToLive);
        Assert.Equal("192.168.0.1", header.Source.ToString());
        Assert.Equal("192.168.0.199", header.Destination.ToString());
        Assert.False(header.IsFragmented);
        Assert.Equal(0xC0A80001u, header.SourceAddress);
    }

    [Fact]
    public void Ipv4WriteRoundTripsThroughParse()
    {
        var packet = new byte[20 + 8];
        var written = Ipv4Header.Write(
            packet,
            Ipv4Header.ToNumeric(IPAddress.Parse("10.7.0.2")),
            Ipv4Header.ToNumeric(IPAddress.Parse("1.1.1.1")),
            Ipv4Header.TcpProtocol,
            8);

        Assert.Equal(20, written);
        Assert.True(Ipv4Header.TryParse(packet, out var header));
        Assert.Equal("10.7.0.2", header.Source.ToString());
        Assert.Equal("1.1.1.1", header.Destination.ToString());
        Assert.Equal(Ipv4Header.TcpProtocol, header.Protocol);
        Assert.Equal(28, header.TotalLength);
        Assert.Equal(8, header.PayloadLength);
        Assert.Equal(Ipv4Header.DefaultTimeToLive, header.TimeToLive);
    }

    [Theory]
    [InlineData(19)]     // shorter than a header
    [InlineData(20)]     // a header with a corrupted checksum
    public void Ipv4ParseRejectsShortOrCorruptHeaders(int length)
    {
        var packet = new byte[length];
        KnownHeader.AsSpan(0, Math.Min(length, KnownHeader.Length)).CopyTo(packet);

        Assert.False(Ipv4Header.TryParse(packet, out _));
    }

    [Fact]
    public void Ipv4ParseRejectsWrongVersionAndBadLengths()
    {
        var packet = new byte[0x73];
        KnownHeader.CopyTo(packet, 0);

        var ipv6 = packet.ToArray();
        ipv6[0] = 0x65;
        Assert.False(Ipv4Header.TryParse(ipv6, out _));

        var tinyIhl = packet.ToArray();
        tinyIhl[0] = 0x44;
        Assert.False(Ipv4Header.TryParse(tinyIhl, out _));

        var overlong = packet.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(overlong.AsSpan(2), 0x2000);
        Assert.False(Ipv4Header.TryParse(overlong, out _));

        var truncated = packet.AsSpan(0, 40).ToArray();
        Assert.False(Ipv4Header.TryParse(truncated, out _));
    }

    [Fact]
    public void Ipv4ParseFlagsFragments()
    {
        var packet = new byte[0x73];
        KnownHeader.CopyTo(packet, 0);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), 0x2000);

        // The checksum no longer matches, so repair it before parsing.
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), 0);
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(10),
            InternetChecksum.Complete(InternetChecksum.Accumulate(0, packet.AsSpan(0, 20))));

        Assert.True(Ipv4Header.TryParse(packet, out var header));
        Assert.True(header.IsFragmented);
    }

    [Fact]
    public void TcpChecksumMatchesAnIndependentComputation()
    {
        var payload = "GET / HTTP/1.1\r\n\r\n"u8.ToArray();
        var segment = new byte[TcpSegment.MinHeaderLength + payload.Length];
        var headerLength = TcpSegment.Write(
            segment,
            40000,
            443,
            0x11223344,
            0x55667788,
            TcpFlags.Ack | TcpFlags.Psh,
            65535);
        payload.CopyTo(segment.AsSpan(headerLength));
        TcpSegment.FinalizeChecksum(segment, 0x0A070002, 0x01010101);

        var stored = BinaryPrimitives.ReadUInt16BigEndian(segment.AsSpan(16));

        // The independent computation must see the checksum field as zero.
        var zeroed = segment.ToArray();
        zeroed[16] = 0;
        zeroed[17] = 0;
        var independent = (ushort)~TestPackets.Sum(
            zeroed,
            TestPackets.PseudoSeed(0x0A070002, 0x01010101, segment.Length));

        Assert.Equal(independent, stored);
        Assert.NotEqual(0, stored);
        Assert.True(TcpSegment.IsChecksumValid(segment, 0x0A070002, 0x01010101));
        Assert.Equal(stored, TcpSegment.ComputeChecksum(segment, 0x0A070002, 0x01010101));
        Assert.Equal(stored, TcpSegment.ComputeChecksum(zeroed, 0x0A070002, 0x01010101));
    }

    [Fact]
    public void TcpChecksumCoversThePseudoHeader()
    {
        var segment = new byte[TcpSegment.MinHeaderLength];
        TcpSegment.Write(segment, 1, 2, 3, 4, TcpFlags.Ack, 1024);
        TcpSegment.FinalizeChecksum(segment, 0x0A000001, 0x0A000002);

        Assert.True(TcpSegment.IsChecksumValid(segment, 0x0A000001, 0x0A000002));
        Assert.False(TcpSegment.IsChecksumValid(segment, 0x0A000009, 0x0A000002));
        Assert.False(TcpSegment.IsChecksumValid(segment, 0x0A000001, 0x0A000009));
        Assert.False(TcpSegment.IsChecksumValid(segment, 0x0A000001, 0x0A000002 + 1));
    }

    [Fact]
    public void TcpChecksumDetectsACorruptedPayload()
    {
        var payload = "hello wireguard"u8.ToArray();
        var segment = new byte[TcpSegment.MinHeaderLength + payload.Length];
        TcpSegment.Write(segment, 1234, 80, 7, 9, TcpFlags.Ack | TcpFlags.Psh, 4096);
        payload.CopyTo(segment.AsSpan(TcpSegment.MinHeaderLength));
        TcpSegment.FinalizeChecksum(segment, 0x7F000001, 0x5DB8D822);

        Assert.True(TcpSegment.IsChecksumValid(segment, 0x7F000001, 0x5DB8D822));

        segment[^1] ^= 0x01;
        Assert.False(TcpSegment.IsChecksumValid(segment, 0x7F000001, 0x5DB8D822));
    }

    [Fact]
    public void TcpSegmentRoundTripsWithMssOption()
    {
        var payload = "abc"u8.ToArray();
        var segment = new byte[TcpSegment.MinHeaderLength + TcpSegment.MssOptionLength + payload.Length];
        var headerLength = TcpSegment.Write(
            segment,
            50000,
            80,
            1000,
            2000,
            TcpFlags.Syn,
            32768,
            mss: 1400);
        payload.CopyTo(segment.AsSpan(headerLength));
        TcpSegment.FinalizeChecksum(segment, 0x0A000001, 0x0A000002);

        Assert.Equal(TcpSegment.MinHeaderLength + TcpSegment.MssOptionLength, headerLength);
        Assert.True(TcpSegment.TryParse(segment, out var parsed));
        Assert.Equal(50000, parsed.SourcePort);
        Assert.Equal(80, parsed.DestinationPort);
        Assert.Equal(1000u, parsed.SequenceNumber);
        Assert.Equal(2000u, parsed.AcknowledgmentNumber);
        Assert.Equal(TcpFlags.Syn, parsed.Flags);
        Assert.True(parsed.HasFlag(TcpFlags.Syn));
        Assert.False(parsed.HasFlag(TcpFlags.Ack));
        Assert.Equal(32768, parsed.WindowSize);
        Assert.Equal(1400, parsed.Mss);
        Assert.True(parsed.HasMss);
        Assert.Equal(3, parsed.PayloadLength);
        Assert.Equal(headerLength, parsed.PayloadOffset);
    }

    [Fact]
    public void TcpSegmentWithoutMssReportsNoMss()
    {
        var segment = new byte[TcpSegment.MinHeaderLength];
        TcpSegment.Write(segment, 1, 2, 3, 4, TcpFlags.Ack, 100);
        TcpSegment.FinalizeChecksum(segment, 1, 2);

        Assert.True(TcpSegment.TryParse(segment, out var parsed));
        Assert.False(parsed.HasMss);
        Assert.Equal(-1, parsed.Mss);
        Assert.Equal(0, parsed.PayloadLength);
    }

    [Fact]
    public void TcpParseRejectsMalformedHeaders()
    {
        var segment = new byte[TcpSegment.MinHeaderLength];
        TcpSegment.Write(segment, 1, 2, 3, 4, TcpFlags.Ack, 100);
        TcpSegment.FinalizeChecksum(segment, 1, 2);

        Assert.False(TcpSegment.TryParse(segment.AsSpan(0, 19), out _));

        var smallOffset = segment.ToArray();
        smallOffset[12] = 4 << 4;
        Assert.False(TcpSegment.TryParse(smallOffset, out _));

        var pastEnd = segment.ToArray();
        pastEnd[12] = 15 << 4;
        Assert.False(TcpSegment.TryParse(pastEnd, out _));

        var brokenOption = new byte[24];
        TcpSegment.Write(brokenOption, 1, 2, 3, 4, TcpFlags.Syn, 100, mss: 1400);
        brokenOption[20] = 2;
        brokenOption[21] = 9;
        Assert.False(TcpSegment.TryParse(brokenOption, out _));

        Assert.True(TcpSegment.TryParse(segment, out _));
    }

    [Fact]
    public void TcpOptionsAreSkippedRatherThanRejected()
    {
        // NOP, NOP, MSS, then end-of-list padding: the shape a real peer sends.
        var segment = new byte[28];
        TcpSegment.Write(segment, 1, 2, 3, 4, TcpFlags.Syn, 100);
        segment[12] = 7 << 4;
        segment[20] = 1;
        segment[21] = 1;
        segment[22] = 2;
        segment[23] = 4;
        BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(24), 1200);
        segment[26] = 0;
        segment[27] = 0;

        Assert.True(TcpSegment.TryParse(segment, out var parsed));
        Assert.Equal(28, parsed.HeaderLength);
        Assert.Equal(1200, parsed.Mss);
    }

    [Fact]
    public void AddressConversionRoundTrips()
    {
        var address = IPAddress.Parse("203.0.113.7");
        var numeric = Ipv4Header.ToNumeric(address);

        Assert.Equal(0xCB007107u, numeric);
        Assert.Equal(address, Ipv4Header.ToAddress(numeric));
        Assert.Throws<ArgumentException>(() => Ipv4Header.ToNumeric(IPAddress.IPv6Loopback));
    }
}
