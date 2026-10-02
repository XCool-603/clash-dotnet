using System.Buffers.Binary;
using Clash.Tests.Netstack;

namespace Clash.Tests.WireGuard;

/// <summary>
/// A hand-written IPv4/UDP codec for the tests, kept separate from the TCP one and
/// from the adapter's own builder. The pseudo-header is spelled out here rather
/// than shared, so a mistake in the adapter's checksum arithmetic cannot hide
/// behind the test's.
/// </summary>
internal static class TestUdp
{
    internal const int IpHeaderLength = 20;
    internal const int UdpHeaderLength = 8;
    internal const byte UdpProtocol = 17;

    /// <summary>Builds a complete IPv4/UDP datagram with both checksums.</summary>
    internal static byte[] Build(
        uint source,
        uint destination,
        ushort sourcePort,
        ushort destinationPort,
        ReadOnlySpan<byte> payload)
    {
        var udpLength = UdpHeaderLength + payload.Length;
        var packet = new byte[IpHeaderLength + udpLength];

        packet[0] = 0x45;
        WriteUInt16(packet, 2, (ushort)packet.Length);
        WriteUInt16(packet, 6, 0x4000);
        packet[8] = 64;
        packet[9] = UdpProtocol;
        WriteUInt32(packet, 12, source);
        WriteUInt32(packet, 16, destination);
        WriteUInt16(packet, 10, (ushort)~TestPackets.Sum(packet.AsSpan(0, IpHeaderLength), 0));

        var udp = packet.AsSpan(IpHeaderLength);
        WriteUInt16(packet, 20, sourcePort);
        WriteUInt16(packet, 22, destinationPort);
        WriteUInt16(packet, 24, (ushort)udpLength);
        payload.CopyTo(udp[UdpHeaderLength..]);

        // The UDP pseudo-header is never on the wire, so it is seeded explicitly.
        var seed = (source >> 16) + (source & 0xFFFF) + (destination >> 16) + (destination & 0xFFFF)
            + UdpProtocol + (uint)udpLength;

        var checksum = (ushort)~TestPackets.Sum(udp, seed);
        if (checksum == 0) checksum = 0xFFFF;
        WriteUInt16(packet, 26, checksum);

        return packet;
    }

    /// <summary>Parses a datagram, validating both checksums.</summary>
    internal static bool TryParse(byte[] packet, out ParsedUdp parsed)
    {
        parsed = default!;

        if (packet.Length < IpHeaderLength + UdpHeaderLength || (packet[0] >> 4) != 4) return false;

        var ihl = (packet[0] & 0x0F) * 4;
        if (ihl < IpHeaderLength || packet.Length < ihl) return false;

        var totalLength = ReadUInt16(packet, 2);
        if (totalLength > packet.Length || totalLength < ihl + UdpHeaderLength) return false;
        if (packet[9] != UdpProtocol) return false;

        var source = ReadUInt32(packet, 12);
        var destination = ReadUInt32(packet, 16);
        var udp = packet.AsSpan(ihl, totalLength - ihl);
        var udpLength = ReadUInt16(packet, ihl + 4);
        if (udpLength != udp.Length) return false;

        var seed = (source >> 16) + (source & 0xFFFF) + (destination >> 16) + (destination & 0xFFFF)
            + UdpProtocol + (uint)udpLength;

        parsed = new ParsedUdp(
            source,
            destination,
            ReadUInt16(packet, ihl),
            ReadUInt16(packet, ihl + 2),
            udp[UdpHeaderLength..].ToArray(),
            TestPackets.Sum(packet.AsSpan(0, ihl), 0) == 0xFFFF,
            TestPackets.Sum(udp, seed) == 0xFFFF);

        return true;
    }

    private static ushort ReadUInt16(byte[] data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);

    private static uint ReadUInt32(byte[] data, int offset)
        => ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) | ((uint)data[offset + 2] << 8) | data[offset + 3];

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value >> 8);
        data[offset + 1] = (byte)value;
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value >> 24);
        data[offset + 1] = (byte)(value >> 16);
        data[offset + 2] = (byte)(value >> 8);
        data[offset + 3] = (byte)value;
    }
}

/// <summary>One IPv4/UDP datagram as the test codec saw it.</summary>
internal sealed record ParsedUdp(
    uint SourceAddress,
    uint DestinationAddress,
    ushort SourcePort,
    ushort DestinationPort,
    byte[] Payload,
    bool IpChecksumValid,
    bool UdpChecksumValid)
{
    /// <summary>The source address as a dotted quad.</summary>
    internal string SourceText => TestPackets.Format(SourceAddress);

    /// <summary>The destination address as a dotted quad.</summary>
    internal string DestinationText => TestPackets.Format(DestinationAddress);
}
