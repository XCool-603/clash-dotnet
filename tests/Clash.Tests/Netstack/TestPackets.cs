using System.Text;

namespace Clash.Tests.Netstack;

/// <summary>
/// A hand-written IPv4/TCP codec used only by the tests. It works on plain
/// arrays with explicit offsets and its own long-based checksum arithmetic, so
/// that a mistake shared with <c>Clash.Core.Netstack</c> cannot hide behind it.
/// </summary>
internal static class TestPackets
{
    public const int IpHeaderLength = 20;
    public const int TcpHeaderLength = 20;
    public const int TcpHeaderWithMssLength = 24;
    public const byte TcpProtocol = 6;

    public const byte FlagFin = 0x01;
    public const byte FlagSyn = 0x02;
    public const byte FlagRst = 0x04;
    public const byte FlagPsh = 0x08;
    public const byte FlagAck = 0x10;

    /// <summary>Parses a dotted quad into the numeric value the stack uses.</summary>
    public static uint Address(string dotted)
    {
        var parts = dotted.Split('.');
        var value = 0u;
        foreach (var part in parts)
        {
            value = (value << 8) | byte.Parse(part);
        }

        return value;
    }

    /// <summary>The independent checksum: a long accumulator, folded at the end.</summary>
    public static ushort Sum(ReadOnlySpan<byte> data, long seed)
    {
        var sum = seed;
        var index = 0;
        for (; index + 1 < data.Length; index += 2)
        {
            sum += (data[index] << 8) | data[index + 1];
        }

        if (index < data.Length)
        {
            sum += data[index] << 8;
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)sum;
    }

    /// <summary>The IPv4 pseudo-header, as a seed for <see cref="Sum"/>.</summary>
    public static long PseudoSeed(uint source, uint destination, int segmentLength)
        => (source >> 16) + (source & 0xFFFF) + (destination >> 16) + (destination & 0xFFFF)
           + TcpProtocol + segmentLength;

    /// <summary>Builds a complete IPv4/TCP packet from scratch.</summary>
    public static byte[] Build(
        uint sourceAddress,
        uint destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        uint sequence,
        uint acknowledgment,
        byte flags,
        ReadOnlySpan<byte> payload,
        ushort window = 65535,
        int mss = -1,
        bool corruptChecksum = false)
    {
        var tcpHeaderLength = mss > 0 ? TcpHeaderWithMssLength : TcpHeaderLength;
        var packet = new byte[IpHeaderLength + tcpHeaderLength + payload.Length];

        packet[0] = 0x45;
        packet[1] = 0;
        WriteUInt16(packet, 2, (ushort)packet.Length);
        WriteUInt16(packet, 6, 0x4000);
        packet[8] = 64;
        packet[9] = TcpProtocol;
        WriteUInt32(packet, 12, sourceAddress);
        WriteUInt32(packet, 16, destinationAddress);
        WriteUInt16(packet, 10, (ushort)~Sum(packet.AsSpan(0, IpHeaderLength), 0));

        var tcp = packet.AsSpan(IpHeaderLength);
        WriteUInt16(packet, 20, sourcePort);
        WriteUInt16(packet, 22, destinationPort);
        WriteUInt32(packet, 24, sequence);
        WriteUInt32(packet, 28, acknowledgment);
        packet[32] = (byte)((tcpHeaderLength / 4) << 4);
        packet[33] = flags;
        WriteUInt16(packet, 34, window);

        if (mss > 0)
        {
            packet[40] = 2;
            packet[41] = 4;
            WriteUInt16(packet, 42, (ushort)mss);
        }

        payload.CopyTo(packet.AsSpan(IpHeaderLength + tcpHeaderLength));

        var checksum = (ushort)~Sum(tcp, PseudoSeed(sourceAddress, destinationAddress, tcp.Length));
        if (corruptChecksum)
        {
            checksum ^= 0x00FF;
        }

        WriteUInt16(packet, 36, checksum);
        return packet;
    }

    /// <summary>Parses a packet without trusting anything about it.</summary>
    public static bool TryParse(byte[] packet, out ParsedPacket parsed)
    {
        parsed = default!;

        if (packet.Length < IpHeaderLength + TcpHeaderLength || (packet[0] >> 4) != 4)
        {
            return false;
        }

        var ihl = (packet[0] & 0x0F) * 4;
        if (ihl < IpHeaderLength || packet.Length < ihl)
        {
            return false;
        }

        var totalLength = ReadUInt16(packet, 2);
        if (totalLength > packet.Length || totalLength < ihl + TcpHeaderLength)
        {
            return false;
        }

        var source = ReadUInt32(packet, 12);
        var destination = ReadUInt32(packet, 16);
        var tcp = packet.AsSpan(ihl, totalLength - ihl);
        var dataOffset = (tcp[12] >> 4) * 4;
        if (dataOffset < TcpHeaderLength || dataOffset > tcp.Length)
        {
            return false;
        }

        var mss = -1;
        var index = TcpHeaderLength;
        while (index < dataOffset)
        {
            var kind = tcp[index];
            if (kind == 0)
            {
                break;
            }

            if (kind == 1)
            {
                index++;
                continue;
            }

            var length = tcp[index + 1];
            if (length < 2 || index + length > dataOffset)
            {
                break;
            }

            if (kind == 2 && length == 4)
            {
                mss = ReadUInt16(tcp, index + 2);
            }

            index += length;
        }

        parsed = new ParsedPacket(
            packet,
            source,
            destination,
            ReadUInt16(packet, ihl),
            ReadUInt16(packet, ihl + 2),
            ReadUInt32(packet, ihl + 4),
            ReadUInt32(packet, ihl + 8),
            tcp[13],
            ReadUInt16(packet, ihl + 14),
            tcp[dataOffset..].ToArray(),
            mss,
            ihl,
            Sum(packet.AsSpan(0, ihl), 0) == 0xFFFF,
            Sum(tcp, PseudoSeed(source, destination, tcp.Length)) == 0xFFFF);

        return true;
    }

    /// <summary>Formats a numeric address as a dotted quad.</summary>
    public static string Format(uint address)
        => $"{(address >> 24) & 0xFF}.{(address >> 16) & 0xFF}.{(address >> 8) & 0xFF}.{address & 0xFF}";

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset)
        => (ushort)((data[offset] << 8) | data[offset + 1]);

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset)
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

/// <summary>One segment as the fake peer saw it.</summary>
internal sealed record ParsedPacket(
    byte[] Raw,
    uint SourceAddress,
    uint DestinationAddress,
    ushort SourcePort,
    ushort DestinationPort,
    uint Sequence,
    uint Acknowledgment,
    byte Flags,
    ushort Window,
    byte[] Payload,
    int Mss,
    int IpHeaderLength,
    bool IpChecksumValid,
    bool ChecksumValid)
{
    /// <summary>True when the FIN bit is set.</summary>
    public bool Fin => (Flags & TestPackets.FlagFin) != 0;

    /// <summary>True when the SYN bit is set.</summary>
    public bool Syn => (Flags & TestPackets.FlagSyn) != 0;

    /// <summary>True when the RST bit is set.</summary>
    public bool Rst => (Flags & TestPackets.FlagRst) != 0;

    /// <summary>True when the PSH bit is set.</summary>
    public bool Psh => (Flags & TestPackets.FlagPsh) != 0;

    /// <summary>True when the ACK bit is set.</summary>
    public bool Ack => (Flags & TestPackets.FlagAck) != 0;

    /// <summary>The payload decoded as ASCII, for assertions.</summary>
    public string Text => Encoding.ASCII.GetString(Payload);

    /// <summary>The source address as a dotted quad.</summary>
    public string SourceText => TestPackets.Format(SourceAddress);

    /// <summary>The destination address as a dotted quad.</summary>
    public string DestinationText => TestPackets.Format(DestinationAddress);
}
