using System.Buffers.Binary;

namespace Clash.Core.Netstack;

/// <summary>The TCP control bits, in their on-the-wire positions.</summary>
[Flags]
public enum TcpFlags : byte
{
    /// <summary>No flags set.</summary>
    None = 0x00,

    /// <summary>Sender has no more data (consumes one sequence number).</summary>
    Fin = 0x01,

    /// <summary>Synchronise sequence numbers (consumes one sequence number).</summary>
    Syn = 0x02,

    /// <summary>Abort the connection.</summary>
    Rst = 0x04,

    /// <summary>Push buffered data to the application.</summary>
    Psh = 0x08,

    /// <summary>The acknowledgement field is meaningful.</summary>
    Ack = 0x10,

    /// <summary>The urgent pointer is meaningful.</summary>
    Urg = 0x20,

    /// <summary>ECN echo.</summary>
    Ece = 0x40,

    /// <summary>Congestion window reduced.</summary>
    Cwe = 0x80,
}

/// <summary>
/// A parsed TCP segment header, plus the writers that build one.
/// <para>
/// Only the MSS option is interpreted; the rest of the option space is skipped,
/// which is what makes this stack compatible with peers that send NOP padding,
/// window scale or SACK-permitted without negotiating anything back. A malformed
/// option list fails the parse rather than being guessed at, and every parse
/// failure returns false instead of throwing because this runs inside the
/// tunnel's receive loop.
/// </para>
/// <para>
/// Out of scope: window scaling, timestamps, SACK, and TCP Fast Open. The window
/// field is therefore capped at 65535 bytes, which is plenty for the HTTP/TLS
/// flows this client exists to carry.
/// </para>
/// </summary>
public readonly struct TcpSegment
{
    /// <summary>Length of a TCP header with no options.</summary>
    public const int MinHeaderLength = 20;

    /// <summary>Length of a TCP header with every option (unused, but a useful bound).</summary>
    public const int MaxHeaderLength = 60;

    /// <summary>Length of the MSS option, kind and length bytes included.</summary>
    public const int MssOptionLength = 4;

    /// <summary>Kind byte of the maximum segment size option.</summary>
    public const byte MssOptionKind = 2;

    /// <summary>The largest TCP segment that fits under a 20-byte IPv4 header.</summary>
    public const int MaxSegmentLength = ushort.MaxValue - Ipv4Header.MinHeaderLength;

    /// <summary>Sender port.</summary>
    public ushort SourcePort { get; private init; }

    /// <summary>Receiver port.</summary>
    public ushort DestinationPort { get; private init; }

    /// <summary>Sequence number of the first payload byte (or of the SYN/FIN itself).</summary>
    public uint SequenceNumber { get; private init; }

    /// <summary>Next sequence number the sender expects from its peer.</summary>
    public uint AcknowledgmentNumber { get; private init; }

    /// <summary>Header length in bytes, options included.</summary>
    public int HeaderLength { get; private init; }

    /// <summary>Control bits.</summary>
    public TcpFlags Flags { get; private init; }

    /// <summary>Advertised receive window in bytes.</summary>
    public ushort WindowSize { get; private init; }

    /// <summary>The checksum as it appeared on the wire.</summary>
    public ushort Checksum { get; private init; }

    /// <summary>Urgent pointer.</summary>
    public ushort UrgentPointer { get; private init; }

    /// <summary>Offset of the payload inside the segment.</summary>
    public int PayloadOffset { get; private init; }

    /// <summary>Payload length in bytes.</summary>
    public int PayloadLength { get; private init; }

    /// <summary>The peer's MSS option, or -1 when the segment did not carry one.</summary>
    public int Mss { get; private init; }

    /// <summary>True when the segment carried an MSS option.</summary>
    public bool HasMss => Mss > 0;

    /// <summary>True when <paramref name="flag"/> is set.</summary>
    /// <param name="flag">The flag to test.</param>
    public bool HasFlag(TcpFlags flag) => (Flags & flag) == flag;

    /// <summary>
    /// Parses and validates a TCP segment. Returns false for anything malformed:
    /// too short, a data offset below 5 or past the end, or a broken option list.
    /// </summary>
    /// <param name="segment">The TCP segment, starting at the TCP header.</param>
    /// <param name="parsed">The parsed segment on success.</param>
    public static bool TryParse(ReadOnlySpan<byte> segment, out TcpSegment parsed)
    {
        parsed = default;

        if (segment.Length < MinHeaderLength)
        {
            return false;
        }

        var headerLength = (segment[12] >> 4) * 4;
        if (headerLength < MinHeaderLength || headerLength > segment.Length)
        {
            return false;
        }

        var mss = -1;
        var index = MinHeaderLength;
        while (index < headerLength)
        {
            var kind = segment[index];
            if (kind == 0)
            {
                // End of option list; the rest is padding.
                break;
            }

            if (kind == 1)
            {
                // No-op padding.
                index++;
                continue;
            }

            if (index + 1 >= headerLength)
            {
                return false;
            }

            var length = segment[index + 1];
            if (length < 2 || index + length > headerLength)
            {
                return false;
            }

            if (kind == MssOptionKind && length == MssOptionLength)
            {
                mss = BinaryPrimitives.ReadUInt16BigEndian(segment[(index + 2)..]);
            }

            index += length;
        }

        parsed = new TcpSegment
        {
            SourcePort = BinaryPrimitives.ReadUInt16BigEndian(segment),
            DestinationPort = BinaryPrimitives.ReadUInt16BigEndian(segment[2..]),
            SequenceNumber = BinaryPrimitives.ReadUInt32BigEndian(segment[4..]),
            AcknowledgmentNumber = BinaryPrimitives.ReadUInt32BigEndian(segment[8..]),
            HeaderLength = headerLength,
            Flags = (TcpFlags)segment[13],
            WindowSize = BinaryPrimitives.ReadUInt16BigEndian(segment[14..]),
            Checksum = BinaryPrimitives.ReadUInt16BigEndian(segment[16..]),
            UrgentPointer = BinaryPrimitives.ReadUInt16BigEndian(segment[18..]),
            PayloadOffset = headerLength,
            PayloadLength = segment.Length - headerLength,
            Mss = mss,
        };

        return true;
    }

    /// <summary>
    /// The one's complement sum of the IPv4 pseudo-header (RFC 9293 section 3.1),
    /// left unfolded so a caller can keep accumulating into it.
    /// </summary>
    /// <param name="source">Source address as a numeric dotted-quad value.</param>
    /// <param name="destination">Destination address as a numeric dotted-quad value.</param>
    /// <param name="segmentLength">TCP segment length, header included.</param>
    public static uint PseudoHeaderSum(uint source, uint destination, int segmentLength)
    {
        var sum = (source >> 16) + (source & 0xFFFF) + (destination >> 16) + (destination & 0xFFFF);
        sum += Ipv4Header.TcpProtocol;
        sum += (uint)segmentLength;
        return sum;
    }

    /// <summary>
    /// Computes the checksum for a complete TCP segment. The checksum field is
    /// ignored on input, so a partially built segment — or one that already
    /// carries a checksum — can be passed as-is.
    /// </summary>
    /// <param name="segment">The complete TCP segment, header and payload.</param>
    /// <param name="source">Source address as a numeric dotted-quad value.</param>
    /// <param name="destination">Destination address as a numeric dotted-quad value.</param>
    public static ushort ComputeChecksum(ReadOnlySpan<byte> segment, uint source, uint destination)
    {
        var sum = InternetChecksum.Accumulate(PseudoHeaderSum(source, destination, segment.Length), segment);

        // One's complement addition is a plain integer sum reduced modulo 2^16-1,
        // so removing the stored field is an ordinary subtraction.
        sum -= BinaryPrimitives.ReadUInt16BigEndian(segment[16..]);
        return InternetChecksum.Complete(sum);
    }

    /// <summary>
    /// True when the segment's stored checksum matches its contents and the
    /// pseudo-header. A checksum that folds to zero is rejected: the stack never
    /// emits one, and treating it as valid would let a corrupt segment through.
    /// </summary>
    /// <param name="segment">The complete TCP segment, header and payload.</param>
    /// <param name="source">Source address as a numeric dotted-quad value.</param>
    /// <param name="destination">Destination address as a numeric dotted-quad value.</param>
    public static bool IsChecksumValid(ReadOnlySpan<byte> segment, uint source, uint destination)
        => InternetChecksum.IsValid(
            InternetChecksum.Accumulate(PseudoHeaderSum(source, destination, segment.Length), segment));

    /// <summary>
    /// Writes a TCP header and returns its length in bytes. The caller writes the
    /// payload immediately after it and then calls <see cref="FinalizeChecksum"/>
    /// on the whole segment, which is what keeps the header and the payload in one
    /// buffer without an intermediate copy.
    /// </summary>
    /// <param name="destination">A buffer of at least 20, or 24 with <paramref name="mss"/>, bytes.</param>
    /// <param name="sourcePort">Sender port.</param>
    /// <param name="destinationPort">Receiver port.</param>
    /// <param name="sequenceNumber">Sequence number.</param>
    /// <param name="acknowledgmentNumber">Acknowledgement number.</param>
    /// <param name="flags">Control bits.</param>
    /// <param name="windowSize">Advertised receive window.</param>
    /// <param name="mss">MSS option value, or a value &lt;= 0 to omit the option.</param>
    public static int Write(
        Span<byte> destination,
        ushort sourcePort,
        ushort destinationPort,
        uint sequenceNumber,
        uint acknowledgmentNumber,
        TcpFlags flags,
        ushort windowSize,
        int mss = -1)
    {
        var includeMss = mss > 0;
        var headerLength = includeMss ? MinHeaderLength + MssOptionLength : MinHeaderLength;
        if (destination.Length < headerLength)
        {
            throw new ArgumentException($"a TCP header needs {headerLength} bytes", nameof(destination));
        }

        var header = destination[..headerLength];
        header.Clear();

        BinaryPrimitives.WriteUInt16BigEndian(header, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], destinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(header[4..], sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(header[8..], acknowledgmentNumber);
        header[12] = (byte)((headerLength / 4) << 4);
        header[13] = (byte)flags;
        BinaryPrimitives.WriteUInt16BigEndian(header[14..], windowSize);

        if (includeMss)
        {
            header[20] = MssOptionKind;
            header[21] = MssOptionLength;
            BinaryPrimitives.WriteUInt16BigEndian(header[22..], (ushort)mss);
        }

        return headerLength;
    }

    /// <summary>
    /// Stamps the checksum of a complete segment (header plus payload) into the
    /// checksum field.
    /// </summary>
    /// <param name="segment">The complete TCP segment.</param>
    /// <param name="source">Source address as a numeric dotted-quad value.</param>
    /// <param name="destination">Destination address as a numeric dotted-quad value.</param>
    public static void FinalizeChecksum(Span<byte> segment, uint source, uint destination)
    {
        segment[16] = 0;
        segment[17] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(
            segment[16..],
            ComputeChecksum(segment, source, destination));
    }
}
