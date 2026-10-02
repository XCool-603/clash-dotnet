using System.Buffers.Binary;
using System.Net;

namespace Clash.Core.Netstack;

/// <summary>
/// A parsed IPv4 header, plus the writers that build one.
/// <para>
/// Addresses are kept as the numeric dotted-quad value (127.0.0.1 is
/// <c>0x7F000001</c>) rather than as <see cref="IPAddress"/> so that parsing and
/// comparing them on the packet path allocates nothing and never depends on the
/// machine's endianness; <see cref="Source"/> materialises an
/// <see cref="IPAddress"/> only when a caller asks for one at the API boundary.
/// </para>
/// <para>
/// Out of scope for this stack, and deliberately rejected rather than
/// half-supported: IPv6, IP options (IHL &gt; 5 is accepted but the options are
/// skipped), and IP fragmentation — a fragment is dropped, because reassembling
/// one is not something an outbound-only TCP client can be trusted to do.
/// </para>
/// </summary>
public readonly struct Ipv4Header
{
    /// <summary>Length of an IPv4 header with no options.</summary>
    public const int MinHeaderLength = 20;

    /// <summary>The IP protocol number of TCP.</summary>
    public const byte TcpProtocol = 6;

    /// <summary>The TTL stamped on packets this stack emits.</summary>
    public const byte DefaultTimeToLive = 64;

    /// <summary>Header length in bytes, including any options.</summary>
    public int HeaderLength { get; private init; }

    /// <summary>Total datagram length in bytes, header included.</summary>
    public int TotalLength { get; private init; }

    /// <summary>The IP protocol number carried in the payload.</summary>
    public byte Protocol { get; private init; }

    /// <summary>Source address as a numeric dotted-quad value.</summary>
    public uint SourceAddress { get; private init; }

    /// <summary>Destination address as a numeric dotted-quad value.</summary>
    public uint DestinationAddress { get; private init; }

    /// <summary>Time to live.</summary>
    public byte TimeToLive { get; private init; }

    /// <summary>True when this datagram is a fragment (offset or MF set).</summary>
    public bool IsFragmented { get; private init; }

    /// <summary>Length of the payload following the header.</summary>
    public int PayloadLength => TotalLength - HeaderLength;

    /// <summary>The source address as an <see cref="IPAddress"/>.</summary>
    public IPAddress Source => ToAddress(SourceAddress);

    /// <summary>The destination address as an <see cref="IPAddress"/>.</summary>
    public IPAddress Destination => ToAddress(DestinationAddress);

    /// <summary>
    /// Parses and validates an IPv4 datagram. Every failure returns false instead
    /// of throwing: this runs inside the tunnel's receive loop, where one
    /// malformed datagram from a peer must never take the loop down.
    /// </summary>
    /// <param name="packet">The datagram, which may be longer than its total length.</param>
    /// <param name="header">The parsed header on success.</param>
    public static bool TryParse(ReadOnlySpan<byte> packet, out Ipv4Header header)
    {
        header = default;

        if (packet.Length < MinHeaderLength)
        {
            return false;
        }

        var versionAndIhl = packet[0];
        if ((versionAndIhl >> 4) != 4)
        {
            return false;
        }

        var headerLength = (versionAndIhl & 0x0F) * 4;
        if (headerLength < MinHeaderLength || packet.Length < headerLength)
        {
            return false;
        }

        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        if (totalLength < headerLength || totalLength > packet.Length)
        {
            return false;
        }

        if (!InternetChecksum.IsValid(InternetChecksum.Accumulate(0, packet[..headerLength])))
        {
            return false;
        }

        var flagsAndOffset = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);

        header = new Ipv4Header
        {
            HeaderLength = headerLength,
            TotalLength = totalLength,
            Protocol = packet[9],
            TimeToLive = packet[8],
            SourceAddress = BinaryPrimitives.ReadUInt32BigEndian(packet[12..]),
            DestinationAddress = BinaryPrimitives.ReadUInt32BigEndian(packet[16..]),
            IsFragmented = (flagsAndOffset & 0x3FFF) != 0,
        };

        return true;
    }

    /// <summary>
    /// Writes a 20-byte IPv4 header, checksum included, and returns its length.
    /// </summary>
    /// <param name="destination">A buffer of at least <see cref="MinHeaderLength"/> bytes.</param>
    /// <param name="source">Source address as a numeric dotted-quad value.</param>
    /// <param name="destinationAddress">Destination address as a numeric dotted-quad value.</param>
    /// <param name="protocol">The protocol number of the payload.</param>
    /// <param name="payloadLength">Payload length in bytes.</param>
    /// <param name="timeToLive">TTL to stamp.</param>
    /// <remarks>
    /// The identification field is left at zero and the don't-fragment bit is set:
    /// this stack only ever emits complete, unfragmented segments over a
    /// point-to-point tunnel, so an identification value would carry no
    /// information.
    /// </remarks>
    public static int Write(
        Span<byte> destination,
        uint source,
        uint destinationAddress,
        byte protocol,
        int payloadLength,
        byte timeToLive = DefaultTimeToLive)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(payloadLength);
        if (payloadLength > ushort.MaxValue - MinHeaderLength)
        {
            throw new ArgumentOutOfRangeException(nameof(payloadLength));
        }

        if (destination.Length < MinHeaderLength)
        {
            throw new ArgumentException($"an IPv4 header needs {MinHeaderLength} bytes", nameof(destination));
        }

        var header = destination[..MinHeaderLength];
        header.Clear();

        header[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], (ushort)(MinHeaderLength + payloadLength));
        BinaryPrimitives.WriteUInt16BigEndian(header[6..], 0x4000);
        header[8] = timeToLive;
        header[9] = protocol;
        BinaryPrimitives.WriteUInt32BigEndian(header[12..], source);
        BinaryPrimitives.WriteUInt32BigEndian(header[16..], destinationAddress);
        BinaryPrimitives.WriteUInt16BigEndian(
            header[10..],
            InternetChecksum.Complete(InternetChecksum.Accumulate(0, header)));

        return MinHeaderLength;
    }

    /// <summary>Converts an IPv4 <see cref="IPAddress"/> to its numeric dotted-quad value.</summary>
    /// <param name="address">An IPv4 address.</param>
    /// <exception cref="ArgumentException">The address is not IPv4.</exception>
    public static uint ToNumeric(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        Span<byte> bytes = stackalloc byte[4];
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || !address.TryWriteBytes(bytes, out var written)
            || written != 4)
        {
            throw new ArgumentException("an IPv4 address is required", nameof(address));
        }

        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    /// <summary>Converts a numeric dotted-quad value back to an <see cref="IPAddress"/>.</summary>
    /// <param name="value">The numeric address.</param>
    public static IPAddress ToAddress(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }
}
