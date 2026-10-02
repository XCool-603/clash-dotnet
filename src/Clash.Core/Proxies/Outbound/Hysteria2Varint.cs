using Clash.Core.Common;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The QUIC variable-length integer of RFC 9000 §16, which is the only integer
/// encoding hysteria2 uses on the wire.
/// <para>
/// The two most significant bits of the first byte select the total width — 1, 2, 4
/// or 8 bytes — and the remaining 6, 14, 30 or 62 bits carry the value big-endian.
/// The encoding is <em>not</em> minimal on the wire: a peer may legally send the
/// value 1 in eight bytes, so the reader must honour the declared width rather than
/// the magnitude. This codec therefore always picks the shortest form when writing
/// (what the reference's <c>varintPut</c> does) but accepts any width when reading.
/// </para>
/// <para>
/// .NET ships no helper for this: <c>System.Net.Quic</c> keeps its varint codec
/// internal to the transport, so the hysteria2 framing has to carry its own.
/// </para>
/// </summary>
internal static class Hysteria2Varint
{
    /// <summary>The largest value a QUIC varint can carry (2^62 - 1).</summary>
    internal const ulong MaxValue = (1UL << 62) - 1;

    /// <summary>How many bytes <see cref="Write"/> needs for <paramref name="value"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="value"/> needs more than 62 bits.</exception>
    internal static int Size(ulong value) => value switch
    {
        < 1UL << 6 => 1,
        < 1UL << 14 => 2,
        < 1UL << 30 => 4,
        <= MaxValue => 8,
        _ => throw new ArgumentOutOfRangeException(
            nameof(value),
            value,
            "a QUIC variable-length integer carries at most 62 bits"),
    };

    /// <summary>
    /// Writes <paramref name="value"/> in its shortest form and returns how many bytes
    /// that took. The concrete example the protocol documents is the TCP request
    /// frame type: <c>0x401</c> becomes <c>44 01</c>.
    /// </summary>
    internal static int Write(Span<byte> destination, ulong value)
    {
        var size = Size(value);
        if (destination.Length < size)
        {
            throw new ArgumentException($"destination must be at least {size} bytes, got {destination.Length}", nameof(destination));
        }

        switch (size)
        {
            case 1:
                destination[0] = (byte)value;
                break;

            case 2:
                destination[0] = (byte)(0x40 | (value >> 8));
                destination[1] = (byte)value;
                break;

            case 4:
                destination[0] = (byte)(0x80 | (value >> 24));
                destination[1] = (byte)(value >> 16);
                destination[2] = (byte)(value >> 8);
                destination[3] = (byte)value;
                break;

            default:
                destination[0] = (byte)(0xC0 | (value >> 56));
                destination[1] = (byte)(value >> 48);
                destination[2] = (byte)(value >> 40);
                destination[3] = (byte)(value >> 32);
                destination[4] = (byte)(value >> 24);
                destination[5] = (byte)(value >> 16);
                destination[6] = (byte)(value >> 8);
                destination[7] = (byte)value;
                break;
        }

        return size;
    }

    /// <summary>
    /// Reads one varint from <paramref name="source"/>. Returns false when the buffer
    /// is too short to hold the width the first byte declares, which is how the frame
    /// readers below tell "not yet complete" from "malformed".
    /// </summary>
    internal static bool TryRead(ReadOnlySpan<byte> source, out ulong value, out int consumed)
    {
        value = 0;
        consumed = 0;
        if (source.IsEmpty) return false;

        var length = 1 << (source[0] >> 6);
        if (source.Length < length) return false;

        var result = (ulong)(source[0] & 0x3F);
        for (var i = 1; i < length; i++) result = (result << 8) | source[i];

        value = result;
        consumed = length;
        return true;
    }

    /// <summary>
    /// Reads one varint from a stream, throwing rather than returning a partial value
    /// so a truncated frame cannot be mistaken for a short one.
    /// </summary>
    internal static async ValueTask<ulong> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var head = new byte[1];
        await OutboundIo.ReadExactlyAsync(stream, head, cancellationToken).ConfigureAwait(false);

        var length = 1 << (head[0] >> 6);
        var value = (ulong)(head[0] & 0x3F);
        if (length == 1) return value;

        var rest = new byte[length - 1];
        await OutboundIo.ReadExactlyAsync(stream, rest, cancellationToken).ConfigureAwait(false);
        foreach (var b in rest) value = (value << 8) | b;
        return value;
    }

    /// <summary>Writes one varint to a growable buffer, used by the QPACK encoder.</summary>
    internal static void Append(List<byte> destination, ulong value)
    {
        ArgumentNullException.ThrowIfNull(destination);

        var size = Size(value);
        var scratch = new byte[size];
        Write(scratch, value);
        destination.AddRange(scratch);
    }
}
