namespace Clash.Core.Netstack;

/// <summary>
/// The 16-bit one's complement checksum of RFC 1071, shared by the IPv4 header
/// and the TCP pseudo-header.
/// <para>
/// Why hand-rolled rather than a <c>System.Net</c> helper: the checksum must be
/// computed over pieces that are never contiguous in memory — an IPv4 header
/// plus a TCP segment, and for TCP a pseudo-header that never appears on the
/// wire at all. The accumulator is therefore exposed separately from the final
/// fold so a caller can add the pseudo-header, then the segment, without copying
/// either into a scratch buffer. Everything works on spans, so no allocation is
/// involved on the packet path.
/// </para>
/// </summary>
public static class InternetChecksum
{
    /// <summary>
    /// Adds <paramref name="data"/> to a running one's complement sum. An odd
    /// trailing byte is padded with a zero low byte, as the RFC requires.
    /// </summary>
    /// <param name="sum">The running sum, from a previous call or a pseudo-header.</param>
    /// <param name="data">The bytes to add.</param>
    public static uint Accumulate(uint sum, ReadOnlySpan<byte> data)
    {
        var index = 0;
        while (index + 1 < data.Length)
        {
            sum += (uint)((data[index] << 8) | data[index + 1]);
            index += 2;
        }

        if (index < data.Length)
        {
            sum += (uint)(data[index] << 8);
        }

        return sum;
    }

    /// <summary>Folds a running sum down to 16 bits, keeping the carry bits.</summary>
    /// <param name="sum">A running sum from <see cref="Accumulate"/>.</param>
    public static ushort Fold(uint sum)
    {
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)sum;
    }

    /// <summary>The value to store in a checksum field for a running sum.</summary>
    /// <param name="sum">A running sum from <see cref="Accumulate"/>.</param>
    public static ushort Complete(uint sum) => (ushort)~Fold(sum);

    /// <summary>
    /// True when a running sum that already includes the stored checksum folds to
    /// all ones, which is the receiver-side form of the same test.
    /// </summary>
    /// <param name="sumIncludingChecksum">Pseudo-header plus header plus payload, checksum field included.</param>
    public static bool IsValid(uint sumIncludingChecksum) => Fold(sumIncludingChecksum) == 0xFFFF;
}
