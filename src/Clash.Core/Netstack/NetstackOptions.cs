using System.Net;
using System.Net.Sockets;

namespace Clash.Core.Netstack;

/// <summary>
/// Tuning for <see cref="NetstackHost"/>.
/// <para>
/// <see cref="TimeProvider"/> supplies the clock that retransmit and close
/// deadlines are measured against, and it may be replaced. The wakeup that
/// checks those deadlines is still a real-time wait, so a test that wants to see
/// a retransmission quickly should shorten <see cref="InitialRetransmitTimeout"/>
/// rather than only advancing a fake clock. The defaults are chosen for a tunnel
/// that already has its own reliability: a 300&#160;ms initial retransmit timeout,
/// five attempts with exponential backoff, and a small fixed window. There is no
/// congestion control beyond that — see <see cref="TcpConnection"/> for what is
/// deliberately absent.
/// </para>
/// </summary>
public sealed class NetstackOptions
{
    /// <summary>
    /// The address this stack pretends to own, used as the source of every packet
    /// it emits and as the only destination it accepts. In a WireGuard outbound
    /// this is the tunnel interface address.
    /// </summary>
    public IPAddress LocalAddress { get; set; } = IPAddress.Loopback;

    /// <summary>
    /// Maximum segment size advertised in the SYN and used to split writes. 1400
    /// leaves room for the IPv4 and TCP headers inside a 1500-byte tunnel MTU.
    /// </summary>
    public int Mss { get; set; } = 1400;

    /// <summary>
    /// The receive window advertised in every segment, and the hard cap on how
    /// much unread data a connection will buffer. Window scaling is out of scope,
    /// so the maximum meaningful value is 65535.
    /// </summary>
    public int ReceiveWindowSize { get; set; } = 65535;

    /// <summary>How much out-of-order data one connection will hold before dropping.</summary>
    public int MaxReorderBytes { get; set; } = 65536;

    /// <summary>How many out-of-order segments one connection will hold before dropping.</summary>
    public int MaxReorderSegments { get; set; } = 128;

    /// <summary>The retransmit timeout for the first attempt; it doubles from there.</summary>
    public TimeSpan InitialRetransmitTimeout { get; set; } = TimeSpan.FromMilliseconds(300);

    /// <summary>The ceiling the retransmit timeout backs off to.</summary>
    public TimeSpan MaxRetransmitTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>How many times an unacknowledged segment is retransmitted before the flow is reset.</summary>
    public int MaxRetransmitAttempts { get; set; } = 5;

    /// <summary>
    /// How long a connection that has sent its FIN waits for the peer's FIN (or
    /// for its own FIN to be acknowledged) before it is torn down. This is what
    /// keeps a peer that vanishes mid-close from leaking a connection forever.
    /// </summary>
    public TimeSpan CloseTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The clock the retransmit timer reads. It may be replaced; note that only
    /// the deadline arithmetic follows it, not the wakeup itself.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    /// <summary>Throws when a value cannot be honoured.</summary>
    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(LocalAddress);
        ArgumentNullException.ThrowIfNull(TimeProvider);

        if (LocalAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentOutOfRangeException(nameof(LocalAddress), "netstack is IPv4 only");
        }

        if (Mss is < 256 or > MaxSegmentSize)
        {
            throw new ArgumentOutOfRangeException(nameof(Mss), $"MSS must be between 256 and {MaxSegmentSize}");
        }

        if (ReceiveWindowSize < Mss || ReceiveWindowSize > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ReceiveWindowSize),
                $"the receive window must be between the MSS ({Mss}) and {ushort.MaxValue}");
        }

        if (MaxReorderBytes < Mss)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxReorderBytes));
        }

        if (MaxReorderSegments < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxReorderSegments));
        }

        if (InitialRetransmitTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(InitialRetransmitTimeout));
        }

        if (MaxRetransmitTimeout < InitialRetransmitTimeout)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxRetransmitTimeout));
        }

        if (MaxRetransmitAttempts < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxRetransmitAttempts));
        }

        if (CloseTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(CloseTimeout));
        }
    }

    /// <summary>The largest MSS a single IPv4 datagram can carry.</summary>
    private const int MaxSegmentSize = ushort.MaxValue - Ipv4Header.MinHeaderLength - TcpSegment.MinHeaderLength;
}
