using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Clash.Core.Common;
using Clash.Core.Netstack;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// One peer's WireGuard association, carrying <em>raw IPv4 packets</em> in and out
/// over the session's UDP datagram pipe.
/// <para>
/// Why raw packets and not datagrams: WireGuard is a layer-3 tunnel. There is no
/// destination-address field, no port field, no connect command and no stream id
/// anywhere in the protocol — an inner packet is encapsulated exactly as it is and
/// the peer's <c>allowed-ips</c> (a purely local routing decision) decides where it
/// goes. That is why <see cref="SupportsMultipleDestinations"/> is false and why
/// <see cref="SendAsync"/> ignores its <c>destination</c> argument: the peer is
/// fixed by configuration, so there is nothing to address. It is also why carrying
/// a TCP flow needs the userspace stack in <see cref="NetstackHost"/>, which this
/// connection is the packet boundary for.
/// </para>
/// <para>
/// The receive pump routes each decrypted inner packet by its IPv4 protocol number:
/// TCP to the queue this type's own <see cref="IPacketConnection"/> surface serves
/// (that is the netstack's feed), UDP to the queue a
/// <see cref="WireGuardUdpPacketConnection"/> view serves. Routing in one place is
/// what lets a TCP flow and a UDP flow share one session — and therefore one
/// handshake — without stealing each other's packets.
/// </para>
/// <para>
/// Out of scope, refused rather than approximated: IPv6 (the inner packets are
/// IPv4 only), IP fragmentation (a fragmented inner packet is dropped, exactly as
/// the netstack drops one), and any protocol other than TCP and UDP.
/// </para>
/// </summary>
public sealed class WireGuardPacketConnection : IPacketConnection
{
    /// <summary>The IPv4 protocol number of UDP.</summary>
    internal const byte UdpProtocol = 17;

    /// <summary>How many inbound UDP packets are held for a UDP view before the oldest is dropped.</summary>
    private const int UdpQueueDepth = 64;

    private readonly WireGuardSession _session;
    private readonly Channel<byte[]> _tcp = Channel.CreateUnbounded<byte[]>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly Channel<byte[]> _udp = Channel.CreateBounded<byte[]>(
        new BoundedChannelOptions(UdpQueueDepth)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = true,
        });

    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _pump;
    private int _disposed;

    /// <summary>Wraps a session and starts routing its inbound packets.</summary>
    /// <param name="session">The peer session; it is disposed with this connection.</param>
    public WireGuardPacketConnection(WireGuardSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        _session = session;
        _pump = Task.Run(PumpAsync);
    }

    /// <summary>The session this association carries.</summary>
    public WireGuardSession Session => _session;

    /// <inheritdoc />
    /// <remarks>
    /// False: WireGuard names no destination on the wire, so one association
    /// reaches exactly the one configured peer and a caller must not assume it can
    /// be reused for a second destination.
    /// </remarks>
    public bool SupportsMultipleDestinations => false;

    /// <inheritdoc />
    public EndPoint? LocalEndPoint => _session.LocalEndPoint;

    /// <summary>
    /// Encapsulates <paramref name="payload"/> as one inner IPv4 packet. The
    /// <paramref name="destination"/> is deliberately ignored — see the type
    /// remarks.
    /// </summary>
    /// <param name="payload">A complete IPv4 datagram.</param>
    /// <param name="destination">Ignored; WireGuard carries no destination.</param>
    /// <param name="cancellationToken">Cancels the handshake and the send.</param>
    public async ValueTask<int> SendAsync(
        ReadOnlyMemory<byte> payload,
        EndPoint destination,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(destination);
        RequireIpv4(payload.Span);

        await SendRawAsync(payload, cancellationToken).ConfigureAwait(false);
        return payload.Length;
    }

    /// <summary>
    /// Sends a complete inner IPv4 datagram without the <see cref="IPacketConnection"/>
    /// argument checking. Used by <see cref="WireGuardUdpPacketConnection"/>, which
    /// builds its packets here.
    /// </summary>
    /// <param name="packet">A complete IPv4 datagram.</param>
    /// <param name="cancellationToken">Cancels the handshake and the send.</param>
    public async ValueTask SendRawAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _session.SendAsync(packet, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Waits for the next inbound IPv4/TCP packet. Datagrams carrying anything
    /// else are routed elsewhere and never surface here.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">Ends the wait.</param>
    public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var packet = await ReadQueueAsync(_tcp, cancellationToken).ConfigureAwait(false);
        var copied = OutboundIo.CopyInto(packet, buffer);
        return new PacketResult(copied, _session.RemoteEndPoint);
    }

    /// <summary>
    /// Creates the UDP view of this association: the same session and the same peer,
    /// with the layer-3 datagrams translated to and from UDP payloads.
    /// </summary>
    /// <param name="localAddress">The inner IPv4 address this tunnel owns.</param>
    public WireGuardUdpPacketConnection CreateUdpView(IPAddress localAddress)
    {
        ArgumentNullException.ThrowIfNull(localAddress);
        return new WireGuardUdpPacketConnection(this, localAddress);
    }

    /// <summary>Waits for the next inbound UDP packet and hands it to a view.</summary>
    /// <param name="cancellationToken">Ends the wait.</param>
    internal Task<byte[]> ReadUdpAsync(CancellationToken cancellationToken) => ReadQueueAsync(_udp, cancellationToken);

    /// <summary>Stops the pump and tears the session — and the transport — down.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        await _lifetime.CancelAsync().ConfigureAwait(false);
        _tcp.Writer.TryComplete();
        _udp.Writer.TryComplete();

        try
        {
            await _pump.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Cancellation, or a stalled transport; the session is disposed next.
        }

        await _session.DisposeAsync().ConfigureAwait(false);
        _lifetime.Dispose();
    }

    private async Task<byte[]> ReadQueueAsync(Channel<byte[]> queue, CancellationToken cancellationToken)
    {
        try
        {
            return await queue.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            throw new ClashException("wireguard: the association was closed");
        }
    }

    /// <summary>
    /// Turns decrypted plaintext into routed inner packets. The plaintext still
    /// carries its zero padding, so the inner IPv4 header's total-length field —
    /// not the datagram length — says how much of it is real.
    /// </summary>
    private async Task PumpAsync()
    {
        var token = _lifetime.Token;
        var buffer = new byte[ushort.MaxValue];

        try
        {
            while (!token.IsCancellationRequested)
            {
                var length = await _session.ReceiveAsync(buffer, token).ConfigureAwait(false);
                if (length <= 0) break;

                if (!Ipv4Header.TryParse(buffer.AsSpan(0, length), out var ip)) continue;
                if (ip.IsFragmented) continue;

                var packet = buffer.AsSpan(0, ip.TotalLength).ToArray();
                switch (ip.Protocol)
                {
                    case Ipv4Header.TcpProtocol:
                        _tcp.Writer.TryWrite(packet);
                        break;
                    case UdpProtocol:
                        _udp.Writer.TryWrite(packet);
                        break;
                    default:
                        // ICMP, IGMP and anything else have no consumer here.
                        break;
                }
            }
        }
        catch (Exception)
        {
            // Cancellation, or the session ended: either way this pump is done.
        }
        finally
        {
            _tcp.Writer.TryComplete();
            _udp.Writer.TryComplete();
        }
    }

    private static void RequireIpv4(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < Ipv4Header.MinHeaderLength || (packet[0] >> 4) != 4)
        {
            throw new ClashException(
                "wireguard: SendAsync expects one complete IPv4 datagram; WireGuard carries no destination field, "
                + "so a bare payload cannot be addressed");
        }
    }
}

/// <summary>
/// The UDP view of a <see cref="WireGuardPacketConnection"/>.
/// <para>
/// Why this exists at all: a UDP caller hands over a payload plus a destination,
/// while WireGuard carries a whole IP packet. This type is the translation — it
/// owns the ephemeral inner source port for each destination, writes the IPv4 and
/// UDP headers (checksums included, using the pseudo-header the BCL will not build
/// for you), and on the way back unwraps the inner packet and reports the inner
/// source as the remote endpoint.
/// </para>
/// <para>
/// One datagram in, one IP packet out: WireGuard's <c>PaddingMultiple</c> of 16
/// means the packet on the wire is the payload rounded up, but the inner header's
/// length field keeps the boundary exact, so no per-datagram framing is needed and
/// none is invented.
/// </para>
/// <para>
/// The association is shared with every other UDP flow on the same adapter —
/// there is one session, and therefore one <c>receive_index</c>, per peer — so
/// <see cref="DisposeAsync"/> deliberately does not tear the carrier down. The
/// carrier's lifetime is the adapter's.
/// </para>
/// </summary>
public sealed class WireGuardUdpPacketConnection : IPacketConnection
{
    /// <summary>Length of a UDP header.</summary>
    private const int UdpHeaderLength = 8;

    /// <summary>The first inner source port handed out, inside the IANA dynamic range.</summary>
    private const ushort FirstPort = 49152;

    /// <summary>How many ports to try before giving up on finding a free one.</summary>
    private const int PortRange = ushort.MaxValue - FirstPort + 1;

    private readonly WireGuardPacketConnection _carrier;
    private readonly uint _localAddress;
    private readonly Lock _gate = new();
    private readonly Dictionary<IPEndPoint, ushort> _sourcePorts = [];
    private readonly Dictionary<ushort, IPEndPoint> _destinations = [];
    private int _nextPort = FirstPort;

    internal WireGuardUdpPacketConnection(WireGuardPacketConnection carrier, IPAddress localAddress)
    {
        _carrier = carrier;
        _localAddress = Ipv4Header.ToNumeric(localAddress);
    }

    /// <inheritdoc />
    /// <remarks>
    /// True: the association reaches any destination the peer's <c>allowed-ips</c>
    /// routes, so a caller must not cache one per destination.
    /// </remarks>
    public bool SupportsMultipleDestinations => true;

    /// <inheritdoc />
    public EndPoint? LocalEndPoint => _carrier.LocalEndPoint;

    /// <summary>
    /// Wraps <paramref name="payload"/> in IPv4 and UDP for
    /// <paramref name="destination"/> and sends it as one inner packet.
    /// </summary>
    /// <param name="payload">The UDP payload.</param>
    /// <param name="destination">The inner IPv4 destination.</param>
    /// <param name="cancellationToken">Cancels the handshake and the send.</param>
    public async ValueTask<int> SendAsync(
        ReadOnlyMemory<byte> payload,
        EndPoint destination,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);

        if (destination is not IPEndPoint endpoint)
        {
            throw new NotSupportedException($"wireguard: unsupported UDP destination {destination}");
        }

        if (endpoint.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new NotSupportedException($"wireguard: IPv6 is out of scope ({endpoint.Address})");
        }

        var sourcePort = AllocateSourcePort(endpoint);
        var packet = BuildPacket(_localAddress, Ipv4Header.ToNumeric(endpoint.Address), sourcePort, (ushort)endpoint.Port, payload.Span);
        await _carrier.SendRawAsync(packet, cancellationToken).ConfigureAwait(false);
        return payload.Length;
    }

    /// <summary>
    /// Waits for an inbound inner UDP packet addressed to one of this
    /// association's ephemeral ports and returns its payload with the inner source
    /// as the remote endpoint.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">Ends the wait.</param>
    public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var packet = await _carrier.ReadUdpAsync(cancellationToken).ConfigureAwait(false);

            if (!Ipv4Header.TryParse(packet, out var ip)) continue;
            var udp = packet.AsSpan(ip.HeaderLength);
            if (udp.Length < UdpHeaderLength) continue;

            var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(udp);
            var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(udp[2..]);

            lock (_gate)
            {
                if (!_destinations.ContainsKey(destinationPort)) continue;
            }

            var payload = udp[UdpHeaderLength..];
            var copied = OutboundIo.CopyInto(payload, buffer);
            return new PacketResult(copied, new IPEndPoint(ip.Source, sourcePort));
        }
    }

    /// <summary>
    /// A no-op. The association belongs to the adapter, not to the caller: there
    /// is exactly one session per peer, so a flow that disposed it would break
    /// every other flow through the same adapter.
    /// </summary>
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private ushort AllocateSourcePort(IPEndPoint destination)
    {
        lock (_gate)
        {
            if (_sourcePorts.TryGetValue(destination, out var existing)) return existing;

            for (var attempt = 0; attempt < PortRange; attempt++)
            {
                var candidate = (ushort)_nextPort++;
                if (_nextPort > ushort.MaxValue) _nextPort = FirstPort;

                if (_destinations.ContainsKey(candidate)) continue;

                _sourcePorts[destination] = candidate;
                _destinations[candidate] = destination;
                return candidate;
            }

            throw new ClashException("wireguard: no free inner UDP source port");
        }
    }

    /// <summary>
    /// Builds a complete IPv4/UDP datagram. The UDP checksum covers a
    /// pseudo-header that never appears on the wire, which is why the running sum
    /// is seeded with it rather than computed over the buffer alone.
    /// </summary>
    private static byte[] BuildPacket(uint source, uint destination, ushort sourcePort, ushort destinationPort, ReadOnlySpan<byte> payload)
    {
        var udpLength = UdpHeaderLength + payload.Length;
        var packet = new byte[Ipv4Header.MinHeaderLength + udpLength];

        Ipv4Header.Write(packet, source, destination, WireGuardPacketConnection.UdpProtocol, udpLength);

        var udp = packet.AsSpan(Ipv4Header.MinHeaderLength);
        BinaryPrimitives.WriteUInt16BigEndian(udp, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(udp[2..], destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp[4..], (ushort)udpLength);
        payload.CopyTo(udp[UdpHeaderLength..]);

        var seed = (source >> 16) + (source & 0xFFFF) + (destination >> 16) + (destination & 0xFFFF)
            + WireGuardPacketConnection.UdpProtocol + (uint)udpLength;

        var checksum = InternetChecksum.Complete(InternetChecksum.Accumulate(seed, udp));
        // RFC 768: a checksum that computes to zero is transmitted as all ones, so
        // that zero keeps its "not computed" meaning.
        if (checksum == 0) checksum = 0xFFFF;
        BinaryPrimitives.WriteUInt16BigEndian(udp[6..], checksum);

        return packet;
    }
}
