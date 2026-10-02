using System.Net;
using System.Net.Sockets;

namespace Clash.Core.Netstack;

/// <summary>
/// The userspace TCP host: it owns every <see cref="TcpConnection"/>, turns
/// inbound IP packets into state-machine input, and hands outbound IP packets to
/// a sink.
/// <para>
/// Why this shape: the only thing a WireGuard outbound has is a UDP-like packet
/// association to a peer, so the boundary is deliberately two calls —
/// <see cref="ProcessPacket"/> for a datagram that arrived, and
/// <see cref="PacketSink"/> for a datagram that must leave. Nothing here knows
/// about sockets, and nothing here needs a background receive loop of its own.
/// </para>
/// <code>
/// var host = new NetstackHost(options, packet => wg.SendPacket(packet.Span));
/// host.ProcessPacket(inboundDatagram);            // from the tunnel
/// var stream = await host.ConnectAsync(remote);   // relay it like any other outbound
/// </code>
/// <para>
/// Buffer ownership: the memory handed to <see cref="PacketSink"/> is rented and
/// reused as soon as the delegate returns, so a sink must copy what it needs
/// before returning and must not call back into this host. For a
/// <see cref="Clash.Core.Common.IPacketConnection"/> peer, use
/// <see cref="NetstackPacketConnectionAdapter"/>, which does exactly that.
/// </para>
/// <para>
/// Out of scope: IPv6, listening, and any packet that is not an unfragmented
/// IPv4/TCP segment addressed to <see cref="NetstackOptions.LocalAddress"/>.
/// A segment that matches no connection is answered with a RST, as a real stack
/// would, except when it is itself a RST.
/// </para>
/// </summary>
public sealed class NetstackHost : IAsyncDisposable
{
    /// <summary>First port handed out to a connection, following the IANA dynamic range.</summary>
    private const int FirstEphemeralPort = 49152;

    /// <summary>How many ports to try before giving up on finding a free one.</summary>
    private const int EphemeralPortRange = ushort.MaxValue - FirstEphemeralPort + 1;

    private readonly Dictionary<ushort, TcpConnection> _connections = [];
    private readonly Lock _gate = new();
    private readonly NetstackOptions _options;
    private readonly uint _localAddress;
    private Action<ReadOnlyMemory<byte>>? _sink;
    private int _nextPort = FirstEphemeralPort;
    private int _disposed;

    /// <summary>Creates a host.</summary>
    /// <param name="options">Tuning; defaults are used when null.</param>
    /// <param name="packetSink">
    /// Where outbound IP packets go. It may be assigned later through
    /// <see cref="PacketSink"/>, which is what an adapter that is constructed in
    /// two steps needs.
    /// </param>
    public NetstackHost(NetstackOptions? options = null, Action<ReadOnlyMemory<byte>>? packetSink = null)
    {
        _options = options ?? new NetstackOptions();
        _options.Validate();
        _localAddress = Ipv4Header.ToNumeric(_options.LocalAddress);
        _sink = packetSink;
    }

    /// <summary>
    /// The sink that receives every outbound IP packet. Set it to null to drop
    /// outbound packets (a connection will then simply time out).
    /// </summary>
    public Action<ReadOnlyMemory<byte>>? PacketSink
    {
        get => Volatile.Read(ref _sink);
        set => Volatile.Write(ref _sink, value);
    }

    /// <summary>The address this host answers for.</summary>
    public IPAddress LocalAddress => _options.LocalAddress;

    /// <summary>How many connections are currently tracked.</summary>
    public int ConnectionCount
    {
        get
        {
            lock (_gate)
            {
                return _connections.Count;
            }
        }
    }

    /// <summary>
    /// Opens a flow to <paramref name="remote"/> and completes once the three-way
    /// handshake has finished. The returned stream is the caller's to dispose.
    /// </summary>
    /// <param name="remote">The IPv4 destination.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <exception cref="IOException">The peer refused or reset the connection, or it never answered.</exception>
    public async ValueTask<Stream> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(remote);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (remote.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new NotSupportedException("netstack is IPv4 only");
        }

        if (remote.Port is <= 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(remote), "a port in 1..65535 is required");
        }

        TcpConnection connection;
        lock (_gate)
        {
            connection = new TcpConnection(
                _options,
                _localAddress,
                remote,
                AllocatePortLocked(),
                Emit,
                OnConnectionClosed);
            _connections.Add((ushort)connection.LocalPort, connection);
        }

        try
        {
            // Started after registration so an immediate reply can find it.
            connection.Start();
            await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        return connection.Stream;
    }

    /// <summary>
    /// Feeds one IP packet received from the tunnel. Malformed, non-TCP,
    /// fragmented, mis-addressed and checksum-failing packets are dropped
    /// silently: this runs in the tunnel's receive loop, where throwing would end
    /// every flow at once.
    /// </summary>
    /// <param name="packet">The complete IPv4 datagram.</param>
    public void ProcessPacket(ReadOnlyMemory<byte> packet)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        var datagram = packet.Span;
        if (!Ipv4Header.TryParse(datagram, out var ip))
        {
            return;
        }

        if (ip.Protocol != Ipv4Header.TcpProtocol || ip.DestinationAddress != _localAddress)
        {
            return;
        }

        var segmentBytes = datagram.Slice(ip.HeaderLength, ip.TotalLength - ip.HeaderLength);
        if (!TcpSegment.TryParse(segmentBytes, out var segment))
        {
            return;
        }

        if (!TcpSegment.IsChecksumValid(segmentBytes, ip.SourceAddress, ip.DestinationAddress))
        {
            return;
        }

        TcpConnection? connection;
        lock (_gate)
        {
            _connections.TryGetValue(segment.DestinationPort, out connection);
        }

        if (connection is null)
        {
            SendReset(ip, segment);
            return;
        }

        connection.ProcessSegment(ip, segment, segmentBytes.Slice(segment.PayloadOffset, segment.PayloadLength));
    }

    /// <summary>
    /// Closes every flow and forgets the sink. Connections are torn down without
    /// a FIN: by the time a host is disposed the tunnel that carried the packets
    /// is going away too.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        TcpConnection[] connections;
        lock (_gate)
        {
            connections = [.. _connections.Values];
            _connections.Clear();
        }

        foreach (var connection in connections)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }

        Volatile.Write(ref _sink, null);
    }

    private void Emit(ReadOnlyMemory<byte> packet) => Volatile.Read(ref _sink)?.Invoke(packet);

    private void OnConnectionClosed(TcpConnection connection)
    {
        lock (_gate)
        {
            if (_connections.TryGetValue((ushort)connection.LocalPort, out var tracked)
                && ReferenceEquals(tracked, connection))
            {
                _connections.Remove((ushort)connection.LocalPort);
            }
        }
    }

    private ushort AllocatePortLocked()
    {
        for (var attempt = 0; attempt < EphemeralPortRange; attempt++)
        {
            var candidate = _nextPort++;
            if (_nextPort > ushort.MaxValue)
            {
                _nextPort = FirstEphemeralPort;
            }

            var port = (ushort)candidate;
            if (!_connections.ContainsKey(port))
            {
                return port;
            }
        }

        throw new InvalidOperationException("netstack: no free ephemeral port");
    }

    /// <summary>
    /// Answers a segment that belongs to no connection with a RST, following
    /// RFC 9293 section 3.10.7.1: reset the sequence space rather than the
    /// acknowledgement space when the incoming segment acknowledged something.
    /// </summary>
    private void SendReset(in Ipv4Header ip, in TcpSegment segment)
    {
        if (segment.HasFlag(TcpFlags.Rst))
        {
            return;
        }

        var sink = Volatile.Read(ref _sink);
        if (sink is null)
        {
            return;
        }

        uint sequence;
        uint acknowledgment;
        TcpFlags flags;
        if (segment.HasFlag(TcpFlags.Ack))
        {
            sequence = segment.AcknowledgmentNumber;
            acknowledgment = 0;
            flags = TcpFlags.Rst;
        }
        else
        {
            sequence = 0;
            acknowledgment = segment.SequenceNumber
                + (uint)segment.PayloadLength
                + (segment.HasFlag(TcpFlags.Syn) ? 1u : 0u)
                + (segment.HasFlag(TcpFlags.Fin) ? 1u : 0u);
            flags = TcpFlags.Rst | TcpFlags.Ack;
        }

        var packet = new byte[Ipv4Header.MinHeaderLength + TcpSegment.MinHeaderLength];
        Ipv4Header.Write(packet, _localAddress, ip.SourceAddress, Ipv4Header.TcpProtocol, TcpSegment.MinHeaderLength);
        TcpSegment.Write(
            packet.AsSpan(Ipv4Header.MinHeaderLength),
            segment.DestinationPort,
            segment.SourcePort,
            sequence,
            acknowledgment,
            flags,
            0);
        TcpSegment.FinalizeChecksum(packet.AsSpan(Ipv4Header.MinHeaderLength), _localAddress, ip.SourceAddress);
        sink(packet);
    }
}
