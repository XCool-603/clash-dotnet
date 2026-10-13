using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Netstack;
using Clash.Core.Tunnel;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Tun;

/// <summary>
/// The packet side of a TUN device: whole IP packets in, whole IP packets out.
/// <para>
/// The relay is written against this seam rather than against
/// <see cref="TunAdapter"/> directly for two reasons. A Wintun session needs an
/// administrator process, so anything that touches the driver cannot be unit
/// tested; and the read blocks on a driver event, so the pump must own a thread
/// instead of a thread-pool work item. <see cref="DelegateTunPacketDevice"/> is
/// the one-line bridge to a real session.
/// </para>
/// </summary>
public interface ITunPacketDevice
{
    /// <summary>
    /// Reads one IP packet. Returns the number of bytes copied, or 0 when the
    /// timeout expired. The implementation may block the calling thread.
    /// </summary>
    int Read(Span<byte> destination, int timeoutMilliseconds);

    /// <summary>Hands one complete IP packet back to the device.</summary>
    void Write(ReadOnlySpan<byte> packet);
}

/// <summary>A blocking packet read, e.g. <c>TunAdapter.Read</c>.</summary>
public delegate int TunPacketReader(Span<byte> destination, int timeoutMilliseconds);

/// <summary>A packet write, e.g. <c>TunAdapter.Write</c>.</summary>
public delegate void TunPacketWriter(ReadOnlySpan<byte> packet);

/// <summary>
/// Wraps a pair of delegates as an <see cref="ITunPacketDevice"/>, so a
/// <see cref="TunAdapter"/> can drive the relay without the adapter having to
/// know about it: <c>new DelegateTunPacketDevice(session.Read, session.Write)</c>.
/// </summary>
public sealed class DelegateTunPacketDevice : ITunPacketDevice
{
    private readonly TunPacketReader _read;
    private readonly TunPacketWriter _write;

    /// <summary>Creates the device from its two operations.</summary>
    /// <param name="read">Blocking packet read; see <see cref="ITunPacketDevice.Read"/>.</param>
    /// <param name="write">Packet write; see <see cref="ITunPacketDevice.Write"/>.</param>
    public DelegateTunPacketDevice(TunPacketReader read, TunPacketWriter write)
    {
        _read = read ?? throw new ArgumentNullException(nameof(read));
        _write = write ?? throw new ArgumentNullException(nameof(write));
    }

    /// <inheritdoc />
    public int Read(Span<byte> destination, int timeoutMilliseconds) => _read(destination, timeoutMilliseconds);

    /// <inheritdoc />
    public void Write(ReadOnlySpan<byte> packet) => _write(packet);
}

/// <summary>
/// Receives the packets the UDP relay does not consume, so one device read can
/// feed both halves of the inbound: a Wintun session has a single read ring, and
/// this relay is its reader.
/// </summary>
/// <param name="packet">
/// A complete IP packet, valid only for the duration of the call: it points into
/// the relay's pooled read buffer.
/// </param>
public delegate void TunPacketObserver(ReadOnlyMemory<byte> packet);

/// <summary>
/// Answers one hijacked DNS query. Returns the encoded response to send back, or
/// null when the query must be dropped (malformed, or a response already).
/// </summary>
/// <param name="query">The raw DNS message carried by the hijacked datagram.</param>
/// <param name="source">The client that sent it.</param>
/// <param name="cancellationToken">Cancels the lookup.</param>
public delegate Task<ReadOnlyMemory<byte>?> TunDnsHijackHandler(
    ReadOnlyMemory<byte> query,
    IPEndPoint source,
    CancellationToken cancellationToken);

/// <summary>
/// The UDP half of the Windows TUN inbound.
/// <para>
/// It owns the device's packet pump: every IPv4/UDP datagram the host routes
/// into the adapter is either answered locally (when its destination matches
/// <c>tun.dns-hijack</c>) or handed to the tunnel's UDP path, and every reply
/// comes back out as a complete IP/UDP packet addressed to the client that sent
/// the datagram.
/// </para>
/// <para>
/// Direction conventions follow the rest of the project (see
/// <c>NatPacketConnection</c>): the association handed to
/// <see cref="ITunnel.HandleUdpAsync"/> yields a datagram with its
/// <see cref="PacketResult.Remote"/> set to the destination the client asked
/// for, and <see cref="IPacketConnection.SendAsync"/> is the reply path, where
/// the destination argument is the endpoint the reply arrived from.
/// </para>
/// <para>
/// Scope: IPv4 only, which is what the user-space stack in
/// <c>Clash.Core.Netstack</c> carries. TCP packets are not carried here — the
/// acceptor owns them, and they are handed over through
/// <see cref="TunPacketObserver"/> so one device read can feed both halves of the
/// inbound. A datagram whose IP header checksum is wrong is dropped rather than
/// guessed at, but the UDP checksum is deliberately not enforced on the way in: a
/// NIC with checksum offload may hand the host stack a zero checksum, and
/// dropping real traffic is worse than relaying it.
/// </para>
/// </summary>
public sealed class TunUdpRelay : IAsyncDisposable
{
    /// <summary>The IP protocol number of UDP.</summary>
    public const byte UdpProtocol = 17;

    /// <summary>How long one blocking read waits before the pump re-checks its token.</summary>
    private const int ReadTimeoutMilliseconds = 200;

    /// <summary>How long the tunnel's UDP handler is given to stop when the pump ends.</summary>
    private static readonly TimeSpan TunnelShutdownTimeout = TimeSpan.FromSeconds(2);

    // Constant drop reasons: the packet path must not allocate a string for every
    // packet the relay is not responsible for, which on a busy adapter is most of them.
    private const string MalformedPacket = "a packet that is not a valid IPv4 datagram";
    private const string NotUdpPacket = "a packet that is not UDP and has no observer to hand it to";
    private const string FragmentedPacket = "an IP fragment";
    private const string TruncatedDatagram = "a truncated UDP datagram";
    private const string UnroutableReply = "a reply whose addresses are not IPv4";
    private const string OversizedReply = "a reply that does not fit one IP datagram";
    private const string OrphanReply = "a reply with no client to send it to";

    private readonly ITunPacketDevice _device;
    private readonly ITunnel _tunnel;
    private readonly TunDnsHijackHandler _dnsHandler;
    private readonly IDnsCodec _codec;
    private readonly DnsHijackMatcher _dnsHijack;
    private readonly TunPacketObserver? _observer;
    private readonly ILogger? _logger;
    private readonly string? _inboundName;
    private readonly UdpAssociation _association;
    private readonly CancellationTokenSource _lifetime = new();

    private CancellationTokenRegistration _externalCancellation;
    private Task? _pump;
    private int _disposed;
    private long _datagramsForwarded;
    private long _queriesHijacked;
    private long _repliesWritten;
    private long _packetsDropped;

    /// <summary>Creates the relay. Nothing is read until <see cref="Start"/> is called.</summary>
    /// <param name="device">The TUN session, or a fake in tests.</param>
    /// <param name="tunnel">Where non-hijacked datagrams are routed.</param>
    /// <param name="tun">The <c>tun</c> section, for <c>dns-hijack</c>.</param>
    /// <param name="dnsHandler">
    /// Answers hijacked queries; defaults to the tunnel's resolver, which is what
    /// answers fake-IP allocations without leaving the process.
    /// </param>
    /// <param name="inboundName">Listener name reported on the API's connections.</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="codec">DNS codec; defaults to <see cref="DnsCodec"/>.</param>
    /// <param name="observer">
    /// Receives the packets this relay does not consume (TCP, and any other
    /// protocol), which is how the acceptor shares the device's single read ring.
    /// </param>
    public TunUdpRelay(
        ITunPacketDevice device,
        ITunnel tunnel,
        TunConfig tun,
        TunDnsHijackHandler? dnsHandler = null,
        string? inboundName = null,
        ILogger? logger = null,
        IDnsCodec? codec = null,
        TunPacketObserver? observer = null)
    {
        _device = device ?? throw new ArgumentNullException(nameof(device));
        _tunnel = tunnel ?? throw new ArgumentNullException(nameof(tunnel));
        ArgumentNullException.ThrowIfNull(tun);

        _logger = logger;
        _inboundName = inboundName;
        _codec = codec ?? new DnsCodec();
        _dnsHandler = dnsHandler ?? AnswerFromResolverAsync;
        _dnsHijack = DnsHijackMatcher.Parse(tun.DnsHijack, ReportInvalidHijack);
        _observer = observer;
        _association = new UdpAssociation(this);
    }

    /// <summary>Datagrams handed to the tunnel's UDP path.</summary>
    public long DatagramsForwarded => Interlocked.Read(ref _datagramsForwarded);

    /// <summary>DNS queries matched by <c>dns-hijack</c> and answered locally.</summary>
    public long QueriesHijacked => Interlocked.Read(ref _queriesHijacked);

    /// <summary>IP packets written back to the device.</summary>
    public long RepliesWritten => Interlocked.Read(ref _repliesWritten);

    /// <summary>Packets that were not ours to carry, or were malformed.</summary>
    public long PacketsDropped => Interlocked.Read(ref _packetsDropped);

    /// <summary>True while the pump is running.</summary>
    public bool IsRunning => _pump is { IsCompleted: false };

    /// <summary>True when at least one <c>dns-hijack</c> pattern applies to UDP.</summary>
    public bool DnsHijackEnabled => !_dnsHijack.IsEmpty;

    /// <summary>
    /// Starts the packet pump on a dedicated thread, because a driver read blocks.
    /// </summary>
    /// <param name="cancellationToken">Stops the pump as well as <see cref="DisposeAsync"/>.</param>
    /// <returns>The pump task, which completes when the relay stops.</returns>
    public Task Start(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (_pump is not null)
        {
            throw new InvalidOperationException("the TUN UDP relay is already running");
        }

        if (cancellationToken.CanBeCanceled)
        {
            _externalCancellation = cancellationToken.Register(static state => Cancel(((TunUdpRelay)state!)._lifetime), this);
        }

        _pump = Task.Factory.StartNew(
            () => Pump(_lifetime.Token),
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);

        return _pump;
    }

    /// <summary>Stops the pump and waits for it, without disposing the relay.</summary>
    public async ValueTask StopAsync()
    {
        Cancel(_lifetime);

        var pump = _pump;
        if (pump is not null)
        {
            try
            {
                await pump.WaitAsync(TunnelShutdownTimeout + TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // A stalled device read must not hold shutdown open.
            }
        }

        _externalCancellation.Dispose();
        _pump = null;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await StopAsync().ConfigureAwait(false);
        await _association.DisposeAsync().ConfigureAwait(false);
        _lifetime.Dispose();
        GC.SuppressFinalize(this);
    }

    // ── The pump ────────────────────────────────────────────────────────────

    /// <summary>
    /// The device read loop. It runs synchronously on the dedicated thread
    /// <see cref="Start"/> created; the tunnel's handler and the DNS answers run
    /// on the thread pool so a slow lookup can never stall packet intake.
    /// </summary>
    private void Pump(CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(WintunInterop.MaxIpPacketSize);
        Task? tunnelTask = null;

        try
        {
            var metadata = new Metadata
            {
                Network = Network.Udp,
                InboundType = "tun",
                InboundName = _inboundName,
            };

            tunnelTask = Task.Run(
                () => _tunnel.HandleUdpAsync(_association, metadata, cancellationToken),
                CancellationToken.None);

            while (!cancellationToken.IsCancellationRequested)
            {
                int read;
                try
                {
                    read = _device.Read(buffer, ReadTimeoutMilliseconds);
                }
                catch (Exception error)
                {
                    if (!cancellationToken.IsCancellationRequested)
                    {
                        _logger?.LogWarning(error, "tun: reading from the adapter failed; the UDP relay is stopping");
                    }

                    break;
                }

                if (read <= 0)
                {
                    continue;
                }

                try
                {
                    HandlePacket(buffer.AsMemory(0, read));
                }
                catch (Exception error)
                {
                    // One hostile datagram must never take the pump down.
                    Drop("a datagram that could not be handled", error);
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);

            // Completing the queue is what lets the tunnel's receive loop end
            // even when it never observed the cancellation token.
            _association.Complete();
            if (tunnelTask is not null) WaitForTunnel(tunnelTask);

            try
            {
                _association.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            catch (Exception)
            {
                // Nothing left to release.
            }
        }
    }

    private void WaitForTunnel(Task tunnelTask)
    {
        try
        {
            if (!tunnelTask.Wait(TunnelShutdownTimeout))
            {
                _logger?.LogDebug(
                    "tun: the tunnel's UDP handler did not stop within {Seconds}s",
                    TunnelShutdownTimeout.TotalSeconds);
            }
        }
        catch (Exception)
        {
            // Cancellation, or the handler faulted while shutting down.
        }
    }

    private void HandlePacket(ReadOnlyMemory<byte> packet)
    {
        var span = packet.Span;

        if (!Ipv4Header.TryParse(span, out var header))
        {
            Drop(MalformedPacket);
            return;
        }

        if (header.Protocol != UdpProtocol)
        {
            // TCP belongs to the acceptor; anything else is not ours to carry.
            if (_observer is not null)
            {
                _observer(packet);
                return;
            }

            Drop(NotUdpPacket);
            return;
        }

        if (header.IsFragmented)
        {
            // A fragment carries no ports, and reassembly belongs to the host stack.
            Drop(FragmentedPacket);
            return;
        }

        if (!TryParseUdp(span[header.HeaderLength..header.TotalLength], out var datagram))
        {
            Drop(TruncatedDatagram);
            return;
        }

        var source = new IPEndPoint(header.Source, datagram.SourcePort);
        var destination = new IPEndPoint(header.Destination, datagram.DestinationPort);

        if (_dnsHijack.Matches(destination))
        {
            Interlocked.Increment(ref _queriesHijacked);

            // Deliberately not awaited: a lookup that goes upstream must not
            // stop the pump from draining the adapter.
            _ = AnswerQueryAsync(datagram.Payload, source, destination, _lifetime.Token);
            return;
        }

        Interlocked.Increment(ref _datagramsForwarded);
        _association.Forward(datagram.Payload, source, destination);
    }

    // ── DNS hijack ──────────────────────────────────────────────────────────

    private async Task AnswerQueryAsync(byte[] query, IPEndPoint source, IPEndPoint destination, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _dnsHandler(query, source, cancellationToken).ConfigureAwait(false);
            if (response is not { } wire || wire.IsEmpty)
            {
                return;
            }

            // The answer must look like it came from the address the client
            // asked, or the host's resolver will discard it.
            WriteReply(wire.Span, destination, source);
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
        catch (Exception error)
        {
            _logger?.LogDebug(error, "tun: answering a hijacked DNS query from {Source} failed", source);
        }
    }

    /// <summary>
    /// The default hijack handler: decode, ask the tunnel's resolver, encode.
    /// In <c>fake-ip</c> mode the resolver allocates from the fake range and
    /// answers without any upstream exchange, which is the point of the hijack.
    /// </summary>
    private async Task<ReadOnlyMemory<byte>?> AnswerFromResolverAsync(
        ReadOnlyMemory<byte> query,
        IPEndPoint source,
        CancellationToken cancellationToken)
    {
        DnsMessage decoded;
        try
        {
            decoded = _codec.Decode(query.Span);
        }
        catch (DnsException error)
        {
            _logger?.LogDebug("tun: dropping a malformed DNS query from {Source}: {Message}", source, error.Message);
            return null;
        }

        if (decoded.IsResponse)
        {
            return null;
        }

        var response = await _tunnel.Dns.ExchangeAsync(decoded, cancellationToken).ConfigureAwait(false);

        // The resolver preserves the id itself; it is the one field a client
        // always checks, so it is not left to chance.
        response.Id = decoded.Id;
        return _codec.Encode(response);
    }

    private void ReportInvalidHijack(string message)
        => _logger?.LogWarning("tun: dns-hijack entry {Message}", message);

    // ── The reply path ──────────────────────────────────────────────────────

    /// <summary>
    /// Writes one IP/UDP packet back to the device, addressed as a reply from
    /// <paramref name="from"/> to <paramref name="to"/>.
    /// </summary>
    private void WriteReply(ReadOnlySpan<byte> payload, IPEndPoint from, IPEndPoint to)
    {
        if (from.Address.AddressFamily != AddressFamily.InterNetwork
            || to.Address.AddressFamily != AddressFamily.InterNetwork)
        {
            // The adapter carries IPv4; a reply for anything else cannot be framed.
            Drop(UnroutableReply);
            return;
        }

        var total = Ipv4Header.MinHeaderLength + TunUdpPacket.UdpHeaderLength + payload.Length;
        if (total > ushort.MaxValue)
        {
            Drop(OversizedReply);
            return;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            var packet = buffer.AsSpan(0, total);
            var source = Ipv4Header.ToNumeric(from.Address);
            var destination = Ipv4Header.ToNumeric(to.Address);

            Ipv4Header.Write(packet, source, destination, UdpProtocol, TunUdpPacket.UdpHeaderLength + payload.Length);
            TunUdpPacket.Write(
                packet[Ipv4Header.MinHeaderLength..],
                (ushort)from.Port,
                (ushort)to.Port,
                payload,
                source,
                destination);

            _device.Write(packet);
            Interlocked.Increment(ref _repliesWritten);
        }
        catch (Exception error)
        {
            Drop("writing a reply to the adapter", error);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool TryParseUdp(ReadOnlySpan<byte> payload, out UdpDatagram datagram)
    {
        datagram = default;

        if (payload.Length < TunUdpPacket.UdpHeaderLength)
        {
            return false;
        }

        var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(payload);
        var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(payload[2..]);
        var length = BinaryPrimitives.ReadUInt16BigEndian(payload[4..]);

        if (length < TunUdpPacket.UdpHeaderLength || length > payload.Length)
        {
            return false;
        }

        // The payload is copied because the read buffer is reused by the next packet.
        datagram = new UdpDatagram(sourcePort, destinationPort, payload[TunUdpPacket.UdpHeaderLength..length].ToArray());
        return true;
    }

    private void Drop(string reason)
    {
        Interlocked.Increment(ref _packetsDropped);
        _logger?.LogDebug("tun: dropped {Reason}", reason);
    }

    private void Drop(string reason, Exception error)
    {
        Interlocked.Increment(ref _packetsDropped);
        _logger?.LogDebug(error, "tun: dropped {Reason}", reason);
    }

    private static void Cancel(CancellationTokenSource source)
    {
        try
        {
            source.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already torn down.
        }
    }

    private readonly record struct UdpDatagram(ushort SourcePort, ushort DestinationPort, byte[] Payload);

    // ── The association the tunnel drives ───────────────────────────────────

    /// <summary>
    /// The <see cref="IPacketConnection"/> handed to
    /// <see cref="ITunnel.HandleUdpAsync"/>: the pump's datagrams go into a queue,
    /// and the tunnel's replies come back out of <see cref="SendAsync"/> as
    /// finished IP packets.
    /// <para>
    /// Reply routing is keyed by the endpoint a reply arrived from, with the most
    /// recent client as the fallback — the same NAT convention
    /// <c>NatPacketConnection</c> uses for TPROXY. Two clients addressing the same
    /// remote endpoint at the same time therefore share one mapping, which is a
    /// limitation of that convention rather than of this type.
    /// </para>
    /// </summary>
    private sealed class UdpAssociation : IPacketConnection
    {
        private readonly record struct Datagram(byte[] Payload, IPEndPoint Destination);

        private readonly TunUdpRelay _relay;
        private readonly Channel<Datagram> _inbound = Channel.CreateUnbounded<Datagram>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
        private readonly ConcurrentDictionary<string, IPEndPoint> _clients = new(StringComparer.Ordinal);

        private IPEndPoint? _lastClient;
        private int _disposed;

        public UdpAssociation(TunUdpRelay relay) => _relay = relay;

        /// <inheritdoc />
        public bool SupportsMultipleDestinations => true;

        /// <inheritdoc />
        public EndPoint? LocalEndPoint => null;

        /// <summary>The client of the most recent datagram, for diagnostics.</summary>
        public IPEndPoint? LastClient => Volatile.Read(ref _lastClient);

        /// <summary>Queues one datagram for the tunnel, remembering where replies go.</summary>
        public void Forward(byte[] payload, IPEndPoint source, IPEndPoint destination)
        {
            _clients[destination.ToString()] = source;
            Volatile.Write(ref _lastClient, source);

            if (!_inbound.Writer.TryWrite(new Datagram(payload, destination)))
            {
                _relay.Drop("a datagram that arrived after the association closed");
            }
        }

        /// <inheritdoc />
        public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (await _inbound.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (_inbound.Reader.TryRead(out var datagram))
                {
                    var length = Math.Min(datagram.Payload.Length, buffer.Length);
                    datagram.Payload.AsSpan(0, length).CopyTo(buffer.Span);

                    // Remote is the destination the client asked for, not the client.
                    return new PacketResult(length, datagram.Destination);
                }
            }

            return new PacketResult(0, null);
        }

        /// <inheritdoc />
        public ValueTask<int> SendAsync(ReadOnlyMemory<byte> payload, EndPoint destination, CancellationToken cancellationToken = default)
        {
            if (payload.IsEmpty || destination is not IPEndPoint remote)
            {
                return ValueTask.FromResult(0);
            }

            var client = ClientFor(destination);
            if (client is null)
            {
                _relay.Drop(OrphanReply);
                return ValueTask.FromResult(0);
            }

            _relay.WriteReply(payload.Span, remote, client);
            return ValueTask.FromResult(payload.Length);
        }

        /// <summary>Stops accepting datagrams; the reader then sees end-of-stream.</summary>
        public void Complete() => _inbound.Writer.TryComplete();

        /// <inheritdoc />
        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return ValueTask.CompletedTask;
            }

            _inbound.Writer.TryComplete();
            _clients.Clear();
            Volatile.Write(ref _lastClient, null);
            return ValueTask.CompletedTask;
        }

        private IPEndPoint? ClientFor(EndPoint destination)
        {
            if (_clients.TryGetValue(destination.ToString() ?? string.Empty, out var client))
            {
                return client;
            }

            return Volatile.Read(ref _lastClient);
        }
    }
}

/// <summary>
/// The UDP framing this relay writes: an 8-byte header plus the RFC 768 checksum
/// over the pseudo-header, which is the one part of the packet the driver will
/// not compute for us.
/// </summary>
internal static class TunUdpPacket
{
    /// <summary>Length of a UDP header with no options.</summary>
    public const int UdpHeaderLength = 8;

    /// <summary>
    /// Writes a UDP header and payload into <paramref name="destination"/>, which
    /// must be at least <see cref="UdpHeaderLength"/> plus the payload long.
    /// </summary>
    /// <param name="destination">Where the datagram is framed.</param>
    /// <param name="sourcePort">Source port.</param>
    /// <param name="destinationPort">Destination port.</param>
    /// <param name="payload">The datagram's payload.</param>
    /// <param name="sourceAddress">Source address as a numeric dotted-quad value.</param>
    /// <param name="destinationAddress">Destination address as a numeric dotted-quad value.</param>
    public static void Write(
        Span<byte> destination,
        ushort sourcePort,
        ushort destinationPort,
        ReadOnlySpan<byte> payload,
        uint sourceAddress,
        uint destinationAddress)
    {
        var length = UdpHeaderLength + payload.Length;
        if (destination.Length < length)
        {
            throw new ArgumentException($"a {length}-byte datagram does not fit the buffer", nameof(destination));
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(destination[4..], (ushort)length);

        // Zero while summing: a zero field is what the checksum is defined over.
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..], 0);
        payload.CopyTo(destination[UdpHeaderLength..]);

        var sum = InternetChecksum.Accumulate(0, destination[..length]) + PseudoHeader(sourceAddress, destinationAddress, length);
        var checksum = InternetChecksum.Complete(sum);

        // A computed zero is transmitted as all ones: in UDP a zero checksum
        // means "not computed", so it can never be sent as a real value.
        BinaryPrimitives.WriteUInt16BigEndian(destination[6..], checksum == 0 ? (ushort)0xFFFF : checksum);
    }

    /// <summary>The IPv4 pseudo-header sum for a UDP datagram of <paramref name="udpLength"/> bytes.</summary>
    public static uint PseudoHeader(uint sourceAddress, uint destinationAddress, int udpLength)
        => (sourceAddress >> 16)
           + (sourceAddress & 0xFFFF)
           + (destinationAddress >> 16)
           + (destinationAddress & 0xFFFF)
           + TunUdpRelay.UdpProtocol
           + (uint)udpLength;
}

/// <summary>
/// The <c>tun.dns-hijack</c> patterns, matched against an IPv4 destination.
/// <para>
/// Supported forms, which are the ones mihomo accepts for this key:
/// <c>any:53</c>, <c>0.0.0.0:53</c>, <c>8.8.8.8:53</c>, a CIDR such as
/// <c>198.18.0.0/16:53</c>, and the same with a <c>udp://</c> or <c>tcp://</c>
/// prefix. A missing port means every port. A <c>tcp://</c> entry is kept out of
/// the way of this relay, and an IPv6 entry is reported as having no effect
/// because the adapter carries IPv4 only.
/// </para>
/// </summary>
internal sealed class DnsHijackMatcher
{
    private readonly List<Entry> _entries;

    private DnsHijackMatcher(List<Entry> entries) => _entries = entries;

    /// <summary>True when no pattern can ever match, so no query is hijacked.</summary>
    public bool IsEmpty => _entries.Count == 0;

    /// <summary>Number of usable patterns.</summary>
    public int Count => _entries.Count;

    /// <summary>The patterns, for diagnostics.</summary>
    public IReadOnlyList<string> Patterns => [.. _entries.Select(entry => entry.Raw)];

    /// <summary>
    /// Parses the configured patterns. Entries that cannot be understood are
    /// reported through <paramref name="onInvalid"/> and skipped: a typo in one
    /// entry must not stop the relay from serving the others.
    /// </summary>
    public static DnsHijackMatcher Parse(IEnumerable<string>? patterns, Action<string>? onInvalid = null)
    {
        var entries = new List<Entry>();
        if (patterns is null)
        {
            return new DnsHijackMatcher(entries);
        }

        foreach (var raw in patterns)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            var value = raw.Trim();
            var udp = true;

            var scheme = value.IndexOf("://", StringComparison.Ordinal);
            if (scheme > 0)
            {
                var kind = value[..scheme].Trim().ToLowerInvariant();
                value = value[(scheme + 3)..];

                if (kind == "tcp")
                {
                    udp = false;
                }
                else if (kind != "udp")
                {
                    onInvalid?.Invoke($"'{raw}' names an unknown transport '{kind}'; the entry is ignored");
                    continue;
                }
            }

            if (!udp)
            {
                // A TCP-only hijack is the acceptor's business, not this relay's.
                continue;
            }

            if (!TrySplitHostPort(value, out var host, out var port) || port is < 0 or > ushort.MaxValue)
            {
                onInvalid?.Invoke($"'{raw}' is not a host:port pattern; the entry is ignored");
                continue;
            }

            // Lowercased because the wildcard forms are words, and a config that
            // spells them "ANY" means the same thing.
            host = host.Trim().ToLowerInvariant();
            if (host is "any" or "*" or "" or "0.0.0.0")
            {
                entries.Add(new Entry { AnyAddress = true, Port = port ?? 0, Raw = raw });
                continue;
            }

            var slash = host.IndexOf('/');
            var addressPart = slash >= 0 ? host[..slash] : host;
            var prefix = 32;

            if (slash >= 0 && (!int.TryParse(host[(slash + 1)..], out prefix) || prefix is < 0 or > 32))
            {
                onInvalid?.Invoke($"'{raw}' has a prefix length the IPv4 relay cannot use; the entry is ignored");
                continue;
            }

            if (!IPAddress.TryParse(addressPart, out var address))
            {
                onInvalid?.Invoke($"'{raw}' does not name an address; the entry is ignored");
                continue;
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (!address.IsIPv4MappedToIPv6)
                {
                    onInvalid?.Invoke($"'{raw}' is an IPv6 pattern; the TUN UDP relay carries IPv4, so the entry has no effect");
                    continue;
                }

                address = address.MapToIPv4();
            }

            entries.Add(new Entry
            {
                Network = Ipv4Header.ToNumeric(address),
                Prefix = prefix,
                Port = port ?? 0,
                Raw = raw,
            });
        }

        return new DnsHijackMatcher(entries);
    }

    /// <summary>True when <paramref name="destination"/> is a query this relay answers itself.</summary>
    public bool Matches(IPEndPoint destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var address = Ipv4Header.ToNumeric(destination.Address);

        foreach (var entry in _entries)
        {
            if (entry.Matches(address, destination.Port))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Splits <c>host:port</c>, <c>host</c>, <c>[v6]:port</c> or <c>[v6]</c>.</summary>
    private static bool TrySplitHostPort(string value, out string host, out int? port)
    {
        port = null;

        if (value.StartsWith('['))
        {
            var close = value.IndexOf(']');
            if (close < 0)
            {
                host = value;
                return false;
            }

            host = value[1..close];
            var rest = value[(close + 1)..];
            if (rest.Length == 0)
            {
                return true;
            }

            if (!rest.StartsWith(':') || !int.TryParse(rest[1..], out var bracketed))
            {
                host = value;
                return false;
            }

            port = bracketed;
            return true;
        }

        var colon = value.LastIndexOf(':');
        if (colon < 0 || value.IndexOf(':') != colon)
        {
            // No port, or a bare IPv6 literal, which needs brackets to carry one.
            host = value;
            return true;
        }

        host = value[..colon];
        if (!int.TryParse(value[(colon + 1)..], out var parsed))
        {
            host = value;
            return false;
        }

        port = parsed;
        return true;
    }

    private static bool InPrefix(uint address, uint network, int prefix)
    {
        if (prefix <= 0)
        {
            return true;
        }

        if (prefix >= 32)
        {
            return address == network;
        }

        var mask = uint.MaxValue << (32 - prefix);
        return (address & mask) == (network & mask);
    }

    private sealed class Entry
    {
        /// <summary>True for <c>any</c>: every address matches.</summary>
        public bool AnyAddress { get; init; }

        /// <summary>The network address, as a numeric dotted-quad value.</summary>
        public uint Network { get; init; }

        /// <summary>Prefix length of the entry's network.</summary>
        public int Prefix { get; init; }

        /// <summary>Port to match, or 0 for every port.</summary>
        public int Port { get; init; }

        /// <summary>The configured text, for diagnostics.</summary>
        public string Raw { get; init; } = string.Empty;

        public bool Matches(uint address, int port)
        {
            if (Port != 0 && Port != port)
            {
                return false;
            }

            return AnyAddress || InPrefix(address, Network, Prefix);
        }
    }
}
