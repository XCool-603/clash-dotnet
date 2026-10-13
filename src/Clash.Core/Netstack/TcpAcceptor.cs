using System.Buffers;
using System.Net;
using System.Threading.Channels;
using Clash.Core.Common;

namespace Clash.Core.Netstack;

/// <summary>
/// The passive half of the userspace TCP stack: it answers a SYN that the
/// operating system sent into the TUN interface and hands the established flow
/// to a consumer as a <see cref="TcpAcceptStream"/>.
/// <para>
/// Why it exists: <see cref="NetstackHost"/> only dials out — every connection it
/// owns begins in SYN-SENT, so a bare inbound SYN is not something it can act on.
/// TUN mode needs the opposite direction, because there the operating system is
/// the client: it opens a socket against a routed destination, the packet lands
/// in the userspace stack, and the stack must complete the handshake as the
/// server. This type owns that half and nothing else.
/// </para>
/// <para>
/// Relationship to <see cref="NetstackHost"/>: siblings, not layers. Both parse
/// an inbound IPv4/TCP datagram the same way, both validate both checksums, and
/// both answer a segment that matches no flow with a RST. A process that needs
/// both directions creates one of each and routes packets to both.
/// </para>
/// <para>
/// Destination addressing: by default only packets addressed to
/// <see cref="NetstackOptions.LocalAddress"/> are accepted, exactly as the host
/// does. A TUN interface carrying synthetic (fake-ip) destinations is addressed
/// to the synthetic address instead, so <see cref="DestinationFilter"/> exists to
/// widen that test. Whatever address the SYN was sent to becomes the source of
/// every reply for that flow, which is what makes the operating system accept the
/// answer and match it to its socket.
/// </para>
/// <para>
/// Threading: <see cref="ProcessPacket"/> is meant to be driven by one packet
/// pump thread. It never blocks and never runs application code — an established
/// flow is queued for <see cref="AcceptAsync"/> instead, so a slow consumer
/// throttles at the backlog rather than stalling the pump. When the backlog is
/// full the newest handshake is reset rather than silently dropped.
/// </para>
/// <para>
/// Deliberately out of scope, as in <see cref="TcpConnection"/>: IPv6, IP
/// fragmentation, TCP options other than MSS, window scaling, SACK, timestamps,
/// congestion control beyond a fixed window, and TIME-WAIT linger. There is no
/// SYN-flood defence either: the handshake table is bounded only by the backlog
/// and by the retransmission limit on a half-open connection.
/// </para>
/// </summary>
public sealed class TcpAcceptor : IAsyncDisposable
{
    /// <summary>
    /// How many established flows may wait in the accept queue before the next
    /// handshake is refused with a reset.
    /// </summary>
    public const int DefaultBacklog = 128;

    /// <summary>Identifies one flow: both endpoints, exactly as a socket would.</summary>
    private readonly record struct FlowKey(
        uint LocalAddress,
        ushort LocalPort,
        uint RemoteAddress,
        ushort RemotePort);

    private readonly Dictionary<FlowKey, TcpPassiveConnection> _connections = [];
    private readonly Channel<TcpAcceptStream> _accepted;
    private readonly Lock _gate = new();
    private readonly NetstackOptions _options;
    private readonly uint _localAddress;
    private Action<ReadOnlyMemory<byte>>? _sink;
    private int _acceptedCount;
    private int _rejectedCount;
    private int _disposed;

    /// <summary>Creates an acceptor.</summary>
    /// <param name="options">Tuning; the defaults are used when null.</param>
    /// <param name="packetSink">
    /// Where outbound IP packets go. It may be assigned later through
    /// <see cref="PacketSink"/>, which is what an adapter constructed in two steps
    /// needs.
    /// </param>
    /// <param name="backlog">How many established flows may wait to be accepted.</param>
    public TcpAcceptor(
        NetstackOptions? options = null,
        Action<ReadOnlyMemory<byte>>? packetSink = null,
        int backlog = DefaultBacklog)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(backlog, 1);

        _options = options ?? new NetstackOptions();
        _options.Validate();
        _localAddress = Ipv4Header.ToNumeric(_options.LocalAddress);
        _sink = packetSink;
        _accepted = Channel.CreateBounded<TcpAcceptStream>(new BoundedChannelOptions(backlog)
        {
            // Wait (rather than DropWrite) so a full queue is reported by TryWrite
            // instead of silently discarding a connection the peer already
            // believes is established.
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = false,
        });
    }

    /// <summary>
    /// The sink that receives every outbound IP packet. Set it to null to drop
    /// outbound packets, in which case a peer will simply time out.
    /// </summary>
    public Action<ReadOnlyMemory<byte>>? PacketSink
    {
        get => Volatile.Read(ref _sink);
        set => Volatile.Write(ref _sink, value);
    }

    /// <summary>
    /// Decides whether a destination address belongs to this stack. When null —
    /// the default — only <see cref="NetstackOptions.LocalAddress"/> is accepted.
    /// Set it to answer for a synthetic (fake-ip) range as well; the address the
    /// SYN carried is then used as the source address of every reply.
    /// </summary>
    public Func<uint, bool>? DestinationFilter { get; set; }

    /// <summary>The address this acceptor answers for when no filter is set.</summary>
    public IPAddress LocalAddress => _options.LocalAddress;

    /// <summary>How many flows are currently tracked, handshakes included.</summary>
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

    /// <summary>How many handshakes have been queued for <see cref="AcceptAsync"/>.</summary>
    public int AcceptedCount => Volatile.Read(ref _acceptedCount);

    /// <summary>How many handshakes were reset because the accept backlog was full.</summary>
    public int RejectedCount => Volatile.Read(ref _rejectedCount);

    /// <summary>
    /// Feeds one IP packet that arrived from the interface. Malformed, non-TCP,
    /// fragmented, mis-addressed and checksum-failing packets are dropped
    /// silently: this runs in the packet pump, where throwing would end every flow
    /// at once.
    /// </summary>
    /// <param name="packet">The complete IPv4 datagram.</param>
    public void ProcessPacket(ReadOnlyMemory<byte> packet)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        var datagram = packet.Span;
        if (!Ipv4Header.TryParse(datagram, out var ip) || ip.IsFragmented)
        {
            return;
        }

        if (ip.Protocol != Ipv4Header.TcpProtocol || !AcceptsAddress(ip.DestinationAddress))
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

        var key = new FlowKey(
            ip.DestinationAddress,
            segment.DestinationPort,
            ip.SourceAddress,
            segment.SourcePort);

        TcpPassiveConnection? connection;
        lock (_gate)
        {
            _connections.TryGetValue(key, out connection);
        }

        if (connection is not null)
        {
            connection.ProcessSegment(ip, segment, segmentBytes.Slice(segment.PayloadOffset, segment.PayloadLength));
            return;
        }

        if (segment.HasFlag(TcpFlags.Syn) && !segment.HasFlag(TcpFlags.Rst))
        {
            // A passive open: the flow is created by the SYN, and the reply
            // address is the address the SYN was sent to, not this stack's own.
            connection = new TcpPassiveConnection(
                _options,
                ip.DestinationAddress,
                ip.SourceAddress,
                segment.DestinationPort,
                segment.SourcePort,
                Emit,
                OnConnectionClosed,
                OnAccepted);

            lock (_gate)
            {
                _connections[key] = connection;
            }

            connection.Start(segment);
            return;
        }

        SendReset(ip, segment);
    }

    /// <summary>
    /// Waits for the next established flow. The returned stream is the caller's to
    /// dispose; disposing it sends a FIN rather than tearing the connection down.
    /// </summary>
    /// <param name="cancellationToken">Cancels the wait; the flow stays queued.</param>
    /// <exception cref="ObjectDisposedException">The acceptor was disposed.</exception>
    public async ValueTask<TcpAcceptStream> AcceptAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        try
        {
            return await _accepted.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            // Disposal completes the queue, which is how a waiting consumer is
            // released rather than left parked forever.
            throw new ObjectDisposedException(nameof(TcpAcceptor));
        }
    }

    /// <summary>
    /// Tears down every flow and releases waiting consumers. Connections are torn
    /// down without a FIN: by the time an acceptor is disposed the interface that
    /// carried the packets is going away too.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        TcpPassiveConnection[] connections;
        lock (_gate)
        {
            connections = [.. _connections.Values];
            _connections.Clear();
        }

        foreach (var connection in connections)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }

        _accepted.Writer.TryComplete();
        Volatile.Write(ref _sink, null);
    }

    private bool AcceptsAddress(uint address)
        => DestinationFilter is { } filter ? filter(address) : address == _localAddress;

    private void Emit(ReadOnlyMemory<byte> packet) => Volatile.Read(ref _sink)?.Invoke(packet);

    /// <summary>
    /// Queues a completed handshake. Called from the connection while it holds its
    /// own lock, so this must not touch any other connection — it only hands the
    /// stream to the queue, and reports false when the queue is full so the
    /// connection can reset itself.
    /// </summary>
    private bool OnAccepted(TcpPassiveConnection connection)
    {
        if (_accepted.Writer.TryWrite(connection.Stream))
        {
            Interlocked.Increment(ref _acceptedCount);
            return true;
        }

        Interlocked.Increment(ref _rejectedCount);
        return false;
    }

    private void OnConnectionClosed(TcpPassiveConnection connection)
    {
        var key = new FlowKey(
            connection.LocalAddressNumeric,
            connection.LocalPort,
            connection.RemoteAddressNumeric,
            connection.RemotePort);

        lock (_gate)
        {
            if (_connections.TryGetValue(key, out var tracked) && ReferenceEquals(tracked, connection))
            {
                _connections.Remove(key);
            }
        }
    }

    /// <summary>
    /// Answers a segment that belongs to no flow with a RST, following RFC 9293
    /// section 3.10.7.1: reset the sequence space rather than the acknowledgement
    /// space when the incoming segment acknowledged something.
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
        Ipv4Header.Write(
            packet,
            ip.DestinationAddress,
            ip.SourceAddress,
            Ipv4Header.TcpProtocol,
            TcpSegment.MinHeaderLength);
        TcpSegment.Write(
            packet.AsSpan(Ipv4Header.MinHeaderLength),
            segment.DestinationPort,
            segment.SourcePort,
            sequence,
            acknowledgment,
            flags,
            0);
        TcpSegment.FinalizeChecksum(
            packet.AsSpan(Ipv4Header.MinHeaderLength),
            ip.DestinationAddress,
            ip.SourceAddress);
        sink(packet);
    }
}

/// <summary>
/// One inbound (passively opened) TCP connection: the server half of RFC 9293's
/// state machine, driven entirely by <see cref="ProcessSegment"/> (inbound) and
/// <see cref="WriteAsync"/> (outbound).
/// <para>
/// Why it is not <see cref="TcpConnection"/>: that type is hard-wired to active
/// open — it allocates its own sequence number, transmits a SYN from
/// <c>Start</c>, and ignores anything that is not a SYN-ACK while it is in
/// SYN-SENT. Passive open is the mirror image (SYN-SENT becomes SYN-RECEIVED, the
/// SYN-ACK is the reply to a peer's SYN rather than the opening move, and the
/// handshake ends on a bare ACK that may carry data). Sharing one state machine
/// between the two directions would mean rewriting the tested one, so this is its
/// own, deliberately narrow implementation.
/// </para>
/// <para>
/// Concurrency: all state is mutated under one lock, and that lock is never held
/// across an <c>await</c>. The packet sink and the accept callback are invoked
/// while the lock is held, so both must be non-blocking and must not call back
/// into the stack — <see cref="TcpAcceptor"/> satisfies that.
/// </para>
/// <para>
/// Out of scope, as in <see cref="TcpConnection"/>: IPv6, congestion control
/// beyond a fixed window, slow start, SACK, timestamps, window scaling, delayed
/// acknowledgements, and TIME-WAIT linger (when both FINs have been exchanged the
/// connection is torn down immediately).
/// </para>
/// </summary>
internal sealed class TcpPassiveConnection : IAsyncDisposable
{
    private enum State
    {
        SynReceived,
        Established,
        CloseWait,
        FinWait1,
        FinWait2,
        Closing,
        LastAck,
        TimeWait,
        Closed,
        Reset,
    }

    /// <summary>A segment this connection sent and must be able to send again.</summary>
    private sealed class OutboundSegment
    {
        /// <summary>Rented buffer holding the complete IP packet.</summary>
        public byte[] Packet = [];

        /// <summary>Number of valid bytes in <see cref="Packet"/>.</summary>
        public int PacketLength;

        /// <summary>Sequence number of the first byte.</summary>
        public uint Sequence;

        /// <summary>Payload length in bytes.</summary>
        public int PayloadLength;

        /// <summary>The SYN bit consumes one sequence number.</summary>
        public bool Syn;

        /// <summary>The FIN bit consumes one sequence number.</summary>
        public bool Fin;

        /// <summary>One past the last sequence number this segment occupies.</summary>
        public uint SequenceEnd => Sequence + (uint)(PayloadLength + (Syn ? 1 : 0) + (Fin ? 1 : 0));
    }

    /// <summary>A rented chunk of received payload.</summary>
    private sealed class InboundChunk(byte[] buffer, int length)
    {
        /// <summary>The rented buffer.</summary>
        public readonly byte[] Buffer = buffer;

        /// <summary>Offset of the first unconsumed byte.</summary>
        public int Offset;

        /// <summary>Number of unconsumed bytes.</summary>
        public int Length = length;
    }

    private readonly Lock _gate = new();
    private readonly NetstackOptions _options;
    private readonly TimeProvider _time;
    private readonly Action<ReadOnlyMemory<byte>> _sink;
    private readonly Action<TcpPassiveConnection> _onClosed;
    private readonly Func<TcpPassiveConnection, bool> _onAccepted;
    private readonly uint _localAddress;
    private readonly uint _remoteAddress;
    private readonly ushort _localPort;
    private readonly ushort _remotePort;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _timerSignal = new(0, 1);
    private readonly SemaphoreSlim _readSignal = new(0, 1);
    private readonly SemaphoreSlim _writeSignal = new(0, 1);
    private readonly List<OutboundSegment> _unacked = [];
    private readonly Queue<InboundChunk> _inbound = [];

    /// <summary>
    /// Out-of-order segments keyed by sequence number. Numeric ordering matches
    /// sequence ordering as long as everything buffered is inside one receive
    /// window, which the byte and segment caps below guarantee.
    /// </summary>
    private readonly SortedDictionary<uint, InboundChunk> _reorder = [];
    private readonly byte[] _scratch = new byte[Ipv4Header.MinHeaderLength + TcpSegment.MaxHeaderLength];

    private State _state = State.SynReceived;
    private uint _iss;
    private uint _sndUna;
    private uint _sndNxt;
    private uint _sndWnd;
    private uint _rcvNxt;
    private uint? _finSequence;
    private int _inboundBytes;
    private int _reorderBytes;
    private int _retransmitAttempts;
    private int _sendMss;
    private int _advertisedWindow;
    private TimeSpan _rto;
    private DateTimeOffset _lastSend;
    private DateTimeOffset? _closeDeadline;
    private bool _peerFin;
    private bool _sentFin;
    private bool _notified;
    private bool _finalized;
    private bool _started;
    private bool _disposed;
    private Exception? _failure;

    internal TcpPassiveConnection(
        NetstackOptions options,
        uint localAddress,
        uint remoteAddress,
        ushort localPort,
        ushort remotePort,
        Action<ReadOnlyMemory<byte>> sink,
        Action<TcpPassiveConnection> onClosed,
        Func<TcpPassiveConnection, bool> onAccepted)
    {
        _options = options;
        _time = options.TimeProvider;
        _localAddress = localAddress;
        _remoteAddress = remoteAddress;
        _localPort = localPort;
        _remotePort = remotePort;
        _sink = sink;
        _onClosed = onClosed;
        _onAccepted = onAccepted;
        _sendMss = options.Mss;
        _rto = options.InitialRetransmitTimeout;
        Stream = new TcpAcceptStream(this);
    }

    /// <summary>The address the peer sent its SYN to; the source of every reply.</summary>
    public uint LocalAddressNumeric => _localAddress;

    /// <summary>The peer's address.</summary>
    public uint RemoteAddressNumeric => _remoteAddress;

    /// <summary>The port the peer connected to.</summary>
    public ushort LocalPort => _localPort;

    /// <summary>The peer's port.</summary>
    public ushort RemotePort => _remotePort;

    /// <summary>The peer this connection was opened by.</summary>
    public IPEndPoint RemoteEndPoint => new(Ipv4Header.ToAddress(_remoteAddress), _remotePort);

    /// <summary>The address and port the peer connected to.</summary>
    public IPEndPoint LocalEndPoint => new(Ipv4Header.ToAddress(_localAddress), _localPort);

    /// <summary>The stream that carries this connection's payload.</summary>
    public TcpAcceptStream Stream { get; }

    /// <summary>True once the connection has been closed or reset.</summary>
    public bool IsClosed
    {
        get
        {
            lock (_gate)
            {
                return _state is State.Closed or State.Reset;
            }
        }
    }

    /// <summary>True once a FIN has been sent, after which no payload can be written.</summary>
    public bool SendClosed
    {
        get
        {
            lock (_gate)
            {
                return _sentFin;
            }
        }
    }

    /// <summary>Answers the peer's SYN with a SYN-ACK and starts the retransmit timer.</summary>
    /// <param name="syn">The SYN that created this connection.</param>
    internal void Start(in TcpSegment syn)
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }

            _started = true;
            _iss = (uint)Random.Shared.NextInt64();
            _sndUna = _iss;
            _sndNxt = _iss + 1;
            _sndWnd = syn.WindowSize;
            _sendMss = syn.HasMss ? Math.Clamp(syn.Mss, 256, _options.Mss) : _options.Mss;
            _rcvNxt = syn.SequenceNumber + 1;
            _state = State.SynReceived;

            // The SYN-ACK is retained, so a peer whose copy was lost gets the same
            // sequence number again rather than a fresh connection.
            TransmitLocked(_iss, _rcvNxt, TcpFlags.Syn | TcpFlags.Ack, default, retain: true);
        }

        _ = RunTimersAsync();
    }

    /// <summary>
    /// Feeds one inbound segment to the state machine. The caller has already
    /// validated the IPv4 and TCP checksums.
    /// </summary>
    /// <param name="ip">The parsed IPv4 header.</param>
    /// <param name="segment">The parsed TCP header.</param>
    /// <param name="payload">The segment payload.</param>
    internal void ProcessSegment(in Ipv4Header ip, in TcpSegment segment, ReadOnlySpan<byte> payload)
    {
        lock (_gate)
        {
            if (_disposed || _finalized)
            {
                return;
            }

            if (segment.SourcePort != _remotePort || ip.SourceAddress != _remoteAddress)
            {
                return;
            }

            if (segment.HasFlag(TcpFlags.Rst))
            {
                AbortLocked(new IOException("netstack: the peer reset the connection"));
                return;
            }

            if (segment.HasFlag(TcpFlags.Syn))
            {
                // A retransmitted SYN means the SYN-ACK was lost: send the same one
                // again instead of starting a second connection.
                if (_state == State.SynReceived && segment.SequenceNumber + 1 == _rcvNxt)
                {
                    RetransmitLocked();
                }

                return;
            }

            if (_state == State.SynReceived)
            {
                if (!segment.HasFlag(TcpFlags.Ack) || segment.AcknowledgmentNumber != _iss + 1)
                {
                    return;
                }

                CompleteHandshakeLocked(segment.WindowSize);
            }

            if (_state is State.Closed or State.Reset)
            {
                return;
            }

            if (segment.HasFlag(TcpFlags.Ack))
            {
                HandleAckLocked(segment.AcknowledgmentNumber, segment.WindowSize);
            }

            if (_state is State.Closed or State.Reset)
            {
                return;
            }

            if (payload.Length > 0)
            {
                AcceptPayloadLocked(segment.SequenceNumber, payload);
            }

            if (segment.HasFlag(TcpFlags.Fin))
            {
                NoteFinLocked(segment.SequenceNumber + (uint)payload.Length);
            }
        }

        if (_finalized)
        {
            _lifetime.Cancel();
        }
    }

    /// <summary>
    /// Reads payload, blocking until data arrives, the peer's FIN is reached, or
    /// the connection fails.
    /// </summary>
    /// <param name="buffer">Destination buffer.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>Bytes read, or zero at end of stream.</returns>
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
        {
            return 0;
        }

        while (true)
        {
            lock (_gate)
            {
                if (_failure is not null)
                {
                    throw _failure;
                }

                if (_inbound.Count > 0)
                {
                    return DrainLocked(buffer.Span);
                }

                if (_peerFin || _finalized || _state is State.Closed or State.Reset)
                {
                    return 0;
                }
            }

            await _readSignal.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Queues payload for transmission, splitting it on the MSS and on whatever
    /// the peer's window currently allows. Returns as soon as the data has been
    /// handed to the packet sink; acknowledgement is tracked separately.
    /// </summary>
    /// <param name="buffer">Payload to send.</param>
    /// <param name="cancellationToken">Cancels a wait for window space.</param>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var remaining = buffer;
        while (!remaining.IsEmpty)
        {
            var written = 0;
            lock (_gate)
            {
                ThrowIfBrokenLocked();
                if (_state is not (State.Established or State.CloseWait))
                {
                    throw new IOException($"netstack: cannot write while the connection is {_state}");
                }

                var usable = (long)_sndWnd - (long)(uint)(_sndNxt - _sndUna);
                if (usable > 0)
                {
                    written = (int)Math.Min(Math.Min(usable, _sendMss), remaining.Length);
                    TransmitLocked(
                        _sndNxt,
                        _rcvNxt,
                        TcpFlags.Ack | TcpFlags.Psh,
                        remaining.Span[..written],
                        retain: true);
                    _sndNxt += (uint)written;
                    remaining = remaining[written..];
                }
            }

            if (_finalized)
            {
                _lifetime.Cancel();
            }

            if (written == 0)
            {
                // The peer's window is closed; an acknowledgement that opens it, or
                // a reset, will wake us.
                await _writeSignal.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Sends a FIN and stops accepting writes, while leaving reads working so the
    /// peer's remaining data can still be drained.
    /// </summary>
    public void ShutdownSend()
    {
        lock (_gate)
        {
            ShutdownSendLocked();
        }

        if (_finalized)
        {
            _lifetime.Cancel();
        }
    }

    /// <summary>
    /// Graceful close: a FIN when the connection is still open, otherwise nothing.
    /// Returns immediately rather than waiting for the peer's FIN; the connection
    /// tears itself down when the handshake completes or
    /// <see cref="NetstackOptions.CloseTimeout"/> expires.
    /// </summary>
    public void Close() => ShutdownSend();

    /// <summary>
    /// Tears the connection down without a FIN. This is the acceptor's shutdown
    /// path, not something a well-behaved caller needs.
    /// </summary>
    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return ValueTask.CompletedTask;
            }

            _disposed = true;
            if (_state is not (State.Closed or State.Reset))
            {
                _state = State.Reset;
                _failure ??= new IOException("netstack: the connection was disposed");
            }

            FinalizeLocked();
            WakeAllLocked();
            _onClosed(this);
        }

        _lifetime.Cancel();
        return ValueTask.CompletedTask;
    }

    private static bool SeqLessThan(uint a, uint b) => (int)(a - b) < 0;

    private static bool SeqLessThanOrEqual(uint a, uint b) => (int)(a - b) <= 0;

    /// <summary>
    /// The peer's acknowledgement of the SYN-ACK: the handshake is finished, so
    /// the flow is published to the accept queue.
    /// </summary>
    private void CompleteHandshakeLocked(ushort window)
    {
        _sndUna = _iss + 1;
        _sndWnd = window;
        TrimAcknowledgedLocked();
        _retransmitAttempts = 0;
        _rto = _options.InitialRetransmitTimeout;
        _state = State.Established;

        if (_notified)
        {
            return;
        }

        _notified = true;
        if (!_onAccepted(this))
        {
            // Nobody is listening: refuse the connection rather than leaving the
            // peer to believe it is established.
            AbortLocked(new IOException("netstack: the accept backlog is full"), sendReset: true);
        }
    }

    private void HandleAckLocked(uint acknowledgment, ushort window)
    {
        if (SeqLessThan(_sndUna, acknowledgment) && SeqLessThanOrEqual(acknowledgment, _sndNxt))
        {
            _sndUna = acknowledgment;
            TrimAcknowledgedLocked();
            _retransmitAttempts = 0;
            _rto = _options.InitialRetransmitTimeout;
            WakeLocked(_writeSignal);
        }

        if (window != _sndWnd)
        {
            var grew = window > _sndWnd;
            _sndWnd = window;
            if (grew)
            {
                WakeLocked(_writeSignal);
            }
        }

        if (_sndUna != _sndNxt)
        {
            return;
        }

        switch (_state)
        {
            case State.FinWait1:
                _state = State.FinWait2;
                SetCloseDeadlineLocked();
                break;
            case State.Closing:
            case State.LastAck:
                CloseLocked();
                break;
            default:
                break;
        }
    }

    private void AcceptPayloadLocked(uint sequence, ReadOnlySpan<byte> payload)
    {
        if (SeqLessThan(sequence, _rcvNxt))
        {
            var overlap = (int)(_rcvNxt - sequence);
            if (overlap >= payload.Length)
            {
                // A pure duplicate: re-acknowledge so the peer stops retrying.
                SendAckLocked();
                return;
            }

            sequence = _rcvNxt;
            payload = payload[overlap..];
        }

        if (SeqLessThan(_rcvNxt, sequence))
        {
            BufferOutOfOrderLocked(sequence, payload);
            SendAckLocked();
            return;
        }

        if (!DeliverLocked(payload))
        {
            // The window is full; drop and re-acknowledge so the peer retries once
            // the application has drained what is already buffered.
            SendAckLocked();
            return;
        }

        _rcvNxt += (uint)payload.Length;
        FlushReorderLocked();
        TryCompleteFinLocked();
        SendAckLocked();
    }

    private void BufferOutOfOrderLocked(uint sequence, ReadOnlySpan<byte> payload)
    {
        if (_reorder.ContainsKey(sequence))
        {
            return;
        }

        if (_reorderBytes + payload.Length > _options.MaxReorderBytes
            || _reorder.Count >= _options.MaxReorderSegments)
        {
            // Bounded memory wins over completeness: the duplicate acknowledgement
            // this segment triggers makes the peer resend it later.
            return;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(payload.Length);
        payload.CopyTo(buffer);
        _reorder[sequence] = new InboundChunk(buffer, payload.Length);
        _reorderBytes += payload.Length;
    }

    private void FlushReorderLocked()
    {
        while (_reorder.Count > 0)
        {
            var key = 0u;
            InboundChunk? chunk = null;
            foreach (var pair in _reorder)
            {
                key = pair.Key;
                chunk = pair.Value;
                break;
            }

            if (chunk is null)
            {
                return;
            }

            if (SeqLessThan(key, _rcvNxt))
            {
                _reorder.Remove(key);
                _reorderBytes -= chunk.Length;
                ArrayPool<byte>.Shared.Return(chunk.Buffer);
                continue;
            }

            if (key != _rcvNxt)
            {
                return;
            }

            _reorder.Remove(key);
            _reorderBytes -= chunk.Length;
            if (!DeliverChunkLocked(chunk))
            {
                ArrayPool<byte>.Shared.Return(chunk.Buffer);
                return;
            }

            _rcvNxt += (uint)chunk.Length;
        }
    }

    private bool DeliverLocked(ReadOnlySpan<byte> payload)
    {
        if (_inboundBytes + payload.Length > _options.ReceiveWindowSize)
        {
            return false;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(payload.Length);
        payload.CopyTo(buffer);
        _inbound.Enqueue(new InboundChunk(buffer, payload.Length));
        _inboundBytes += payload.Length;
        WakeLocked(_readSignal);
        return true;
    }

    private bool DeliverChunkLocked(InboundChunk chunk)
    {
        if (_inboundBytes + chunk.Length > _options.ReceiveWindowSize)
        {
            return false;
        }

        _inbound.Enqueue(chunk);
        _inboundBytes += chunk.Length;
        WakeLocked(_readSignal);
        return true;
    }

    private int DrainLocked(Span<byte> destination)
    {
        var copied = 0;
        while (copied < destination.Length && _inbound.Count > 0)
        {
            var chunk = _inbound.Peek();
            var take = Math.Min(chunk.Length, destination.Length - copied);
            chunk.Buffer.AsSpan(chunk.Offset, take).CopyTo(destination[copied..]);
            chunk.Offset += take;
            chunk.Length -= take;
            copied += take;

            if (chunk.Length == 0)
            {
                _inbound.Dequeue();
                ArrayPool<byte>.Shared.Return(chunk.Buffer);
            }
        }

        _inboundBytes -= copied;

        if (copied > 0)
        {
            var window = CurrentWindowLocked();
            if (_advertisedWindow == 0 && window > 0 || _advertisedWindow - window >= _options.Mss)
            {
                // A window update, so a peer that stopped sending on a zero window
                // learns that room is available again.
                SendAckLocked();
            }
        }

        return copied;
    }

    private void NoteFinLocked(uint finSequence)
    {
        if (_peerFin)
        {
            return;
        }

        if (_finSequence is not { } existing || SeqLessThan(finSequence, existing))
        {
            _finSequence = finSequence;
        }

        TryCompleteFinLocked();
    }

    private void TryCompleteFinLocked()
    {
        if (_peerFin || _finSequence is not { } finSequence || finSequence != _rcvNxt)
        {
            return;
        }

        _peerFin = true;
        _rcvNxt = finSequence + 1;

        switch (_state)
        {
            case State.Established:
                _state = State.CloseWait;
                break;
            case State.FinWait1:
                _state = State.Closing;
                break;
            case State.FinWait2:
                _state = State.TimeWait;
                break;
            default:
                break;
        }

        SendAckLocked();
        WakeLocked(_readSignal);

        if (_state == State.TimeWait)
        {
            CloseLocked();
        }
    }

    private void ShutdownSendLocked()
    {
        if (_disposed || _finalized)
        {
            return;
        }

        switch (_state)
        {
            case State.Established:
                SendFinLocked();
                _state = State.FinWait1;
                SetCloseDeadlineLocked();
                break;
            case State.CloseWait:
                SendFinLocked();
                _state = State.LastAck;
                SetCloseDeadlineLocked();
                break;
            case State.SynReceived:
                AbortLocked(new IOException("netstack: the connection was closed during the handshake"));
                break;
            default:
                break;
        }
    }

    private void SendFinLocked()
    {
        TransmitLocked(_sndNxt, _rcvNxt, TcpFlags.Fin | TcpFlags.Ack, default, retain: true);
        _sndNxt += 1;
        _sentFin = true;
    }

    private void SendAckLocked()
    {
        if (_state is State.SynReceived or State.Closed or State.Reset || _finalized)
        {
            return;
        }

        TransmitLocked(_sndNxt, _rcvNxt, TcpFlags.Ack, default, retain: false);
        _advertisedWindow = CurrentWindowLocked();
    }

    private void TrimAcknowledgedLocked()
    {
        while (_unacked.Count > 0)
        {
            var head = _unacked[0];
            if (!SeqLessThanOrEqual(head.SequenceEnd, _sndUna))
            {
                break;
            }

            _unacked.RemoveAt(0);
            ArrayPool<byte>.Shared.Return(head.Packet);
        }
    }

    private int CurrentWindowLocked()
    {
        var window = _options.ReceiveWindowSize - _inboundBytes;
        return window < 0 ? 0 : Math.Min(window, ushort.MaxValue);
    }

    /// <summary>
    /// Builds and emits one segment. When <paramref name="retain"/> is set the
    /// packet is kept until it is acknowledged so the timer can resend it; a
    /// header-only packet reuses a scratch buffer instead of renting.
    /// </summary>
    private void TransmitLocked(
        uint sequenceNumber,
        uint acknowledgmentNumber,
        TcpFlags flags,
        ReadOnlySpan<byte> payload,
        bool retain)
    {
        var includeMss = flags.HasFlag(TcpFlags.Syn) && _options.Mss > 0;
        var tcpHeaderLength = includeMss ? TcpSegment.MinHeaderLength + TcpSegment.MssOptionLength : TcpSegment.MinHeaderLength;
        var packetLength = Ipv4Header.MinHeaderLength + tcpHeaderLength + payload.Length;

        var buffer = retain || packetLength > _scratch.Length
            ? ArrayPool<byte>.Shared.Rent(packetLength)
            : _scratch;

        var packet = buffer.AsSpan(0, packetLength);
        Ipv4Header.Write(
            packet,
            _localAddress,
            _remoteAddress,
            Ipv4Header.TcpProtocol,
            tcpHeaderLength + payload.Length);
        var written = TcpSegment.Write(
            packet[Ipv4Header.MinHeaderLength..],
            _localPort,
            _remotePort,
            sequenceNumber,
            acknowledgmentNumber,
            flags,
            (ushort)CurrentWindowLocked(),
            includeMss ? _options.Mss : -1);
        payload.CopyTo(packet[(Ipv4Header.MinHeaderLength + written)..]);
        TcpSegment.FinalizeChecksum(packet[Ipv4Header.MinHeaderLength..], _localAddress, _remoteAddress);

        if (retain)
        {
            _unacked.Add(new OutboundSegment
            {
                Packet = buffer,
                PacketLength = packetLength,
                Sequence = sequenceNumber,
                PayloadLength = payload.Length,
                Syn = flags.HasFlag(TcpFlags.Syn),
                Fin = flags.HasFlag(TcpFlags.Fin),
            });
            _lastSend = _time.GetUtcNow();
            SignalTimerLocked();
        }

        try
        {
            _sink(buffer.AsMemory(0, packetLength));
        }
        catch (Exception)
        {
            // A sink that throws must not take the caller's packet loop down; a
            // retained segment is simply retransmitted by the timer.
        }
        finally
        {
            if (!retain && !ReferenceEquals(buffer, _scratch))
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    /// <summary>Re-emits everything still unacknowledged, oldest first.</summary>
    private void RetransmitLocked()
    {
        _lastSend = _time.GetUtcNow();

        foreach (var segment in _unacked)
        {
            try
            {
                _sink(segment.Packet.AsMemory(0, segment.PacketLength));
            }
            catch (Exception)
            {
                // As in TransmitLocked: a broken sink is not fatal here.
            }
        }
    }

    private async Task RunTimersAsync()
    {
        var token = _lifetime.Token;
        try
        {
            while (!token.IsCancellationRequested)
            {
                TimeSpan delay;
                lock (_gate)
                {
                    if (_disposed || _finalized)
                    {
                        return;
                    }

                    delay = NextTimerDelayLocked();
                }

                if (delay == Timeout.InfiniteTimeSpan)
                {
                    await _timerSignal.WaitAsync(token).ConfigureAwait(false);
                    continue;
                }

                if (delay > TimeSpan.Zero
                    && await _timerSignal.WaitAsync(delay, token).ConfigureAwait(false))
                {
                    // Woken early because the state changed; recompute the delay.
                    continue;
                }

                lock (_gate)
                {
                    if (_disposed || _finalized)
                    {
                        return;
                    }

                    OnTimerLocked();
                }

                if (_finalized)
                {
                    _lifetime.Cancel();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The connection ended; the timer has nothing left to do.
        }
        catch (ObjectDisposedException)
        {
            // Same.
        }
    }

    private TimeSpan NextTimerDelayLocked()
    {
        var now = _time.GetUtcNow();
        TimeSpan? due = null;

        if (_unacked.Count > 0)
        {
            var at = _lastSend + _rto;
            due = at <= now ? TimeSpan.Zero : at - now;
        }

        if (_closeDeadline is { } deadline)
        {
            var remaining = deadline <= now ? TimeSpan.Zero : deadline - now;
            if (due is null || remaining < due)
            {
                due = remaining;
            }
        }

        return due ?? Timeout.InfiniteTimeSpan;
    }

    private void OnTimerLocked()
    {
        var now = _time.GetUtcNow();

        if (_unacked.Count > 0 && now - _lastSend >= _rto)
        {
            if (_retransmitAttempts >= _options.MaxRetransmitAttempts)
            {
                // A half-open connection the peer never finished is torn down here,
                // which is what keeps a lost SYN-ACK from leaking a flow.
                AbortLocked(
                    new IOException("netstack: the peer stopped acknowledging; retransmission limit reached"),
                    sendReset: true);
                return;
            }

            _retransmitAttempts++;
            _rto = TimeSpan.FromTicks(Math.Min(_rto.Ticks * 2, _options.MaxRetransmitTimeout.Ticks));
            RetransmitLocked();
            return;
        }

        if (_closeDeadline is { } deadline && now >= deadline)
        {
            AbortLocked(new IOException("netstack: the peer did not finish closing in time"));
        }
    }

    private void SetCloseDeadlineLocked()
    {
        _closeDeadline ??= _time.GetUtcNow() + _options.CloseTimeout;
        SignalTimerLocked();
    }

    private void CloseLocked()
    {
        if (_state is State.Closed or State.Reset)
        {
            return;
        }

        _state = State.Closed;
        FinalizeLocked();
        WakeAllLocked();
        _onClosed(this);
    }

    private void AbortLocked(Exception failure, bool sendReset = false)
    {
        if (_state is State.Closed or State.Reset)
        {
            return;
        }

        if (sendReset)
        {
            TransmitLocked(_sndNxt, _rcvNxt, TcpFlags.Rst | TcpFlags.Ack, default, retain: false);
        }

        _state = State.Reset;
        _failure = failure;
        FinalizeLocked();
        WakeAllLocked();
        _onClosed(this);
    }

    private void ThrowIfBrokenLocked()
    {
        if (_failure is not null)
        {
            throw _failure;
        }

        if (_finalized || _state is State.Closed or State.Reset)
        {
            throw new IOException("netstack: the connection is closed");
        }
    }

    /// <summary>Returns every pooled buffer and marks the connection unusable.</summary>
    private void FinalizeLocked()
    {
        if (_finalized)
        {
            return;
        }

        _finalized = true;

        foreach (var segment in _unacked)
        {
            ArrayPool<byte>.Shared.Return(segment.Packet);
        }

        _unacked.Clear();

        while (_inbound.Count > 0)
        {
            ArrayPool<byte>.Shared.Return(_inbound.Dequeue().Buffer);
        }

        _inboundBytes = 0;

        foreach (var chunk in _reorder.Values)
        {
            ArrayPool<byte>.Shared.Return(chunk.Buffer);
        }

        _reorder.Clear();
        _reorderBytes = 0;
    }

    private void SignalTimerLocked() => WakeLocked(_timerSignal);

    private void WakeAllLocked()
    {
        WakeLocked(_timerSignal);
        WakeLocked(_readSignal);
        WakeLocked(_writeSignal);
    }

    private static void WakeLocked(SemaphoreSlim semaphore)
    {
        if (semaphore.CurrentCount == 0)
        {
            try
            {
                semaphore.Release();
            }
            catch (SemaphoreFullException)
            {
                // Another thread got there first; the waiter will re-check state.
            }
        }
    }
}

/// <summary>
/// A <see cref="Stream"/> over one accepted (passively opened) connection, so the
/// tunnel can relay an inbound TUN flow exactly like any other stream.
/// <para>
/// Why it is a real stream rather than an <c>IPacketConnection</c>: the tunnel
/// relays with <see cref="Stream"/> pumps and relies on half-close to let a
/// response drain after the request is finished. This type implements
/// <see cref="IHalfCloseable"/> so <c>ShutdownSend</c> becomes a FIN instead of a
/// teardown, and it is disposable without blocking: <see cref="Dispose"/> sends
/// the FIN and returns, leaving the connection to finish closing in the
/// background under <see cref="NetstackOptions.CloseTimeout"/>.
/// </para>
/// <para>
/// It also carries the endpoints, because that is the only place the tunnel can
/// learn the destination the operating system actually asked for: for an accepted
/// flow that is <see cref="LocalEndPoint"/>, not the address the proxy connected
/// to.
/// </para>
/// </summary>
public sealed class TcpAcceptStream : Stream, IHalfCloseable
{
    private readonly TcpPassiveConnection _connection;
    private int _disposed;

    internal TcpAcceptStream(TcpPassiveConnection connection) => _connection = connection;

    /// <summary>The peer that opened the connection.</summary>
    public IPEndPoint RemoteEndPoint => _connection.RemoteEndPoint;

    /// <summary>The address and port the peer connected to.</summary>
    public IPEndPoint LocalEndPoint => _connection.LocalEndPoint;

    /// <summary>The port the peer connected to.</summary>
    public int LocalPort => _connection.LocalPort;

    /// <inheritdoc />
    public override bool CanRead => Volatile.Read(ref _disposed) == 0;

    /// <inheritdoc />
    public override bool CanWrite => Volatile.Read(ref _disposed) == 0 && !_connection.SendClosed;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public void ShutdownSend()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        _connection.ShutdownSend();
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateRange(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    }

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
        => ReadAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _connection.ReadAsync(buffer, cancellationToken);
    }

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ValidateRange(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
    {
        ValidateRange(buffer, offset, count);
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    }

    /// <inheritdoc />
    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _connection.WriteAsync(buffer, cancellationToken);
    }

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ValidateRange(buffer, offset, count);
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc />
    public override void Flush()
    {
        // Every write is emitted immediately; there is nothing buffered here.
    }

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>
    /// Closes the flow gracefully: a FIN is sent when the connection is still open,
    /// and the peer's remaining data is discarded. The connection finishes closing
    /// in the background.
    /// </summary>
    /// <param name="disposing">True when called from user code.</param>
    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _connection.Close();
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    public override ValueTask DisposeAsync()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    private static void ValidateRange(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (buffer.Length - offset < count)
        {
            throw new ArgumentException("offset and count exceed the buffer length");
        }
    }
}
