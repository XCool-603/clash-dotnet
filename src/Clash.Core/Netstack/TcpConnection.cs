using System.Buffers;
using System.Net;

namespace Clash.Core.Netstack;

/// <summary>
/// One outbound TCP connection: the client half of RFC 9293's state machine,
/// driven entirely by <see cref="ProcessSegment"/> (inbound) and
/// <see cref="WriteAsync"/> (outbound).
/// <para>
/// Why it exists: a WireGuard outbound is layer 3. It can carry raw IP packets
/// but has no notion of a socket, so a TCP flow has to be terminated in user
/// space and re-emitted as segments. This class is that termination point — it
/// sits beside <see cref="Clash.Core.Common.IPacketConnection"/> rather than
/// replacing it, and it deliberately speaks only the subset of TCP that an
/// outbound HTTP/TLS client needs.
/// </para>
/// <para>
/// Concurrency: all state is mutated under one lock, and that lock is never held
/// across an <c>await</c>. The packet sink is invoked while the lock is held, so
/// a sink must copy synchronously and must not call back into the stack (the
/// adapter in this folder satisfies both).
/// </para>
/// <para>
/// Deliberately out of scope, so that nobody assumes otherwise: IPv6, listening
/// or accepting, congestion control beyond a fixed window, slow start, SACK,
/// timestamps, window scaling, path-MTU discovery, TCP Fast Open, Nagle-style
/// coalescing, delayed acknowledgements, and any kernel-bypass behaviour. There
/// is no TIME_WAIT linger either: when both FINs have been exchanged the
/// connection is torn down immediately, and a late duplicate is answered by the
/// host's RST path.
/// </para>
/// </summary>
public sealed class TcpConnection : IAsyncDisposable
{
    private enum State
    {
        SynSent,
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
    private readonly Action<ReadOnlyMemory<byte>> _sink;
    private readonly Action<TcpConnection> _onClosed;
    private readonly TimeProvider _time;
    private readonly uint _localAddress;
    private readonly uint _remoteAddress;
    private readonly ushort _localPort;
    private readonly ushort _remotePort;
    private readonly TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _timerSignal = new(0, 1);
    private readonly SemaphoreSlim _readSignal = new(0, 1);
    private readonly SemaphoreSlim _writeSignal = new(0, 1);
    private readonly List<OutboundSegment> _unacked = [];
    private readonly Queue<InboundChunk> _inbound = new();

    /// <summary>
    /// Out-of-order segments keyed by sequence number. Numeric ordering matches
    /// sequence ordering as long as everything buffered is inside one receive
    /// window, which the byte and segment caps below guarantee.
    /// </summary>
    private readonly SortedDictionary<uint, InboundChunk> _reorder = [];
    private readonly byte[] _scratch = new byte[Ipv4Header.MinHeaderLength + TcpSegment.MaxHeaderLength];

    private State _state = State.SynSent;
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
    private bool _finalized;
    private bool _started;
    private bool _disposed;
    private Exception? _failure;

    internal TcpConnection(
        NetstackOptions options,
        uint localAddress,
        IPEndPoint remote,
        ushort localPort,
        Action<ReadOnlyMemory<byte>> sink,
        Action<TcpConnection> onClosed)
    {
        _options = options;
        _time = options.TimeProvider;
        _localAddress = localAddress;
        _remoteAddress = Ipv4Header.ToNumeric(remote.Address);
        _remotePort = (ushort)remote.Port;
        _localPort = localPort;
        _sink = sink;
        _onClosed = onClosed;
        _sendMss = options.Mss;
        _rto = options.InitialRetransmitTimeout;
        Stream = new TcpFlowStream(this);
    }

    /// <summary>The peer this connection talks to.</summary>
    public IPEndPoint RemoteEndPoint => new(Ipv4Header.ToAddress(_remoteAddress), _remotePort);

    /// <summary>The ephemeral local port this connection was given.</summary>
    public int LocalPort => _localPort;

    /// <summary>The stream that carries this connection's payload.</summary>
    public TcpFlowStream Stream { get; }

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

    /// <summary>
    /// Completes when the handshake has finished, or faults with the reason it
    /// did not (a reset, a retransmission limit, or cancellation).
    /// </summary>
    public Task Connected => _connected.Task;

    /// <summary>Sends the initial SYN and starts the retransmission timer.</summary>
    internal void Start()
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }

            _started = true;
            _iss = NextInitialSequenceNumber();
            _sndUna = _iss;
            _sndNxt = _iss;
            TransmitLocked(_iss, 0, TcpFlags.Syn, default, retain: true);
            _sndNxt = _iss + 1;
        }

        _ = RunTimersAsync();
    }

    /// <summary>Waits for the handshake to finish.</summary>
    /// <param name="cancellationToken">Cancels the wait; the connection is then the caller's to dispose.</param>
    public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        => await _connected.Task.WaitAsync(cancellationToken).ConfigureAwait(false);

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
                HandleSynLocked(in segment);
                return;
            }

            if (_state == State.SynSent)
            {
                // Nothing but a SYN-ACK is meaningful before the handshake ends.
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
                // The peer's window is closed; an acknowledgement that opens it,
                // or a reset, will wake us.
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
    /// Tears the connection down without a FIN. This is the host's shutdown path,
    /// not something a well-behaved caller needs.
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
                _connected.TrySetException(_failure);
            }

            FinalizeLocked();
            WakeAllLocked();
            _onClosed(this);
        }

        _lifetime.Cancel();
        return ValueTask.CompletedTask;
    }

    private static uint NextInitialSequenceNumber() => (uint)Random.Shared.NextInt64();

    private static bool SeqLessThan(uint a, uint b) => (int)(a - b) < 0;

    private static bool SeqLessThanOrEqual(uint a, uint b) => (int)(a - b) <= 0;

    private void HandleSynLocked(in TcpSegment segment)
    {
        if (_state != State.SynSent)
        {
            return;
        }

        if (!segment.HasFlag(TcpFlags.Ack) || segment.AcknowledgmentNumber != _iss + 1)
        {
            return;
        }

        _sndUna = segment.AcknowledgmentNumber;
        _sndWnd = segment.WindowSize;
        _sendMss = segment.HasMss ? Math.Clamp(segment.Mss, 256, _options.Mss) : _options.Mss;
        TrimAcknowledgedLocked();
        _retransmitAttempts = 0;
        _rto = _options.InitialRetransmitTimeout;
        _rcvNxt = segment.SequenceNumber + 1;
        _state = State.Established;
        _connected.TrySetResult();
        SendAckLocked();
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
            // The window is full; drop and re-acknowledge so the peer retries
            // once the application has drained what is already buffered.
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
            case State.SynSent:
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
        if (_state is State.SynSent or State.Closed or State.Reset || _finalized)
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
                AbortLocked(
                    new IOException("netstack: the peer stopped acknowledging; retransmission limit reached"),
                    sendReset: true);
                return;
            }

            _retransmitAttempts++;
            _rto = TimeSpan.FromTicks(Math.Min(_rto.Ticks * 2, _options.MaxRetransmitTimeout.Ticks));
            _lastSend = now;

            // Go-back-N: everything still unacknowledged goes out again, oldest
            // first. With a bounded window this is at most a few dozen segments.
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
        _connected.TrySetException(failure);
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
